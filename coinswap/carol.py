from __future__ import print_function
import jmbitcoin as btc
from jmclient import estimate_tx_fee
from twisted.internet import reactor, task
from txjsonrpc.web.jsonrpc import Proxy
from txjsonrpc.web import jsonrpc
from twisted.web import server
from .btscript import *
from .configure import get_log
from decimal import Decimal
import binascii
import time
import os
import random
import abc
import sys
from pprint import pformat
import json
from coinswap import (CoinSwapException, CoinSwapPublicParameters,
                      CoinSwapParticipant, CoinSwapTX, CoinSwapTX01,
                      CoinSwapTX23, CoinSwapTX45, CoinSwapRedeemTX23Secret,
                      CoinSwapRedeemTX23Timeout, COINSWAP_SECRET_ENTROPY_BYTES,
                      get_coinswap_secret, get_current_blockheight,
                      create_hash_script, get_secret_from_vin,
                      generate_escrow_redeem_script, cs_single,
                      get_transactions_from_block)

cslog = get_log()

class CoinSwapCarol(CoinSwapParticipant):
    """
    State machine:
    State 0: pre-initialisation
    State 1: handshake complete
    State 2: Parameter negotiation complete.
    ========SETUP PHASE===============================
    State 3: TX0id, H(x), TX2sig received from Alice.
    State 4: TX1id, TX2sig, TX3sig sent to Alice.
    State 5: TX3 sig received and TX0 seen confirmed.
    State 6: TX1 broadcast and confirmed.
    ==================================================
    
    ========REDEEM PHASE==============================
    State 7: X received.
    State 8: Sent TX5 sig.
    State 9: TX4 sig received valid from Alice.
    State 10: TX4 broadcast.
    ==================================================
    """
    required_key_names = ["key_2_2_AC_1", "key_2_2_CB_0",
                                  "key_TX2_secret", "key_TX3_lock"]

    def consume_nonce(self, nonce):
        """Keep track of nonces for this session to prevent
        a replay attack.
        """
        if nonce in self.consumed_nonces:
            return False
        self.consumed_nonces.append(nonce)
        return True

    def validate_alice_sig(self, sig, msg):
        return btc.ecdsa_verify(str(msg), sig,
                self.coinswap_parameters.pubkeys["key_session"])

    def get_rpc_response(self, cmethod, paramlist):
        try:
            response_method = getattr(self, "jsonrpc_" + cmethod)
        except:
            return (False, "Method not found: " + str(cmethod))
        return response_method(*paramlist)

    def jsonrpc_negotiate(self, *alice_parameter_list):
        """Receive Alice's half of the public parameters,
        and return our half if acceptable.
        """
        return self.sm.tick(alice_parameter_list)

    def jsonrpc_tx0id_hx_tx2sig(self, *params):
        return self.sm.tick(*params)

    def jsonrpc_sigtx3(self, sig):
        return self.sm.tick(sig)

    def jsonrpc_phase2_ready(self):
        return self.is_phase2_ready()

    def jsonrpc_secret(self, secret):
        return self.sm.tick(secret)

    def jsonrpc_sigtx4(self, sig, txid5):
        return self.sm.tick(sig, txid5)

    def jsonrpc_confirm_tx4(self):
        return self.is_tx4_confirmed()

    def get_state_machine_callbacks(self):
        return [(self.handshake, False, -1),
                (self.negotiate_coinswap_parameters, False, -1),
                (self.receive_tx0_hash_tx2sig, False, -1),
                (self.send_tx1id_tx2_sig_tx3_sig, True, -1),
                (self.receive_tx3_sig, False, -1),
                 #alice waits for confirms before sending secret; this accounts
                 #for propagation delays.
                (self.push_tx1, False,
                 cs_single().one_confirm_timeout * cs_single().config.getint(
                     "TIMEOUT", "tx01_confirm_wait")),
                #we also wait for the confirms our side
                (self.receive_secret, False,
                 cs_single().one_confirm_timeout * cs_single().config.getint(
                     "TIMEOUT", "tx01_confirm_wait")),
                 #alice waits for confirms on TX5 before sending TX4 sig
                (self.send_tx5_sig, True, -1),
                (self.receive_tx4_sig, False, cs_single().one_confirm_timeout),
                (self.broadcast_tx4, True, -1)]

    def set_handshake_parameters(self):
        """Sets the conditions under which Carol is
        prepared to do a coinswap.
        """
        c = cs_single().config
        self.source_chain = c.get("SERVER", "source_chain")
        self.destination_chain = c.get("SERVER", "destination_chain")
        self.minimum_amount = c.getint("SERVER", "minimum_amount")
        self.maximum_amount = c.getint("SERVER", "maximum_amount")

    def handshake(self, alice_handshake):
        """Check that the proposed coinswap parameters
        are acceptable.
        """
        self.set_handshake_parameters()
        self.bbmb = self.wallet.get_balance_by_mixdepth(verbose=False)
        try:
            d = alice_handshake[3]
            if d["coinswapcs_version"] != cs_single().CSCS_VERSION:
                return (False, "wrong CoinSwapCS version, was: " + \
                        str(d["coinswapcs_version"]) + ", should be: " + \
                        str(cs_single().CSCS_VERSION))
            #Allow client to decide how long to wait, but within our range:
            tx01min, tx01max = [int(x) for x in cs_single().config.get(
                "SERVER", "tx01_confirm_range").split(",")]
            if not isinstance(d["tx01_confirm_wait"], int):
                return (False, "Invalid type confirm wait type (should be int)")
            if d["tx01_confirm_wait"] < tx01min or d["tx01_confirm_wait"] > tx01max:
                return (False, "Mismatched tx01_confirm_wait, was: " + str(
                    d["tx01_confirm_wait"]))
            self.coinswap_parameters.set_tx01_confirm_wait(d["tx01_confirm_wait"])
            self.sm.reset_timeouts([5, 6], cs_single().one_confirm_timeout * d[
                "tx01_confirm_wait"])
            if not "key_session" in d:
                #TODO validate that it's a real pubkey
                return (False, "no session key from Alice")
            if d["source_chain"] != self.source_chain:
                return (False, "source chain was wrong: " + d["source_chain"])
            if d["destination_chain"] != self.destination_chain:
                return (False, "destination chain was wrong: " + d[
                    "destination_chain"])
            if not isinstance(d["amount"], int):
                return (False, "Invalid amount type (should be int)")
            if d["amount"] < self.minimum_amount:
                return (False, "Requested amount too small: " + str(d["amount"]))
            if d["amount"] > self.maximum_amount:
                return (False, "Requested amount too large: " + str(d["amount"]))
            self.coinswap_parameters.set_base_amount(d["amount"])
            if not isinstance(d["bitcoin_fee"], int):
                return (False, "Invalid type for bitcoin fee, should be int.")
            if d["bitcoin_fee"] < estimate_tx_fee((1, 2, 2), 1,
                                                  txtype='p2shMofN')/2.0:
                return (False, "Suggested bitcoin transaction fee is too low.")
            if d["bitcoin_fee"] > estimate_tx_fee((1, 2, 2), 1,
                                                  txtype='p2shMofN')*2.0:
                return (False, "Suggested bitcoin transaction fee is too high.")
            self.coinswap_parameters.set_bitcoin_fee(d["bitcoin_fee"])
            #set the session pubkey for authorising future requests
            self.coinswap_parameters.set_pubkey("key_session", d["key_session"])
        except Exception as e:
            return (False,
                    "Error parsing handshake from counterparty, ignoring: " + \
                    repr(e))
        return (self.coinswap_parameters.session_id,
                "Handshake parameters from Alice accepted")

    def negotiate_coinswap_parameters(self, params):
        #receive parameters and ephemeral keys, destination address from Alice.
        #Send back ephemeral keys and destination address, or rejection,
        #if invalid, to Alice.
        for k in self.required_key_names:
            self.coinswap_parameters.set_pubkey(k, self.keyset[k][1])
        try:
            self.coinswap_parameters.set_pubkey("key_2_2_AC_0", params[0])
            self.coinswap_parameters.set_pubkey("key_2_2_CB_1", params[1])
            self.coinswap_parameters.set_pubkey("key_TX2_lock", params[2])
            self.coinswap_parameters.set_pubkey("key_TX3_secret", params[3])
            #Client's locktimes must be in the acceptable range.
            cbh = get_current_blockheight()
            serverlockrange = cs_single().config.get("SERVER",
                                                     "server_locktime_range")
            serverlockmin, serverlockmax = [
                int(x) for x in serverlockrange.split(",")]
            clientlockrange = cs_single().config.get("SERVER",
                                                     "client_locktime_range")
            clientlockmin, clientlockmax = [
                int(x) for x in clientlockrange.split(",")]
            if params[4] not in range(cbh + clientlockmin, cbh + clientlockmax+1):
                return (False, "Counterparty LOCK0 out of range")
            if params[5] not in range(cbh + serverlockmin, cbh + serverlockmax+1):
                return (False, "Counterparty LOCK1 out of range")
            #This is enforced in CoinSwapPublicParameters with assert, it must
            #not trigger in the server from external input.
            if params[4] <= params[5]:
                return (False, "LOCK1 must be before LOCK0")
            self.coinswap_parameters.set_timeouts(params[4], params[5])
            self.coinswap_parameters.set_addr_data(addr5=params[6])
        except Exception as e:
            return (False,
                    "Invalid parameter set from counterparty, abandoning: " + \
                    repr(e))

        #on receipt of valid response, complete the CoinswapPublicParameters instance
        for k in self.required_key_names:
            self.coinswap_parameters.set_pubkey(k, self.keyset[k][1])
        if not self.coinswap_parameters.is_complete():
            cslog.debug("addresses: " + str(self.coinswap_parameters.addresses_complete))
            cslog.debug("pubkeys: " + str(self.coinswap_parameters.pubkeys_complete))
            cslog.debug("timeouts: " + str(self.coinswap_parameters.timeouts_complete))
            return (False, "Coinswap parameters is not complete")
        #Calculate the fee required for the swap now we have valid data.
        #The coinswap fee is assessed against the base amount proposed by the client.
        self.coinswap_parameters.set_coinswap_fee(
            self.coinswap_parameters.fee_policy.get_fee(
            self.coinswap_parameters.base_amount))
        #Calculate a one time blinding amount for this coinswap within the
        #configured max and min
        bl_amt = random.randint(cs_single().config.getint("SERVER", "blinding_amount_min"),
                                cs_single().config.getint("SERVER", "blinding_amount_max"))
        #TODO check that we can serve an amount up to base_amt + bl_amt + csfee;
        #otherwise need to retry selecting a blinding factor (or do something more
        #intelligent).
        self.coinswap_parameters.set_blinding_amount(bl_amt)
        #first entry confirms acceptance of parameters
        to_send = [True,
        self.coinswap_parameters.pubkeys["key_2_2_AC_1"],
        self.coinswap_parameters.pubkeys["key_2_2_CB_0"],
        self.coinswap_parameters.pubkeys["key_TX2_secret"],
        self.coinswap_parameters.pubkeys["key_TX3_lock"],
        self.coinswap_parameters.output_addresses["tx4_address"],
        self.coinswap_parameters.coinswap_fee,
        self.coinswap_parameters.blinding_amount,
        self.coinswap_parameters.output_addresses["tx2_carol_address"],
        self.coinswap_parameters.output_addresses["tx3_carol_address"],
        self.coinswap_parameters.output_addresses["tx5_carol_address"],
        self.coinswap_parameters.session_id]
        #We can now initiate file logging also; .log will be automatically appended
        cs_single().logs_path = os.path.join(cs_single().homedir, "logs", self.state_file)
        return (to_send, "OK")

    def receive_tx0_hash_tx2sig(self, txid0, hashed_secret, tx2sig):
        """On receipt of a utxo for TX0, a hashed secret, and a sig for TX2,
        construct TX2, verify the provided signature, create our own sig,
        construct TX3, create our own sig,
        return back to Alice, the txid1, the sig of TX2 and the sig of TX3.
        """
        self.txid0 = txid0
        self.hashed_secret = hashed_secret
        #**CONSTRUCT TX2**
        #,using TXID0 as input; note "txid0" is a utxo string
        self.tx2 = CoinSwapTX23.from_params(
            self.coinswap_parameters.pubkeys["key_2_2_AC_0"],
                self.coinswap_parameters.pubkeys["key_2_2_AC_1"],
                self.coinswap_parameters.pubkeys["key_TX2_secret"],
                utxo_in=self.txid0,
                recipient_amount=self.coinswap_parameters.tx2_amounts["script"],
                hashed_secret=self.hashed_secret,
                absolutelocktime=self.coinswap_parameters.timeouts["LOCK0"],
                refund_pubkey=self.coinswap_parameters.pubkeys["key_TX2_lock"],
        carol_only_address=self.coinswap_parameters.output_addresses["tx2_carol_address"],
        carol_only_amount=self.coinswap_parameters.tx2_amounts["carol"])
        if not self.tx2.include_signature(0, tx2sig):
            return (False, "Counterparty sig for TX2 invalid; backing out.")
        #create our own signature for it
        self.tx2.sign_at_index(self.keyset["key_2_2_AC_1"][0], 1)
        self.tx2.attach_signatures()
        self.watch_for_tx(self.tx2)
        return (True, "OK")

    def send_tx1id_tx2_sig_tx3_sig(self):
        our_tx2_sig = self.tx2.signatures[0][1]

        #**CONSTRUCT TX1**
        #This call can throw insufficient funds; handled by backout.
        #But, this should be avoided (see handshake). At least, any
        #throw here will not cause fees for client.
        print('wallet used coins is: ', self.wallet.used_coins)
        self.initial_utxo_inputs = self.wallet.select_utxos(0,
                                    self.coinswap_parameters.tx1_amount,
                                    utxo_filter=self.wallet.used_coins)
        #Lock these coins; only unlock if there is a pre-funding backout.
        self.wallet.used_coins.extend(self.initial_utxo_inputs.keys())
        total_in = sum([x['value'] for x in self.initial_utxo_inputs.values()])
        self.signing_privkeys = []
        for i, v in enumerate(self.initial_utxo_inputs.values()):
            privkey = self.wallet.get_key_from_addr(v['address'])
            if not privkey:
                raise CoinSwapException("Failed to get key to sign TX1")
            self.signing_privkeys.append(privkey)
        signing_pubkeys = [[btc.privkey_to_pubkey(x)] for x in self.signing_privkeys]
        signing_redeemscripts = [btc.address_to_script(
            x['address']) for x in self.initial_utxo_inputs.values()]
        change_amount = total_in - self.coinswap_parameters.tx1_amount - \
            self.coinswap_parameters.bitcoin_fee
        cslog.debug("got tx1 change amount: " + str(change_amount))
        #get a change address in same mixdepth
        change_address = self.wallet.get_internal_addr(0)
        self.tx1 = CoinSwapTX01.from_params(
            self.coinswap_parameters.pubkeys["key_2_2_CB_0"],
                                self.coinswap_parameters.pubkeys["key_2_2_CB_1"],
                                utxo_ins=self.initial_utxo_inputs.keys(),
                                signing_pubkeys=signing_pubkeys,
                                signing_redeem_scripts=signing_redeemscripts,
                                output_amount=self.coinswap_parameters.tx1_amount,
                                change_address=change_address,
                                change_amount=change_amount)
        #sign and hold signature, recover txid
        self.tx1.signall(self.signing_privkeys)
        self.tx1.attach_signatures()
        self.tx1.set_txid()
        cslog.info("Carol created and signed TX1:")
        cslog.info(self.tx1)
        #**CONSTRUCT TX3**
        utxo_in = self.tx1.txid + ":"+str(self.tx1.pay_out_index)
        self.tx3 = CoinSwapTX23.from_params(
            self.coinswap_parameters.pubkeys["key_2_2_CB_0"],
                self.coinswap_parameters.pubkeys["key_2_2_CB_1"],
                self.coinswap_parameters.pubkeys["key_TX3_secret"],
                utxo_in=utxo_in,
                recipient_amount=self.coinswap_parameters.tx3_amounts["script"],
                hashed_secret=self.hashed_secret,
                absolutelocktime=self.coinswap_parameters.timeouts["LOCK1"],
                refund_pubkey=self.coinswap_parameters.pubkeys["key_TX3_lock"],
        carol_only_address=self.coinswap_parameters.output_addresses["tx3_carol_address"],
        carol_only_amount=self.coinswap_parameters.tx3_amounts["carol"])
        #create our signature on TX3
        self.tx3.sign_at_index(self.keyset["key_2_2_CB_0"][0], 0)
        our_tx3_sig = self.tx3.signatures[0][0]
        cslog.info("Carol now has partially signed TX3:")
        cslog.info(self.tx3)
        return ([self.tx1.txid + ":" + str(self.tx1.pay_out_index),
                our_tx2_sig, our_tx3_sig], "OK")

    def receive_tx3_sig(self, sig):
        """Receives the sig on transaction TX3 which pays from our txid of TX1,
        to the 2 of 2 agreed CB. Then, wait until TX0 seen on network.
        """
        if not self.tx3.include_signature(1, sig):
            return (False, "TX3 signature received is invalid")
        cslog.info("Carol now has fully signed TX3:")
        cslog.info(self.tx3)
        self.tx3.attach_signatures()
        self.watch_for_tx(self.tx3)
        #wait until TX0 is seen before pushing ours.
        self.loop = task.LoopingCall(self.check_for_phase1_utxos, [self.txid0])
        self.loop.start(3.0)        
        return (True, "Received TX3 sig OK")

    def push_tx1(self):
        """Having seen TX0 confirmed, broadcast TX1 and wait for confirmation.
        """
        errmsg, success = self.tx1.push()
        if not success:
            return (False, "Failed to push TX1")
        #Monitor the output address of TX1 by importing
        cs_single().bc_interface.rpc("importaddress",
                            [self.tx1.output_address,
                            cs_single().bc_interface.get_wallet_name(self.wallet),
                            False])
        #Wait until TX1 seen before confirming phase2 ready.
        self.loop = task.LoopingCall(self.check_for_phase1_utxos,
                                         [self.tx1.txid + ":" + str(
                                             self.tx1.pay_out_index)],
                                         self.receive_confirmation_tx_0_1)
        self.loop.start(3.0)
        return (True, "TX1 broadcast OK")

    def receive_confirmation_tx_0_1(self):
        """We wait until client code has confirmed both pay-in txs
        before proceeding; note that this doesn't necessarily mean
        *1* confirmation, could be safer.
        """
        self.phase2_ready = True

    def is_phase2_ready(self):
        return self.phase2_ready

    def receive_secret(self, secret):
        """Receive the secret (preimage of hashed_secret),
        validate it, if valid, update state, construct TX4 and sig
        and send to Alice.
        """
        dummy, verifying_hash = get_coinswap_secret(raw_secret=secret)
        if not verifying_hash == self.hashed_secret:
            return (False, "Received invalid coinswap secret.")
        #Known valid; must be persisted in case recovery needed.
        self.secret = secret
        return (True, "OK")

    def send_tx5_sig(self):
        utxo_in = self.tx1.txid + ":" + str(self.tx1.pay_out_index)
        #We are now ready to directly spend, make TX5 and half-sign.
        self.tx5 = CoinSwapTX45.from_params(
            self.coinswap_parameters.pubkeys["key_2_2_CB_0"],
            self.coinswap_parameters.pubkeys["key_2_2_CB_1"],
            utxo_in=utxo_in,
            destination_address=self.coinswap_parameters.output_addresses["tx5_address"],
            destination_amount=self.coinswap_parameters.tx5_amounts["alice"],
        carol_change_address=self.coinswap_parameters.output_addresses["tx5_carol_address"],
        carol_change_amount=self.coinswap_parameters.tx5_amounts["carol"])
        self.tx5.sign_at_index(self.keyset["key_2_2_CB_0"][0], 0)
        sig = self.tx5.signatures[0][0]
        return (sig, "OK")
    
    def receive_tx4_sig(self, sig, txid5):
        """Receives and validates signature on TX4, and the TXID
        for TX5 (purely for convenience, not checked.
        """
        self.txid5 = txid5
        self.tx4 = CoinSwapTX45.from_params(
            self.coinswap_parameters.pubkeys["key_2_2_AC_0"],
            self.coinswap_parameters.pubkeys["key_2_2_AC_1"],
            utxo_in=self.txid0,
            destination_address=self.coinswap_parameters.output_addresses["tx4_address"],
            destination_amount=self.coinswap_parameters.tx4_amounts["carol"],
        carol_change_address=None,
        carol_change_amount=None)
        if not self.tx4.include_signature(0, sig):
            return (False, "Received invalid TX4 signature")
        return (True, "OK")

    def broadcast_tx4(self):
        self.tx4.sign_at_index(self.keyset["key_2_2_AC_1"][0], 1)
        errmsg, success = self.tx4.push()
        if not success:
            return (False, "Failed to push TX4")
        self.tx4_loop = task.LoopingCall(self.wait_for_tx4_confirmed)
        self.tx4_loop.start(3.0)
        return (True, "OK")

    def wait_for_tx4_confirmed(self):
        result = cs_single().bc_interface.query_utxo_set([self.tx4.txid+":0"],
                                                         includeconf=True)
        if None in result:
            return
        for u in result:
            if u['confirms'] < 1:
                return
        self.tx4_loop.stop()
        self.tx4_confirmed = True
        cslog.info("Carol received: " + self.tx4.txid + ", now ending.")
        self.quit()

    def is_tx4_confirmed(self):
        if self.tx4_confirmed:
            return self.tx4.txid
        else:
            return False

    def find_secret_from_tx3_redeem(self, expected_txid=None):
        """Given a txid assumed to be a transaction which spends from TX1
        (so must be TX3 whether ours or theirs, since this is the only
        doubly-signed tx), and assuming it has been spent from (so this
        function is only called if redeeming TX3 fails), find the redeeming
        transaction and extract the coinswap secret from its scriptSig(s).
        The secret is returned.
        If expected_txid is provided, checks that this is the redeeming txid,
        in which case returns "True".
        """
        assert self.tx3.spending_tx
        deser_spending_tx = btc.deserialize(self.tx3.spending_tx)
        cslog.info("Here is the spending transaction: " + str(deser_spending_tx))
        vins = deser_spending_tx['ins']
        self.secret = get_secret_from_vin(vins, self.hashed_secret)
        if not self.secret:
            cslog.info("Critical error; TX3 spent but no "
                      "coinswap secret was found.")
            return False
        return self.secret

    def redeem_tx3_with_lock(self):
        """Must be called after LOCK1, and TX3 must be
        broadcast but not-already-spent. Returns True if succeeds
        in broadcasting a redemption (to tx5_address), False otherwise.
        """
        if not self.tx3.txid:
            cslog.info("Failed to find TX3 txid, cannot redeem from it")
            return False
        #**CONSTRUCT TX3-redeem-timeout; use a fresh address to redeem
        dest_addr = self.wallet.get_new_addr(0, 1, True)
        self.tx3redeem = CoinSwapRedeemTX23Timeout(
            self.coinswap_parameters.pubkeys["key_TX3_secret"],
            self.hashed_secret,
            self.coinswap_parameters.timeouts["LOCK1"],
            self.coinswap_parameters.pubkeys["key_TX3_lock"],
            self.tx3.txid + ":0",
            self.coinswap_parameters.tx3_amounts["script"],
            dest_addr)
        self.tx3redeem.sign_at_index(self.keyset["key_TX3_lock"][0], 0)
        wallet_name = cs_single().bc_interface.get_wallet_name(self.wallet)
        msg, success = self.tx3redeem.push()
        cslog.info("Redeem tx: ")
        cslog.info(self.tx3redeem)
        if not success:
            cslog.info("RPC error message: " + msg)
            cslog.info("Failed to broadcast TX3 redeem; here is raw form: ")
            cslog.info(self.tx3redeem.fully_signed_tx)
            cslog.info("Readable form: ")
            cslog.info(self.tx3redeem)
            return False
        return True

    def redeem_tx2_with_secret(self):
        #Broadcast TX3
        msg, success = self.tx2.push()
        if not success:
            cslog.info("RPC error message: " + msg)
            cslog.info("Failed to broadcast TX2; here is raw form: ")
            cslog.info(self.tx2.fully_signed_tx)
            return False
        #**CONSTRUCT TX2-redeem-secret; use a fresh address to redeem
        dest_addr = self.wallet.get_new_addr(0, 1, True)
        tx2redeem_secret = CoinSwapRedeemTX23Secret(self.secret,
                        self.coinswap_parameters.pubkeys["key_TX2_secret"],
                        self.coinswap_parameters.timeouts["LOCK0"],
                        self.coinswap_parameters.pubkeys["key_TX2_lock"],
                        self.tx2.txid+":0",
                        self.coinswap_parameters.tx2_amounts["script"],
                        dest_addr)
        tx2redeem_secret.sign_at_index(self.keyset["key_TX2_secret"][0], 0)
        wallet_name = cs_single().bc_interface.get_wallet_name(self.wallet)
        msg, success = tx2redeem_secret.push()
        cslog.info("Redeem tx: ")
        cslog.info(tx2redeem_secret)
        if not success:
            cslog.info("RPC error message: " + msg)
            cslog.info("Failed to broadcast TX2 redeem; here is raw form: ")
            cslog.info(tx2redeem_secret.fully_signed_tx)
            cslog.info(tx2redeem_secret)
            return False
        else:
            cslog.info("Successfully redeemed funds via TX2, to address: "+\
                      dest_addr + ", in txid: " +\
                      tx2redeem_secret.txid)
            return True

    def watch_for_tx3_spends(self, redeeming_txid):
        """Function used to check whether our, or a competing
        tx, successfully spends out of TX3. Meant to be polled.
        """
        assert self.sm.state in [6, 7, 8]
        if self.tx3redeem.is_confirmed:
            self.carol_watcher_loop.stop()
            cslog.info("Redeemed funds via TX3 OK, txid of redeeming transaction "
                      "is: " + self.tx3redeem.txid)
            self.quit(complete=False, failed=False)
            return
        if self.tx3.is_spent:
            if btc.txhash(self.tx3.spending_tx) != redeeming_txid:
                cslog.info("Detected TX3 spent by other party; backing out to TX2")
                retval = self.find_secret_from_tx3_redeem()
                if not retval:
                    cslog.info("CRITICAL ERROR: Failed to find secret from TX3 redeem.")
                    self.quit(False, True)
                    return
                rt2s_success = self.redeem_tx2_with_secret()
                self.quit(False, not rt2s_success)
                return

    def scan_blockchain_for_secret(self):
        """Only required by Carol; in cases where the wallet
        monitoring fails (principally because a secret-redeeming
        transaction by Alice occurred when we were not on-line),
        we must be able to find the secret directly from scanning
        the blockchain. This could be achieved with indexing on
        our Bitcoin Core instance, but since this requires a lot of
        resources, it's simpler to directly parse the relevant blocks.
        """
        bh = get_current_blockheight()
        starting_blockheight = self.coinswap_parameters.timeouts[
            "LOCK0"] - cs_single().config.getint("TIMEOUT", "lock_client")
        while bh >= starting_blockheight:
            found_txs = get_transactions_from_block(bh)
            for t in found_txs:
                retval = get_secret_from_vin(t['ins'], self.hashed_secret)
                if retval:
                    self.secret = retval
                    return True
            bh -= 1
        cslog.info("Failed to find secret from scanning blockchain.")
        return False
