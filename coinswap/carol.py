from __future__ import print_function
import jmbitcoin as btc
from jmclient import (load_program_config, jm_single, Wallet,
                      get_p2pk_vbyte, get_p2sh_vbyte, estimate_tx_fee,
                      sync_wallet, RegtestBitcoinCoreInterface,
                      BitcoinCoreInterface, get_log)
from twisted.internet import reactor, task
from txjsonrpc.web.jsonrpc import Proxy
from txjsonrpc.web import jsonrpc
from twisted.web import server
from .btscript import *
import pytest
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
                      create_hash_script, detect_spent, get_secret_from_vin,
                      generate_escrow_redeem_script)

jlog = get_log()

class CoinSwapCarol(CoinSwapParticipant):
    """
    State machine:
    * indicates not reached in cooperative case.
    ** indicates end.
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

    def get_state_machine_callbacks(self):
        """Return the callbacks for each state transition.
        For each a boolean flag is used to indicate whether
        it should be automatically triggered by the previous
        state transition completing.
        """
        return [(self.handshake, False),
                (self.negotiate_coinswap_parameters, False),
                (self.receive_tx0_hash_tx2sig, False),
                (self.send_tx1id_tx2_sig_tx3_sig, True),
                (self.receive_tx3_sig, False),
                (self.push_tx1, False),
                (self.receive_secret, False),
                (self.send_tx5_sig, True),
                (self.receive_tx4_sig, False),
                (self.broadcast_tx4, True)]

    def set_handshake_parameters(self, source_chain="BTC",
                                 destination_chain="BTC",
                                 minimum_amount=1000000,
                                 maximum_amount=100000000):
        """Sets the conditions under which Carol is
        prepared to do a coinswap.
        """
        self.source_chain = source_chain
        self.destination_chain = destination_chain
        self.minimum_amount = minimum_amount
        self.maximum_amount = maximum_amount

    def handshake(self, d):
        """Check that the proposed coinswap parameters
        are acceptable.
        """
        self.bbmb = self.wallet.get_balance_by_mixdepth()
        if d["source_chain"] != self.source_chain:
            return (False, "source chain was wrong: " + d["source_chain"])
        if d["destination_chain"] != self.destination_chain:
            return (False, "destination chain was wrong: " + d["destination_chain"])
        if d["amount"] < self.minimum_amount:
            return (False, "Requested amount too small: " + d["amount"])
        if d["amount"] > self.maximum_amount:
            return (False, "Requested amount too large: " + d["amount"])
        return (True, "Handshake parameters from Alice accepted")

    def negotiate_coinswap_parameters(self, params):
        #receive parameters and ephemeral keys, destination address from Alice.
        #Send back ephemeral keys and destination address, or rejection,
        #if invalid, to Alice.
        for k in self.required_key_names:
            self.coinswap_parameters.set_pubkey(k, self.keyset[k][1])
        try:
            self.coinswap_parameters.tx0_amount = params[0]
            self.coinswap_parameters.tx2_recipient_amount = params[1]
            self.coinswap_parameters.tx3_recipient_amount = params[2]
            self.coinswap_parameters.set_pubkey("key_2_2_AC_0", params[3])
            self.coinswap_parameters.set_pubkey("key_2_2_CB_1", params[4])
            self.coinswap_parameters.set_pubkey("key_TX2_lock", params[5])
            self.coinswap_parameters.set_pubkey("key_TX3_secret", params[6])
            self.coinswap_parameters.set_timeouts(params[7], params[8])
            self.coinswap_parameters.set_tx5_address(params[9])
        except:
            return (False, "Invalid parameter set from counterparty, abandoning")

        #on receipt of valid response, complete the CoinswapPublicParameters instance
        for k in self.required_key_names:
            self.coinswap_parameters.set_pubkey(k, self.keyset[k][1])
        if not self.coinswap_parameters.is_complete():
            jlog.debug("addresses: " + str(self.coinswap_parameters.addresses_complete))
            jlog.debug("pubkeys: " + str(self.coinswap_parameters.pubkeys_complete))
            jlog.debug("timeouts: " + str(self.coinswap_parameters.timeouts_complete))
            return (False, "Coinswap parameters is not complete")
        #first entry confirms acceptance of parameters
        to_send = [True,
        self.coinswap_parameters.pubkeys["key_2_2_AC_1"],
        self.coinswap_parameters.pubkeys["key_2_2_CB_0"],
        self.coinswap_parameters.pubkeys["key_TX2_secret"],
        self.coinswap_parameters.pubkeys["key_TX3_lock"],
        self.coinswap_parameters.tx4_address]
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
                recipient_amount=self.coinswap_parameters.tx2_recipient_amount,
                hashed_secret=self.hashed_secret,
                absolutelocktime=self.coinswap_parameters.timeouts["LOCK0"],
                refund_pubkey=self.coinswap_parameters.pubkeys["key_TX2_lock"])
        if not self.tx2.include_signature(0, tx2sig):
            return (False, "Counterparty sig for TX2 invalid; backing out.")
        return (True, "OK")

    def send_tx1id_tx2_sig_tx3_sig(self):
        #create our own signature for it
        self.tx2.sign_at_index(self.keyset["key_2_2_AC_1"][0], 1)
        our_tx2_sig = self.tx2.signatures[0][1]

        #**CONSTRUCT TX1**
        self.initial_utxo_inputs = self.wallet.select_utxos(0,
                                    self.coinswap_parameters.tx1_amount)
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
        #calculate size of change output; default p2pkh assumed
        fee = estimate_tx_fee(len(self.initial_utxo_inputs), 2)
        jlog.debug("got tx1 fee: " + str(fee))
        jlog.debug("for tx1 input amount: " + str(total_in))
        change_amount = total_in - self.coinswap_parameters.tx1_amount - fee
        jlog.debug("got tx1 change amount: " + str(change_amount))
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
        jlog.info("Carol created and signed TX1:")
        jlog.info(self.tx1)
        #**CONSTRUCT TX3**
        utxo_in = self.tx1.txid + ":"+str(self.tx1.pay_out_index)
        self.tx3 = CoinSwapTX23.from_params(
            self.coinswap_parameters.pubkeys["key_2_2_CB_0"],
                self.coinswap_parameters.pubkeys["key_2_2_CB_1"],
                self.coinswap_parameters.pubkeys["key_TX3_secret"],
                utxo_in=utxo_in,
                recipient_amount=self.coinswap_parameters.tx3_recipient_amount,
                hashed_secret=self.hashed_secret,
                absolutelocktime=self.coinswap_parameters.timeouts["LOCK1"],
                refund_pubkey=self.coinswap_parameters.pubkeys["key_TX3_lock"])
        self.import_address(self.tx3.output_address)
        #create our signature on TX3
        self.tx3.sign_at_index(self.keyset["key_2_2_CB_0"][0], 0)
        our_tx3_sig = self.tx3.signatures[0][0]
        jlog.info("Carol now has partially signed TX3:")
        jlog.info(self.tx3)
        return ([self.tx1.txid + ":" + str(self.tx1.pay_out_index),
                our_tx2_sig, our_tx3_sig], "OK")

    def receive_tx3_sig(self, sig):
        """Receives the sig on transaction TX3 which pays from our txid of TX1,
        to the 2 of 2 agreed CB. Then, wait until TX0 seen on network.
        """
        if not self.tx3.include_signature(1, sig):
            return (False, "TX3 signature received is invalid")
        jlog.info("Carol now has fully signed TX3:")
        jlog.info(self.tx3)
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
        #Wait until TX1 seen before confirming phase2 ready.
        self.loop = task.LoopingCall(self.check_for_phase1_utxos,
                                         [self.tx1.txid + ":" + str(
                                             self.tx1.pay_out_index)],
                                         1, self.receive_confirmation_tx_0_1)
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
            destination_address=self.coinswap_parameters.tx5_address,
            destination_amount=self.coinswap_parameters.tx5_amount)
        self.tx5.sign_at_index(self.keyset["key_2_2_CB_0"][0], 0)
        sig = self.tx5.signatures[0][0]
        return (sig, "OK")
    
    def receive_tx4_sig(self, sig):
        self.tx4 = CoinSwapTX45.from_params(
            self.coinswap_parameters.pubkeys["key_2_2_AC_0"],
            self.coinswap_parameters.pubkeys["key_2_2_AC_1"],
            utxo_in=self.txid0,
            destination_address=self.coinswap_parameters.tx4_address,
            destination_amount=self.coinswap_parameters.tx4_amount)
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
        result = jm_single().bc_interface.query_utxo_set([self.tx4.txid+":0"],
                                                         includeconf=True)
        if None in result:
            return
        for u in result:
            if u['confirms'] < 1:
                return
        self.tx4_loop.stop()
        self.tx4_confirmed = True
        jlog.info("Carol received: " + self.tx4.txid + ", now ending.")
        sync_wallet(self.wallet)
        self.bbma = self.wallet.get_balance_by_mixdepth()
        jlog.info("Wallet before: ")
        jlog.info(pformat(self.bbmb))
        jlog.info("Wallet after: ")
        jlog.info(pformat(self.bbma))

    def is_tx4_confirmed(self):
        if self.tx4_confirmed:
            return self.tx4.txid
        else:
            return False

    def watch_for_tx3_spends(self, redeeming_txid):
        """Function used to check whether our, or a competing
        tx, successfully spends out of TX3. Meant to be polled.
        """
        assert self.sm.state in [6, 7, 8]
        spent = detect_spent(self.tx3.txid, 0, unconf=True)
        if not spent:
            return
        #It was spent; did we receive it?
        #Crude method: get the txid of each new transaction from listtransaction
        #(pay attention to order)
        #pass it to getrawtransaction 1 (so serialized)
        #read the input txids.
        jlog.info("TX3 (" + self.tx3.txid + "), was spent.")
        #list the recent transactions (TODO)
        wallet_name = jm_single().bc_interface.get_wallet_name(self.wallet)
        recent_txs = jm_single().bc_interface.rpc("listtransactions",
                                                  [wallet_name, 100, 0, True])
        for rt in recent_txs:
            try:
                txid = rt["txid"]
                rawtx = jm_single().bc_interface.rpc("getrawtransaction", [txid, 1])
            except:
                continue
            #check if inputs are from TX1:
            for vin in rawtx["vin"]:
                if "txid" not in vin:
                    #coinbase transactions
                    continue
                if vin["txid"] == self.tx3.txid:
                    jlog.info("Found transaction which spent TX3: " + self.tx3.txid)
                    if txid == redeeming_txid:
                        jlog.info("Our spend of TX3 was successful")
                        self.successful_tx3_redeem = True
                        self.carol_watcher_loop.stop()
                        return
                    else:
                        #We were double spent on. We need to store the consumed
                        #secret before falling back to TX2 spend. In state 6+,
                        #we already have the secret.
                        if not self.secret:
                            self.secret = get_secret_from_vin(rawtx["vin"],
                                                              self.hashed_secret)
                            if not self.secret:
                                jlog.info("Critical error; TX3 spent but no "
                                         "coinswap secret was found.")
                                reactor.stop()
                        self.successful_tx3_redeem = False
                        self.carol_watcher_loop.stop()
                        return
        #reaching end of tx loop means no spend found, allow loop to continue

    def react_to_tx3_spend(self):
        if self.successful_tx3_redeem is None:
            return
        if self.successful_tx3_redeem:
            jlog.info("Our back-out via TX3 was successful, funds were returned "
                     "in this TXID: " + self.tx3.txid)
            jlog.info("Ending.")
            reactor.stop()
            #self.carol_waiting_loop.stop()
        else:
            jlog.info("Our back-out via TX3 was unsuccessful; we retrieved "
                     "the secret X from the double spend tx: " + self.secret)
            jlog.info("We will now spend out from TX2 using the secret.")
            #push TX2; construct TX2-redeem-on-secret; spend.
            #note we already checked/warned if after LOCK0, but nothing else
            #left to try anyway.
            msg, success = self.tx2.push()
            if not success:
                jlog.info("RPC error message: ", msg)
                jlog.info("Failed to broadcast TX2; here is raw form: ")
                jlog.info(self.tx2.fully_signed_tx)
                reactor.stop()
            tx2redeem_secret = CoinSwapRedeemTX23Secret(self.secret,
                                self.coinswap_parameters.pubkeys["key_TX2_secret"],
                                self.coinswap_parameters.timeouts["LOCK0"],
                                self.coinswap_parameters.pubkeys["key_TX2_lock"],
                                self.tx2.txid+":0",
                                self.coinswap_parameters.tx4_amount,
                                self.coinswap_parameters.tx4_address)
            tx2redeem_secret.sign_at_index(self.keyset["key_TX2_secret"][0], 0)
            msg, success = tx2redeem_secret.push()
            if not success:
                jlog.info("RPC error message: ", msg)
                jlog.info("Failed to broadcast TX2 redemption; here is raw form: ")
                jlog.info(tx2redeem_secret.fully_signed_tx)
                reactor.stop()
            jlog.info("Successfully pushed redemption from TX2, txid is: " + \
                     tx2redeem_secret.txid)
            reactor.stop()