from __future__ import print_function
import jmbitcoin as btc
from jmclient import estimate_tx_fee
from twisted.internet import reactor, task
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
from .base import (CoinSwapException, CoinSwapPublicParameters,
                      CoinSwapParticipant, CoinSwapTX, CoinSwapTX01,
                      CoinSwapTX23, CoinSwapTX45, CoinSwapRedeemTX23Secret,
                      CoinSwapRedeemTX23Timeout, COINSWAP_SECRET_ENTROPY_BYTES,
                      get_coinswap_secret, get_current_blockheight,
                      create_hash_script, get_secret_from_vin,
                      generate_escrow_redeem_script, prepare_ecdsa_msg)
from coinswap import cs_single

cslog = get_log()

class CoinSwapAlice(CoinSwapParticipant):
    """
    State machine:
    State 0: pre-initialisation
    State 1: handshake complete
    State 2: Parameter negotiation initiated.
    State 3: Parameter negotiation complete.
    ========SETUP PHASE===============================
    State 4: TX0id, H(x), TX2sig sent to Carol.
    State 5: TX1id, TX2sig, TX3sig received from Carol.
    State 6: TX3 sent to Carol.
    State 7: TX0 broadcast.
    State 8: TX0, TX1 seen
    State 9: TX0, TX1 seen confirmed by Carol
    ==================================================
    
    ========REDEEM PHASE==============================
    State 10: X sent to Carol.
    State 11: TX5 sig received, validated
    State 12: TX5 broadcast.
    State 13: Sent TX4 sig. (complete)
    ==================================================
    """
    required_key_names = ["key_2_2_AC_0", "key_2_2_CB_1",
                                "key_TX2_lock", "key_TX3_secret", "key_session"]

    def set_jsonrpc_client(self, jsonrpcclient):
        self.jsonrpcclient = jsonrpcclient
    
    def get_state_machine_callbacks(self):
        return [(self.handshake, False, -1),
                (self.negotiate_coinswap_parameters, False, -1),
                (self.complete_negotiation, False, -1),
                (self.send_tx0id_hx_tx2sig, True, -1),
                (self.receive_txid1_tx23sig, False, -1),
                (self.send_tx3, True, -1),
                (self.broadcast_tx0, False, -1),
                (self.see_tx0_tx1, True, -1),
                #The timeout here is on waiting for confirmations, so very long
                (self.wait_for_phase_2, False,
                 cs_single().one_confirm_timeout * cs_single().config.getint(
                     "TIMEOUT", "tx01_confirm_wait")),
                #only updates after confirmation; the custom delay here is to
                #account for network propagation delays for the TX0/TX1 conf.
                (self.send_coinswap_secret, False, cs_single().config.getint(
                    "TIMEOUT", "propagation_buffer")),
                (self.receive_tx5_sig, False, -1),
                #Give enough time for bitcoin network propagation here
                (self.broadcast_tx5, True, cs_single().config.getint(
                    "TIMEOUT", "propagation_buffer")),
                #this state only completes on confirmation of TX5.
                #We shouldn't really timeout here; honest behaviour means
                #always send the tx4 sig; hence crucial to pay good fees.
                (self.send_tx4_sig, False, cs_single().one_confirm_timeout)]

    def get_msg_nonce(self):
        return binascii.hexlify(os.urandom(16))

    def send(self, *args):
        """The state machine state maps to a specific call in the
        JSON RPC API. The return value is passed to the callback, which
        is the statemachine .tick() function, which passes that return
        value to the next state transition function. All method calls
        must be prefaced by the sessionid for distinction of client, other
        than the handshake which inits the session.
        """
        mn = self.jsonrpcclient.method_names[self.sm.state]
        nonce = self.get_msg_nonce()
        msg_to_sign = prepare_ecdsa_msg(nonce, mn, *args)
        sig = btc.ecdsa_sign(msg_to_sign, self.keyset["key_session"][0])
        noncesig = {"nonce": nonce, "sig": sig}
        params = [self.coinswap_parameters.session_id, noncesig, mn] + list(args)
        if  mn != "handshake":
            return self.jsonrpcclient.send("coinswap", *params)
        else:
            return self.jsonrpcclient.send("handshake", *params)

    def send_poll(self, method, callback):
        nonce = self.get_msg_nonce()
        msg_to_sign = prepare_ecdsa_msg(nonce, method)
        sig = btc.ecdsa_sign(msg_to_sign, self.keyset["key_session"][0])
        noncesig = {"nonce": nonce, "sig": sig}
        return self.jsonrpcclient.send_poll(method, callback, noncesig,
                                            self.coinswap_parameters.session_id)
    def handshake(self):
        """Record the state of the wallet at the start of the process.
        Send a handshake message to Carol with required parameters for
        this Coinswap.
        """
        self.bbmb = self.wallet.get_balance_by_mixdepth(verbose=False)
        to_send = {"coinswapcs_version": cs_single().CSCS_VERSION,
                   "key_session": self.keyset["key_session"][1],
                   "tx01_confirm_wait": cs_single().config.getint("TIMEOUT",
                                                            "tx01_confirm_wait"),
                   "source_chain": "BTC",
                   "destination_chain": "BTC",
                   "amount": self.coinswap_parameters.base_amount,
                   "bitcoin_fee": self.coinswap_parameters.bitcoin_fee}
        self.send(to_send)
        return (True, "Handshake OK")

    def negotiate_coinswap_parameters(self, carol_response):
        """send parameters and ephemeral keys, destination address to Carol.
        Receive back ephemeral keys and destination address, or rejection,
        from Carol.
        """
        if not (carol_response and carol_response[0]):
            return (False, carol_response[1])
        if not len(carol_response[0]) == 32:
            return (False, "Error: server returned invalid session ID")
        self.coinswap_parameters.set_session_id(carol_response[0])
        to_send = [self.keyset["key_2_2_AC_0"][1],
                   self.keyset["key_2_2_CB_1"][1],
                   self.keyset["key_TX2_lock"][1],
                   self.keyset["key_TX3_secret"][1],
                   self.coinswap_parameters.timeouts["LOCK0"],
                   self.coinswap_parameters.timeouts["LOCK1"],
                   self.coinswap_parameters.output_addresses["tx5_address"]]
        self.send(*to_send)
        return (True, "Coinswap parameters sent OK")

    def complete_negotiation(self, carol_response):
        """Receive Carol's coinswap parameters.
        """
        cslog.debug('Carol response for param negotiation: ' + str(carol_response))
        if not carol_response[0]:
            return (False, "Negative response from Carol in negotiation")
        #on receipt of valid response, complete the CoinswapPublicParameters instance
        #note that we only finish our ephemeral pubkeys part here, after they're
        #accepted
        for k in self.required_key_names:
            self.coinswap_parameters.set_pubkey(k, self.keyset[k][1])
        self.coinswap_parameters.set_pubkey("key_2_2_AC_1", carol_response[0][1])
        self.coinswap_parameters.set_pubkey("key_2_2_CB_0", carol_response[0][2])
        self.coinswap_parameters.set_pubkey("key_TX2_secret", carol_response[0][3])
        self.coinswap_parameters.set_pubkey("key_TX3_lock", carol_response[0][4])
        proposed_fee = carol_response[0][6]
        if self.fee_checker:
            if not self.fee_checker(proposed_fee):
                return (False, "Server's proposed fee: " + str(proposed_fee) + \
                        " is not accepted.")
            else:
                cslog.info("Server proposed fee: " + str(proposed_fee) + \
                           ", accepted.")
        self.coinswap_parameters.set_coinswap_fee(carol_response[0][6])
        proposed_blinding_amount = carol_response[0][7]
        #Is this blinding factor good enough according to our wishes?
        if proposed_blinding_amount < cs_single().config.getint("POLICY",
                                                        "minimum_blinding_amount"):
            return (False, "Blinding amount is too small for us: " + \
                    str(proposed_blinding_amount) + "but we require at least: " + \
            str(cs_single().config.getint("POLICY", "minimum_blinding_amount")))
        self.coinswap_parameters.set_blinding_amount(proposed_blinding_amount)
        self.coinswap_parameters.set_addr_data(addr4=carol_response[0][5],
                                               addr_2_carol=carol_response[0][8],
                                               addr_3_carol=carol_response[0][9],
                                               addr_5_carol=carol_response[0][10])
        proposed_sessionid = carol_response[0][11]
        if not len(proposed_sessionid) == 32:
            return (False, "Invalid sessionid proposal: " + str(proposed_sessionid))
        self.coinswap_parameters.set_session_id(proposed_sessionid)
        #The state file name setting had to be deferred until here:
        self.state_file = self.state_file + proposed_sessionid + ".json"
        #We can now initiate file logging also; .log will be automatically appended
        cs_single().logs_path = os.path.join(cs_single().homedir, "logs", self.state_file)
        if not self.coinswap_parameters.is_complete():
            return (False,
                    "Coinswap public parameter negotiation failed, incomplete.")
        return (True, "Coinswap public parameter negotiation OK")

    def send_tx0id_hx_tx2sig(self):
        """Create coinswap secret, create TX0 paying into 2 of 2 AC,
        use the utxo/txid:n of it to create TX2, sign it, and send the hash,
        the tx2 sig and the utxo to Carol.
        """
        self.secret, self.hashed_secret = get_coinswap_secret()
        #**CONSTRUCT TX0**
        #precompute the entirely signed transaction, so as to pass the txid
        self.initial_utxo_inputs = self.wallet.select_utxos(0,
                                    self.coinswap_parameters.tx0_amount)
        total_in = sum([x['value'] for x in self.initial_utxo_inputs.values()])
        self.signing_privkeys = []
        for i, v in enumerate(self.initial_utxo_inputs.values()):
            privkey = self.wallet.get_key_from_addr(v['address'])
            if not privkey:
                raise CoinSwapException("Failed to get key to sign TX0")
            self.signing_privkeys.append(privkey)
        signing_pubkeys = [[btc.privkey_to_pubkey(x)] for x in self.signing_privkeys]
        signing_redeemscripts = [btc.address_to_script(
            x['address']) for x in self.initial_utxo_inputs.values()]
        change_amount = total_in - self.coinswap_parameters.tx0_amount - \
            self.coinswap_parameters.bitcoin_fee
        cslog.debug("got tx0 change amount: " + str(change_amount))
        #get a change address in same mixdepth
        change_address = self.wallet.get_internal_addr(0)
        self.tx0 = CoinSwapTX01.from_params(self.coinswap_parameters.pubkeys["key_2_2_AC_0"],
                                self.coinswap_parameters.pubkeys["key_2_2_AC_1"],
                                utxo_ins=self.initial_utxo_inputs.keys(),
                                signing_pubkeys=signing_pubkeys,
                                signing_redeem_scripts=signing_redeemscripts,
                                output_amount=self.coinswap_parameters.tx0_amount,
                                change_address=change_address,
                                change_amount=change_amount)
        #sign and hold signature, recover txid
        self.tx0.signall(self.signing_privkeys)
        self.tx0.attach_signatures()
        self.tx0.set_txid()
        cslog.info("Alice created and signed TX0:")
        cslog.info(self.tx0)
        #**CONSTRUCT TX2**
        #Input is outpoint from TX0
        utxo_in = self.tx0.txid + ":"+str(self.tx0.pay_out_index)
        self.tx2 = CoinSwapTX23.from_params(
            self.coinswap_parameters.pubkeys["key_2_2_AC_0"],
                self.coinswap_parameters.pubkeys["key_2_2_AC_1"],
                self.coinswap_parameters.pubkeys["key_TX2_secret"],
                utxo_in=utxo_in,
                recipient_amount=self.coinswap_parameters.tx2_amounts["script"],
                hashed_secret=self.hashed_secret,
                absolutelocktime=self.coinswap_parameters.timeouts["LOCK0"],
                refund_pubkey=self.coinswap_parameters.pubkeys["key_TX2_lock"],
        carol_only_address=self.coinswap_parameters.output_addresses["tx2_carol_address"],
        carol_only_amount=self.coinswap_parameters.tx2_amounts["carol"])
        #Create our own signature for TX2
        self.tx2.sign_at_index(self.keyset["key_2_2_AC_0"][0], 0)
        sigtx2 = self.tx2.signatures[0][0]
        self.send(self.tx0.txid + ":" + str(self.tx0.pay_out_index),
                  self.hashed_secret, sigtx2)
        return (True, "TX0id, H(X), TX2 sig sent OK")

    def receive_txid1_tx23sig(self, params):
        """Receives the TX2 and TX3 sigs which pay from our txid of TX0,
        and Carol's created TX1, the 2 of 2s (AC, CB).
        Create our version of TX3 and validate the sigs for TX2 and TX3.
        Then create our sig on TX3 and send to Carol.
        """
        innerparams, msg = params
        if not innerparams:
            return (False, "Carol did not send TXID1,TX23sig, error message: " + \
                    msg)
        txid1, sigtx2, sigtx3 = innerparams
        self.txid1 = txid1
        if not self.tx2.include_signature(1, sigtx2):
            return (False, "Counterparty signature for TX2 invalid.")
        cslog.info("Alice now has completely signed TX2:")
        cslog.info(self.tx2)
        #TX2 must now be watched for updates
        self.tx2.attach_signatures()
        self.watch_for_tx(self.tx2)
        #**CONSTRUCT TX3**
        #,using TXID1 as input; note "txid1" is a utxo string,
        self.tx3 = CoinSwapTX23.from_params(
            self.coinswap_parameters.pubkeys["key_2_2_CB_0"],
                self.coinswap_parameters.pubkeys["key_2_2_CB_1"],
                self.coinswap_parameters.pubkeys["key_TX3_secret"],
                utxo_in=self.txid1,
                recipient_amount=self.coinswap_parameters.tx3_amounts["script"],
                hashed_secret=self.hashed_secret,
                absolutelocktime=self.coinswap_parameters.timeouts["LOCK1"],
                refund_pubkey=self.coinswap_parameters.pubkeys["key_TX3_lock"],
        carol_only_address=self.coinswap_parameters.output_addresses["tx3_carol_address"],
        carol_only_amount=self.coinswap_parameters.tx3_amounts["carol"])
        cslog.info("Alice is working with this TX3: " + str(self.tx3))
        if not self.tx3.include_signature(0, sigtx3):
            return (False, "Counterparty signature for TX3 invalid.")
        #TX3 must be watched for updates
        #create our own signature for it
        self.tx3.sign_at_index(self.keyset["key_2_2_CB_1"][0], 1)
        self.tx3.attach_signatures()
        self.watch_for_tx(self.tx3)
        return (True, "Received TX1id, TX2sig, TX3 sig OK.")

    def send_tx3(self):
        sig = self.tx3.signatures[0][1]
        self.send(sig)
        return (True, "Sent TX3 sig OK.")

    def broadcast_tx0(self, acceptedmsg):
        #We have completed first-phase processing.
        #We push our TX0 and wait for the other side to complete by
        #pushing TX1.
        accepted, msg = acceptedmsg
        if not accepted:
            return (False, "Counterparty did not accept our TX3 signature, " + \
                    "error message: " + msg)
        errmsg, success = self.tx0.push()
        if not success:
            return (False, "Failed to push TX0, errmsg: " + errmsg)
        return (True, "Pushed TX0 OK: " + self.tx0.txid)

    def see_tx0_tx1(self):
        self.loop = task.LoopingCall(self.check_for_phase1_utxos,
                                     [self.tx0.txid + ":" + str(
                                         self.tx0.pay_out_index), self.txid1])
        self.loop.start(3.0)
        return (True, "Monitoring loop for TX0 started")

    def wait_for_phase_2(self):
        """This is fired when both TX0 and TX1 are seen confirmed.
        But, we do not continue until the other side returns positive from
        the rpc call phase2_ready, i.e. they confirm they see them also. 
        """
        self.phase2_loop = task.LoopingCall(self.send_poll, "phase2_ready",
                                            self.phase2_callback)
        self.phase2_loop.start(3.0)
        return (True, "Wait for phase2 loop started")

    def phase2_callback(self, result):
        """Proceeds to next state when Carol confirms
        that TX0 and TX1 are confirmed.
        """
        if not result:
            return
        self.phase2_loop.stop()
        self.sm.tick()
        
    def send_coinswap_secret(self):
        """Sends coinswap secret pre-image X
        to Carol.
        """
        self.send(self.secret)
        return (True, "Secret sent OK")
    
    def receive_tx5_sig(self, sigmsg):
        """Receive Carol's signature on TX5, reconstruct and verify,
        then sign ourselves and broadcast. Then wait for confirmation before
        TX4 construction.
        """
        sig, msg = sigmsg
        if not sig:
            return (False, "Failed to receive TX5 sig from Carol, error " + \
                    "message: " + msg)
        self.tx5 = CoinSwapTX45.from_params(
            self.coinswap_parameters.pubkeys["key_2_2_CB_0"],
                                self.coinswap_parameters.pubkeys["key_2_2_CB_1"],
                                utxo_in=self.txid1,
                                destination_address=self.coinswap_parameters.output_addresses["tx5_address"],
                                destination_amount=self.coinswap_parameters.tx5_amounts["alice"],
        carol_change_address=self.coinswap_parameters.output_addresses["tx5_carol_address"],
        carol_change_amount=self.coinswap_parameters.tx5_amounts["carol"])
        if not self.tx5.include_signature(0, sig):
            return (False, "Counterparty signature for TX5 not valid; backing out.")
        return (True, "Counterparty signature for TX5 OK.")

    def broadcast_tx5(self):
        """Sign TX5 ourselves, then broadcast
        """
        self.tx5.sign_at_index(self.keyset["key_2_2_CB_1"][0], 1)
        errmsg, success = self.tx5.push()
        if not success:
            return (False, "Failed to push TX5, errmsg: " + errmsg)
        self.loop_tx5 = task.LoopingCall(self.wait_for_tx5_confirmation)
        self.loop_tx5.start(3.0)
        return (True, "TX5 broadcast OK")

    def wait_for_tx5_confirmation(self, confs=1):
        """Looping task to wait for TX5 on network before TX4.
        """
        result = cs_single().bc_interface.query_utxo_set([self.tx5.txid+":0"],
                                                         includeconf=True)
        if None in result:
            return
        for u in result:
            if u['confirms'] < confs:
                return
        self.loop_tx5.stop()
        self.sm.tick()

    def send_tx4_sig(self):
        """Send partial signature on TX4 (out of TX0)
        to Carol for her to complete sign and broadcast.
        """
        utxo_in = self.tx0.txid + ":" + str(self.tx0.pay_out_index)
        self.tx4 = CoinSwapTX45.from_params(self.coinswap_parameters.pubkeys["key_2_2_AC_0"],
                                        self.coinswap_parameters.pubkeys["key_2_2_AC_1"],
                                        utxo_in=utxo_in,
                                        destination_address=self.coinswap_parameters.output_addresses["tx4_address"],
                                        destination_amount=self.coinswap_parameters.tx4_amounts["carol"],
                                        carol_change_address=None,
                                        carol_change_amount=None)
        self.tx4.sign_at_index(self.keyset["key_2_2_AC_0"][0], 0)
        sig = self.tx4.signatures[0][0]
        self.send(sig, self.tx5.txid)
        self.tx4broadcast_counter = 0
        self.loop_tx4 = task.LoopingCall(self.wait_for_tx4_confirmation)
        self.loop_tx4.start(3.0)
        return (True, "TX4 signature sent.")

    def wait_for_tx4_confirmation(self):
        """Receives notification from Carol that tx4 is seen on network;
        we use it to trigger finalization of run. This is only a 'courtesy',
        since it has no effect on us, so we don't wait forever.
        """
        self.tx4broadcast_counter += 1
        if self.tx4broadcast_counter > 10:
            cslog.info("Timed out waiting for Carol to confirm broadcast "
                      "of TX4; this has no effect on us, so we give up.")
            self.tx4_callback("None")
            return
        self.send_poll("confirm_tx4", self.tx4_callback)
    
    def tx4_callback(self, result):
        """Once Carol has confirmed receipt of TX4, retrieve
        txid for our records, and finish the Coinswap protocol.
        """
        if not result:
            return
        self.txid4 = result
        self.loop_tx4.stop()
        self.quit()

    def check_server_status(self, status):
        """Retrieve the server status and validate that it allows
        coinswaps with the chosen parameters to start.
        """
        assert self.sm.state == 0
        if not all([x in status.keys() for x in ["source_chain",
                "destination_chain", "cscs_version", "minimum_amount",
                "maximum_amount", "busy"]]):
            cslog.info("Server gave invalid status response.")
            reactor.stop()
        elif status["source_chain"] != "BTC" or status["destination_chain"] != "BTC":
            cslog.info("Server is not BTC-BTC chain")
            reactor.stop()
        elif status["cscs_version"] != cs_single().CSCS_VERSION:
            cslog.info("Server has wrong CSCS version, aborting")
            reactor.stop()
        elif status["busy"] or status["maximum_amount"] < 0:
            cslog.info("Server is not currently available")
            reactor.stop()
        elif self.coinswap_parameters.base_amount < status["minimum_amount"]:
            cslog.info("Amount too small for server")
            reactor.stop()
        elif self.coinswap_parameters.base_amount > status["maximum_amount"]:
            cslog.info("Amount too large for server")
            reactor.stop()
        else:
            cslog.info("Server settings are compatible, continuing...")
            self.sm.tick()
