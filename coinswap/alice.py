from __future__ import print_function
import jmbitcoin as btc
from jmclient import (load_program_config, jm_single, Wallet,
                      get_p2pk_vbyte, get_p2sh_vbyte, estimate_tx_fee,
                      sync_wallet, RegtestBitcoinCoreInterface,
                      BitcoinCoreInterface, get_log)
from twisted.internet import reactor, task
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
from .base import (CoinSwapException, CoinSwapPublicParameters,
                      CoinSwapParticipant, CoinSwapTX, CoinSwapTX01,
                      CoinSwapTX23, CoinSwapTX45, CoinSwapRedeemTX23Secret,
                      CoinSwapRedeemTX23Timeout, COINSWAP_SECRET_ENTROPY_BYTES,
                      get_coinswap_secret, get_current_blockheight,
                      create_hash_script, detect_spent, get_secret_from_vin,
                      generate_escrow_redeem_script)

jlog = get_log()

class CoinSwapAlice(CoinSwapParticipant):
    """
    State machine:
    * indicates not reached in cooperative case.
    ** indicates end.
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
                                  "key_TX2_lock", "key_TX3_secret"]

    def set_jsonrpc_client(self, jsonrpcclient):
        self.jsonrpcclient = jsonrpcclient
    
    def get_state_machine_callbacks(self):
        """Return the callbacks for each state transition.
        For each a boolean flag is used to indicate whether
        it should be automatically triggered by the previous
        state transition completing.
        """
        return [(self.handshake, False),
                (self.negotiate_coinswap_parameters, False),
                (self.complete_negotiation, False),
                (self.send_tx0id_hx_tx2sig, True),
                (self.receive_txid1_tx23sig, False),
                (self.send_tx3, True),
                (self.broadcast_tx0, False),
                (self.see_tx0_tx1, True),
                (self.wait_for_phase_2, False),
                (self.send_coinswap_secret, False),
                (self.receive_tx5_sig, False),
                (self.broadcast_tx5, True),
                (self.send_tx4_sig, False),
                (self.confirm_tx4_sig_receipt, False)]

    def send(self, send_id, *args):
        """The sending id is an integer that maps to a specific call in the
        JSON RPC API. The return values from the JSON call are returned directly.
        """
        return self.jsonrpcclient.send(self.jsonrpcclient.method_names[send_id], *args)

    def handshake(self):
        to_send = {"source_chain": "BTC",
                   "destination_chain": "BTC",
                   "amount": self.coinswap_parameters.tx0_amount}
        self.send(0, to_send)
        return (True, "Handshake OK")

    def negotiate_coinswap_parameters(self, accepted):
        """send parameters and ephemeral keys, destination address to Carol.
        Receive back ephemeral keys and destination address, or rejection,
        from Carol.
        """
        print('starting negotiate')
        if not accepted:
            return (False, "Carol rejected handshake.")
        print('accepted OK')
        to_send = [self.coinswap_parameters.tx0_amount,
                   self.coinswap_parameters.tx2_recipient_amount,
                   self.coinswap_parameters.tx3_recipient_amount,
                   self.keyset["key_2_2_AC_0"][1],
                   self.keyset["key_2_2_CB_1"][1],
                   self.keyset["key_TX2_lock"][1],
                   self.keyset["key_TX3_secret"][1],
                   self.coinswap_parameters.timeouts["LOCK0"],
                   self.coinswap_parameters.timeouts["LOCK1"],
                   self.coinswap_parameters.tx4_address]
        self.send(1, *to_send)
        return (True, "Coinswap parameters sent OK")

    def complete_negotiation(self, carol_response):
        jlog.debug('Carol response for param negotiation: ' + str(carol_response))
        if not carol_response[0]:
            return (False, "Negative response from Carol in negotiation")
        #on receipt of valid response, complete the CoinswapPublicParameters instance
        #note that we only finish our ephemeral pubkeys part here, after they're
        #accepted
        for k in self.required_key_names:
            self.coinswap_parameters.set_pubkey(k, self.keyset[k][1])
        self.coinswap_parameters.set_pubkey("key_2_2_AC_1", carol_response[1])
        self.coinswap_parameters.set_pubkey("key_2_2_CB_0", carol_response[2])
        self.coinswap_parameters.set_pubkey("key_TX2_secret", carol_response[3])
        self.coinswap_parameters.set_pubkey("key_TX3_lock", carol_response[4])
        self.coinswap_parameters.set_tx5_address(carol_response[5])
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
        #calculate size of change output; default p2pkh assumed
        fee = estimate_tx_fee(len(self.initial_utxo_inputs), 2)
        jlog.debug("got tx0 fee: " + str(fee))
        jlog.debug("for tx0 input amount: " + str(total_in))
        change_amount = total_in - self.coinswap_parameters.tx0_amount - fee
        jlog.debug("got tx0 change amount: " + str(change_amount))
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
        jlog.info("Alice created and signed TX0:")
        jlog.info(self.tx0)
        #**CONSTRUCT TX2**
        #Input is outpoint from TX0
        utxo_in = self.tx0.txid + ":"+str(self.tx0.pay_out_index)
        self.tx2 = CoinSwapTX23.from_params(
            self.coinswap_parameters.pubkeys["key_2_2_AC_0"],
                self.coinswap_parameters.pubkeys["key_2_2_AC_1"],
                self.coinswap_parameters.pubkeys["key_TX2_secret"],
                utxo_in=utxo_in,
                recipient_amount=self.coinswap_parameters.tx2_recipient_amount,
                hashed_secret=self.hashed_secret,
                absolutelocktime=self.coinswap_parameters.timeouts["LOCK0"],
                refund_pubkey=self.coinswap_parameters.pubkeys["key_TX2_lock"])
        #Create our own signature for TX2
        self.tx2.sign_at_index(self.keyset["key_2_2_AC_0"][0], 0)
        sigtx2 = self.tx2.signatures[0][0]
        self.send(3, self.tx0.txid + ":" + str(self.tx0.pay_out_index),
                  self.hashed_secret, sigtx2)
        return (True, "TX0id, H(X), TX2 sig sent OK")

    def receive_txid1_tx23sig(self, params):
        """Receives the TX2 and TX3 sigs which pay from our txid of TX0,
        and Carol's created TX1, the 2 of 2s (AC, CB).
        Create our version of TX3 and validate the sigs for TX2 and TX3.
        Then create our sig on TX3 and send to Carol.
        """
        txid1, sigtx2, sigtx3 = params
        self.txid1 = txid1
        if not self.tx2.include_signature(1, sigtx2):
            return (False, "Counterparty signature for TX2 invalid.")
        jlog.info("Alice now has partially signed TX2:")
        jlog.info(self.tx2)
        #**CONSTRUCT TX3**
        #,using TXID1 as input; note "txid1" is a utxo string,
        self.tx3 = CoinSwapTX23.from_params(
            self.coinswap_parameters.pubkeys["key_2_2_CB_0"],
                self.coinswap_parameters.pubkeys["key_2_2_CB_1"],
                self.coinswap_parameters.pubkeys["key_TX3_secret"],
                utxo_in=self.txid1,
                recipient_amount=self.coinswap_parameters.tx3_recipient_amount,
                hashed_secret=self.hashed_secret,
                absolutelocktime=self.coinswap_parameters.timeouts["LOCK1"],
                refund_pubkey=self.coinswap_parameters.pubkeys["key_TX3_lock"])
        if not self.tx3.include_signature(0, sigtx3):
            return (False, "Counterparty signature for TX3 invalid.")
        return (True, "Received TX1id, TX2sig, TX3 sig OK.")

    def send_tx3(self):
        #create our own signature for it
        self.tx3.sign_at_index(self.keyset["key_2_2_CB_1"][0], 1)
        sig = self.tx3.signatures[0][1]
        self.send(5, sig)
        return (True, "Sent TX3 sig OK.")

    def broadcast_tx0(self, accepted):
        #We have completed first-phase processing.
        #We push our TX0 and wait for the other side to complete by
        #pushing TX1.
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
        print('starting wait for phase2 callback in Alice')
        self.phase2_loop = task.LoopingCall(self.jsonrpcclient.send_poll,
                                            "phase2_ready", self.phase2_callback)
        self.phase2_loop.start(3.0)
        return (True, "Wait for phase2 loop started")

    def phase2_callback(self, result):
        if not result:
            return
        self.phase2_loop.stop()
        self.sm.tick()
        
    def send_coinswap_secret(self):
        self.send(8, self.secret)
        return (True, "Secret sent OK")
    
    def receive_tx5_sig(self, sig):
        """Receive Carol's signature on TX5, reconstruct and verify,
        then sign ourselves and broadcast. Then wait for confirmation before
        TX4 construction.
        """
        self.tx5 = CoinSwapTX45.from_params(
            self.coinswap_parameters.pubkeys["key_2_2_CB_0"],
                                self.coinswap_parameters.pubkeys["key_2_2_CB_1"],
                                utxo_in=self.txid1,
                                destination_address=self.coinswap_parameters.tx5_address,
                                destination_amount=self.coinswap_parameters.tx5_amount)
        if not self.tx5.include_signature(0, sig):
            return (False, "Counterparty signature for TX5 not valid; backing out.")
        return (True, "Counterparty signature for TX5 OK.")

    def broadcast_tx5(self):
        #We immediately sign TX5 ourselves, then broadcast
        self.tx5.sign_at_index(self.keyset["key_2_2_CB_1"][0], 1)
        errmsg, success = self.tx5.push()
        if not success:
            return (False, "Failed to push TX4, errmsg: " + errmsg)
        self.loop_tx5 = task.LoopingCall(self.wait_for_tx5_confirmation)
        self.loop_tx5.start(3.0)
        return (True, "TX5 broadcast OK")

    def wait_for_tx5_confirmation(self, confs=1):
        """Looping task to wait for TX5 on network before TX4.
        """
        result = jm_single().bc_interface.query_utxo_set([self.tx5.txid+":0"],
                                                         includeconf=True)
        if None in result:
            return
        for u in result:
            if u['confirms'] < confs:
                return
        self.loop_tx5.stop()
        self.sm.tick()

    def send_tx4_sig(self):
        utxo_in = self.tx0.txid + ":" + str(self.tx0.pay_out_index)
        self.tx4 = CoinSwapTX45.from_params(self.coinswap_parameters.pubkeys["key_2_2_AC_0"],
                                        self.coinswap_parameters.pubkeys["key_2_2_AC_1"],
                                        utxo_in=utxo_in,
                                        destination_address=self.coinswap_parameters.tx4_address,
                                        destination_amount=self.coinswap_parameters.tx4_amount)
        self.tx4.sign_at_index(self.keyset["key_2_2_AC_0"][0], 0)
        sig = self.tx4.signatures[0][0]
        self.send(11, sig)
        self.loop_tx4 = task.LoopingCall(self.wait_for_tx4_confirmation)
        self.loop_tx4.start(3.0)        
        return (True, "TX4 signature sent.")

    def confirm_tx4_sig_receipt(self, result):
        jlog.info("Got this response from Carol to our TX4 sig: " + str(result))
        return (result, "Carol received TX4 sig OK.")

    def wait_for_tx4_confirmation(self):
        """Receives notification from Carol that tx4 is seen on network;
        we check whether we see it also, for convenience, but don't act on it.
        """
        print('starting wait for tx4 callback in Alice')
        self.tx4_loop = task.LoopingCall(self.jsonrpcclient.send_poll,
                                            "confirm_tx4", self.tx4_callback)
        self.tx4_loop.start(3.0)
        return (True, "Wait for tx4 loop started")
    
    def tx4_callback(self, result):
        if not result:
            return
        self.txid4 = result
        self.tx4_loop.stop()
        jlog.info("Coinswap successfully completed.")
        self.final_report()
        reactor.stop()