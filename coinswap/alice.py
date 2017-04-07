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
    State 0: handshake complete
    State 1: Parameter negotiation complete.
    ========SETUP PHASE===============================
    State 2: TX0id, H(x), TX2sig sent to Carol.
    State 3: TX1id, TX2sig, TX3sig received from Carol.
    State 4: TX0 broadcast.
    State 5: TX1 seen and X sent to Carol.
    ==================================================
    
    ========REDEEM PHASE==============================
    State 6: TX4 sig received, validated, and TX4 broadcast.
    State 7: Sent TX5 sig.
    ==================================================
    """
    required_key_names = ["key_2_2_AC_0", "key_2_2_CB_1",
                                  "key_TX2_lock", "key_TX3_secret"]

    def set_jsonrpc_client(self, jsonrpcclient):
        self.jsonrpcclient = jsonrpcclient

    def get_jsonrpc_callbacks(self):
        return {"handshake": self.negotiate_coinswap_parameters,
                "negotiate": self.complete_negotiation,
                "tx0id_hx_tx2sig": self.receive_txid1_tx23sig, 
                "sigtx3": self.check_response,
                "phase2_ready": self.phase2_callback,
                "secret": self.receive_tx4_sig,
                "sigtx5": self.check_response,
                "confirm_tx5": self.tx5_confirm_callback}
    
    def check_response(self, *args):
        """Response function for ACK/NACK type responses.
        """
        if not args[0]:
            self.backout("Response negative from Carol: ", args)
            return

    def send(self, send_id, *args):
        """The sending id is an integer that maps to a specific call in the
        JSON RPC API. The return values from the JSON call are returned directly.
        """
        return self.jsonrpcclient.send(self.jsonrpcclient.method_names[send_id], *args)

    def handshake(self):
        to_send = {"source_chain": "BTC",
                   "destination_chain": "BTC",
                   "amount": self.coinswap_parameters.tx0_amount}
        self.send(-1, to_send)

    def negotiate_coinswap_parameters(self, carol_response):
        """send parameters and ephemeral keys, destination address to Carol.
        Receive back ephemeral keys and destination address, or rejection,
        from Carol.
        """
        print('starting negotiate')
        self.update(0)
        print('starting negotiate after update')
        if not carol_response:
            self.backout("Carol rejected handshake.")
            return
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
        carol_response = self.send(0, *to_send)

    def complete_negotiation(self, carol_response):
        jlog.debug('Carol response for param negotiation: ' + str(carol_response))
        if not carol_response[0]:
            self.backout("BACKOUT: negative response in Alice in negotiation")
            return
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
            self.backout()
            return
        self.update(1)
        self.start()

    def start(self):
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
        self.update(2)
        self.send(1, self.tx0.txid + ":" + str(self.tx0.pay_out_index),
                  self.hashed_secret, sigtx2)

    def receive_txid1_tx23sig(self, params):
        """Receives the TX2 and TX3 sigs which pay from our txid of TX0,
        and Carol's created TX1, the 2 of 2s (AC, CB).
        Create our version of TX3 and validate the sigs for TX2 and TX3.
        Then create our sig on TX3 and send to Carol.
        """
        assert self.state == 2
        txid1, sigtx2, sigtx3 = params
        self.txid1 = txid1
        if not self.tx2.include_signature(1, sigtx2):
            self.backout("Counterparty signature for TX2 invalid; backing out.")
            return
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
            self.backout("Counterparty signature for TX3 invalid; backing out.")
            return
        #create our own signature for it
        self.tx3.sign_at_index(self.keyset["key_2_2_CB_1"][0], 1)
        sig = self.tx3.signatures[0][1]
        self.update(3)
        self.send(3, sig)
        #Now state 3 is reached, we have completed first-phase processing.
        #We push our TX0 and wait for the other side to complete by
        #pushing TX1.
        errmsg, success = self.tx0.push()
        if not success:
            self.backout("Failed to push TX0, errmsg: " + errmsg)
            return
        self.update(4)
        self.loop = task.LoopingCall(self.check_for_phase1_utxos,
                                     [self.tx0.txid +":" + str(
                                         self.tx0.pay_out_index), self.txid1],
                                     self.wait_for_phase_2)
        self.loop.start(3.0)

    def wait_for_phase_2(self, txid01):
        """This is fired when both TX0 and TX1 are seen confirmed.
        But, we do not continue until the other side returns positive from
        the rpc call phase2_ready, i.e. they confirm they see them also. 
        """
        self.loop.stop()
        print('starting wait for phase2 callback in Alice')
        self.phase2_loop = task.LoopingCall(self.send, 4)
        self.phase2_loop.start(3.0)

    def phase2_callback(self, result):
        if not result:
            return
        self.phase2_loop.stop()
        self.receive_confirmation_tx_0_1()
        
    def receive_confirmation_tx_0_1(self):
        """Note that we need not check the txids, as they
        were checked in check_phase1_utxos. Once both sides
        confirm TX0 and TX1 are confirmed, we proceed by sending the secret.
        """
        assert self.state == 4
        self.send(5, self.secret)
        self.update(5)
    
    def receive_tx4_sig(self, sig):
        """Receive Carol's signature on TX4, reconstruct and verify,
        then sign ourselves and broadcast. Then wait for confirmation before
        TX5 construction.
        """
        assert self.state == 5
        self.tx4 = CoinSwapTX45.from_params(
            self.coinswap_parameters.pubkeys["key_2_2_CB_0"],
                                self.coinswap_parameters.pubkeys["key_2_2_CB_1"],
                                utxo_in=self.txid1,
                                destination_address=self.coinswap_parameters.tx4_address,
                                destination_amount=self.coinswap_parameters.tx4_amount)
        if not self.tx4.include_signature(0, sig):
            self.backout("Counterparty signature for TX4 not valid; backing out.")
            return
        self.update(6)
        #We immediately sign TX4 ourselves, then broadcast
        self.tx4.sign_at_index(self.keyset["key_2_2_CB_1"][0], 1)
        errmsg, success = self.tx4.push()
        if not success:
            self.backout("Failed to push TX4, errmsg: " + errmsg)
            return
        self.loop_tx4 = task.LoopingCall(self.wait_for_tx4_confirmation)
        self.loop_tx4.start(3.0)

    def wait_for_tx4_confirmation(self, confs=1):
        """Looping task to wait for TX4 on network before TX5.
        """
        result = jm_single().bc_interface.query_utxo_set([self.tx4.txid+":0"],
                                                         includeconf=True)
        if None in result:
            return
        for u in result:
            if u['confirms'] < confs:
                return
        self.loop_tx4.stop()
        self.receive_tx4_confirmation()

    def receive_tx4_confirmation(self):
        assert self.state == 6
        utxo_in = self.tx0.txid + ":" + str(self.tx0.pay_out_index)
        self.tx5 = CoinSwapTX45.from_params(self.coinswap_parameters.pubkeys["key_2_2_AC_0"],
                                        self.coinswap_parameters.pubkeys["key_2_2_AC_1"],
                                        utxo_in=utxo_in,
                                        destination_address=self.coinswap_parameters.tx5_address,
                                        destination_amount=self.coinswap_parameters.tx5_amount)
        self.tx5.sign_at_index(self.keyset["key_2_2_AC_0"][0], 0)
        sig = self.tx5.signatures[0][0]
        self.send(6, sig)
        self.update(7)
        self.loop_tx5 = task.LoopingCall(self.wait_for_tx5_confirmation)
        self.loop_tx5.start(3.0)

    def wait_for_tx5_confirmation(self):
        """This is used to wait, asynchronously,
        for the counterparty to confirm seeing TX5 on the network,
        also, before starting the redeem phase.
        """
        self.send(7)

    def tx5_confirm_callback(self, result):
        if not result:
            return
        self.loop_tx5.stop()
        self.receive_confirmation_tx5(result)
        
    def receive_confirmation_tx5(self, txid5):
        """Receives notification from Carol that tx5 is seen on network;
        we check whether we see it also, for convenience, but don't act on it.
        """
        assert self.state == 7
        result = jm_single().bc_interface.query_utxo_set([txid5])
        if None in result:
            jlog.info("Carol confirms seeing txid but we can't: " + txid5)
        jlog.info("Coinswap successfully completed.")
        self.txid5 = txid5
        self.final_report()
        reactor.stop()