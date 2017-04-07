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
    State 0: handshake complete
    State 1: Parameter negotiation complete.
    ========SETUP PHASE===============================
    State 2: TX0id, H(x), TX2sig received from Alice.
    State 3: TX1id, TX2sig, TX3sig sent to Alice.
    State 4: TX0 seen confirmed.
    State 5: TX1 broadcast.
    ==================================================
    
    ========REDEEM PHASE==============================
    State 6: TX1 confirmed and X received.
    State 7: Sent TX4 sig.
    State 8: Tx5 sig received valid from Alice, broadcast.
    ==================================================
    """
    required_key_names = ["key_2_2_AC_1", "key_2_2_CB_0",
                                  "key_TX2_secret", "key_TX3_lock"]

    def negotiate_coinswap_parameters(self, params):
        #receive parameters and ephemeral keys, destination address from Alice.
        #Send back ephemeral keys and destination address, or rejection,
        #if invalid, to Alice.
        self.update(0)
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
            self.coinswap_parameters.set_tx4_address(params[9])
        except:
            self.backout("Invalid parameter set from counterparty, abandoning")
            return

        #on receipt of valid response, complete the CoinswapPublicParameters instance
        for k in self.required_key_names:
            self.coinswap_parameters.set_pubkey(k, self.keyset[k][1])
        if not self.coinswap_parameters.is_complete():
            jlog.debug("addresses: " + str(self.coinswap_parameters.addresses_complete))
            jlog.debug("pubkeys: " + str(self.coinswap_parameters.pubkeys_complete))
            jlog.debug("timeouts: " + str(self.coinswap_parameters.timeouts_complete))
            self.backout("Coinswap parameters is not complete")
            return
        #first entry confirms acceptance of parameters
        to_send = [True,
        self.coinswap_parameters.pubkeys["key_2_2_AC_1"],
        self.coinswap_parameters.pubkeys["key_2_2_CB_0"],
        self.coinswap_parameters.pubkeys["key_TX2_secret"],
        self.coinswap_parameters.pubkeys["key_TX3_lock"],
        self.coinswap_parameters.tx5_address]
        return to_send

    def receive_tx0_hash_tx2sig(self, txid0, hashed_secret, tx2sig):
        """On receipt of a utxo for TX0, a hashed secret, and a sig for TX2,
        construct TX2, verify the provided signature, create our own sig,
        construct TX3, create our own sig,
        return back to Alice, the txid1, the sig of TX2 and the sig of TX3.
        """
        assert self.state == 0
        self.update(1)
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
            self.backout("Counterparty sig for TX2 invalid; backing out.")
            return
        self.update(2)
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
        #create our signature on TX3
        self.tx3.sign_at_index(self.keyset["key_2_2_CB_0"][0], 0)
        our_tx3_sig = self.tx3.signatures[0][0]
        jlog.info("Carol now has partially signed TX3:")
        jlog.info(self.tx3)
        self.update(3)
        return (self.tx1.txid + ":" + str(self.tx1.pay_out_index),
                our_tx2_sig, our_tx3_sig)

    def receive_tx_3_sig(self, sig):
        """Receives the sig on transaction TX3 which pays from our txid of TX1,
        to the 2 of 2 agreed CB. Then, wait until TX0 seen on network.
        """
        assert self.state == 3
        if not self.tx3.include_signature(1, sig):
            self.backout("Counterparty signature for TX2 invalid; backing out.")
            return
        jlog.info("Carol now has fully signed TX3:")
        jlog.info(self.tx3)
        self.update(4)
        #wait until TX0 is seen before pushing ours.
        self.loop = task.LoopingCall(self.check_for_phase1_utxos,
                                     [self.txid0], self.push_tx1)
        self.loop.start(3.0)        
        return True

    def push_tx1(self, txids):
        """Having seen TX0 confirmed, broadcast TX1 and wait for confirmation.
        """
        self.loop.stop()
        errmsg, success = self.tx1.push()
        if not success:
            self.backout("Failed to push TX1, errmsg: " + errmsg)
            return
        #Wait until TX1 seen before confirming phase2 ready.
        print('carol about to start tx1 loop call')
        self.tx1_loop = task.LoopingCall(self.check_for_phase1_utxos,
                                         [self.tx1.txid + ":" + str(
                                             self.tx1.pay_out_index)],
                                         self.receive_confirmation_tx_0_1)
        print('created tx1 loop')
        self.tx1_loop.start(3.0)
        print('started tx1 loop')

    def receive_confirmation_tx_0_1(self, txid1):
        """We wait until client code has confirmed both pay-in txs
        before proceeding; note that this doesn't necessarily mean
        *1* confirmation, could be safer.
        """
        assert self.state == 4
        if not txid1[0] == self.tx1.txid + ":" + str(
            self.tx1.pay_out_index):
            self.backout("Error: received confirmation of wrong txid.")
            return
        self.tx1_loop.stop()
        #No action at end; Alice instigates redeem phase (except timeout backout).
        self.update(5)
        self.phase2_ready = True

    def is_phase2_ready(self):
        return self.phase2_ready

    def receive_secret(self, secret):
        """Receive the secret (preimage of hashed_secret),
        validate it, if valid, update state, construct TX4 and sig
        and send to Alice.
        """
        assert self.state == 5
        print('started receive secret')
        dummy, verifying_hash = get_coinswap_secret(raw_secret=secret)
        if not verifying_hash == self.hashed_secret:
            self.backout("Counterparty provided invalid preimage secret, backing out.")
            return
        #Known valid; must be persisted in case recovery needed.
        self.secret = secret
        self.update(6)
        utxo_in = self.tx1.txid + ":" + str(self.tx1.pay_out_index)
        #We are now ready to directly spend, make TX4 and half-sign.
        self.tx4 = CoinSwapTX45.from_params(
            self.coinswap_parameters.pubkeys["key_2_2_CB_0"],
            self.coinswap_parameters.pubkeys["key_2_2_CB_1"],
            utxo_in=utxo_in,
            destination_address=self.coinswap_parameters.tx4_address,
            destination_amount=self.coinswap_parameters.tx4_amount)
        self.tx4.sign_at_index(self.keyset["key_2_2_CB_0"][0], 0)
        sig = self.tx4.signatures[0][0]
        self.update(7)
        return sig
    
    def receive_tx5_sig(self, sig):
        assert self.state == 7
        print('starting recieve tx5 sig')
        self.tx5 = CoinSwapTX45.from_params(
            self.coinswap_parameters.pubkeys["key_2_2_AC_0"],
            self.coinswap_parameters.pubkeys["key_2_2_AC_1"],
            utxo_in=self.txid0,
            destination_address=self.coinswap_parameters.tx5_address,
            destination_amount=self.coinswap_parameters.tx5_amount)
        if not self.tx5.include_signature(0, sig):
            self.backout("Counterparty signature for TX5 not valid; backing out.")
            return False
        self.update(8)
        #We immediately broadcast
        self.tx5.sign_at_index(self.keyset["key_2_2_AC_1"][0], 1)
        errmsg, success = self.tx5.push()
        if not success:
            self.backout("Failed to push TX5, errmsg: " + errmsg)
            return False
        self.tx5_loop = task.LoopingCall(self.wait_for_tx5_confirmed)
        self.tx5_loop.start(3.0)
        return True

    def wait_for_tx5_confirmed(self):
        assert self.state == 8
        result = jm_single().bc_interface.query_utxo_set([self.tx5.txid+":0"],
                                                         includeconf=True)
        if None in result:
            return
        for u in result:
            if u['confirms'] < 1:
                return
        self.tx5_loop.stop()
        self.tx5_confirmed = True
        jlog.info("Carol received: " + self.tx5.txid + ", now ending.")
        self.persist()        

    def is_tx5_confirmed(self):
        if self.tx5_confirmed:
            return self.tx5.txid + ":0"
        return False

    def watch_for_tx3_spends(self, redeeming_txid):
        """Function used to check whether our, or a competing
        tx, successfully spends out of TX3. Meant to be polled.
        """
        assert self.state in [5, 6, 7]
        spent = detect_spent(self.tx3.txid, 0)
        if not spent:
            return
        #It was spent; did we receive it?
        #Crude method: get the txid of each new transaction from listtransaction
        #(pay attention to order)
        #pass it to getrawtransaction 1 (so serialized)
        #read the input txids.
        jlog.info("TX3 (", self.tx3.txid, "), was spent.")
        #list the recent transactions (TODO)
        recent_txs = jm_single().bc_interface.rpc("listtransactions", ["*", 100])
        for rt in recent_txs:
            #only confirmed
            if rt["confirmations"] < 1:
                continue
            txid = rt["txid"]
            rawtx = jm_single().bc_interface.rpc("getrawtransaction", [txid, 1])
            #check if inputs are from TX1:
            for vin in rawtx["vin"]:
                if vin["txid"] == self.tx3.txid:
                    jlog.info("Found transaction which spent TX3: ", txid)
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
                            self.secret = get_secret_from_vin(vin,
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
                                self.coinswap_parameters.tx5_address)
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