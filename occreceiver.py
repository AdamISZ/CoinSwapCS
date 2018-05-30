#!/usr/bin/env python
from __future__ import print_function
import jmbitcoin as btc
from jmclient import (SegwitWallet, WalletError, estimate_tx_fee,
                      validate_address)
from jmbase.support import get_password
from coinswap import (cs_single, sync_wallet,
                      get_current_blockheight, RegtestBitcoinCoreInterface,
                      BitcoinCoreInterface, get_log, load_coinswap_config,
                      get_coinswap_parser)
from occbase import (OCCTemplate, OCCTemplateTX, OCCTx, btc_to_satoshis,
                     get_our_keys, get_utxos_from_wallet, create_realtxs_from_template,
                     apply_keys_to_template, satoshis_to_btc)

from twisted.protocols import amp
from twisted.internet import reactor
from twisted.internet.protocol import ServerFactory
from twisted.internet.error import (ConnectionLost, ConnectionAborted,
                                    ConnectionClosed, ConnectionDone)
from twisted.python import log

from occcommands import *

import time
import os
import sys
import json

cslog = get_log()


class OCCServerProtocol(amp.AMP):

    def __init__(self, factory, wallet):
        self.factory = factory
        self.wallet = wallet

    def checkClientResponse(self, response):
        """A generic check of client acceptance; any failure
        is considered criticial.
        """
        if 'accepted' not in response or not response['accepted']:
            reactor.stop() #pragma: no cover

    def defaultErrback(self, failure):
        """TODO better network error handling.
        """
        failure.trap(ConnectionAborted, ConnectionClosed,
                     ConnectionDone, ConnectionLost)

    def defaultCallbacks(self, d):
        d.addCallback(self.checkClientResponse)
        d.addErrback(self.defaultErrback)

    @OCCSetup.responder
    def on_SETUP(self, amtdata):
        amtdata = json.loads(amtdata)
        self.our_ins, msg = get_utxos_from_wallet(self.wallet, amtdata)
        if not self.our_ins:
            raise Exception("Failed to get utxos, reason: " + str(msg))
        d = self.callRemote(OCCSetupResponse,
                            template_ins=json.dumps(self.our_ins))
        self.defaultCallbacks(d)
        return {'accepted': True}

    @OCCKeys.responder
    def on_KEYS(self, template_ins, our_keys, template_data):
        counterparty_ins = json.loads(template_ins)
        counterparty_keys = json.loads(our_keys)
        template_data = json.loads(template_data)
        self.template = OCCTemplate(template_data)
        nkeys_us = self.template.keys_needed(1)
        our_keys, our_addresses = get_our_keys(self.wallet, nkeys_us)
        self.lt = get_current_blockheight() + 100
        self.realtxs, self.realbackouttxs = create_realtxs_from_template(self.wallet,
                                                               self.template, 2, 1, self.lt)
        apply_keys_to_template(self.wallet, self.template, self.realtxs,
                               self.realbackouttxs, [x[2] for x in counterparty_ins],
                               counterparty_keys, 2, 0)
        apply_keys_to_template(self.wallet, self.template, self.realtxs,
                               self.realbackouttxs, [x[2] for x in self.our_ins],
                               our_keys, 2, 1)
        for t in self.realtxs:
            t.mktx()
        for t in self.realbackouttxs:
            t.mktx()
        #Create our signatures for all txs except funding.
        sigs_to_send = []
        for i, tx in enumerate(self.realtxs[1:]):
            for j in range(len(tx.ins)):
                x = self.template.txs[i+1].ins[j]
                if x.spk_type == "NN" or x.counterparty == 1:
                    sigs_to_send.append(tx.sign_at_index(j))
        for tx in self.realbackouttxs:
            for j in range(len(tx.ins)):
                sigs_to_send.append(tx.sign_at_index(j))
        d = self.callRemote(OCCKeysResponse,
                            our_keys=json.dumps(our_keys),
                            our_sigs=json.dumps(sigs_to_send))
        self.defaultCallbacks(d)
        return {'accepted': True}

    @OCCSigs.responder
    def on_SIGS(self, our_sigs):
        counterparty_sigs = json.loads(our_sigs)
        #Include their signatures (automatically verifying),
        #then send them the funding sig.
        for i, tx in enumerate(self.realtxs[1:]):
            for j in range(len(tx.ins)):
                x = self.template.txs[i+1].ins[j]
                if x.spk_type == "NN" or 0 in tx.keys["ins"][j]:
                    #pop removes the used signature for the next iteration
                    tx.include_signature(j, 0, counterparty_sigs.pop(0))

        for tx in self.realbackouttxs:
            for j in range(len(tx.ins)):
                tx.include_signature(j, 0, counterparty_sigs.pop(0))

        #sign the funding transaction
        sigs_to_send = []
        for i in range(len(self.realtxs[0].ins)):
            if 1 in self.realtxs[0].keys["ins"][i]:
                sigs_to_send.append(self.realtxs[0].sign_at_index(i))

        d = self.callRemote(OCCSigsResponse,
                            funding_sigs=json.dumps(sigs_to_send))
        self.defaultCallbacks(d)
        return {'accepted': True}


class OCCServerProtocolFactory(ServerFactory):
    protocol = OCCServerProtocol
    def __init__(self, wallet):
        self.wallet = wallet

    def buildProtocol(self, addr):
        return self.protocol(self, self.wallet)

def start_daemon(host, port, factory):
    reactor.listenTCP(int(port), factory, interface=host)

def main(finalizer=None, finalizer_args=None):
    #twisted logging (TODO disable for non-debug runs)
    
    parser = get_coinswap_parser()
    (options, args) = parser.parse_args()
    #Will only be used by client
    log.startLogging(sys.stdout)
    load_coinswap_config()
    #to allow testing of confirm/unconfirm callback for multiple txs
    if isinstance(cs_single().bc_interface, RegtestBitcoinCoreInterface):
        cs_single().bc_interface.tick_forward_chain_interval = 2
        cs_single().bc_interface.simulating = True

    wallet_name = args[0]
    server, port = args[1:3]
    #depth 0: spend in, depth 1: receive out, depth 2: for backout transactions.
    max_mix_depth = 3
    wallet_dir = os.path.join(cs_single().homedir, 'wallets')
    if not os.path.exists(os.path.join(wallet_dir, wallet_name)):
        wallet = SegwitWallet(wallet_name, None, max_mix_depth, 6,
                              wallet_dir=wallet_dir)
    else:
        while True:
            try:
                pwd = get_password("Enter wallet decryption passphrase: ")
                wallet = SegwitWallet(wallet_name, pwd, max_mix_depth, 6,
                                      wallet_dir=wallet_dir)
            except WalletError:
                print("Wrong password, try again.")
                continue
            except Exception as e:
                print("Failed to load wallet, error message: " + repr(e))
                sys.exit(0)
            break
    #funding the wallet with outputs specifically suitable for the starting point.
    funding_utxo_addr = wallet.get_new_addr(0, 0, True)
    bob_promise_utxo_addr = wallet.get_new_addr(0, 0, True)
    cs_single().bc_interface.grab_coins(funding_utxo_addr, 1.0)
    cs_single().bc_interface.grab_coins(bob_promise_utxo_addr, 0.5)    
    sync_wallet(wallet, fast=options.fastsync)
    wallet.used_coins = None
    factory = OCCServerProtocolFactory(wallet)
    start_daemon(server , port, factory)
    if finalizer:
        reactor.addSystemEventTrigger("after", "shutdown", finalizer,
                                      finalizer_args)
    reactor.run()

if __name__ == "__main__":
    main()
