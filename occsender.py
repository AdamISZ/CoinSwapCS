#! /usr/bin/env python
from __future__ import print_function
from twisted.internet import protocol, reactor, task
from twisted.internet.error import (ConnectionLost, ConnectionAborted,
                                    ConnectionClosed, ConnectionDone)
from twisted.protocols import amp
from twisted.python.log import startLogging
from occcommands import *

import json
import hashlib
import os
import sys
import pprint
import jmbitcoin as btc
from jmclient import (SegwitWallet, get_p2pk_vbyte, get_p2sh_vbyte, estimate_tx_fee)
from coinswap import (cs_single, sync_wallet,
                      get_current_blockheight, RegtestBitcoinCoreInterface,
                      BitcoinCoreInterface, get_log, load_coinswap_config,
                      get_coinswap_parser)
from occbase import (OCCTemplate, OCCTemplateTX, OCCTx, btc_to_satoshis,
                     get_our_keys, get_utxos_from_wallet, create_realtxs_from_template,
                     apply_keys_to_template, satoshis_to_btc)

cslog = get_log()

class OCCClientProtocol(amp.AMP):
    def __init__(self, factory, wallet):
        self.wallet = wallet
        self.factory = factory

    def checkClientResponse(self, response):
        """A generic check of client acceptance; any failure
        is considered criticial.
        """
        if 'accepted' not in response or not response['accepted']:
            #Unintended client shutdown cannot be tested easily in twisted
            reactor.stop() #pragma: no cover

    def defaultErrback(self, failure):
        #see testing note above
        failure.trap(ConnectionAborted, ConnectionClosed, ConnectionDone,
                     ConnectionLost) #pragma: no cover

    def defaultCallbacks(self, d):
        d.addCallback(self.checkClientResponse)
        d.addErrback(self.defaultErrback)

    def connectionMade(self):
        print('connection was made, starting client')
        self.clientStart()

    def clientStart(self):
        #First step: set template, set range required to request
        #from counterparty
        #choose our ins for template
        amtdata = [(0.8, 1.2), (0.2, 0.4)]
        self.template_inputs, msg = get_utxos_from_wallet(self.wallet, amtdata)
        if not self.template_inputs:
            raise Exception("Failed to get appropriate input utxos for amounts: " + str(amtdata))
        #request ins from N-1 counterparties
        amtdata = [(0.8, 1.2), (0.4, 0.6)]
        d = self.callRemote(OCCSetup,
                            amtdata=json.dumps(amtdata))
        self.defaultCallbacks(d)

    @OCCSetupResponse.responder
    def on_OCC_SETUP_RESPONSE(self, template_ins):
        self.counterparty_ins = json.loads(template_ins)
        #create template
        template_data_set = {"n": 2, "N": 5,
                             "out_list": [(0, 0, -1, 1.0), (1, 0, 0, 0.4), (1, 1, -1, 0.4),
                                          (1, 2, -1, 0.2), (2, 0, 1, 2/15.0), (2, 1, 0, 2/15.0),
                                          (2, 2, -1, 11/15.0), (3, 0, 1, 3/8.0), (3, 1, -1, 5/8.0),
                                          (4, 0, 0, 0.3), (4, 1, 1, 0.3), (4, 2, 1, 0.4)],
                             "inflows": [(0, 0, self.template_inputs[0][1],
                                          self.template_inputs[0][0], self.template_inputs[0][3]),
                                         (0, 1, self.counterparty_ins[0][1],
                                          self.counterparty_ins[0][0], self.counterparty_ins[0][3]),
                                         (2, 0, self.template_inputs[1][1],
                                          self.template_inputs[1][0], self.template_inputs[1][3]),
                                         (3, 1, self.counterparty_ins[1][1],
                                          self.counterparty_ins[1][0], self.counterparty_ins[1][3])]
                             }
        self.template = OCCTemplate(template_data_set)
        #pre-choose our keys for template
        #how many keys do we need?
        nkeys_us = self.template.keys_needed(0)
        self.our_keys, our_addresses = get_our_keys(self.wallet, nkeys_us)
        #send filled out template to N-1 counterparties, with
        #our keys to be added to fill out partially.
        #They respond with their keys, and they also sign everything
        #except the funding.
        d = self.callRemote(OCCKeys,
                            template_ins=json.dumps(self.template_inputs),
                            our_keys=json.dumps(self.our_keys),
                            template_data=json.dumps(template_data_set))
        self.defaultCallbacks(d)
        return {"accepted": True}

    @OCCKeysResponse.responder
    def on_OCC_KEYS_RESPONSE(self, our_keys, our_sigs):
        counterparty_keys = json.loads(our_keys)
        self.counterparty_sigs = json.loads(our_sigs)
        self.lt = get_current_blockheight() + 100
        self.realtxs, self.realbackouttxs = create_realtxs_from_template(
            self.wallet, self.template, 2, 0, self.lt)
        apply_keys_to_template(self.wallet, self.template, self.realtxs,
                               self.realbackouttxs,
                               [x[2] for x in self.template_inputs],
                               self.our_keys, 2, 0)
        apply_keys_to_template(self.wallet, self.template, self.realtxs,
                               self.realbackouttxs,
                               [x[2] for x in self.counterparty_ins],
                               counterparty_keys, 2, 1)
        for t in self.realtxs:
            t.mktx()
        for t in self.realbackouttxs:
            t.mktx()
        #Create our signatures for all txs except funding.
        sigs_to_send = []
        for i, tx in enumerate(self.realtxs[1:]):
            for j in range(len(tx.ins)):
                x = self.template.txs[i+1].ins[j]
                if x.spk_type == "NN" or x.counterparty == 0:
                    sigs_to_send.append(tx.sign_at_index(j))

        for tx in self.realbackouttxs:
            for j in range(len(tx.ins)):
                sigs_to_send.append(tx.sign_at_index(j))
        d = self.callRemote(OCCSigs,
                            our_sigs=json.dumps(sigs_to_send))
        self.defaultCallbacks(d)
        return {"accepted": True}

    @OCCSigsResponse.responder
    def on_OCC_SIGS_RESPONSE(self, funding_sigs):
        ba = cs_single().config.getint("POLICY", "broadcast_all")
        funding_sigs = json.loads(funding_sigs)
        #Verify all, including funding, then broadcast.
        for i, tx in enumerate(self.realtxs[1:]):
            for j in range(len(tx.ins)):
                x = self.template.txs[i+1].ins[j]
                if x.spk_type == "NN" or 1 in tx.keys["ins"][j]:
                    #pop removes the used signature for the next iteration
                    tx.include_signature(j, 1, self.counterparty_sigs.pop(0))
            if not ba == 1:
                tx.attach_signatures()
            
        for tx in self.realbackouttxs:
            for j in range(len(tx.ins)):
                tx.include_signature(j, 1, self.counterparty_sigs.pop(0))
            if not ba == 1:
                tx.attach_signatures()
        #Now all transactions except Funding are validly, fully signed,
        #so we are safe to complete signing on the Funding and broadcast
        #that one first. We'll print out all transactions for broadcast,
        #too.
        for i in range(len(self.realtxs[0].ins)):
            if 0 in self.realtxs[0].keys["ins"][i]:
                self.realtxs[0].sign_at_index(i)
            if 1 in self.realtxs[0].keys["ins"][i]:
                self.realtxs[0].include_signature(i, 1, funding_sigs.pop(0))
        #push the funding
        txid, reason = self.realtxs[0].push()
        if not txid:
            cslog.info("Failed to push transaction, reason: " + reason)
        else:
            cslog.info("Succeeded push, txid: " + txid)
            with open("occresults.txt", "wb") as f:
                f.write("Here are the rest of the transactions to push:\n")
                for i, tx in enumerate(self.realtxs[1:]):
                    f.write("Transaction number: " + str(i)+"\n")
                    f.write(str(tx)+"\n")
                for i, tx in enumerate(self.realbackouttxs):
                    f.write("Backout transaction number: " + str(i)+"\n")
                    f.write(str(tx)+"\n")
        if ba == 1:
            #we'll push all the others, one by one
            for i in range(len(self.realtxs)-1):
                reactor.callLater(float(i/10.0), self.realtxs[i+1].push)
            reactor.callLater(5.0, self.final_checks)
        return {"accepted": True}

    def final_checks(self):
        """Check that our keys have received the right funds
        in the wallet (all the single-owned outpoints to p2sh-p2wpkh
        outpoints should contain utxos that own the intended number
        of coins).
        """
        match = True
        total_coins = 0
        for i, tx in enumerate(self.template.txs):
            txid = self.realtxs[i].txid
            for j, tout in enumerate(tx.outs):
                if tout.counterparty == 0:
                    expected_amount = tout.amount
                    print("We expected this amount out: ", expected_amount)
                    actual_key = self.realtxs[i].keys["outs"][j][0]
                    actual_address = btc.pubkey_to_p2sh_p2wpkh_address(actual_key, get_p2sh_vbyte())
                    #direct query on blockchain for the transaction,
                    #then check if it pays to our address and in what amount
                    res = cs_single().bc_interface.rpc('gettxout', [txid, j, True])
                    if not ("scriptPubKey" in res and "addresses" in res["scriptPubKey"]):
                        print("Failed to query the tx: ", txid)
                    found_address = str(res["scriptPubKey"]["addresses"][0])
                    if not found_address == actual_address:
                        print("Error, transaction, vout: ",
                              txid, j,
                              "has address: ", found_address,
                              ", but should have been address: ",
                              actual_address)
                    print("Amount received was: ", res["value"],
                          " at address: ", actual_address)
                    sat_value = btc_to_satoshis(res["value"])
                    total_coins += res["value"]
                    if not sat_value == expected_amount or not actual_address == found_address:
                        match = False
        if match:
            print("Success! Received back total coins: ", total_coins)
        else:
            print("Failure! Not all expected coins received, see above summary.")
        reactor.stop()

class OCCClientProtocolFactory(protocol.ClientFactory):
    protocol = OCCClientProtocol

    def __init__(self, wallet):
        self.wallet = wallet

    def buildProtocol(self, addr):
        return self.protocol(self, self.wallet)

def start_reactor(host, port, factory, ish=True):
    startLogging(sys.stdout)
    reactor.connectTCP(host, int(port), factory)
    reactor.run(installSignalHandlers=ish)
    if isinstance(cs_single().bc_interface, RegtestBitcoinCoreInterface):
        cs_single().bc_interface.shutdown_signal = True

if __name__ == "__main__":
    #choose wallet
    parser = get_coinswap_parser()
    (options, args) = parser.parse_args()
    load_coinswap_config()
    wallet_name = args[0]
    serv, port = args[1:3]
    if len(sys.argv) > 4:
        cs_single().config.set("POLICY", "broadcast_all", "1")
    else:
        cs_single().config.set("POLICY", "broadcast_all", "0")
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
    alice_promise_utxo_addr = wallet.get_new_addr(0, 0, True)
    #TODO even with a fixed template, the template must be parametrized
    #by the input and promise values, this can be read in from arguments
    #and then applied to these grabs (which are only for POC anyway);
    #next step would be to have the parametrization based on wallet
    #contents (still needs ranges though).
    cs_single().bc_interface.grab_coins(funding_utxo_addr, 1.0)
    cs_single().bc_interface.grab_coins(alice_promise_utxo_addr, 0.3)
    sync_wallet(wallet, fast=options.fastsync)
    factory = OCCClientProtocolFactory(wallet)
    start_reactor(serv, port, factory)
    print('done')
