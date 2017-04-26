#!/home/adam/virtualenvs/escrow/bin/python
from __future__ import print_function
import jmbitcoin as btc
from jmclient import Wallet, estimate_tx_fee, validate_address
from coinswap import (cs_single, CoinSwapPublicParameters, CoinSwapAlice,
                      CoinSwapCarol, CoinSwapJSONRPCClient, sync_wallet,
                      get_current_blockheight, RegtestBitcoinCoreInterface,
                      BitcoinCoreInterface, get_log, load_coinswap_config,
                      get_coinswap_parser, CoinSwapCarolJSONServer)

from twisted.internet import reactor
from twisted.python import log
from twisted.web import server

import time
import os
import sys

cslog = get_log()

def main_server(options, wallet):
    #to allow testing of confirm/unconfirm callback for multiple txs
    if isinstance(cs_single().bc_interface, RegtestBitcoinCoreInterface):
        cs_single().bc_interface.tick_forward_chain_interval = 2
        cs_single().bc_interface.simulating = True
        cs_single().config.set("BLOCKCHAIN", "notify_port", "62652")
        cs_single().config.set("BLOCKCHAIN", "rpc_host", "127.0.0.2")
    #if restart option selected, read state and backout
    #(TODO is to attempt restarting normally before backing out)
    #TODO sessionid
    if options.recover:
        session_id = options.recover
        carol = CoinSwapCarol(wallet, 'carolstate')
        carol.bbmb = wallet.get_balance_by_mixdepth(verbose=False)
        carol.load(sessionid=session_id)
        carol.backout("Recovering from shutdown")
        reactor.run()
        return
    #TODO currently ignores server setting here and uses localhost
    _server, port = options.serverport.split(":")
    reactor.listenTCP(int(port), server.Site(CoinSwapCarolJSONServer(wallet)))
    reactor.run()

def main():
    #twisted logging (TODO disable for non-debug runs)
    log.startLogging(sys.stdout)
    #Joinmarket wallet
    parser = get_coinswap_parser()
    (options, args) = parser.parse_args()
    load_coinswap_config()
    wallet_name = args[0]
    #depth 0: spend in, depth 1: receive out, depth 2: for backout transactions.
    max_mix_depth = 3
    if not os.path.exists(os.path.join('wallets', wallet_name)):
        wallet = Wallet(wallet_name, None, max_mix_depth, 6)
    else:
        while True:
            try:
                pwd = get_password("Enter wallet decryption passphrase: ")
                wallet = Wallet(wallet_name, pwd, max_mix_depth, 6)
            except WalletError:
                print("Wrong password, try again.")
                continue
            except Exception as e:
                print("Failed to load wallet, error message: " + repr(e))
                sys.exit(0)
            break
    #for testing, need funds.
    if isinstance(cs_single().bc_interface, RegtestBitcoinCoreInterface):
        cs_single().bc_interface.grab_coins(wallet.get_new_addr(0, 0), 2.0)
        time.sleep(3)
    sync_wallet(wallet, fast=options.fastsync)
    wallet.used_coins = None
    if options.serve:
        #sanity check that client params were not provided:
        if len(args) > 1:
            print("Extra parameters provided for running as server. "
                  "Are you sure you didn't want to run as client?")
            sys.exit(0)
        main_server(options, wallet)
        return
    tx01_amount = int(args[1])
    #Reset the targetting for backout transactions
    oldtarget = cs_single().config.get("POLICY", "tx_fees")
    newtarget = cs_single().config.getint("POLICY", "backout_fee_target")
    multiplier = float(cs_single().config.get("POLICY", "backout_fee_multiplier"))
    cs_single().config.set("POLICY", "tx_fees", str(newtarget))
    tx23fee = estimate_tx_fee((1, 2, 2), 1, txtype='p2shMofN')
    tx23fee = int(multiplier * tx23fee)
    tx24_recipient_amount = tx01_amount - tx23fee
    tx35_recipient_amount = tx01_amount - tx23fee
    cs_single().config.set("POLICY", "tx_fees", oldtarget)
    #to allow testing of confirm/unconfirm callback for multiple txs
    if isinstance(cs_single().bc_interface, RegtestBitcoinCoreInterface):
        cs_single().bc_interface.tick_forward_chain_interval = 2
        cs_single().bc_interface.simulating = True
        cs_single().config.set("BLOCKCHAIN", "notify_port", "62653")
        cs_single().config.set("BLOCKCHAIN", "rpc_host", "127.3.0.2")
    
    #if restart option selected, read state and backout
    if options.recover:
        session_id = options.recover
        alice = CoinSwapAlice(wallet, 'alicestate')
        alice.bbmb = wallet.get_balance_by_mixdepth(verbose=False)
        alice.load(sessionid=session_id)
        alice.backout("Recovering from shutdown")
        reactor.run()
        return
    if len(args) > 2:
        tx5address = args[2]
        if not validate_address(tx5address):
            print("Invalid address: ", tx5address)
            sys.exit(0)
    else:
        #Our destination address should be in a separate mixdepth
        tx5address = wallet.get_new_addr(1, 1)
    #instantiate the parameters, but don't yet have the ephemeral pubkeys
    #or destination addresses.
    cpp = CoinSwapPublicParameters(tx01_amount, tx24_recipient_amount,
                                   tx35_recipient_amount)
    #Alice must set the unique identifier for this run.
    cpp.set_session_id()
    cpp.set_tx5_address(tx5address)
    alice = CoinSwapAlice(wallet, 'alicestate', cpp)
    server, port = options.serverport.split(":")
    alice_client = CoinSwapJSONRPCClient(server, port,
                                         alice.sm.tick, alice.backout)
    alice.set_jsonrpc_client(alice_client)
    reactor.callWhenRunning(alice.sm.tick)
    reactor.run()

if __name__ == "__main__":
    main()
