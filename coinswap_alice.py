#!/home/adam/virtualenvs/escrow/bin/python
from __future__ import print_function
import jmbitcoin as btc
from jmclient import Wallet, estimate_tx_fee
from coinswap import (cs_single, CoinSwapPublicParameters, CoinSwapAlice,
                      CoinSwapJSONRPCClient, get_current_blockheight,
                      sync_wallet, RegtestBitcoinCoreInterface,
                      BitcoinCoreInterface, get_log, load_coinswap_config)

from twisted.internet import reactor
from twisted.python import log

import time
import os
import sys

cslog = get_log()

def main():
    #twisted logging (TODO disable for non-debug runs)
    log.startLogging(sys.stdout)
    #Joinmarket wallet
    wallet_name = sys.argv[1]
    load_coinswap_config()
    #to allow testing of confirm/unconfirm callback for multiple txs
    if isinstance(cs_single().bc_interface, RegtestBitcoinCoreInterface):
        cs_single().bc_interface.tick_forward_chain_interval = 2
        cs_single().bc_interface.simulating = True
        cs_single().config.set("BLOCKCHAIN", "notify_port", "62653")
        cs_single().config.set("BLOCKCHAIN", "rpc_host", "127.3.0.2")
    #depth 0: spend in, depth 1: receive out, depth 2: for backout transactions.
    max_mix_depth = 3
    if not os.path.exists(os.path.join('wallets', wallet_name)):
        alicewallet = Wallet(wallet_name, None, max_mix_depth, 6)
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
        cs_single().bc_interface.grab_coins(alicewallet.get_new_addr(0, 0), 2.0)
        time.sleep(3)
    sync_wallet(alicewallet)
    #if restart option selected, read state and backout
    #(TODO is to attempt restarting normally before backing out)
    if sys.argv[2].lower() == 'true':
        alice = CoinSwapAlice(alicewallet, 'alicestate')
        alice.bbmb = alicewallet.get_balance_by_mixdepth()
        alice.load()
        alice.backout("Recovering from shutdown")
        return

    #TODO create config file and set vars.
    #for new runs, read amount parameters
    tx01_amount, tx24_recipient_amount, tx35_recipient_amount = [int(
        x) for x in sys.argv[3:6]]
    #Our destination address should be in a separate mixdepth
    tx5address = alicewallet.get_new_addr(1, 1)
    #instantiate the parameters, but don't yet have the ephemeral pubkeys
    #or destination addresses.
    cpp = CoinSwapPublicParameters(tx01_amount, tx24_recipient_amount,
                                   tx35_recipient_amount)
    #Alice must set the unique identifier for this run.
    cpp.set_session_id()
    cpp.set_tx5_address(tx5address)
    alice = CoinSwapAlice(alicewallet, 'alicestate', cpp)
    alice_client = CoinSwapJSONRPCClient("127.0.0.1", "7080",
                                         alice.sm.tick, alice.backout)
    alice.set_jsonrpc_client(alice_client)
    #call to alice's start(), when running, will initiate the protocol
    reactor.callWhenRunning(alice.sm.tick)
    reactor.run()

if __name__ == "__main__":
    main()
