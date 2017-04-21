#!/home/adam/virtualenvs/escrow/bin/python
from __future__ import print_function
import jmbitcoin as btc
from jmclient import (load_program_config, jm_single, Wallet,
                      get_p2pk_vbyte, get_p2sh_vbyte, estimate_tx_fee,
                      sync_wallet, RegtestBitcoinCoreInterface,
                      BitcoinCoreInterface, get_log)
from coinswap import (CoinSwapPublicParameters, CoinSwapAlice,
                      CoinSwapJSONRPCClient, get_current_blockheight)

from twisted.internet import reactor
from twisted.python import log

import time
import os
import sys

def shutdown_block_simulator():
    jm_single().bc_interface.send_thread_shutdown()

def main():
    #twisted logging (TODO disable for non-debug runs)
    log.startLogging(sys.stdout)
    #Joinmarket wallet
    wallet_name = sys.argv[1]
    load_program_config()
    #to allow testing of confirm/unconfirm callback for multiple txs
    if isinstance(jm_single().bc_interface, RegtestBitcoinCoreInterface):
        jm_single().bc_interface.tick_forward_chain_interval = 2
        jm_single().bc_interface.simulating = True
        jm_single().config.set("BLOCKCHAIN", "notify_port", "62653")
        jm_single().config.set("BLOCKCHAIN", "rpc_host", "127.3.0.2")
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
    if isinstance(jm_single().bc_interface, RegtestBitcoinCoreInterface):
        jm_single().bc_interface.grab_coins(alicewallet.get_new_addr(0, 0), 2.0)
        time.sleep(3)
    sync_wallet(alicewallet)
    #if restart option selected, read state and backout
    #(TODO is to attempt restarting normally before backing out)
    if sys.argv[2].lower() == 'true':
        alice = CoinSwapAlice(alicewallet, 'alicestate.json')
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
    #For now let's use a simple default of 10 blocks for LOCK1 and 20 for LOCK0
    current_blockheight = get_current_blockheight()
    lock0 = current_blockheight + 20
    lock1 = current_blockheight + 10
    #instantiate the parameters, but don't yet have the ephemeral pubkeys
    #or destination addresses.
    cpp = CoinSwapPublicParameters(tx01_amount, tx24_recipient_amount,
                                   tx35_recipient_amount)
    cpp.set_tx5_address(tx5address)
    cpp.set_timeouts(lock0, lock1)
    alice = CoinSwapAlice(alicewallet, 'alicestate.json', cpp)
    alice_client = CoinSwapJSONRPCClient("127.0.0.1", "7080",
                                         alice.sm.tick, alice.backout)
    alice.set_jsonrpc_client(alice_client)
    #call to alice's start(), when running, will initiate the protocol
    reactor.callWhenRunning(alice.sm.tick)
    reactor.run()

if __name__ == "__main__":
    main()
