#!/home/adam/virtualenvs/escrow/bin/python
from __future__ import print_function
import jmbitcoin as btc
from jmclient import (load_program_config, jm_single, Wallet,
                      get_p2pk_vbyte, get_p2sh_vbyte, estimate_tx_fee,
                      sync_wallet, RegtestBitcoinCoreInterface,
                      BitcoinCoreInterface, get_log)
from coinswap import (CoinSwapPublicParameters, CoinSwapCarol,
                      CoinSwapCarolJSONServer, get_current_blockheight)

from twisted.internet import reactor
from twisted.web import server
from twisted.python import log

import time
import os
import sys

def main():
    log.startLogging(sys.stdout)
    wallet_name = sys.argv[1]
    load_program_config()
    #to allow testing of confirm/unconfirm callback for multiple txs
    if isinstance(jm_single().bc_interface, RegtestBitcoinCoreInterface):
        jm_single().bc_interface.tick_forward_chain_interval = 2
        jm_single().bc_interface.simulating = True
        jm_single().config.set("BLOCKCHAIN", "notify_port", "62652")
        jm_single().config.set("BLOCKCHAIN", "rpc_host", "127.0.0.2")
    #depth 0: spend in, depth 1: receive out, depth 2: for backout transactions.
    max_mix_depth = 3
    if not os.path.exists(os.path.join('wallets', wallet_name)):
        carolwallet = Wallet(wallet_name, None, max_mix_depth, 6)
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
    #grab coins ticks forward chain 1 block; must be taken into locktime account
    jm_single().bc_interface.grab_coins(carolwallet.get_new_addr(0, 0), 2.0)
    time.sleep(3)
    sync_wallet(carolwallet)
    #if restart option selected, read state and backout
    #(TODO is to attempt restarting normally before backing out)
    if sys.argv[2].lower() == 'true':
        carol = CoinSwapCarol(carolwallet, 'carolstate.json')
        carol.bbmb = carolwallet.get_balance_by_mixdepth()
        carol.load()
        carol.backout("Recovering from shutdown")
        return
    tx01_amount, tx24_recipient_amount, tx35_recipient_amount = [int(
        x) for x in sys.argv[3:6]]
    tx4address = carolwallet.get_new_addr(1, 1)
    #For now let's use a simple default of 10 blocks for LOCK1 and 20 for LOCK0
    current_blockheight = get_current_blockheight()
    lock0 = current_blockheight + 20
    lock1 = current_blockheight + 10
    #instantiate the parameters, but don't yet have the ephemeral pubkeys
    #or destination addresses.
    cpp = CoinSwapPublicParameters(tx01_amount, tx24_recipient_amount,
                                   tx35_recipient_amount)
    cpp.set_tx4_address(tx4address)
    cpp.set_timeouts(lock0, lock1)
    carol = CoinSwapCarol(carolwallet, 'carolstate.json', cpp)
    #TODO this will be config variables:
    carol.set_handshake_parameters()
    reactor.listenTCP(7080, server.Site(CoinSwapCarolJSONServer(carol)))
    reactor.run()

if __name__ == "__main__":
    main()
