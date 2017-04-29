#!/home/adam/virtualenvs/escrow/bin/python
from __future__ import print_function
import jmbitcoin as btc
from jmclient import Wallet, WalletError, estimate_tx_fee, validate_address
from jmbase.support import get_password
import pytest
import sys
import os
data_dir = os.path.dirname(os.path.dirname(os.path.realpath(__file__)))
sys.path.insert(0, os.path.join(data_dir))

from coinswap import (cs_single, CoinSwapPublicParameters, CoinSwapAlice,
                      CoinSwapCarol, CoinSwapJSONRPCClient, sync_wallet,
                      get_current_blockheight, RegtestBitcoinCoreInterface,
                      BitcoinCoreInterface, get_log, load_coinswap_config,
                      get_coinswap_parser, CoinSwapCarolJSONServer)

from twisted.internet import reactor, task
try:
    from twisted.internet import ssl
except ImportError:
    pass
from twisted.python import log
from twisted.web import server

import time

from commontest import make_wallets, make_sign_and_push
from coinswap_run import main_cs

cslog = get_log()

def miner():
    cs_single().bc_interface.tick_forward_chain(1)

def start_mining(l):
    l.start(4.0)
    
@pytest.mark.parametrize(
    "num_alices, wallet_structures, amounts, funding_amount, dest_addr, fixed_seeds",
    [
        (1, [[1, 0, 0]]*2, [10000000], 2.0, None, False),
    ])
def test_run_both(setup_wallets, num_alices, wallet_structures, amounts,
                  funding_amount, dest_addr, fixed_seeds):
    class Options(object):
        recover = False
        serverport = "http://127.0.0.1:7080"
        fastsync= False
        serve = True
    options_server = Options()
    wallets = make_wallets(num_alices + 1,
                               wallet_structures=wallet_structures,
                               mean_amt=funding_amount)
    args_server = ["dummy"]
    test_data_server = (wallets[num_alices]['seed'], args_server, options_server, False)
    main_cs(test_data_server)
    options_alice = Options()
    options_alice.serve = False
    for i in range(num_alices):
        args_alice = ["dummy", amounts[i]]
        if dest_addr:
            args_alice.append(dest_addr)
        test_data_alice = (wallets[i]['seed'], args_alice, options_alice, False)
        main_cs(test_data_alice)
    l = task.LoopingCall(miner)
    reactor.callWhenRunning(start_mining, l)
    reactor.run()

        
@pytest.fixture(scope="module")
def setup_wallets():
    log.startLogging(sys.stdout)    
    load_coinswap_config()
    cs_single().num_entities_running = 0
