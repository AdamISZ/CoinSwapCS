#!/home/adam/virtualenvs/escrow/bin/python
from __future__ import print_function
import jmbitcoin as btc
import pytest
import sys
import os
data_dir = os.path.dirname(os.path.dirname(os.path.realpath(__file__)))
sys.path.insert(0, os.path.join(data_dir))

from coinswap import cs_single, get_log, load_coinswap_config, sync_wallet
from bad_participants import Fake_Alice_1

from twisted.internet import reactor, task
from twisted.python import log

from commontest import make_wallets, make_sign_and_push
from coinswap_run import main_cs

cslog = get_log()

#fees are low on regtest; tests will fail if larger than this
reasonable_fee_maximum = 20000

class Options(object):
    recover = False
    serverport = "http://127.0.0.1:7080"
    fastsync= False
    serve = True

def miner():
    cs_single().bc_interface.tick_forward_chain(1)

def start_mining(l):
    l.start(4.0)

def get_params():
    """parametrize is not allowed with injected config vars from command line;
    also, multiple runs of the reactor is not supported. So, we just statically
    recover the necessary parameters.
    """
    return (1,
            [[1, 0, 0]]*2,
            [10000000],
            2.0,
            None,
            False)

def case_fake_secret():
    num_alices, wallet_structures, amounts, funding_amount, dest_addr, fixed_seeds = get_params()
    options_server = Options()
    wallets = make_wallets(num_alices + 1,
                               wallet_structures=wallet_structures,
                               mean_amt=funding_amount)
    args_server = ["dummy"]
    test_data_server = (wallets[num_alices]['seed'], args_server, options_server,
                        False, None)
    carol_bbmb = main_cs(test_data_server)
    options_alice = Options()
    options_alice.serve = False
    alices = []
    for i in range(num_alices):
        args_alice = ["dummy", amounts[i]]
        if dest_addr:
            args_alice.append(dest_addr)
        test_data_alice = (wallets[i]['seed'], args_alice, options_alice, False,
                           Fake_Alice_1)
        alices.append(main_cs(test_data_alice))
    l = task.LoopingCall(miner)
    reactor.callWhenRunning(start_mining, l)
    reactor.run()
    return (alices, carol_bbmb, wallets[num_alices]['wallet'])

def case_cooperative():
    num_alices, wallet_structures, amounts, funding_amount, dest_addr, fixed_seeds = get_params()
    options_server = Options()
    wallets = make_wallets(num_alices + 1,
                               wallet_structures=wallet_structures,
                               mean_amt=funding_amount)
    args_server = ["dummy"]
    test_data_server = (wallets[num_alices]['seed'], args_server, options_server,
                        False, None)
    carol_bbmb = main_cs(test_data_server)
    options_alice = Options()
    options_alice.serve = False
    alices = []
    for i in range(num_alices):
        args_alice = ["dummy", amounts[i]]
        if dest_addr:
            args_alice.append(dest_addr)
        test_data_alice = (wallets[i]['seed'], args_alice, options_alice, False,
                           None)
        alices.append(main_cs(test_data_alice))
    l = task.LoopingCall(miner)
    reactor.callWhenRunning(start_mining, l)
    reactor.run()
    return (alices, carol_bbmb, wallets[num_alices]['wallet'])

test_cases = {"cooperative": case_cooperative,
              "fakesecret": case_fake_secret}

def assert_funds_balance(expected_amt, funds_spent, funds_received):
    assert funds_spent > expected_amt, "Expected spent, Actual spent: " + \
                str(expected_amt) + "," + str(funds_spent)
    assert funds_received > expected_amt, "Expected received, Actual received: " + \
           str(expected_amt) + "," + str(funds_received)

def test_run_both(setup_wallets, runtype):
    alices, carol_bbmb, carol_wallet = test_cases[runtype]()
    #test case function will only return on reactor shutdown; Alice and Carol
    #objects are set at the start, but are references so updated.
    #Check the wallet states reflect the expected updates.
    num_alices, wallet_structures, amounts, funding_amount, dest_addr, fixed_seeds = get_params()
    #TODO handle multiple alices with different amounts against one Carol.
    expected_amt = amounts[0] - reasonable_fee_maximum
    for i, alice in enumerate(alices):
        funds_spent = alice.bbmb[0] - alice.bbma[0]
        funds_received = alice.bbma[1] - alice.bbmb[1]
        assert_funds_balance(expected_amt, funds_spent, funds_received)
    #Carol is handled a bit differently, since Carol instances are initiated on
    #the fly, we instead query the wallet object directly for the final balances.
    sync_wallet(carol_wallet)
    carol_bbma = carol_wallet.get_balance_by_mixdepth(verbose=False)
    funds_spent = carol_bbmb[0] - carol_bbma[0]
    funds_received = carol_bbma[1] - carol_bbmb[1]
    assert_funds_balance(expected_amt, funds_spent, funds_received)

@pytest.fixture(scope="module")
def setup_wallets():
    log.startLogging(sys.stdout)    
    load_coinswap_config()
    cs_single().num_entities_running = 0
