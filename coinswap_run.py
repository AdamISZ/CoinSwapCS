#!/home/adam/virtualenvs/escrow/bin/python
from __future__ import print_function
import jmbitcoin as btc
from jmclient import SegwitWallet, WalletError, estimate_tx_fee, validate_address
from jmbase.support import get_password
from coinswap import (cs_single, CoinSwapPublicParameters, CoinSwapAlice,
                      CoinSwapCarol, CoinSwapJSONRPCClient, sync_wallet,
                      get_current_blockheight, RegtestBitcoinCoreInterface,
                      BitcoinCoreInterface, get_log, load_coinswap_config,
                      get_coinswap_parser, CoinSwapCarolJSONServer, start_tor)

from twisted.internet import reactor
try:
    from twisted.internet import ssl
except ImportError:
    pass
from twisted.python import log
from twisted.web import server

import time
import os
import sys
import json

cslog = get_log()

def parse_server_string(server_string):
    scheme, server, port = server_string.split(":")
    print("got this scheme, server, port: ", scheme, server, port)
    if scheme == "https":
        usessl = True
    elif scheme == "http":
        usessl = False
    else:
        print("Invalid server string: ", server_string)
        sys.exit(0)
    if not server[:2] == "//":
        print("Invalid server string: ", server_string)
        sys.exit(0)
    return server, port, usessl

def print_status(status):
    """Used for checkonly option
    """
    print(json.dumps(status, indent=4))
    reactor.stop()

def get_ssl_context():
    """Construct an SSL context factory from the user's privatekey/cert.
    TODO: document set up for server operators.
    """
    pkcdata = {}
    for x, y in zip(["ssl_private_key_location", "ssl_certificate_location"],
                    ["key.pem", "cert.pem"]):
        if cs_single().config.get("SERVER", x) == "0":
            sslpath = os.path.join(cs_single().homedir, "ssl")
            if not os.path.exists(sslpath):
                print("No ssl configuration in home directory, please read "
                      "installation instructions and try again.")
                sys.exit(0)
            pkcdata[x] = os.path.join(sslpath, y)
        else:
            pkcdata[x] = cs_single().config.get("SERVER", x)
    return ssl.DefaultOpenSSLContextFactory(pkcdata["ssl_private_key_location"],
                                            pkcdata["ssl_certificate_location"])

def main_server(options, wallet, test_data=None):
    """The use_ssl option is only for tests, and flags that case.
    """
    if test_data and not test_data['use_ssl']:
        cs_single().config.set("SERVER", "use_ssl", "false")
    cs_single().bc_interface.start_unspent_monitoring(wallet)
    #to allow testing of confirm/unconfirm callback for multiple txs
    if isinstance(cs_single().bc_interface, RegtestBitcoinCoreInterface):
        cs_single().bc_interface.tick_forward_chain_interval = 2
        cs_single().bc_interface.simulating = True
        cs_single().config.set("BLOCKCHAIN", "notify_port", "62652")
        cs_single().config.set("BLOCKCHAIN", "rpc_host", "127.0.0.2")
    #if restart option selected, read state and backout
    #(TODO is to attempt restarting normally before backing out)
    if options.recover:
        session_id = options.recover
        carol = CoinSwapCarol(wallet, 'carolstate')
        carol.bbmb = wallet.get_balance_by_mixdepth(verbose=False)
        carol.load(sessionid=session_id)
        carol.backout("Recovering from shutdown")
        reactor.run()
        return
    #TODO currently ignores server setting here and uses localhost
    port = cs_single().config.getint("SERVER", "port")
    testing_mode = True if test_data else False
    carol_class = test_data['alt_c_class'] if test_data and \
        test_data['alt_c_class'] else CoinSwapCarol
    fcs = test_data["fail_carol_state"] if test_data else None
    #Hidden service has first priority
    if cs_single().config.get("SERVER", "use_onion") != "false":
        s = server.Site(CoinSwapCarolJSONServer(wallet,
                                                    testing_mode=testing_mode,
                                                    carol_class=carol_class,
                                                    fail_carol_state=fcs))
        hiddenservice_dir = os.path.join(cs_single().homedir, "hiddenservice")
        if not os.path.exists(hiddenservice_dir):
            os.makedirs(hiddenservice_dir)
        if 'hs_dir' in cs_single().config.options('SERVER'):
            hiddenservice_dir = cs_single().config.get("SERVER", "hs_dir")
        d = start_tor(s, cs_single().config.getint("SERVER", "onion_port"),
                      hiddenservice_dir)
        #Any callbacks after Tor is inited can be added here with d.addCallback
    elif cs_single().config.get("SERVER", "use_ssl") != "false":
        reactor.listenSSL(int(port), server.Site(CoinSwapCarolJSONServer(wallet,
                testing_mode=testing_mode, carol_class=carol_class,
                fail_carol_state=fcs)), contextFactory = get_ssl_context())
    else:
        cslog.info("WARNING! Serving over HTTP, no TLS used!")
        reactor.listenTCP(int(port), server.Site(CoinSwapCarolJSONServer(wallet,
                                                    testing_mode=testing_mode,
                                                    carol_class=carol_class,
                                                    fail_carol_state=fcs)))
    if not test_data:
        reactor.run()

def main_cs(test_data=None):
    #twisted logging (TODO disable for non-debug runs)
    if test_data:
        wallet_name, args, options, use_ssl, alt_class, alt_c_class, fail_alice_state, fail_carol_state = test_data
        server, port, usessl = parse_server_string(options.serverport)
    else:
        parser = get_coinswap_parser()
        (options, args) = parser.parse_args()
        #Will only be used by client
        server, port, usessl = parse_server_string(options.serverport)
        if options.checkonly:
            #no need for any more data; just query
            alice_client = CoinSwapJSONRPCClient(server[2:], port, usessl=usessl)
            reactor.callWhenRunning(alice_client.send_poll_unsigned,
                                    "status", print_status)
            reactor.run()
            return
        log.startLogging(sys.stdout)
        load_coinswap_config()
        wallet_name = args[0]
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
    #for testing main script (not test framework), need funds.
    if not test_data and isinstance(
        cs_single().bc_interface, RegtestBitcoinCoreInterface):
        for i in range(3):
            cs_single().bc_interface.grab_coins(wallet.get_new_addr(0, 0, True), 2.0)
        wallet.index[0][0] -= 3
        time.sleep(3)
    sync_wallet(wallet, fast=options.fastsync)
    if test_data:
        cs_single().bc_interface.wallet_synced = True
    wallet.used_coins = None
    if options.serve:
        #sanity check that client params were not provided:
        if len(args) > 1:
            print("Extra parameters provided for running as server. "
                  "Are you sure you didn't want to run as client?")
            sys.exit(0)
        if not test_data:
            main_server(options, wallet)
        else:
            main_server(options, wallet, {'use_ssl': use_ssl,
                                          'alt_c_class': alt_c_class,
                                          'fail_carol_state': fail_carol_state})
            return wallet.get_balance_by_mixdepth()
        return
    if not options.recover:
        target_amount = int(args[1])
        #Reset the targetting for backout transactions
        #TODO must be removed/changed for updated fees handling
        oldtarget = cs_single().config.get("POLICY", "tx_fees")
        newtarget = cs_single().config.getint("POLICY", "backout_fee_target")
        multiplier = float(cs_single().config.get("POLICY", "backout_fee_multiplier"))
        cs_single().config.set("POLICY", "tx_fees", str(newtarget))
        tx23fee = estimate_tx_fee((1, 2, 2), 1, txtype='p2shMofN')
        tx23fee = int(multiplier * tx23fee)
        tx24_recipient_amount = target_amount - tx23fee
        tx35_recipient_amount = target_amount - tx23fee
        cs_single().config.set("POLICY", "tx_fees", oldtarget)
    #to allow testing of confirm/unconfirm callback for multiple txs
    if isinstance(cs_single().bc_interface, RegtestBitcoinCoreInterface):
        cs_single().bc_interface.tick_forward_chain_interval = 2
        cs_single().bc_interface.simulating = True
        cs_single().config.set("BLOCKCHAIN", "notify_port", "62652")
        cs_single().config.set("BLOCKCHAIN", "rpc_host", "127.0.0.2")
    
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
        tx5address = wallet.get_new_addr(1, 1, True)
    #instantiate the parameters, but don't yet have the ephemeral pubkeys
    #or destination addresses.
    #TODO figure out best estimate incl. priority
    btcfee_est = estimate_tx_fee((1, 2, 2), 1, txtype='p2shMofN')
    cpp = CoinSwapPublicParameters(base_amount=target_amount, bitcoin_fee=btcfee_est)
    cpp.set_addr_data(addr5=tx5address)
    testing_mode = True if test_data else False
    aliceclass = alt_class if test_data and alt_class else CoinSwapAlice
    if test_data and fail_alice_state:
        alice = aliceclass(wallet, 'alicestate', cpp, testing_mode=testing_mode,
                           fail_state=fail_alice_state)
    else:
        if testing_mode or options.checkfee:
            alice = aliceclass(wallet, 'alicestate', cpp, testing_mode=testing_mode)
        else:
            alice = aliceclass(wallet, 'alicestate', cpp, testing_mode=testing_mode,
                           fee_checker="cli")

    alice_client = CoinSwapJSONRPCClient(server[2:], port,
                                         alice.sm.tick, alice.backout, usessl)
    alice.set_jsonrpc_client(alice_client)
    reactor.callWhenRunning(alice_client.send_poll_unsigned, "status",
                            alice.check_server_status)
    if not test_data:
        reactor.run()
    if test_data:
        return alice

if __name__ == "__main__":
    main_cs()
