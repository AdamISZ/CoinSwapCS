from __future__ import print_function

import abc
import ast
import json
import os
import pprint
import random
import re
import sys
import threading
import time
import urllib
import urllib2
import traceback
import binascii
from decimal import Decimal
from twisted.internet import reactor, task

import jmbitcoin as btc

from jmclient.jsonrpc import JsonRpcConnectionError, JsonRpcError
from jmclient.configure import get_p2pk_vbyte, get_p2sh_vbyte
from jmbase.support import chunks

from coinswap import cs_single, get_log

cslog = get_log()

def is_index_ahead_of_cache(wallet, mix_depth, forchange):
    if mix_depth >= len(wallet.index_cache):
        return True
    return wallet.index[mix_depth][forchange] >= wallet.index_cache[mix_depth][
        forchange]

def sync_wallet(wallet, fast=False):
    """Wrapper function to choose fast syncing where it's
    both possible and requested.
    """
    if fast and (
        isinstance(cs_single().bc_interface, BitcoinCoreInterface) or isinstance(
                cs_single().bc_interface, RegtestBitcoinCoreInterface)):
        cs_single().bc_interface.sync_wallet(wallet, fast=True)
    else:
        cs_single().bc_interface.sync_wallet(wallet)

class BlockchainInterface(object):
    __metaclass__ = abc.ABCMeta

    def __init__(self):
        pass

    def sync_wallet(self, wallet):
        self.sync_addresses(wallet)
        self.sync_unspent(wallet)

    @abc.abstractmethod
    def sync_addresses(self, wallet):
        """Finds which addresses have been used and sets
        wallet.index appropriately"""

    @abc.abstractmethod
    def sync_unspent(self, wallet):
        """Finds the unspent transaction outputs belonging to this wallet,
        sets wallet.unspent """

    @abc.abstractmethod
    def add_tx_notify(self,
                      txd,
                      unconfirmfun,
                      confirmfun,
                      notifyaddr,
                      timeoutfun=None):
        """
        Invokes unconfirmfun and confirmfun when tx is seen on the network
        If timeoutfun not None, called with boolean argument that tells
            whether this is the timeout for unconfirmed or confirmed
            timeout for uncontirmed = False
        """

    @abc.abstractmethod
    def pushtx(self, txhex):
        """pushes tx to the network, returns False if failed"""

    @abc.abstractmethod
    def query_utxo_set(self, txouts, includeconf=False):
        """
        takes a utxo or a list of utxos
        returns None if they are spend or unconfirmed
        otherwise returns value in satoshis, address and output script
        optionally return the coin age in number of blocks
        """
        # address and output script contain the same information btw

    @abc.abstractmethod
    def estimate_fee_per_kb(self, N):
        '''Use the blockchain interface to 
        get an estimate of the transaction fee per kb
        required for inclusion in the next N blocks.
	'''

class BitcoinCoreInterface(BlockchainInterface):

    def __init__(self, jsonRpc, network):
        super(BitcoinCoreInterface, self).__init__()
        self.jsonRpc = jsonRpc
        self.fast_sync_called = False
        blockchainInfo = self.jsonRpc.call("getblockchaininfo", [])
        actualNet = blockchainInfo['chain']

        netmap = {'main': 'mainnet', 'test': 'testnet', 'regtest': 'regtest'}
        if netmap[actualNet] != network:
            raise Exception('wrong network configured')

        self.notifythread = None
        self.txnotify_fun = []
        self.wallet_synced = False
        #task.LoopingCall objects that track transactions, keyed by txids.
        #Format: {"txid": (loop, unconfirmed true/false, confirmed true/false,
        #spent true/false), ..}
        self.tx_watcher_loops = {}

    @staticmethod
    def get_wallet_name(wallet):
        return 'joinmarket-wallet-' + btc.dbl_sha256(wallet.keys[0][0])[:6]

    def get_block(self, blockheight):
        """Returns full serialized block at a given height.
        """
        block_hash = self.rpc('getblockhash', [blockheight])
        block = self.rpc('getblock', [block_hash, False])
        if not block:
            return False
        return block

    def rpc(self, method, args):
        if method not in ['importaddress', 'walletpassphrase', 'getaccount',
                          'getrawtransaction', 'gettransaction', 'getblock',
                          'getblockhash', 'listunspent', 'gettxout']:
            cslog.debug('rpc: ' + method + " " + str(args))
        res = self.jsonRpc.call(method, args)
        if isinstance(res, unicode):
            res = str(res)
        return res

    def import_addresses(self, addr_list, wallet_name):
        cslog.debug('importing ' + str(len(addr_list)) +
                  ' addresses into account ' + wallet_name)
        for addr in addr_list:
            self.rpc('importaddress', [addr, wallet_name, False])

    def add_watchonly_addresses(self, addr_list, wallet_name):
        """For backwards compatibility, this fn name is preserved
        as the case where we quit the program if a rescan is required;
        but in some cases a rescan is not required (if the address is known
        to be new/unused). For that case use import_addresses instead.
        """
        self.import_addresses(addr_list, wallet_name)
        if cs_single().config.get("BLOCKCHAIN",
                                  "blockchain_source") != 'regtest': #pragma: no cover
            #Exit conditions cannot be included in tests
            print('restart Bitcoin Core with -rescan if you\'re '
                  'recovering an existing wallet from backup seed')
            print(' otherwise just restart this joinmarket script')
            sys.exit(0)

    def sync_wallet(self, wallet, fast=False):
        #trigger fast sync if the index_cache is available
        #(and not specifically disabled).
        if fast and wallet.index_cache != [[0,0]] * wallet.max_mix_depth:
            self.sync_wallet_fast(wallet)
            self.fast_sync_called = True
            return
        super(BitcoinCoreInterface, self).sync_wallet(wallet)
        self.fast_sync_called = False

    def sync_wallet_fast(self, wallet):
        """Exploits the fact that given an index_cache,
        all addresses necessary should be imported, so we
        can just list all used addresses to find the right
        index values.
        """
        self.get_address_usages(wallet)
        self.sync_unspent(wallet)

    def get_address_usages(self, wallet):
        """Use rpc `listaddressgroupings` to locate all used
        addresses in the account (whether spent or unspent outputs).
        This will not result in a full sync if working with a new
        Bitcoin Core instance, in which case "fast" should have been
        specifically disabled by the user.
        """
        from jmclient.wallet import BitcoinCoreWallet
        if isinstance(wallet, BitcoinCoreWallet):
            return
        wallet_name = self.get_wallet_name(wallet)
        agd = self.rpc('listaddressgroupings', [])
        #flatten all groups into a single list; then, remove duplicates
        fagd = [tuple(item) for sublist in agd for item in sublist]
        #"deduplicated flattened address grouping data" = dfagd
        dfagd = list(set(fagd))
        #for lookup, want dict of form {"address": amount}
        used_address_dict = {}
        for addr_info in dfagd:
            if len(addr_info) < 3 or addr_info[2] != wallet_name:
                continue
            used_address_dict[addr_info[0]] = (addr_info[1], addr_info[2])

        cslog.debug("Fast sync in progress. Got this many used addresses: " + str(
            len(used_address_dict)))
        #Need to have wallet.index point to the last used address
        #and fill addr_cache.
        #For each branch:
        #If index value is present, collect all addresses up to index+gap limit
        #For each address in that list, mark used if seen in used_address_dict
        used_indices = {}
        for md in range(wallet.max_mix_depth):
            used_indices[md] = {}
            for fc in [0, 1]:
                used_indices[md][fc] = []
                for i in range(wallet.index_cache[md][fc]+wallet.gaplimit):
                    if wallet.get_addr(md, fc, i) in used_address_dict.keys():
                        used_indices[md][fc].append(i)
                        wallet.addr_cache[wallet.get_addr(md, fc, i)] = (md, fc, i)
                if len(used_indices[md][fc]):
                    wallet.index[md][fc] = used_indices[md][fc][-1]
                else:
                    wallet.index[md][fc] = 0
                if not is_index_ahead_of_cache(wallet, md, fc):
                    wallet.index[md][fc] = wallet.index_cache[md][fc]
        self.wallet_synced = True


    def sync_addresses(self, wallet):
        from jmclient.wallet import BitcoinCoreWallet

        if isinstance(wallet, BitcoinCoreWallet):
            return
        cslog.debug('requesting detailed wallet history')
        wallet_name = self.get_wallet_name(wallet)
        #TODO It is worth considering making this user configurable:
        addr_req_count = 20
        wallet_addr_list = []
        for mix_depth in range(wallet.max_mix_depth):
            for forchange in [0, 1]:
                #If we have an index-cache available, we can use it
                #to decide how much to import (note that this list
                #*always* starts from index 0 on each branch).
                #In cases where the Bitcoin Core instance is fresh,
                #this will allow the entire import+rescan to occur
                #in 2 steps only.
                if wallet.index_cache != [[0, 0]] * wallet.max_mix_depth:
                    #Need to request N*addr_req_count where N is least s.t.
                    #N*addr_req_count > index_cache val. This is so that the batching
                    #process in the main loop *always* has already imported enough
                    #addresses to complete.
                    req_count = int(wallet.index_cache[mix_depth][forchange] /
                                    addr_req_count) + 1
                    req_count *= addr_req_count
                else:
                    #If we have *nothing* - no index_cache, and no info
                    #in Core wallet (imports), we revert to a batching mode
                    #with a default size.
                    #In this scenario it could require several restarts *and*
                    #rescans; perhaps user should set addr_req_count high
                    #(see above TODO)
                    req_count = addr_req_count
                wallet_addr_list += [wallet.get_new_addr(mix_depth, forchange, True)
                                     for _ in range(req_count)]
                #Indices are reset here so that the next algorithm step starts
                #from the beginning of each branch
                wallet.index[mix_depth][forchange] = 0
        # makes more sense to add these in an account called "joinmarket-imported" but its much
        # simpler to add to the same account here
        for privkey_list in wallet.imported_privkeys.values():
            for privkey in privkey_list:
                imported_addr = btc.privtoaddr(privkey,
                                               magicbyte=get_p2pk_vbyte())
                wallet_addr_list.append(imported_addr)
        imported_addr_list = self.rpc('getaddressesbyaccount', [wallet_name])
        if not set(wallet_addr_list).issubset(set(imported_addr_list)):
            self.add_watchonly_addresses(wallet_addr_list, wallet_name)
            return

        buf = self.rpc('listtransactions', [wallet_name, 1000, 0, True])
        txs = buf
        # If the buffer's full, check for more, until it ain't
        while len(buf) == 1000:
            buf = self.rpc('listtransactions', [wallet_name, 1000, len(txs),
                                                True])
            txs += buf
        # TODO check whether used_addr_list can be a set, may be faster (if
        # its a hashset) and allows using issubset() here and setdiff() for
        # finding which addresses need importing

        # TODO also check the fastest way to build up python lists, i suspect
        #  using += is slow
        used_addr_list = [tx['address']
                          for tx in txs if tx['category'] == 'receive']
        too_few_addr_mix_change = []
        for mix_depth in range(wallet.max_mix_depth):
            for forchange in [0, 1]:
                unused_addr_count = 0
                last_used_addr = ''
                breakloop = False
                while not breakloop:
                    if unused_addr_count >= wallet.gaplimit and \
                            is_index_ahead_of_cache(wallet, mix_depth,
                                                    forchange):
                        break
                    mix_change_addrs = [
                        wallet.get_new_addr(mix_depth, forchange, True)
                        for _ in range(addr_req_count)
                    ]
                    for mc_addr in mix_change_addrs:
                        if mc_addr not in imported_addr_list:
                            too_few_addr_mix_change.append((mix_depth, forchange
                                                           ))
                            breakloop = True
                            break
                        if mc_addr in used_addr_list:
                            last_used_addr = mc_addr
                            unused_addr_count = 0
                        else:
                            unused_addr_count += 1
#index setting here depends on whether we broke out of the loop
#early; if we did, it means we need to prepare the index
#at the level of the last used address or zero so as to not
#miss any imports in add_watchonly_addresses.
#If we didn't, we need to respect the index_cache to avoid
#potential address reuse.
                if breakloop:
                    if last_used_addr == '':
                        wallet.index[mix_depth][forchange] = 0
                    else:
                        wallet.index[mix_depth][forchange] = \
                            wallet.addr_cache[last_used_addr][2] + 1
                else:
                    if last_used_addr == '':
                        next_avail_idx = max([wallet.index_cache[mix_depth][
                            forchange], 0])
                    else:
                        next_avail_idx = max([wallet.addr_cache[last_used_addr][
                            2] + 1, wallet.index_cache[mix_depth][forchange]])
                    wallet.index[mix_depth][forchange] = next_avail_idx

        wallet_addr_list = []
        if len(too_few_addr_mix_change) > 0:
            indices = [wallet.index[mc[0]][mc[1]]
                       for mc in too_few_addr_mix_change]
            cslog.debug('too few addresses in ' + str(too_few_addr_mix_change) +
                      ' at ' + str(indices))
            for mix_depth, forchange in too_few_addr_mix_change:
                wallet_addr_list += [
                    wallet.get_new_addr(mix_depth, forchange, True)
                    for _ in range(addr_req_count * 3)
                ]

            self.add_watchonly_addresses(wallet_addr_list, wallet_name)
            return

        self.wallet_synced = True

    def start_unspent_monitoring(self, wallet):
        self.unspent_monitoring_loop = task.LoopingCall(self.sync_unspent, wallet)
        self.unspent_monitoring_loop.start(1.0)

    def stop_unspent_monitoring(self):
        self.unspent_monitoring_loop.stop()

    def sync_unspent(self, wallet):
        from jmclient.wallet import BitcoinCoreWallet

        if isinstance(wallet, BitcoinCoreWallet):
            return
        wallet_name = self.get_wallet_name(wallet)
        wallet.unspent = {}

        listunspent_args = []
        if 'listunspent_args' in cs_single().config.options('POLICY'):
            listunspent_args = ast.literal_eval(cs_single().config.get(
                'POLICY', 'listunspent_args'))

        unspent_list = self.rpc('listunspent', listunspent_args)
        for u in unspent_list:
            if 'account' not in u:
                continue
            if u['account'] != wallet_name:
                continue
            if u['address'] not in wallet.addr_cache:
                continue
            wallet.unspent[u['txid'] + ':' + str(u['vout'])] = {
                'address': u['address'],
                'value': int(Decimal(str(u['amount'])) * Decimal('1e8'))
            }
        #useful for testing, but too spammy even for debug:
        #cslog.debug('length of unspent list: ' + str(len(wallet.unspent.keys())))

    def add_tx_notify(self, txd, unconfirmfun, confirmfun, spentfun, notifyaddr,
                      n, timeoutfun=None, c=1):
        """Given a deserialized transaction txd,
        callback functions for broadcast and confirmation of the transaction,
        an address to import, and a callback function for timeout, set up
        a polling loop to check for events on the transaction. Also optionally set
        to trigger "confirmed" callback on number of confirmations c. Also checks
        for spending (if spentfun is not None) of the outpoint n.
        """
        loop = task.LoopingCall(self.tx_watcher, txd, unconfirmfun, confirmfun,
                                spentfun, c, n)
        txid = btc.txhash(btc.serialize(txd))
        print("Created loop object for txid: " + txid)
        self.tx_watcher_loops[txid] = [loop, False, False, False]
        #Hardcoded polling interval, but in any case it can be very short.
        loop.start(3.0)
        #Hardcoded very long timeout interval TODO
        reactor.callLater(7200, self.tx_timeout, txd, txid, timeoutfun)

    def tx_timeout(self, txd, txid, timeoutfun):
        if not timeoutfun:
            return
        if not txid in self.tx_watcher_loops:
            return
        if not self.tx_watcher_loops[txid][1]:
            #Not confirmed after 2 hours; give up
            cslog.info("Timed out waiting for confirmation of: " + str(txid))
            self.tx_watcher_loops[txid][0].stop()
            timeoutfun(txd, txid)

    def get_deser_from_gettransaction(self, rpcretval):
        """Get full transaction deserialization from a call
        to `gettransaction`
        """
        if not "hex" in rpcretval:
            cslog.info("Malformed gettransaction output")
            return None
        #str cast for unicode
        hexval = str(rpcretval["hex"])
        return btc.deserialize(hexval)

    def tx_watcher(self, txd, unconfirmfun, confirmfun, spentfun, c, n):
        """Called at a polling interval, checks if the given deserialized
        transaction (which must be fully signed) is (a) broadcast, (b) confirmed
        and (c) spent from at index n, and notifies confirmation if number
        of confs = c.
        TODO: Deal with conflicts correctly. Here just abandons monitoring.
        """
        txid = btc.txhash(btc.serialize(txd))
        wl = self.tx_watcher_loops[txid]
        try:
            res = self.rpc('gettransaction', [txid, True])
        except JsonRpcError as e:
            return
        if not res:
            return
        if "confirmations" not in res:
            cslog.debug("Malformed gettx result: " + str(res))
            return
        if not wl[1] and res["confirmations"] == 0:
            cslog.debug("Tx: " + str(txid) + " seen on network.")
            unconfirmfun(txd, txid)
            wl[1] = True
            return
        if not wl[2] and res["confirmations"] > 0:
            cslog.debug("Tx: " + str(txid) + " has " + str(
                res["confirmations"]) + " confirmations.")
            confirmfun(txd, txid, res["confirmations"])
            if c <= res["confirmations"]:
                wl[2] = True
                #Note we do not stop the monitoring loop when
                #confirmations occur, since we are also monitoring for spending.
            return
        if res["confirmations"] < 0:
            cslog.debug("Tx: " + str(txid) + " has a conflict. Abandoning.")
            wl[0].stop()
            return
        if not spentfun or wl[3]:
            return
        #To trigger the spent callback, we check if this utxo outpoint appears in
        #listunspent output with 0 or more confirmations. Note that this requires
        #we have added the destination address to the watch-only wallet, otherwise
        #that outpoint will not be returned by listunspent.
        res2 = self.rpc('listunspent', [0, 999999])
        if not res2:
            return
        txunspent = False
        for r in res2:
            if "txid" not in r:
                continue
            if txid == r["txid"] and n == r["vout"]:
                txunspent = True
                break
        if not txunspent:
            #We need to find the transaction which spent this one;
            #assuming the address was added to the wallet, then this
            #transaction must be in the recent list retrieved via listunspent.
            #For each one, use gettransaction to check its inputs.
            #This is a bit expensive, but should only occur once.
            txlist = self.rpc("listtransactions", ["*", 1000, 0, True])
            for tx in txlist[::-1]:
                #changed syntax in 0.14.0; allow both syntaxes
                try:
                    res = self.rpc("gettransaction", [tx["txid"], True])
                except:
                    try:
                        res = self.rpc("gettransaction", [tx["txid"], 1])
                    except:
                        #This should never happen (gettransaction is a wallet rpc).
                        cslog.info("Failed any gettransaction call")
                        res = None
                if not res:
                    continue
                deser = self.get_deser_from_gettransaction(res)
                if deser is None:
                    continue
                for vin in deser["ins"]:
                    if not "outpoint" in vin:
                        #coinbases
                        continue
                    if vin["outpoint"]["hash"] == txid and vin["outpoint"]["index"] == n:
                        #recover the deserialized form of the spending transaction.
                        cslog.info("We found a spending transaction: " + \
                                   btc.txhash(binascii.unhexlify(res["hex"])))
                        res2 = self.rpc("gettransaction", [tx["txid"], True])
                        spending_deser = self.get_deser_from_gettransaction(res2)
                        if not spending_deser:
                            cslog.info("ERROR: could not deserialize spending tx.")
                            #Should never happen, it's a parsing bug.
                            #No point continuing to monitor, we just hope we
                            #can extract the secret by scanning blocks.
                            wl[3] = True
                            return
                        spentfun(spending_deser, vin["outpoint"]["hash"])
                        wl[3] = True
                        return

    def pushtx(self, txhex):
        try:
            txid = self.rpc('sendrawtransaction', [txhex])
        except JsonRpcConnectionError as e:
            cslog.debug('error pushing = ' + repr(e))
            return False
        except JsonRpcError as e:
            cslog.debug('error pushing = ' + str(e.code) + " " + str(e.message))
            return False
        return True

    def query_utxo_set(self, txout, includeconf=False):
        if not isinstance(txout, list):
            txout = [txout]
        result = []
        for txo in txout:
            ret = self.rpc('gettxout', [txo[:64], int(txo[65:]), False])
            if ret is None:
                result.append(None)
            else:
                result_dict = {'value': int(Decimal(str(ret['value'])) *
                                            Decimal('1e8')),
                               'address': ret['scriptPubKey']['addresses'][0],
                               'script': ret['scriptPubKey']['hex']}
                if includeconf:
                    result_dict['confirms'] = int(ret['confirmations'])
                result.append(result_dict)
        return result

    def estimate_fee_per_kb(self, N):
        estimate = Decimal(1e8) * Decimal(self.rpc('estimatefee', [N]))
        if estimate < 0:
            #This occurs when Core has insufficient data to estimate.
            #TODO anything better than a hardcoded default?
            return 30000
        else:
            return estimate

class TickChainThread(threading.Thread):
    """Class for support of RegtestBitcoinCoreInterface; automatically
    mining the chain.
    """
    def __init__(self, bcinterface, forever=False):
        threading.Thread.__init__(self, name='TickChainThread')
        self.bcinterface = bcinterface
        self.forever = forever

    def run(self):
        if self.bcinterface.tick_forward_chain_interval < 0:
            cslog.debug('not ticking forward chain')
            return
        if self.forever:
            while True:
                if self.bcinterface.shutdown_signal:
                    return
                time.sleep(self.bcinterface.tick_forward_chain_interval)
                self.bcinterface.tick_forward_chain(1)
        time.sleep(self.bcinterface.tick_forward_chain_interval)
        self.bcinterface.tick_forward_chain(1)

class RegtestBitcoinCoreInterface(BitcoinCoreInterface): #pragma: no cover
    """Class for regtest chain access. Only to be instantiated
    after network is up with > 100 blocks.
    """
    def __init__(self, jsonRpc):
        super(RegtestBitcoinCoreInterface, self).__init__(jsonRpc, 'regtest')
        self.pushtx_failure_prob = 0
        self.tick_forward_chain_interval = 2
        self.absurd_fees = False
        self.simulating = False
        self.shutdown_signal = False

    def send_thread_shutdown(self):
        self.shutdown_signal = True

    def simulate_blocks(self):
        TickChainThread(self, forever=True).start()
        self.simulating = True

    def estimate_fee_per_kb(self, N):
        if not self.absurd_fees:
            return super(RegtestBitcoinCoreInterface,
                         self).estimate_fee_per_kb(N)
        else:
            return cs_single().config.getint("POLICY",
                                             "absurd_fee_per_kb") + 100

    def pushtx(self, txhex):
        if self.pushtx_failure_prob != 0 and random.random() <\
                self.pushtx_failure_prob:
            cslog.debug('randomly not broadcasting %0.1f%% of the time' %
                      (self.pushtx_failure_prob * 100))
            return True

        ret = super(RegtestBitcoinCoreInterface, self).pushtx(txhex)
        if not self.simulating:
            TickChainThread(self).start()
        return ret

    def tick_forward_chain(self, n):
        """
        Special method for regtest only;
        instruct to mine n blocks.
        """
        try:
            self.rpc('generate', [n])
        except JsonRpcConnectionError:
            #can happen if the blockchain is shut down
            #automatically at the end of tests; this shouldn't
            #trigger an error
            cslog.debug(
                "Failed to generate blocks, looks like the bitcoin daemon \
	    has been shut down. Ignoring.")
            pass

    def grab_coins(self, receiving_addr, amt=50):
        """
        NOTE! amt is passed in Coins, not Satoshis!
        Special method for regtest only:
        take coins from bitcoind's own wallet
        and put them in the receiving addr.
        Return the txid.
        """
        if amt > 500:
            raise Exception("too greedy")
        """
        if amt > self.current_balance:
        #mine enough to get to the reqd amt
        reqd = int(amt - self.current_balance)
        reqd_blocks = int(reqd/50) +1
        if self.rpc('setgenerate', [True, reqd_blocks]):
        raise Exception("Something went wrong")
        """
        # now we do a custom create transaction and push to the receiver
        txid = self.rpc('sendtoaddress', [receiving_addr, amt])
        if not txid:
            raise Exception("Failed to broadcast transaction")
        # confirm
        self.tick_forward_chain(1)
        return txid

