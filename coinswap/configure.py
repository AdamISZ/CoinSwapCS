from __future__ import print_function

import io
import logging
import os
import binascii
import sys

from ConfigParser import SafeConfigParser, NoOptionError

import jmbitcoin as btc

from jmclient import (get_p2pk_vbyte, get_p2sh_vbyte, JsonRpc, set_config,
                      get_network)

logFormatter = logging.Formatter(
    "%(asctime)s [%(threadName)-12.12s] [%(levelname)-5.5s]  %(message)s")
log = logging.getLogger('CoinSwapCS')
log.setLevel(logging.DEBUG)

debug_silence = [False]
import jmbase.support
jmbase.support.debug_silence = [True]
#consoleHandler = logging.StreamHandler(stream=sys.stdout)
class CoinSwapStreamHandler(logging.StreamHandler):

    def __init__(self, stream):
        super(CoinSwapStreamHandler, self).__init__(stream)

    def emit(self, record):
        if not debug_silence[0]:
            super(CoinSwapStreamHandler, self).emit(record)


consoleHandler = CoinSwapStreamHandler(stream=sys.stdout)
consoleHandler.setFormatter(logFormatter)

log.debug('CoinSwapCS logging started.')

class AttributeDict(object):
    """
    A class to convert a nested Dictionary into an object with key-values
    accessibly using attribute notation (AttributeDict.attribute) instead of
    key notation (Dict["key"]). This class recursively sets Dicts to objects,
    allowing you to recurse down nested dicts (like: AttributeDict.attr.attr)
    """

    def __init__(self, **entries):
        self.currentlogpath = None
        self.add_entries(**entries)

    def add_entries(self, **entries):
        for key, value in entries.items():
            if type(value) is dict:
                self.__dict__[key] = AttributeDict(**value)
            else:
                self.__dict__[key] = value

    def __setattr__(self, name, value):
        if name == 'logs_path' and value != self.currentlogpath:
            self.currentlogpath = value
            logFormatter = logging.Formatter(
                ('%(asctime)s [%(threadName)-12.12s] '
                 '[%(levelname)-5.5s]  %(message)s'))
            fileHandler = logging.FileHandler(value + ".log")
            fileHandler.setFormatter(logFormatter)
            log.addHandler(fileHandler)

        super(AttributeDict, self).__setattr__(name, value)

    def __getitem__(self, key):
        """
        Provides dict-style access to attributes
        """
        return getattr(self, key)


global_singleton = AttributeDict()
global_singleton.CSCS_VERSION = 0.1
global_singleton.APPNAME = "CoinSwapCS"
global_singleton.homedir = None
global_singleton.BITCOIN_DUST_THRESHOLD = 2730
global_singleton.DUST_THRESHOLD = 10 * global_singleton.BITCOIN_DUST_THRESHOLD
global_singleton.bc_interface = None
global_singleton.logs_path = None
global_singleton.config = SafeConfigParser()
#This is reset to a full path after load_coinswap_config call
global_singleton.config_location = 'coinswapcs.cfg'
#Not currently exposed in config file but could be; it is not expected that
#confirmation for one block could conceivably take this long
global_singleton.one_confirm_timeout = 7200

def cs_single():
    return global_singleton

def get_log():
    return log

defaultconfig = \
    """
[BLOCKCHAIN]
#options: bitcoin-rpc, regtest, (no non-Bitcoin Core currently supported)
blockchain_source = bitcoin-rpc
network = mainnet
rpc_host = localhost
rpc_port = 8332
rpc_user = bitcoin
rpc_password = password

[TIMEOUT]
#How long to wait, by default, in seconds, before giving up on the counterparty
#and executing backout. This is only applied in cases where response is intended
#to be immediate.
default_network_timeout = 60
#How long to wait (in seconds, integer only) for the counterparty to confirm
#blockchain state that we've already seen (if client);
#this is to account for propagation delays on the BTC network,
#mainly. Used in waiting to proceed to second phase after first (TX0,TX1) is
#complete.
propagation_buffer = 120
#How many blocks to wait for ensured confirmation for the first stage (funding) txs.
#Note that the this value must be agreed with the server.
tx01_confirm_wait = 2
#
#***LOCKTIMES***
#
#These are critical to CoinSwap's design; probably better not to change them,
#but if you do, read the following notes and make sure you understand.
#Also note these variables are ONLY for client, server uses the variable in the
#SERVER section of the config (server/client_locktime_range).
#Locktime for TX3 (server's timeout); the server can refund her pay-in transaction
#after this number of blocks, from the starting time
lock_server = 50
#Locktime for TX2 (client's timeout); the client can refund her pay-in transaction
#after this number of blocks, from the starting time. Note that this has to be a
#longer timeout than that for the server (generally it should be ~2xserver timeout).
lock_client = 100

[SESSIONS]
#Location of directory where sessions are stored for recovery, it is located under
#the main coinswap data directory (APPDATA/.CoinSwapCS/). Note this contains
#keys and other privacy-sensitive information. Deleting its contents should be
#considered, but NEVER delete the contents until you are sure your previous
#coinswaps are completed. Also, NEVER EDIT THE CONTENTS OF SESSION FILES, only
#read them; editing could make a failed coinswap unrecoverable!
sessions_dir = sessions
[POLICY]
#Server should "blind" the amount of his side of the swap by adding an amount,
#here you can set the minimum acceptable to you, i.e. if you set 1000000, you
#require that the difference between your output and the server's output is at
#least 0.1BTC.
minimum_blinding_amount = 1000000
# for dust sweeping, try merge_algorithm = gradual
# for more rapid dust sweeping, try merge_algorithm = greedy
# for most rapid dust sweeping, try merge_algorithm = greediest
merge_algorithm = default
# the fee estimate is based on a projection of how many satoshis
# per kB are needed to get in one of the next N blocks, N set here
# as the value of 'tx_fees'. For CoinSwap, this is set to default
# 1 for highest priority processing; you can reduce it, but if it's
# a lot lower than the server's estimate, the server may refuse to
# transact.
tx_fees = 1
#A value, in satoshis/kB, above which the fee is not allowed to be.
#keep this fairly high, as exceeding it causes the program to 'panic'
#and shut down.
absurd_fee_per_kb = 250000
#The number of blocks to target to calculate the fee for backout transactions;
#these transactions are high priority since in certain cases they may become
#invalid after a certain amount of time (although only if the counterparty is
#malicious).
#Note that this and the following value must be agreed with the server.
backout_fee_target = 1
#Further to the above, an additional fee multiplier may be applied to give
#extra priority (by default target=1 block is considered enough, so x1.0 here).
backout_fee_multiplier = 1.0
# the range of confirmations passed to the `listunspent` bitcoind RPC call
# 1st value is the inclusive minimum, defaults to one confirmation
# 2nd value is the exclusive maximum, defaults to most-positive-bignum (Google Me!)
# leaving it unset or empty defers to bitcoind's default values, ie [1, 9999999]
#listunspent_args = []
# that's what you should do, unless you have a specific reason, eg:
#  spend from unconfirmed transactions:  listunspent_args = [0]
# display only unconfirmed transactions: listunspent_args = [0, 1]
# defend against small reorganizations:  listunspent_args = [3]
#   who is at risk of reorganization?:   listunspent_args = [0, 2]

[LOGGING]
# Set the log level for the output to the terminal/console
# Possible choices: DEBUG / INFO / WARNING / ERROR
# Log level for the files in the logs-folder will always be DEBUG
console_log_level = INFO

[SERVER]
#These settings can be safely ignored if you are running as client ('Alice').
#***
#source and destination chain is reserved for possible future implementations
#cross-chain.
source_chain = BTC
destination_chain = BTC
#Hidden service is the preferred way of serving; if use_onion is set to anything
#except 'false', clearnet modes will be ignored.
#(Tor will be started within the application)
use_onion = true
onion_port = 1234
#Location of hostname and private key for hidden service - Note:
#if not set, default is APPDIR/hiddenservice (~/.CoinSwapCS/hiddenservice)
#hs_dir = /chosen/directory
#port on which to serve clearnet
port = 7080
#whether to use SSL; non-SSL is *strongly* disrecommended, mainly because
#you lose confidentiality, it also allows MITM which is not a loss of funds risk,
#but again a loss of confidentiality risk. Note that client-side verification
#of cert is required to actually prevent MITM.
use_ssl = true
#directory containing private key and cert *.pem files; 0 means default location,
#which is homedir/ssl/ ; replace with fully qualified paths if needed.
ssl_private_key_location = 0
ssl_certificate_location = 0
#minimum and maximum allowable coinswap amounts, in satoshis;
#amounts to offer for coinswap
minimum_amount = 5000000
#note; if your balance in mixdepth 0 falls below this, the server will switch to
#busy state, and refuse further coinswaps until this changes. We do not change
#this value dynamically, as it would be a privacy leak.
maximum_amount = 500000000
#minimum and maximum allowable server and client locktimes (relative to current
#blockheight).
server_locktime_range = 10,50
client_locktime_range = 20,100
#client must choose the number of blocks to wait for confirmation of TX0, TX1.
tx01_confirm_range = 2, 4
#to reduce load/complexity, an upper limit on the number of concurrent coinswaps
maximum_concurrent_coinswaps = 3
#**FEES**
#Note that fees are by default collected across two different outputs in combination
#with other (probably much larger) amounts, so a small fee doesn't imply a dust
#output.
#The minimum acceptable fee in satoshis for a single coinswap
minimum_coinswap_fee = 100000
#Percentage fee for a coinswap (applied as long as it's higher than the above)
coinswap_fee_percent = 0.5
#**
#An amount used to blind/disconnect the two coin flows; setting it too small
#makes it too easy to correlate the transactions, making it too large could be
#a problem for your liquidity. In satoshis. Random value is chosen between
#maximum and minimum (unless too large for your wallet, then reduced but never
#below the minimum).
blinding_amount_min = 2000000
blinding_amount_max = 50000000
"""

def lookup_appdata_folder():
    from os import path, environ
    if sys.platform == 'darwin':
        if "HOME" in environ:
            data_folder = path.join(os.environ["HOME"],
                                   "Library/Application support/",
                                   global_singleton.APPNAME) + '/'
        else:
            print("Could not find home folder")
            os.exit()

    elif 'win32' in sys.platform or 'win64' in sys.platform:
        data_folder = path.join(environ['APPDATA'], global_singleton.APPNAME) + '\\'
    else:
        data_folder = path.expanduser(path.join("~",
                                    "." + global_singleton.APPNAME + "/"))
    return data_folder

def load_coinswap_config(config_path=None, bs=None):
    global_singleton.config.readfp(io.BytesIO(defaultconfig))
    if not config_path:
        global_singleton.homedir = lookup_appdata_folder()
    else:
        global_singleton.homedir = config_path
    if not os.path.exists(global_singleton.homedir):
        os.makedirs(global_singleton.homedir)
    #prepare folders for wallets and logs
    if not os.path.exists(os.path.join(global_singleton.homedir, "wallets")):
        os.makedirs(os.path.join(global_singleton.homedir, "wallets"))
    if not os.path.exists(os.path.join(global_singleton.homedir, "logs")):
        os.makedirs(os.path.join(global_singleton.homedir, "logs"))
    global_singleton.config_location = os.path.join(
        global_singleton.homedir, global_singleton.config_location)
    loadedFiles = global_singleton.config.read([global_singleton.config_location
                                               ])
    if len(loadedFiles) != 1:
        with open(global_singleton.config_location, "w") as configfile:
            configfile.write(defaultconfig)
    # configure the interface to the blockchain on startup
    global_singleton.bc_interface = get_blockchain_interface_instance(
        global_singleton.config)
    # set the console log level and initialize console logger
    try:
        global_singleton.console_log_level = global_singleton.config.get(
            "LOGGING", "console_log_level")
    except (NoSectionError, NoOptionError):
        print("No log level set, using default level INFO ")
    print("Setting console level to: ", global_singleton.console_log_level)
    consoleHandler.setLevel(global_singleton.console_log_level)
    log.addHandler(consoleHandler)
    #inject the configuration to the underlying jmclient code.
    set_config(global_singleton.config, bcint=global_singleton.bc_interface)
    

def get_blockchain_interface_instance(_config):
    from .blockchaininterface import BitcoinCoreInterface, \
        RegtestBitcoinCoreInterface
    source = _config.get("BLOCKCHAIN", "blockchain_source")
    network = _config.get("BLOCKCHAIN", "network")
    testnet = network == 'testnet'
    rpc_host = _config.get("BLOCKCHAIN", "rpc_host")
    rpc_port = _config.get("BLOCKCHAIN", "rpc_port")
    rpc_user = _config.get("BLOCKCHAIN", "rpc_user")
    rpc_password = _config.get("BLOCKCHAIN", "rpc_password")
    rpc = JsonRpc(rpc_host, rpc_port, rpc_user, rpc_password)
    if source == 'bitcoin-rpc': #pragma: no cover
        #This cannot be tested without mainnet or testnet blockchain (not regtest)
        bc_interface = BitcoinCoreInterface(rpc, network)
    elif source == 'regtest':
        bc_interface = RegtestBitcoinCoreInterface(rpc)
    return bc_interface
