from __future__ import absolute_import, print_function
"""A simplified version of the wallet-tool script
   from Joinmarket, usable with CoinSwapCS (the wallets
   are cross-compatible between these applications).
"""
import datetime
import getpass
import json
import os
import sys
from optparse import OptionParser

from jmclient import (get_network, Wallet,
                      encryptData, get_p2pk_vbyte,
                      mn_decode, mn_encode,
                      JsonRpcError, WalletError)
from coinswapcs import (cs_single, get_log,
                      BitcoinCoreInterface, RegtestBitcoinCoreInterface,
                      sync_wallet, load_coinswap_config)
from jmbase.support import get_password
import jmbitcoin as btc

description = (
    'Does useful little tasks involving your bip32 wallet. The '
    'method is one of the following: (display) Shows addresses and '
    'balances. (displayall) Shows ALL addresses and balances. '
    '(summary) Shows a summary of mixing depth balances. (generate) '
    'Generates a new wallet. (recover) Recovers a wallet from the 12 '
    'word recovery seed. (showutxos) Shows all utxos in the wallet, '
    'including the corresponding private keys if -p is chosen; the '
    'data is also written to a file "walletname.json.utxos" if the '
    'option -u is chosen (so be careful about private keys). '
    '(showseed) Shows the wallet recovery seed '
    'and hex seed. (importprivkey) Adds privkeys to this wallet, '
    'privkeys are spaces or commas separated. (dumpprivkey) Export '
    'a single private key, specify an hd wallet path (listwallets) '
    'Lists all wallets with creator and timestamp. (history) Show '
    'all historical transaction details. Requires Bitcoin Core.')

parser = OptionParser(usage='usage: %prog [options] [wallet file] [method]',
                      description=description)

parser.add_option('-p',
                  '--privkey',
                  action='store_true',
                  dest='showprivkey',
                  help='print private key along with address, default false')
parser.add_option('-m',
                  '--maxmixdepth',
                  action='store',
                  type='int',
                  dest='maxmixdepth',
                  help='how many mixing depths to display, default=3')
parser.add_option('-g',
                  '--gap-limit',
                  type="int",
                  action='store',
                  dest='gaplimit',
                  help='gap limit for wallet, default=6',
                  default=6)
parser.add_option('-M',
                  '--mix-depth',
                  type="int",
                  action='store',
                  dest='mixdepth',
                  help='mixing depth to import private key into',
                  default=0)
parser.add_option('--fast',
                  action='store_true',
                  dest='fastsync',
                  default=False,
                  help=('choose to do fast wallet sync, only for Core and '
                  'only for previously synced wallet'))
parser.add_option('-H',
                  '--hd',
                  action='store',
                  type='str',
                  dest='hd_path',
                  help='hd wallet path (e.g. m/0/0/0/000)')
(options, args) = parser.parse_args()

# if the index_cache stored in wallet.json is longer than the default
# then set maxmixdepth to the length of index_cache
maxmixdepth_configured = True
if not options.maxmixdepth:
    maxmixdepth_configured = False
    options.maxmixdepth = 3

noseed_methods = ['generate', 'recover', 'listwallets']
methods = ['display', 'displayall', 'summary', 'showseed', 'importprivkey',
    'history', 'showutxos']
methods.extend(noseed_methods)
noscan_methods = ['showseed', 'importprivkey', 'dumpprivkey']

if len(args) < 1:
    parser.error('Needs a wallet file or method')
    sys.exit(0)

load_coinswap_config()

if args[0] in noseed_methods:
    method = args[0]
else:
    seed = args[0]
    method = ('display' if len(args) == 1 else args[1].lower())
    if not os.path.exists(os.path.join('wallets', seed)):
        wallet = Wallet(seed, None, options.maxmixdepth,
                        options.gaplimit, extend_mixdepth= not maxmixdepth_configured,
                        storepassword=(method == 'importprivkey'))
    else:
        while True:
            try:
                pwd = get_password("Enter wallet decryption passphrase: ")
                wallet = Wallet(seed, pwd,
                        options.maxmixdepth,
                        options.gaplimit,
                        extend_mixdepth=not maxmixdepth_configured,
                        storepassword=(method == 'importprivkey'))
            except WalletError:
                print("Wrong password, try again.")
                continue
            except Exception as e:
                print("Failed to load wallet, error message: " + repr(e))
                sys.exit(0)
            break
    if method not in noscan_methods:
        # if nothing was configured, we override bitcoind's options so that
        # unconfirmed balance is included in the wallet display by default
        if 'listunspent_args' not in cs_single().config.options('POLICY'):
            cs_single().config.set('POLICY','listunspent_args', '[0]')

        sync_wallet(wallet, fast=options.fastsync)

if method == 'showutxos':
    unsp = {}
    if options.showprivkey:
        for u, av in wallet.unspent.iteritems():
            addr = av['address']
            key = wallet.get_key_from_addr(addr)
            wifkey = btc.wif_compressed_privkey(key, vbyte=get_p2pk_vbyte())
            unsp[u] = {'address': av['address'],
                       'value': av['value'], 'privkey': wifkey}
    else:
        unsp = wallet.unspent
    print(json.dumps(unsp, indent=4))
    sys.exit(0)

if method == 'display' or method == 'displayall' or method == 'summary':

    def cus_print(s):
        if method != 'summary':
            print(s)

    total_balance = 0
    for m in range(wallet.max_mix_depth):
        cus_print('mixing depth %d m/0/%d/' % (m, m))
        balance_depth = 0
        for forchange in [0, 1]:
            if forchange == 0:
                xpub_key = btc.bip32_privtopub(wallet.keys[m][forchange])
            else:
                xpub_key = ''
            cus_print(' ' + ('external' if forchange == 0 else 'internal') +
                      ' addresses m/0/%d/%d' % (m, forchange) + ' ' + xpub_key)

            for k in range(wallet.index[m][forchange] + options.gaplimit):
                addr = wallet.get_addr(m, forchange, k)
                balance = 0.0
                for addrvalue in wallet.unspent.values():
                    if addr == addrvalue['address']:
                        balance += addrvalue['value']
                balance_depth += balance
                used = ('used' if k < wallet.index[m][forchange] else ' new')
                if options.showprivkey:
                    privkey = btc.wif_compressed_privkey(
                    wallet.get_key(m, forchange, k), get_p2pk_vbyte())
                else:
                    privkey = ''
                if (method == 'displayall' or balance > 0 or
                    (used == ' new' and forchange == 0)):
                    cus_print('  m/0/%d/%d/%03d %-35s%s %.8f btc %s' %
                              (m, forchange, k, addr, used, balance / 1e8,
                               privkey))
        if m in wallet.imported_privkeys:
            cus_print(' import addresses')
            for privkey in wallet.imported_privkeys[m]:
                addr = btc.privtoaddr(privkey, magicbyte=get_p2pk_vbyte())
                balance = 0.0
                for addrvalue in wallet.unspent.values():
                    if addr == addrvalue['address']:
                        balance += addrvalue['value']
                used = (' used' if balance > 0.0 else 'empty')
                balance_depth += balance
                if options.showprivkey:
                    wip_privkey = btc.wif_compressed_privkey(
                    privkey, get_p2pk_vbyte())
                else:
                    wip_privkey = ''
                cus_print(' ' * 13 + '%-35s%s %.8f btc %s' % (
                    addr, used, balance / 1e8, wip_privkey))
        total_balance += balance_depth
        print('for mixdepth=%d balance=%.8fbtc' % (m, balance_depth / 1e8))
    print('total balance = %.8fbtc' % (total_balance / 1e8))
elif method == 'generate' or method == 'recover':
    if method == 'generate':
        seed = btc.sha256(os.urandom(64))[:32]
        words = mn_encode(seed)
        print('Write down this wallet recovery seed\n\n' + ' '.join(words) +
              '\n')
    elif method == 'recover':
        words = raw_input('Input 12 word recovery seed: ')
        words = words.split()  # default for split is 1 or more whitespace chars
        if len(words) != 12:
            print('ERROR: Recovery seed phrase must be exactly 12 words.')
            sys.exit(0)
        seed = mn_decode(words)
        print(seed)
    password = getpass.getpass('Enter wallet encryption passphrase: ')
    password2 = getpass.getpass('Reenter wallet encryption passphrase: ')
    if password != password2:
        print('ERROR. Passwords did not match')
        sys.exit(0)
    password_key = btc.bin_dbl_sha256(password)
    encrypted_seed = encryptData(password_key, seed.decode('hex'))
    timestamp = datetime.datetime.now().strftime("%Y/%m/%d %H:%M:%S")
    walletfile = json.dumps({'creator': 'joinmarket project',
                             'creation_time': timestamp,
                             'encrypted_seed': encrypted_seed.encode('hex'),
                             'network': get_network()})
    walletname = raw_input('Input wallet file name (default: wallet.json): ')
    if len(walletname) == 0:
        walletname = 'wallet.json'
    walletpath = os.path.join('wallets', walletname)
    # Does a wallet with the same name exist?
    if os.path.isfile(walletpath):
        print('ERROR: ' + walletpath + ' already exists. Aborting.')
        sys.exit(0)
    else:
        fd = open(walletpath, 'w')
        fd.write(walletfile)
        fd.close()
        print('saved to ' + walletname)
elif method == 'showseed':
    hexseed = wallet.seed
    print('hexseed = ' + hexseed)
    words = mn_encode(hexseed)
    print('Wallet recovery seed\n\n' + ' '.join(words) + '\n')
elif method == 'importprivkey':
    print('WARNING: This imported key will not be recoverable with your 12 ' +
          'word mnemonic seed. Make sure you have backups.')
    print('WARNING: Handling of raw ECDSA bitcoin private keys can lead to '
          'non-intuitive behaviour and loss of funds.\n  Recommended instead '
          'is to use the \'sweep\' feature of sendpayment.py ')
    privkeys = raw_input('Enter private key(s) to import: ')
    privkeys = privkeys.split(',') if ',' in privkeys else privkeys.split()
    # TODO read also one key for each line
    for privkey in privkeys:
        # TODO is there any point in only accepting wif format? check what
        # other wallets do
        privkey_bin = btc.from_wif_privkey(privkey,
                                        vbyte=get_p2pk_vbyte()).decode('hex')[:-1]
        encrypted_privkey = encryptData(wallet.password_key, privkey_bin)
        if 'imported_keys' not in wallet.walletdata:
            wallet.walletdata['imported_keys'] = []
        wallet.walletdata['imported_keys'].append(
            {'encrypted_privkey': encrypted_privkey.encode('hex'),
             'mixdepth': options.mixdepth})
    if wallet.walletdata['imported_keys']:
        fd = open(wallet.path, 'w')
        fd.write(json.dumps(wallet.walletdata))
        fd.close()
        print('Private key(s) successfully imported')
elif method == 'dumpprivkey':
    if options.hd_path.startswith('m/0/'):
        m, forchange, k = [int(y) for y in options.hd_path[4:].split('/')]
        key = wallet.get_key(m, forchange, k)
        wifkey = btc.wif_compressed_privkey(key, vbyte=get_p2pk_vbyte())
        print(wifkey)
    else:
        print('%s is not a valid hd wallet path' % options.hd_path)
