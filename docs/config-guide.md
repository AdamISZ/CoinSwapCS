## Configuration guide for CoinSwapCS

The default configuration is found [here](https://github.com/AdamISZ/CoinSwapCS/blob/master/coinswap/configure.py#L98-L241)


Assuming you got here from the [installation guide](INSTALL.md) step 7, you already
have the file `APPDIR/coinswapcs.cfg` (on Linux, `APPDIR` means the
directory `/home/user/.CoinSwapCS`). Open it and edit it. The config is organized into sections,
so we will look at each section one by one.

### BLOCKCHAIN

```
[BLOCKCHAIN]
#options: bitcoin-rpc, regtest, (no non-Bitcoin Core currently supported)
blockchain_source = bitcoin-rpc
network = mainnet
rpc_host = localhost
rpc_port = 8332
rpc_user = bitcoin
rpc_password = password
```

Unless you are using regtest, leave the first setting at `bitcoin-rpc`.

The `network` setting must be `testnet` if testnet, otherwise mainnet.

`rpc_host` will be `localhost` if your Bitcoin Core node is on the same machine;
you can use values like `127.0.0.2` if you set up Bitcoin correctly for it,
but this is outside the scope.

`rpc_port` is 8332 by default for mainnet and 18332 by default for testnet, but
again you can customise in Bitcoin Core if you need to.

`rpc_user`, `rpc_password` must match what is set in your `bitcoin.conf`.

You can test whether these settings are correct without doing Coinswaps using `wallet-tool.py`.

### TIMEOUT

```
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
```

The comments mostly give enough context. Note that for the critical values
`lock_server` and `lock_client`:

* `lock_server` must be lower than `lock_client` else the server will reject
* both values must be within range of what is specified as acceptable by the server.
* These values should be much bigger than `tx_01_confirm_wait`.
* lock_client does not need to be exactly 2x lock_server, but it's as well to stick with that.

About `tx_01_confirm_wait`: this is mostly to defend against re-orgs, which are rare
events in Bitcoin. An outstanding code edit will require the server to specify its min-max,
which you will have to be in-range of; for now it defaults to 2. For mainnet I suspect around 2-6 will
be reasonable for a quick-style swap with a much larger value for a "slow/secure" style swap.

### SESSIONS

```
[SESSIONS]
#Location of directory where sessions are stored for recovery, it is located under
#the main coinswap data directory (APPDATA/.CoinSwapCS/). Note this contains
#keys and other privacy-sensitive information. Deleting its contents should be
#considered, but NEVER delete the contents until you are sure your previous
#coinswaps are completed. Also, NEVER EDIT THE CONTENTS OF SESSION FILES, only
#read them; editing could make a failed coinswap unrecoverable!
sessions_dir = sessions
```

For now this section is trivial, just specifying the location of the session files;
there's no reason to change it. However, **DO** read those warnings in the comments!

### POLICY

```
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
# as the value of 'tx_fees'. This estimate can be extremely high
# if you set N=1, so we choose N=3 for a more reasonable figure,
# as our default.
tx_fees = 3
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
```

There are a few edits I'd recommend here:

* `tx_fees` should be set to 1: this is high-priority processing, and if you set it
low, the server may not accept your proposed fees (it checks that yours are within
a reasonable range of its own target, and rejects the swap if not).
* `backout_fee_target` is 1 by default and should stay that way. Backout transactions
should be considered *ultra* high priority to avoid the danger of having them not
confirm before the respective `lock_client` and `lock_server` number of blocks. For
this reason we allow a multiplier to the fee `backout_fee_multiplier`, but 1.0 should
be OK for this assuming target 1 is actually doing its job. You can be a bit safer
by setting it to 2.0 (i.e. double the highest priority fee).
* `listunspent_args` - I'd recommend setting this to `[0, 9999999]` to show all
unspent outputs, whether confirmed or unconfirmed. The main advantage is that the
final report will show all coins, not only the confirmed ones (will also apply when
you run wallet-tool).
* `minimum_blinding_amount` - this one is purely a matter of preference, see the comment.
* `absurd_fee_per_kb` - this sanity check shuts down the program if a calculated fee
exceeds it (per kB of tx size), so set it high, perhaps 600000 or higher.

### SERVER

As the comment says, you can safely ignore this last section if you're a client
(you don't have to delete it, though).

```
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
#note these are "bounding" values, the actual maximum will change according
#to what's available in mixdepth 0 of the wallet.
minimum_amount = 5000000
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
```

First you should serve on a hidden service; this is preferably for better privacy
first, but also for better security (obscuring your origin). In this case you
should choose some arbitrary `onion_port` and then you can advertise the service
as `http://onionaddress.onion:onion_port`. The onion address is set on the first run
and stored in `~/.CoinSwapCS/hiddenservice`.

If you don't choose to do so, it's possible to serve over TLS by setting
`use_onion` to `false` and `use_ssl` to `true`, in which case the comments above
tell you what you need to know about certificates; however this is a bit
underdeveloped in the code.

The `FEES` subsection explains the primitive pricing algo: a minimum or a percentage.
The blinding amount (`minimum_`, `maximum_blinding_amount`) helps to obscure the nature of the coinswap so is helpful to the
client, but be aware that it means more of your coins are "spent" (back to you) in
transactions. This has implications for the coins you are storing. Note that clients
will have their own *minimum* required blinding amount, so it's a tradeoff.

The range in `tx_01_confirm_range` is the number of blocks you'll allow for treating
as "confirmed" both of TX0 (from the client) and TX1 (from yourself). Note that you'll
wait for both of these separately: e.g. if the value is 3, you'll wait 3 confirmations
before treating TX0 as final and only *then* send TX1, and wait 3 blocks confirmation
again before continuing. In the above setting, you'll accept the client choosing 2, 3
or 4 for this value.

Finally `server_` and `client_locktime_range` are self-explanatory. The tradeoff here
is between the security gain of longer blocktimes and liquidity gain from shorter.