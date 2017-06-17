### Installation

This code uses Python 2.7. (Yes, I know!)

This application *requires* access to a Bitcoin Core node, built with wallet capability, at least version 0.13, over RPC. Make sure you can make rpc requests to your node before starting.

The following guide is for **Linux**; it has been tested on Ubuntu 16.04 (and a little on Debian), so far. If you have specific deltas for specific distros, please submit a PR to this document. Same for Mac or Windows.

#### Steps 1-4 Client or Server
1. Start by installing dependencies (these are mostly for `joinmarket-clientserver`, see below):

```bash
sudo apt-get update
sudo apt-get install python-dev python-pip git virtualenv build-essential automake pkg-config libtool libffi-dev libssl-dev tor
```

Note that the installation of tor will start it in the background, which is what we want if we intend to query a Tor hidden service (the default), or run one. You can of course shut it down with `sudo service tor stop`.

2. Make and activate a virtualenv:

```bash
    mkdir coinswapenv
    virtualenv coinswapenv; source coinswapenv/bin/activate
```
From now on you're operating in a virtualenv so the Python dependencies will be isolated to it. Use `deactivate` to switch back to the system Python environment if you need to (but you won't, here).

3. Follow the instructions to install the Joinmarket client/bitcoin code from
[this](https://github.com/AdamISZ/joinmarket-clientserver) repo. The reason for
doing this is to pick up the bitcoin and wallet code from Joinmarket (this project
reuses that code, and so the wallets are compatible with Joinmarket). Don't use the install guide there,
instead follow this condensed form for our requirements:

```bash
git clone https://github.com/AdamISZ/joinmarket-clientserver
cd joinmarket-clientserver
python setupall.py --client-bitcoin
cd ..
```
This setup will take a little time; it will install Twisted, secp256k1 and several underlying dependencies. Some libraries are actually compiled at this step (hence the above apt-get installs for development packages).

Assuming no errors, continue:

4. Install *this* repository:

```bash
git clone https://github.com/AdamISZ/CoinSwapCS; cd CoinSwapCS
python setup.py install
```

Assuming no errors, you now have CoinSwapCS installed.

5. (Client only, Tor only): configure torsocks

First check that torsocks was installed (it will have been, with Tor), with `which torsocks` and assuming it's found, try `torsocks --version` - you need at least version 2.1. If not, either you will only be able to use non-Tor versions (for the client side; torsocks is not needed for the server). If OK, you need to edit the file `/etc/tor/torsocks.conf` (use sudo, e.g. `sudo vi /etc/tor/torsocks.conf`), and uncomment the line for AllowOutboundLocalhost to read: `AllowOutboundLocalhost 1` (no comment, remove `#`), then save and quit.

6. (Client only) Check the client works

From inside the `CoinSwapCS` directory, try this command:

```bash
torsocks python coinswap_run.py -s http://fwjpp2ae5zcrccv7.onion:1234 -C
```
(fwjpp2ae5zcrccv7.onion is a test server I'll try to keep up long term, testnet of course). After a short delay you should see a status return something like:

```json
{
    "busy": false, 
    "source_chain": "BTC", 
    "fee_policy": {
        "percent_fee": 0.5, 
        "minimum_fee": 100000
    }, 
    "locktimes": {
        "lock_server": {
            "max": 11, 
            "min": 3
        }, 
        "lock_client": {
            "max": 20, 
            "min": 8
        }
    }, 
    "maximum_amount": 500000000, 
    "minimum_amount": 5000000, 
    "destination_chain": "BTC", 
    "cscs_version": 0.1
}
```

7. (Both) Create a config file.
At this point you can be confident you're set up right, but you need to configure your client for your needs by editing the config file. A first version can be created by doing a dummy run with:

```bash
python wallet-tool.py abcd
```
This will error out (it cannot connect to any Bitcoin instance), but will create a default config file in `~/.CoinSwapCS/coinswapcs.cfg`, which you should then edit, following the guide [here](config-guide.md).

8. (Server only) Setting up a hidden service.

It's possible to run a server directly over http but that's highly disrecommended. It's also possible to run over clearnet TLS by configuring a certificate - see the code, particularly in `coinswap/csjson.py` but also the notes in the config file. This needs a bit of improvement but is functional.

The default is to use a hidden service. This is set with the option `use_onion = true` in the `SERVER` section of the config file. Here you can also set the `onion_port` on which to serve publically. A first run of the server will create an onion address and associated private key in `~/.CoinSwapCS/hiddenservice`, so be aware that this directory is sensitive. Further runs will thus keep that address.

9. (Both) Fund a wallet.

Assuming you followed step 7 correctly and your config file points to a valid Bitcoin instance: You can use the script `wallet-tool.py` in basically exactly the same way as you would for Joinmarket. Instructions on creating and funding a Joinmarket wallet can be found [here](https://github.com/JoinMarket-Org/joinmarket/wiki/Using-the-JoinMarket-internal-wallet), but **note** two differences/caveats: (1) fund only into "mixdepth" 0; CoinSwapCS only uses that mixdepth/account as a source of funds for swaps, (2) ignore the warnings related to "Joinmarket 0.2", which are referring to something that doesn't apply here. You are now ready to run real coinswaps.
