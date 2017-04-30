# Instructions for testing

First, you need a recent installation (>= 0.13 should be fine) of Bitcoin Core,
get it from [here](https://bitcoin.org/en/bitcoin-core/) if you need to.

If you use a self-compiled version, note you do not need GUI support but you do
of course need wallet support.

You do **not** need a synced blockchain, either mainnet or testnet, since these
tests only use regtest mode.

You should already have installed CoinSwapCS as explained in the main README file
for this repo.

In the virtualenv you set up, install pytest:

    pip install pytest

Next you need to set up configuration files for Bitcoin and CoinSwapCS for the tests.
The samples in this directory will be mostly OK for your needs, so copy them into
the desired locations:

    cp test/regtest_bitcoin.conf /your/chosen/directory/bitcoin.conf
    cp test/regtest_coinswapcs.cfg ~/.CoinSwapCS/coinswapcs.cfg

The location of the bitcoin.conf will be passed as a parameter on the command line
in the tests, so can be anywhere. The directory `~/.CoinSwapCS` may not exist yet if
you haven't run CoinSwapCS yet, in that case just create it.

You shouldn't need to edit those 2 files (unless I forgot something).

Lastly, edit the file `test/run_all.sh` to modify `your/chosen/directory` as above,
and also `/path/to/bitcoin/bin/` to the directory containing `bitcoind` for your
own Bitcoin Core installation.

Note that `test/run_all.sh` deletes the directory `~/.bitcoin/regtest` between each
run; it doesn't really have to do this, but note this is the default datadir
location for Bitcoin. Finally, don't forget to `chmod +x test/run_all.sh` so you
can run it.

Once all those files are correct, you should be able to navigate to `test/` in the
CoinSwapCS directory and then `./run_all.sh`. It will execute about 20 test cases
(currently), and should take 10-15 minutes in total.

If you want to try individual test cases, simply run the command with the correct
`runtype` flag, e.g. the case where both sides behave normally would be run as:

    py.test --btcroot=/path/to/bitcoin/bin/ --btcpwd=123456abcdef --btcconf=/path/to/bitcoin.conf --runtype=cooperative -s

(The individual test cases are listed in `test_coinswap.py` in the variables
`alice_classes` and `carol_classes`.)

If the tests fail, please report this as an issue on this repo. Thanks.

===

(A technical detail: the use of a shell script wrapping pytest looks a bit stupid
if you're familiar with these things; and arguably it is. The reason is that it
is not possible to run the twisted reactor more than once in one program execution.
It is possible to get round this with the `twisted.trial` module, but it's all a
bit of a mess, so I decided not to bother with it. This bash script will error out
on any pytest failure based on exit codes, so it's good enough, arguably.)