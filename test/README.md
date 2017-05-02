# Instructions for testing

First, you need a recent installation (>= 0.13 should be fine) of Bitcoin Core,
get it from [here](https://bitcoin.org/en/bitcoin-core/) if you need to.

If you use a self-compiled version, note you do not need GUI support but you do
of course need wallet support.

You do **not** need a synced blockchain, either mainnet or testnet, since these
tests only use regtest mode.

You should already have installed CoinSwapCS as explained in the main README file
for this repo.
The test does not currently support the `coinswapcs.cfg` file in any place
other than `~/.CoinSwapCS/coinswapcs.cfg`, so you should also move this file
someplace else (changing the name to e.g. `coinswapcs.mine` is enough).

In the virtualenv you set up, install pytest:

   `pip install pytest`

You should then be able to navigate to `test/` in the CoinSwapCS directory
and then run:

   `./run_all.sh "/path/to/bitcoind" [--keep] [TEST1 TEST2 TEST3...]`

`--keep` - Do not clean up after a run, leaving all test files in the 
           temporary directory.
`TEST..` - Test names in a list, or nothing to run all tests.

For example:

   `./run_all.sh $HOME/software/bitcoin/bin/bitcoind --keep cooperative`

This will execute about 20 test cases (currently), and should take 10-15
minutes in total. Test files are kept in a random directory with the path:
   `/dev/shm/cstest[0-9]*`

If you want to try individual test cases with py.test, simply run the command 
with the correct `runtype` flag, e.g. the case where both sides behave normally
would be run as:

   `py.test --btcroot=/path/to/bitcoin/bin/ --btcpwd=123456abcdef --btcconf=/path/to/bitcoin.conf --runtype=cooperative -s`

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
