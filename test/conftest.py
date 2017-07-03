#!/home/adam/virtualenvs/escrow/bin/python
import pytest
import os
import time
import subprocess

bitcoin_path = None
bitcoin_conf = None
bitcoin_rpcpassword = None
bitcoin_rpcusername = None
miniircd_procs = []

def local_command(command, bg=False, redirect=''):
    if redirect == 'NULL':
        if OS == 'Windows':
            command.append(' > NUL 2>&1')
        elif OS == 'Linux':
            command.extend(['>', '/dev/null', '2>&1'])
        else:
            print "OS not recognised, quitting."
    elif redirect:
        command.extend(['>', redirect])

    if bg:
        #using subprocess.PIPE seems to cause problems
        FNULL = open(os.devnull, 'w')
        return subprocess.Popen(command,
                                stdout=FNULL,
                                stderr=subprocess.STDOUT,
                                close_fds=True)
    else:
        #in case of foreground execution, we can use the output; if not
        #it doesn't matter
        return subprocess.check_output(command)

def pytest_addoption(parser):
    parser.addoption("--btcroot", action="store", default='',
                     help="the fully qualified path to the directory containing "+\
                     "the bitcoin binaries, e.g. /home/user/bitcoin/bin/")
    parser.addoption("--btcconf", action="store",
                         help="the fully qualified path to the location of the "+\
                         "bitcoin configuration file you use for testing, e.g. "+\
                         "/home/user/.bitcoin/bitcoin.conf")
    parser.addoption("--btcpwd",
                     action="store",
                     help="the RPC password for your test bitcoin instance")
    parser.addoption("--btcuser",
                     action="store",
                     default='bitcoinrpc',
                     help="the RPC username for your test bitcoin instance (default=bitcoinrpc)")
    parser.addoption("--runtype",
                     action="store",
                     default="",
                     help="Mode of test, can be one of: cooperative,")

def pytest_generate_tests(metafunc):
    option_value = metafunc.config.option.runtype
    if "runtype" in metafunc.fixturenames and option_value is not None:
        metafunc.parametrize("runtype", [option_value])

def teardown():
    #shut down bitcoin and remove the regtest dir
    local_command([bitcoin_path + "bitcoin-cli", "-regtest",
                   "-rpcuser=" + bitcoin_rpcusername,
                   "-rpcpassword=" + bitcoin_rpcpassword,
                   "-conf=" + bitcoin_conf, "stop"])
    #note, it is better to clean out ~/.bitcoin/regtest but too
    #dangerous to automate it here perhaps


@pytest.fixture(scope="session", autouse=True)
def setup(request):
    print 'starting'
    request.addfinalizer(teardown)

    global bitcoin_conf, bitcoin_path, bitcoin_rpcpassword, bitcoin_rpcusername
    bitcoin_path = request.config.getoption("--btcroot")
    bitcoin_conf = request.config.getoption("--btcconf")
    bitcoin_rpcpassword = request.config.getoption("--btcpwd")
    bitcoin_rpcusername = request.config.getoption("--btcuser")

    #start up regtest blockchain
    btc_proc = subprocess.call([bitcoin_path + "bitcoind", "-regtest",
                                "-daemon", "-conf=" + bitcoin_conf])
    time.sleep(3)
    #generate blocks
    local_command([bitcoin_path + "bitcoin-cli", "-regtest",
                   "-rpcuser=" + bitcoin_rpcusername,
                   "-rpcpassword=" + bitcoin_rpcpassword,
                   "-conf=" + bitcoin_conf, "generate", "601"])
