#! /usr/bin/env python
from __future__ import absolute_import, print_function

"""Module to start the hidden service for CoinSwapCS.
Requires tor to be started on default port (9050):
sudo apt-get install tor
"""

import txtorcon
import tempfile
from twisted.internet import reactor, endpoints

def listening(port):
    # port is a Twisted IListeningPort
    print("Listening on port {}".format(port.getHost().onion_port))
    print("Onion address is: {}".format(port.getHost().onion_uri))

def setup_failed(arg):
    print("SETUP FAILED", arg)
    reactor.stop()

def start_tor(site, hs_public_port, hsdir):
    # set up HS server
    hs_endpoint = endpoints.serverFromString(reactor,
        "onion:"+str(hs_public_port)+":hiddenServiceDir="+hsdir)
    d = hs_endpoint.listen(site)
    #add chain of callbacks for actions after Tor is set up correctly.
    d.addCallback(listening)
    d.addErrback(setup_failed)
    return d