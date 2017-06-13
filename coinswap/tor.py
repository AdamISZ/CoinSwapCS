#! /usr/bin/env python
from __future__ import absolute_import, print_function

"""Module to load tor for
the hidden service for CoinSwapCS.
Dependencies can be loaded with:
sudo apt-get install tor
(then kill the auto-started tor binary)
pip install txtorcon
"""

import txtorcon
import tempfile
from twisted.internet import reactor, endpoints

def listening(port):
    # port is a Twisted IListeningPort
    print("Listening on: {} port 1234".format(port.getHost()))
    print("Onion address is: ".format(port.getHost().onion_uri))

def setup_failed(arg):
    print("SETUP FAILED", arg)
    reactor.stop()

def start_tor(site, hs_public_port, hs_port):
    # set up HS server, start Tor
    hs_endpoint = endpoints.serverFromString(reactor, "onion:1234")
    d = hs_endpoint.listen(site)
    #add chain of callbacks for actions after Tor is set up correctly.
    d.addCallback(listening)
    d.addErrback(setup_failed)
    return d