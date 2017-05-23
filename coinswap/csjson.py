import os
import binascii
import json

from txjsonrpc.web.jsonrpc import Proxy
from txjsonrpc.web import jsonrpc
from twisted.web import server
from twisted.internet import reactor
try:
    from OpenSSL import SSL
    from twisted.internet import ssl
except:
    pass
from .base import (get_current_blockheight, CoinSwapPublicParameters,
                   prepare_ecdsa_msg, FeePolicy)
from .alice import CoinSwapAlice
from .carol import CoinSwapCarol
from .configure import get_log, cs_single
from twisted.internet import defer  

cslog = get_log()

def verifyCallback(connection, x509, errnum, errdepth, ok):
    if not ok:
        cslog.debug('invalid server cert: %s' % x509.get_subject())
        return False
    return True

class AltCtxFactory(ssl.ClientContextFactory):
    def getContext(self):
        ctx = ssl.ClientContextFactory.getContext(self)
        #TODO: replace VERIFY_NONE with VERIFY_PEER when we have
        #a real server with a valid CA signed cert. If that doesn't
        #work it'll be possible to use self-signed certs, if they're distributed,
        #by placing the cert.pem file and location in the config and uncommenting
        #the ctx.load_verify_locations line.
        #As it stands this is using non-authenticated certs, meaning MITM exposed.
        ctx.set_verify(SSL.VERIFY_NONE, verifyCallback)
        #ctx.load_verify_locations("/path/to/cert.pem")
        return ctx

class CoinSwapJSONRPCClient(object):
    """A class encapsulating Alice's json rpc client.
    """
    #Keys map to states as per description of CoinswapAlice
    method_names = {0: "handshake",
                    1: "negotiate",
                    3: "tx0id_hx_tx2sig",
                    5: "sigtx3",
                    9: "secret",
                    12: "sigtx4"}
    def __init__(self, host, port, json_callback=None, backout_callback=None,
                 usessl=False):
        self.host = host
        self.port = int(port)
        #Callback fired on receiving response to send()
        self.json_callback = json_callback
        #Callback fired on receiving any response failure
        self.backout_callback = backout_callback
        if usessl:
            self.proxy = Proxy('https://' + host + ":" + str(port) + "/",
                           ssl_ctx_factory=AltCtxFactory)
        else:
            self.proxy = Proxy('http://' + host + ":" + str(port) + "/")
    
    def error(self, errmsg):
        """error callback implies we must back out at this point.
        Note that this includes stateless queries, as any malformed
        or non-response must be interpreted as malicious.
        """
        self.backout_callback(str(errmsg))

    def send_poll(self, method, callback, noncesig, sessionid, *args):
        """Stateless queries during the run use this call, and provide
        their own callback for the response.
        """
        d = self.proxy.callRemote("coinswap", sessionid, noncesig, method, *args)
        d.addCallback(callback).addErrback(self.error)

    def send_poll_unsigned(self, method, callback, *args):
        """Stateless queries outside of a coinswap run use
        this query method; no nonce, sessionid or signature needed.
        """
        d = self.proxy.callRemote(method, *args)
        d.addCallback(callback).addErrback(self.error)

    def send(self, method, *args):
        """Stateful queries share the same callback: the state machine
        update function.
        """
        d = self.proxy.callRemote(method, *args)
        d.addCallback(self.json_callback).addErrback(self.error)

class CoinSwapCarolJSONServer(jsonrpc.JSONRPC):
    def __init__(self, wallet, testing_mode=False, carol_class=CoinSwapCarol,
                 fail_carol_state=None):
        self.testing_mode = testing_mode
        self.wallet = wallet
        self.carol_class = carol_class
        self.fail_carol_state = fail_carol_state
        self.carols = {}
        self.fee_policy = FeePolicy(cs_single().config)
        self.update_status()
        jsonrpc.JSONRPC.__init__(self)

    def update_status(self):
        #initialise status variables from config; some are updated dynamically
        c = cs_single().config
        source_chain = c.get("SERVER", "source_chain")
        destination_chain = c.get("SERVER", "destination_chain")
        minimum_amount = c.getint("SERVER", "minimum_amount")
        maximum_amount = c.getint("SERVER", "maximum_amount")
        status = {}
        #TODO requires keeping track of endpoints of swaps
        if len(self.carols.keys()) >= c.getint("SERVER",
                                               "maximum_concurrent_coinswaps"):
            status["busy"] = True
        else:
            status["busy"] = False
        #reset minimum and maximum depending on wallet
        #we source only from mixdepth 0
        available_funds = self.wallet.get_balance_by_mixdepth(verbose=False)[0]
        if available_funds < minimum_amount:
            status["busy"] = True
            status["maximum_amount"] = -1
        elif available_funds < maximum_amount:
            status["maximum_amount"] = available_funds
        else:
            status["maximum_amount"] = maximum_amount
        status["minimum_amount"] = minimum_amount
        status["source_chain"] = source_chain
        status["destination_chain"] = destination_chain
        status["cscs_version"] = cs_single().CSCS_VERSION
        status["fee_policy"] = self.fee_policy.get_policy()
        return status

    def jsonrpc_status(self):
        """This can be polled at any time.
        The call to get_balance_by_mixdepth does not involve sync,
        so is not resource intensive.
        """
        return self.update_status()

    def set_carol(self, carol, sessionid):
        """Once a CoinSwapCarol object has been initiated, its session id
        has been set, so it can be added to the dict.
        """
        #should be computationally infeasible; note *we* set this.
        assert sessionid not in self.carols
        self.carols[sessionid] = carol
        return True

    def consume_nonce(self, nonce, sessionid):
        if sessionid not in self.carols:
            return False
        return self.carols[sessionid].consume_nonce(nonce)

    def validate_sig_nonce(self, carol, paramlist):
        noncesig = paramlist[0]
        if not "nonce" in noncesig or not "sig" in noncesig:
            return (False, "Ill formed nonce/sig")
        nonce = noncesig["nonce"]
        sig = noncesig["sig"]
        if not carol.consume_nonce(nonce):
            return (False, "Nonce invalid, probably a repeat")
        #paramlist[1] is method name, the remaining are the args
        msg_to_verify = prepare_ecdsa_msg(nonce, paramlist[1], *paramlist[2:])
        if not carol.validate_alice_sig(sig, msg_to_verify):
            return (False, "ECDSA message signature verification failed")
        return (True, "Nonce and signature OK")

    def jsonrpc_coinswap(self, *paramlist):
        """To get round txjsonrpc's rather funky function naming trick,
        we use 1 generic json rpc method and then read the real method as a field.
        This allows us to handle generic features like signatures and nonces in
        this function before deferring actual methods to sub-calls.
        All calls use syntax:
        sessionid, {noncesig dict}, method, *methodargs
        """
        if len(paramlist) < 3:
            return (False, "Wrong length of paramlist: " + str(len(paramlist)))
        sessionid = paramlist[0]
        if sessionid not in self.carols:
            return (False, "Unrecognized sessionid: " + str(sessionid))
        carol = self.carols[sessionid]
        valid, errmsg = self.validate_sig_nonce(carol, paramlist[1:])
        if not valid:
            return (False, "Invalid message from Alice: " + errmsg)
        return carol.get_rpc_response(paramlist[2], paramlist[3:])

    def jsonrpc_handshake(self, *alice_handshake):
        """The handshake messages initiates the session, so is handled
        differently from other calls (future anti-DOS features may be
        added here). It does not use the sig/nonce since the session key
        is not yet established.
        """
        #Prepare a new CoinSwapCarol instance for this session
        #start with a unique ID of 16 byte entropy:
        sessionid = binascii.hexlify(os.urandom(16))
        #Logic for mixdepths:
        #TX4 output is the normal coinswap output, not combined with original.
        #TX5 output address functions like change, goes back to original.
        #TX2/3 are unambiguous coinswap outs, since adversary can deduce
        #who they belong to, no point in isolating them (go back to start).
        tx4address = self.wallet.get_new_addr(1, 1)
        tx2_carol_address = self.wallet.get_new_addr(0, 1)
        tx3_carol_address = self.wallet.get_new_addr(0, 1)
        tx5_carol_address = self.wallet.get_new_addr(0, 1)
        cpp = CoinSwapPublicParameters()
        cpp.set_session_id(sessionid)
        cpp.set_fee_policy(self.fee_policy)
        cpp.set_addr_data(addr4=tx4address, addr_2_carol= tx2_carol_address,
                          addr_3_carol=tx3_carol_address,
                          addr_5_carol=tx5_carol_address)
        try:
            if self.fail_carol_state:
                if not self.set_carol(self.carol_class(self.wallet, 'carolstate',
                                    cpp, testing_mode=self.testing_mode,
                                    fail_state=self.fail_carol_state), sessionid):
                    return False
            else:
                if not self.set_carol(self.carol_class(self.wallet, 'carolstate', cpp,
                                                testing_mode=self.testing_mode),
                                        sessionid):
                    return False
        except Exception as e:
            return (False, "Error in setting up handshake: " + repr(e))
        if not self.consume_nonce(alice_handshake[1]["nonce"], sessionid):
            return (False, "Invalid nonce in handshake.")
        return self.carols[sessionid].sm.tick_return(
            "handshake", alice_handshake)
