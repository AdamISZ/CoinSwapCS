from txjsonrpc.web.jsonrpc import Proxy
from txjsonrpc.web import jsonrpc
from twisted.web import server
from twisted.internet import reactor
try:
    from OpenSSL import SSL
    from twisted.internet import ssl
except:
    pass
from .base import get_current_blockheight, CoinSwapPublicParameters
from .alice import CoinSwapAlice
from .carol import CoinSwapCarol
from .configure import get_log
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
    def __init__(self, host, port, json_callback, backout_callback, usessl):
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

    def send_poll(self, method, callback, *args):
        """Stateless queries use this call, and provide
        their own callback for the response.
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
    def __init__(self, wallet, testing_mode=False, carol_class=CoinSwapCarol):
        self.testing_mode = testing_mode
        self.wallet = wallet
        self.carol_class = carol_class
        self.carols = {}
        jsonrpc.JSONRPC.__init__(self)

    def set_carol(self, carol, sessionid):
        """Once a CoinSwapCarol object has been initiated, its session id
        has been set, so it can be added to the dict.
        TODO check for sessionid conflicts here.
        """
        self.carols[sessionid] = carol
        return True

    def jsonrpc_handshake(self, alice_handshake):
        """The handshake messages initiates the session, so is handled
        differently from other calls (future anti-DOS features may be
        added here).
        """
        #Prepare a new CoinSwapCarol instance for this session
        tx4address = self.wallet.get_new_addr(1, 1)
        cpp = CoinSwapPublicParameters()
        cpp.set_tx4_address(tx4address)
        try:
            if not self.set_carol(self.carol_class(self.wallet, 'carolstate', cpp,
                                                testing_mode=self.testing_mode),
                                        alice_handshake["session_id"]):
                return False
        except:
            return False
        return self.carols[alice_handshake["session_id"]].sm.tick_return(
            "handshake", alice_handshake)

    def jsonrpc_negotiate(self, *alice_parameter_list):
        """Receive Alice's half of the public parameters,
        and return our half if acceptable.
        """
        return self.carols[alice_parameter_list[0]].sm.tick_return(
            "negotiate_coinswap_parameters", alice_parameter_list[1:])

    def jsonrpc_tx0id_hx_tx2sig(self, *params):
        return self.carols[params[0]].sm.tick_return("receive_tx0_hash_tx2sig",
                                                    *params[1:])
    def jsonrpc_sigtx3(self, sessionid, sig):
        return self.carols[sessionid].sm.tick_return("receive_tx3_sig", sig)

    def jsonrpc_phase2_ready(self, sessionid):
        return self.carols[sessionid].is_phase2_ready()

    def jsonrpc_secret(self, sessionid, secret):
        return self.carols[sessionid].sm.tick_return("receive_secret", secret)

    def jsonrpc_sigtx4(self, sessionid, sig, txid5):
        return self.carols[sessionid].sm.tick_return("receive_tx4_sig", sig, txid5)

    def jsonrpc_confirm_tx4(self, sessionid):
        return self.carols[sessionid].is_tx4_confirmed()
