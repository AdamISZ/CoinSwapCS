from txjsonrpc.web.jsonrpc import Proxy
from txjsonrpc.web import jsonrpc
from twisted.web import server
from twisted.internet import reactor
from .base import get_current_blockheight, CoinSwapPublicParameters
from .alice import CoinSwapAlice
from .carol import CoinSwapCarol
from .configure import get_log
from twisted.internet import defer  

cslog = get_log()

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
    def __init__(self, host, port, json_callback, backout_callback):
        self.host = host
        self.port = int(port)
        #Callback fired on receiving response to send()
        self.json_callback = json_callback
        #Callback fired on receiving any response failure
        self.backout_callback = backout_callback
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
    def __init__(self, wallet):
        self.wallet = wallet
        jsonrpc.JSONRPC.__init__(self)

    def set_carol(self, carol):
        self.carol = carol

    def jsonrpc_handshake(self, alice_handshake):
        #Prepare a new CoinSwapCarol instance for this session
        tx4address = self.wallet.get_new_addr(1, 1)
        cpp = CoinSwapPublicParameters()
        cpp.set_tx4_address(tx4address)
        self.set_carol(CoinSwapCarol(self.wallet, 'carolstate', cpp))
        return self.carol.sm.tick_return("handshake", alice_handshake)
    def jsonrpc_negotiate(self, *alice_parameter_list):
        return self.carol.sm.tick_return("negotiate_coinswap_parameters",
                                         alice_parameter_list)
    def jsonrpc_tx0id_hx_tx2sig(self, *params):
        #params must have form: tx0id, hashed_secret, tx2sig
        return self.carol.sm.tick_return("receive_tx0_hash_tx2sig", *params)
    def jsonrpc_sigtx3(self, sig):
        return self.carol.sm.tick_return("receive_tx3_sig", sig)
    def jsonrpc_phase2_ready(self):
        return self.carol.is_phase2_ready()
    def jsonrpc_secret(self, secret):
        return self.carol.sm.tick_return("receive_secret", secret)
    def jsonrpc_sigtx4(self, sig, txid5):
        return self.carol.sm.tick_return("receive_tx4_sig", sig, txid5)
    def jsonrpc_confirm_tx4(self):
        return self.carol.is_tx4_confirmed()
