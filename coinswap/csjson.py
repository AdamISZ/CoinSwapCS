from txjsonrpc.web.jsonrpc import Proxy
from txjsonrpc.web import jsonrpc
from twisted.web import server
from .alice import CoinSwapAlice
from .carol import CoinSwapCarol
from jmclient import get_log

jlog = get_log()

class CoinSwapJSONRPCClient(object):
    """A class encapsulating Alice's json rpc client.
    """   
    method_names = {-1: "handshake",
                    0: "negotiate",
                    1: "tx0id_hx_tx2sig",
                    3: "sigtx3",
                    4: "phase2_ready",
                    5: "secret",
                    6: "sigtx5",
                    7: "confirm_tx5"}
    def __init__(self, host, port, client_callbacks):
        self.host = host
        self.port = int(port)
        #A dict of functions on method name
        self.client_callbacks = client_callbacks
        self.proxy = Proxy('http://' + host + ":" + str(port) + "/")
    
    def error(self, errmsg):
        jlog.info("JSONRPC client errmsg is: " + str(errmsg))

    def send(self, method, *args):
        #jlog.debug("using method, args: " + method + " , " + str(args))
        d = self.proxy.callRemote(method, *args)
        d.addCallback(self.client_callbacks[method]).addErrback(self.error)

class CoinSwapCarolJSONServer(jsonrpc.JSONRPC):
    def __init__(self, csc):
        assert isinstance(csc, CoinSwapCarol)
        self.carol = csc
        self.set_handshake_parameters()
        jsonrpc.JSONRPC.__init__(self)

    def set_carol(self, carol):
        self.carol = carol

    def set_handshake_parameters(self, source_chain="BTC",
                                 destination_chain="BTC",
                                 minimum_amount=1000000,
                                 maximum_amount=100000000):
        self.source_chain = source_chain
        self.destination_chain = destination_chain
        self.minimum_amount = minimum_amount
        self.maximum_amount = maximum_amount

    def handshake(self, d):
        if d["source_chain"] != self.source_chain:
            return False
        if d["destination_chain"] != self.destination_chain:
            return False
        if d["amount"] < self.minimum_amount:
            return False
        if d["amount"] > self.maximum_amount:
            return False
        return True

    def jsonrpc_handshake(self, alice_handshake):
        retval = self.handshake(alice_handshake)
        print('returning: ', retval)
        return retval
    def jsonrpc_negotiate(self, *alice_parameter_list):
        return self.carol.negotiate_coinswap_parameters(alice_parameter_list)
    def jsonrpc_tx0id_hx_tx2sig(self, tx0id, hashed_secret, tx2sig):
        return self.carol.receive_tx0_hash_tx2sig(tx0id, hashed_secret, tx2sig)
    def jsonrpc_sigtx3(self, sig):
        return self.carol.receive_tx_3_sig(sig)
    def jsonrpc_phase2_ready(self):
        return self.carol.is_phase2_ready()
    def jsonrpc_secret(self, secret):
        return "deadbeef"
        #return self.carol.receive_secret(secret)
    def jsonrpc_sigtx5(self, sig):
        return self.carol.receive_tx5_sig(sig)
    def jsonrpc_confirm_tx5(self):
        return self.carol.is_tx5_confirmed()
