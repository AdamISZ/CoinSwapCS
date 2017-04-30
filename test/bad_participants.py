from __future__ import print_function
from coinswap import CoinSwapAlice, CoinSwapCarol, get_log, get_coinswap_secret

cslog = get_log()

class AliceBadHandshake(CoinSwapAlice):
    """This class will not even trigger the correct instantiation
    of a CoinSwapCarol object, so a hack is needed to trigger test ending,
    see main test file.
    """
    def handshake(self):
        #still need bbmb otherwise final report will error.
        self.bbmb = self.wallet.get_balance_by_mixdepth(verbose=False)
        self.send({"foo": "bar"})
        return (True, "OK")

class AliceBadNegotiate(CoinSwapAlice):
    def negotiate_coinswap_parameters(self, accepted):
        if not accepted:
            return (False, "Carol rejected handshake.")
        to_send = ["foo", "bar"]
        self.send(*to_send)
        return (True, "Coinswap parameters sent OK")

class AliceBadCompleteNegotiation(CoinSwapAlice):
    """Pretending completion succeeds when it didn't results in a serialization
    error (because the CoinSwapPublicParameters is not complete), but this
    is OK because no funds moved, the final report is still correct without
    a valid persistence of any state.
    """
    def complete_negotiation(self, carol_response):
        cslog.debug('Carol response for param negotiation: ' + str(carol_response))
        if not carol_response[0]:
            return (False, "Negative response from Carol in negotiation")
        return (True, "pretend it's OK!")

class AliceFailSendTX0id(CoinSwapAlice):
    def send_tx0id_hx_tx2sig(self):
        self.secret, self.hashed_secret = get_coinswap_secret()
        #any old junk
        self.send("deadbeef:0", "beefdead", None)
        return (True, "TX0id, H(X), TX2 sig pretend sent OK")

class AliceFailReceiveTX1id(CoinSwapAlice):
    """Invalidity of parameters received can be checked with
    malicious Carol classes; here we just check what happens
    if there is a program/processing failure.
    """
    def receive_txid1_tx23sig(self, params):
        raise ValueError("Something supposedly went wrong")

class AliceBadTX3Sig(CoinSwapAlice):
    def send_tx3(self):
        self.send("deadbeef")
        return (True, "TX3 sig sent supposedly OK")

class AliceNoBrTX0(CoinSwapAlice):
    def broadcast_tx0(self, accepted):
        return (False, "Pretend we couldn't broadcast TX0")

class AliceBadTX01Monitor(CoinSwapAlice):
    def see_tx0_tx1(self):
        return (False, "Failed to start monitoring TX0/1")

class AliceWrongSecret(CoinSwapAlice):
    def send_coinswap_secret(self):
        self.send("deadbeef")
        return (True, "OK")

class AliceFailReceiveTX5Sig(CoinSwapAlice):
    def receive_tx5_sig(self, sig):
        raise ValueError("Supposedly failed to receive TX5 sig")
