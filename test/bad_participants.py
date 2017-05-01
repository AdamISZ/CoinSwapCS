from __future__ import print_function
from coinswap import CoinSwapAlice, CoinSwapCarol, get_log, get_coinswap_secret
from bad_state_machine import BadStateMachine
cslog = get_log()

class BadAlice(CoinSwapAlice):
    """A base class that allows injection of failure states to test recovery
    """
    def __init__(self, wallet, state_file, cpp=None, testing_mode=False,
                 fail_state=None):
        #This will call the __init__ of the base class CoinSwapAlice, which is
        #actually the __init__ of its base class (CoinSwapParticipant)
        super(BadAlice, self).__init__(wallet, state_file, cpp, testing_mode)
        #if a BadStateMachine has been requested, overwrite the statemachine object
        if fail_state:
            self.sm = BadStateMachine(self.state, self.backout,
                            self.get_state_machine_callbacks(),
                            (fail_state, self.failure_injection))
            self.sm.set_finalize(self.finalize)

    def failure_injection(self):
        """Used when a BadAlice/BadCarol class decides to interrupt processing,
        simulating a crash; reload state and run backout.
        """
        self.load()
        self.backout("Fake injection")

#This is an exact copy-paste of the above. It's a bit brain-frying to figure
#out how not to do this...
class BadCarol(CoinSwapCarol):
    """A base class that allows injection of failure states to test recovery
    """
    def __init__(self, wallet, state_file, cpp=None, testing_mode=False,
                 fail_state=None):
        #This will call the __init__ of the base class CoinSwapCarol, which is
        #actually the __init__ of its base class (CoinSwapParticipant)
        super(BadCarol, self).__init__(wallet, state_file, cpp, testing_mode)
        #if a BadStateMachine has been requested, overwrite the statemachine object
        if fail_state:
            self.sm = BadStateMachine(self.state, self.backout,
                            self.get_state_machine_callbacks(),
                            (fail_state, self.failure_injection))
            self.sm.set_finalize(self.finalize)

    def failure_injection(self):
        """Used when a BadAlice/BadCarol class decides to interrupt processing,
        simulating a crash; reload state and run backout.
        """
        self.load()
        self.backout("Fake injection")

"""**MALICIOUS ALICE CLASSES**
"""
class AliceBadHandshake(BadAlice):
    """This class will not even trigger the correct instantiation
    of a CoinSwapCarol object, so a hack is needed to trigger test ending,
    see main test file.
    """
    def handshake(self):
        #still need bbmb otherwise final report will error.
        self.bbmb = self.wallet.get_balance_by_mixdepth(verbose=False)
        self.send({"foo": "bar"})
        return (True, "OK")

class AliceBadNegotiate(BadAlice):
    def negotiate_coinswap_parameters(self, accepted):
        if not accepted:
            return (False, "Carol rejected handshake.")
        to_send = ["foo", "bar"]
        self.send(*to_send)
        return (True, "Coinswap parameters sent OK")

class AliceBadCompleteNegotiation(BadAlice):
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

class AliceFailSendTX0id(BadAlice):
    def send_tx0id_hx_tx2sig(self):
        self.secret, self.hashed_secret = get_coinswap_secret()
        #any old junk
        self.send("deadbeef:0", "beefdead", None)
        return (True, "TX0id, H(X), TX2 sig pretend sent OK")

class AliceFailReceiveTX1id(BadAlice):
    """Invalidity of parameters received can be checked with
    malicious Carol classes; here we just check what happens
    if there is a program/processing failure.
    """
    def receive_txid1_tx23sig(self, params):
        raise ValueError("Something supposedly went wrong")

class AliceBadTX3Sig(BadAlice):
    def send_tx3(self):
        self.send("deadbeef")
        return (True, "TX3 sig sent supposedly OK")

class AliceNoBrTX0(BadAlice):
    def broadcast_tx0(self, accepted):
        return (False, "Pretend we couldn't broadcast TX0")

class AliceBadTX01Monitor(BadAlice):
    def see_tx0_tx1(self):
        return (False, "Failed to start monitoring TX0/1")

class AliceWrongSecret(BadAlice):
    def send_coinswap_secret(self):
        self.send("deadbeef")
        return (True, "OK")

class AliceFailReceiveTX5Sig(BadAlice):
    def receive_tx5_sig(self, sig):
        raise ValueError("Supposedly failed to receive TX5 sig")


"""**MALICIOUS CAROL CLASSES**
"""
class CarolBadHandshake(BadCarol):
    def handshake(self, d):
        self.bbmb = self.wallet.get_balance_by_mixdepth(verbose=False)
        return (False, "Test rejection")

class CarolBadNegotiate(BadCarol):
    def negotiate_coinswap_parameters(self, params):
        to_send = ["foo", "bar"]
        return (to_send, "Fake OK")

class CarolFailSendTX1id(BadCarol):
    def send_tx1id_tx2_sig_tx3_sig(self):
        return (["foo", "bar", "baz"], "Supposedly sent TX1id etc")

class CarolFailReceiveTX3Sig(BadCarol):
    def receive_tx3_sig(self, sig):
        raise ValueError("Supposedly failed to receive TX3 sig")

class CarolNoBrTX1(BadCarol):
    def push_tx1(self):
        return (False, "Pretend we couldn't broadcast TX1")

class CarolFailReceiveSecret(BadCarol):
    def receive_secret(self, secret):
        raise ValueError("Supposedly failed to receive secret")

class CarolBadSendTX5Sig(BadCarol):
    def send_tx5_sig(self):
        return ("deadbeef", "Sending invalid TX5 sig")

class CarolFailReceiveTX4Sig(BadCarol):
    def receive_tx4_sig(self, sig, txid5):
        raise ValueError("Supposedly failed to receive TX4 sig")
