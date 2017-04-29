from __future__ import print_function
from coinswap import CoinSwapAlice, CoinSwapCarol


class Fake_Alice_1(CoinSwapAlice):
    def send_coinswap_secret(self):
        self.send("deadbeef")
        return (True, "OK")
