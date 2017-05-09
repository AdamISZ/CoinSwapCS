from __future__ import absolute_import, print_function
import random

"""Command line management
"""

from optparse import OptionParser

def get_coinswap_parser():
    parser = OptionParser(
            usage="Usage: %prog [options] [wallet file] amount(in btc) "
            "[destination-address]",
            description="Run coinswap-clientserver. Use -S to run as "
    "server, else runs as client by default. The first argument is the name of "
    "your (joinmarket or joinmarket-compatible) wallet. Specify the amount to "
    "transfer in satoshis as the second argument. The third argument is optional, "
    "and is an address to receive the funds; if not specified, the funds will "
    "be sent to a new address in mixdepth 1 in the same wallet.")
    parser.add_option("-r", "--recover",
        type="str",
        dest="recover",
        default="",
        help=("Choose this option to recover in case the script crashed."
              " It will execute the backout process to recover funds, using"
              " the data in the session file."))
    parser.add_option(
        "-S",
        "--serve",
        action="store_true",
        dest="serve",
        default=False,
        help=("Run as server (Carol). Make sure to set appropriate settings "
              "in the config file ~/.CoinSwapCS/coinswapcs.cfg, in particular "
              "the settings for the SERVER section."))
    parser.add_option(
            "-s",
            "--serverport",
            type="str",
            dest="serverport",
            default="https://127.0.0.1:7080",
            help=("For client, specify the host and port that will be used "
                  "as given by the server, in formation http[s]://hostname:port. "
                  "Default https://localhost:7048. Use http:// instead of "
                  "https:// to use a non-TLS connection, but this is inadvisable "
                  "and will usually not be supported server-side."))
    parser.add_option(
                "-C",
                "--check-only",
                action="store_true",
                dest="checkonly",
                default=False,
                help=("""
For client, only query the server to check its current
status. The following data will be returned:
CSCS_VERSION: The version of CoinSwapCS served by the server.
SOURCE_CHAIN: The coin type of the source, only BTC supported.
DESTINATION_CHAIN: As above, for the destination coins, only BTC.
MINIMUM_AMOUNT: Lowest amount in satoshis that the server currently
supports; note this changes over time.
MAXIMUM_AMOUNT: Largest amount in satoshis that the server currently
supports; note this changes over time.
BUSY: If True, the server is currently not available (usually because
is serving other requests, or has run out of coins).
Default: False
"""))
    parser.add_option("--fast",
                      action="store_true",
                      dest="fastsync",
                      default=False,
                      help=("choose to do fast wallet sync, only for Core and "
                      "only for previously synced wallet"))
    return parser
