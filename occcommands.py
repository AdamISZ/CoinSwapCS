from __future__ import print_function
"""
Commands defining client-server (daemon)
messaging protocol.
Used for AMP asynchronous messages.
"""
from twisted.protocols.amp import String, Command, Boolean

class DaemonNotReady(Exception):
    pass

class OCCCommand(Command):
    #a default response type
    response = [('accepted', Boolean())]

"""COMMANDS FROM CLIENT TO SERVER
=================================
"""

class OCCSetup(OCCCommand):
    """Passes amtdata as list of ranges [(low, high), (low, high)]
    """
    arguments = [('amtdata', String())]

class OCCKeys(OCCCommand):
    """Sends keys and template to be filled in to server.
    """
    arguments = [('template_ins', String()),
                  ('our_keys', String()),
                  ('template_data', String())]

class OCCSigs(OCCCommand):
    """Send all of our signatures and receive the funding
    transaction signature.
    """
    arguments = [('our_sigs', String())]


"""COMMANDS FROM SERVER TO CLIENT
=================================
"""

class OCCSetupResponse(OCCCommand):
    """Return utxo information in the form
    of a list of tuples: txid:n, amount, pubkey
    """
    arguments = [('template_ins', String())]

class OCCKeysResponse(OCCCommand):
    """The keys to complete the template, the signatures
    for all transactions *except* the Funding to give
    to the client.
    """
    arguments = [('our_keys', String()),
                 ('our_sigs', String())]

class OCCSigsResponse(OCCCommand):
    """Return the funding transaction signatures.
    """
    arguments = [('funding_sigs', String())]
