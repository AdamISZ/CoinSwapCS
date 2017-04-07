from __future__ import print_function
import jmbitcoin as btc
from jmclient import (load_program_config, jm_single, Wallet,
                      get_p2pk_vbyte, get_p2sh_vbyte, estimate_tx_fee,
                      sync_wallet, RegtestBitcoinCoreInterface,
                      BitcoinCoreInterface, get_log)
from twisted.internet import reactor, task
from txjsonrpc.web.jsonrpc import Proxy
from txjsonrpc.web import jsonrpc
from twisted.web import server
from .btscript import *
import pytest
from decimal import Decimal
import binascii
import time
import os
import random
import abc
import sys
from pprint import pformat
import json
#from .alice import CoinSwapAlice
#from .carol import CoinSwapCarol

COINSWAP_SECRET_ENTROPY_BYTES = 14

jlog = get_log()

def _byteify(data, ignore_dicts = False):
    # if this is a unicode string, return its string representation
    if isinstance(data, unicode):
        return data.encode('utf-8')
    # if this is a list of values, return list of byteified values
    if isinstance(data, list):
        return [ _byteify(item, ignore_dicts=True) for item in data ]
    # if this is a dictionary, return dictionary of byteified keys and values
    # but only if we haven't already byteified it
    if isinstance(data, dict) and not ignore_dicts:
        return {
            _byteify(key, ignore_dicts=True): _byteify(value, ignore_dicts=True)
            for key, value in data.iteritems()
        }
    # if it's anything else, return it in its original form
    return data

def get_current_blockheight():
    """returns current blockheight as integer.
    Assumes existence of valid Core blockchain interface instance.
    """
    blockchainInfo = jm_single().bc_interface.jsonRpc.call("getblockchaininfo", [])
    return blockchainInfo["blocks"]

def int_to_tx_ser(x):
    """Given an integer, return the correct byte-serialization
    for pushing onto the stack.
    """
    h = btc.encode(x, 256)
    if ord(h[0]) >=128:
        h = "\x00" + h
    h = h[::-1]
    return h

def detect_spent(txid, n):
    """Uses bitcoin rpc 'listunspent' to find out
    if the utxo specified is still not spent. 
    Assumes use of blockchain_source that has an
    rpc method.
    Assumes that the utxo is associated with an address
    in the wallet (whether default account or watch-only).
    Returns True if not found (i.e. spent), False if found.
    Note that interpreting 'True' as 'spent' implicitly
    assumes that the utxo existed on the network.
    """
    #Using default listunspent arguments 1, 9999999, this means
    #the transaction *containing* the utxo/outpoint must be confirmed.
    unspent_list = jm_single().bc_interface.rpc('listunspent')
    filtered = [u for u in unspent_list if (u['txid'] == txid and u['vout'] == n)]
    return True if len(filtered) == 0 else False

def msig_data_from_pubkeys(pubkeys, N):
    """Create a p2sh address for the list of pubkeys given, N signers required.
    Return both the multisig redeem script and the p2sh address created.
    """
    #todo: lexicographical ordering is better
    multisig_script = btc.mk_multisig_script(pubkeys, N)
    p2sh_address = btc.p2sh_scriptaddr(multisig_script, magicbyte=get_p2sh_vbyte())
    return (multisig_script, p2sh_address)

def get_coinswap_secret(raw_secret=None):
    """Create a preimage of defined entropy and return
    the preimage and hash image, both as byte strings.
    Optionally pass in the raw secret, in hex form.
    """
    if not raw_secret:
        raw_secret = os.urandom(COINSWAP_SECRET_ENTROPY_BYTES)
    else:
        raw_secret = binascii.unhexlify(raw_secret)
        assert len(raw_secret) == COINSWAP_SECRET_ENTROPY_BYTES
    hashed_secret = btc.bin_hash160(raw_secret)
    return (binascii.hexlify(raw_secret), binascii.hexlify(hashed_secret))

def get_secret_from_vin(vins, hashed_secret):
    """Takes a vin array as returned by json rpc getrawtransaction 1,
    and extract the secret assuming at least one of the inputs was
    spending from the custom redeem script.
    """
    #extract scriptSig raw hex
    for vin in vins:
        scriptsig_serialized = vin["hex"]
        #a match will start with (signature, secret, ...) so match only pos 1
        ss_deserialized = btc.deserialize_script(scriptsig_serialized)
        if len(ss_deserialized) != 2*COINSWAP_SECRET_ENTROPY_BYTES:
            continue
        candidate_secret = get_coinswap_secret(raw_secret=ss_deserialized[1])
        if candidate_secret[1] == hashed_secret:
            jlog.info("Found secret on blockchain: ", candidate_secret)
            return candidate_secret[0]
        else:
            jlog.info("Candidate vin had entry of right length, but wrong secret.")
            jlog.info("Vin: ", vin)
    jlog.info("Found no secret in the spending transaction")
    return None
        
def create_hash_script(redeemer_pubkey, hashes):
    """Creates part of the redeem script that deals
        with the hashes
    """
    script = []
    for h in hashes:
        jlog.debug('including hash value: ' + binascii.hexlify(h))
        script += [OP_HASH160, h, OP_EQUALVERIFY]
    script += [redeemer_pubkey, OP_CHECKSIG]
    return script

def generate_escrow_redeem_script(hashed_secret, recipient_pubkey, locktime,
                            refund_pubkey):
    """Generate an output script and address that pays either to the
    recipient on revelation of the preimage of hashed_secret, or refunds
    to the refund key after locktime locktime.
    Returns: serialized_script
    """
    jlog.info("These parameters: " + str([hashed_secret, recipient_pubkey, locktime, refund_pubkey]))
    hashed_secret, recipient_pubkey, refund_pubkey = [binascii.unhexlify(
        x) for x in hashed_secret, recipient_pubkey, refund_pubkey]
    script = create_hash_script(recipient_pubkey, [hashed_secret])
    redeem_script = [OP_IF] + script + [OP_ELSE,
                                        int_to_tx_ser(locktime),
                                        OP_CHECKLOCKTIMEVERIFY, OP_DROP,
                                        refund_pubkey, OP_CHECKSIG,
                                        OP_ENDIF]
    rss = btc.serialize_script(redeem_script)
    return rss

class StateMachine(object):
    def __init__(self, num_states, callbacks=None):
        self.num_states = num_states
        self.callbacks = callbacks
        assert len(self.callbacks) == self.num_states
        self.state = 0

    def set_callbacks(self, callbacks):
        assert len(callbacks) == len(self.callbacks)
        for i in range(len(callbacks)):
            self.set_callback(i, callbacks[i])

    def set_callback(self, i, callback):
        self.callbacks[i] = callback

    def run(self):
        for _ in range(self.num_states):
            if not self.execute_callback():
                return (False, self.state) #trigger backout
    def execute_callback(self):
        retval = self.callbacks[self.state]
        if not self.callbacks[self.state]:
            return False
        #update to next state *only* on success.
        self.state += 1
        return True
        
class CoinSwapTX(object):
    """A generic bitcoin transaction construct,
    currently limited to one output scriptPubKey
    and one (optional) change.
    Note that the positions of the pay, change outputs
    are automatically randomized; but inputs are not, so
    any randomization there must be implemented by the caller.

    Base class provides full signing functionality; subclasses
    must override at least the attach_signatures function
    for creation of valid signed transaction. Subclasses
    only need to override sign_at_index in case there is more
    than one input signing pubkey.
    """
        
    def __init__(self,
                 utxo_ins,
                 output_address,
                 change_address=None,
                 output_amount=None,
                 change_amount=None,
                 signing_redeem_scripts=None,
                 signing_pubkeys=None,
                 signatures=None,
                 locktime=None):
        if utxo_ins == None:
            utxo_ins = []
        if signing_pubkeys == None:
            signing_pubkeys = [[]]*len(utxo_ins)
        if signing_redeem_scripts == None:
            signing_redeem_scripts = []
        if signatures == None:
            signatures = [[]]*len(utxo_ins)
        #Signing pubkeys and signatures are lists of lists;
        #caller must ensure correct ordering thereof.
        self.utxo_ins = utxo_ins
        self.output_address = output_address
        self.output_script = btc.address_to_script(self.output_address)
        self.output_amount = output_amount
        if change_address:
            self.change_address = change_address
            self.change_script = btc.address_to_script(self.change_address)
            self.change_amount = change_amount
        self.signing_redeem_scripts = signing_redeem_scripts
        self.signing_pubkeys = signing_pubkeys
        self.signatures = signatures
        self.locktime = locktime
        pay_out = {"address": self.output_address,
                      "value": self.output_amount}
        if change_address:
            change_out = {"address": self.change_address,
                              "value": self.change_amount}
            if random.random() < 0.5:
                self.outs = [pay_out, change_out]
                self.change_out_index = 1
                self.pay_out_index = 0
            else:
                self.outs = [change_out, pay_out]
                self.change_out_index = 0
                self.pay_out_index = 1
        else:
            self.outs = [pay_out]
            self.pay_out_index = 0
            self.change_address = None
            self.change_amount = None
            self.change_script = None
            self.change_out_index = None
        jlog.debug("Constructing tx with utxoins: " + str(self.utxo_ins))
        self.base_form = btc.mktx(self.utxo_ins, self.outs)
        if self.locktime:
            dtx = btc.deserialize(self.base_form)
            dtx["ins"][0]["sequence"] = 0
            dtx["locktime"] = locktime
            self.base_form = btc.serialize(dtx)
        #This data is set once the transaction is finalized.
        self.fully_signed_tx = None
        self.completed = [False]*len(self.utxo_ins)
        self.txid = None

    def signature_form(self, index):
        assert len(self.signing_redeem_scripts) >= index + 1
        jlog.info("running signature form for index: " + str(index))
        jlog.info("with this redeem script: " + str(self.signing_redeem_scripts[index]))
        return btc.signature_form(self.base_form, index,
                                  self.signing_redeem_scripts[index])
    
    def sign_at_index(self, privkey, in_index):
        """Default sign function signs for a single pubkey input.
        Can be overridden by subclasses.
        """
        assert btc.privkey_to_pubkey(privkey) == self.signing_pubkeys[in_index][0]
        sigform = self.signature_form(in_index)
        sig = btc.ecdsa_tx_sign(sigform, privkey)
        assert btc.verify_tx_input(self.base_form, in_index,
                                   self.signing_redeem_scripts[in_index], sig,
                                   self.signing_pubkeys[in_index][0])
        self.signatures[in_index] = [sig]
        self.completed[in_index] = True
    
    def signall(self, privkeys):
        """Convenience function, see note to sign_at_index.
        """
        for i in range(len(self.utxo_ins)):
            self.sign_at_index(privkeys[i], i)
    
    def fully_signed(self):
        if all([self.completed[x]==True for x in range(len(self.utxo_ins))]):
            return True
        else:
            return False
    
    def attach_signatures(self):
        """Default function is specific to p2pkh inputs.
        """
        assert self.fully_signed()
        dtx = btc.deserialize(self.base_form)
        for i in range(len(self.utxo_ins)):
            dtx["ins"][i]["script"] = btc.serialize_script([self.signatures[i][0],
                                       self.signing_pubkeys[i][0]])
        self.fully_signed_tx = btc.serialize(dtx)
    
    def set_txid(self):
        """Note that it's useful, and in the coinswap case necessary,
        to be able to get the txid before push; it only requires that the
        owner of the inputs signs all, then this can be called without
        broadcast.
        """
        assert self.fully_signed_tx
        self.txid = btc.txhash(self.fully_signed_tx)

    def push(self):
        assert self.fully_signed()
        self.attach_signatures()
        self.set_txid()
        if not jm_single().bc_interface.pushtx(self.fully_signed_tx):
            return ("Failed to push transaction, id: " + self.txid, False)
        else:
            return (self.txid, True)

    def __str__(self):
        """Convenience function for showing tx in current
        state in human readable form. This is not an object
        serialization (see serialize).
        """
        msg = []
        tx = self.base_form
        if not self.fully_signed_tx:
            msg.append("Not fully signed")
            msg.append("Signatures: " + str(self.signatures))
            if self.txid:
                msg.append("Txid: " + self.txid)
        else:
            msg.append("Fully signed.")
            msg.append("Txid: " + self.txid)
            tx = self.fully_signed_tx
        dtx = btc.deserialize(tx)
        return pformat(dtx) + "\n" + "\n".join(msg)

    def serialize(self):
        p = {}
        for v in ['utxo_ins', 'signing_pubkeys', 'signing_redeem_scripts',
                  'signatures', 'output_address', 'change_address',
                  'output_script', 'change_script', 'output_amount',
                  'change_amount', 'locktime', 'outs', 'pay_out_index',
                  'base_form', 'fully_signed_tx', 'completed', 'txid']:
            p[v] = getattr(self, v)
        return p

    def deserialize(self, d):
        try:
            for v in ['utxo_ins', 'signing_pubkeys', 'signing_redeem_scripts',
                  'signatures', 'output_address', 'change_address',
                  'output_script', 'change_script', 'output_amount',
                  'change_amount', 'locktime', 'outs', 'pay_out_index',
                  'base_form', 'fully_signed_tx', 'completed', 'txid']:
                setattr(self, v, d[v])
            return True
        except:
            jlog.info("Failed to deserialize Coinswap TX object")
            return False

class CoinSwapTX01(CoinSwapTX):
    """The starting transaction in the Coinswap flow.
    Pays from user coins into 2of2 multisig, single output
    (change may be added as a later TODO).
    Note that if inputs are p2pkh (TODO: p2sh),
    the base class signing functions can be used to make
    the payment.
    """
    def __init__(self):
        pass

    @classmethod
    def from_dict(cls, d):
        obj = cls()
        obj.deserialize(d)
        return obj

    @classmethod
    def from_params(cls,
                 pubkey1,
                 pubkey2,
                 utxo_ins=None,
                 output_address=None,
                 output_amount=None,
                 change_address=None,
                 change_amount=None,
                 signing_pubkeys=None,
                 signing_redeem_scripts=None,
                 signatures=None):
        obj = cls()
        #Non-optional arguments are used to construct the 2of2 address:
        scr, addr = msig_data_from_pubkeys([pubkey1, pubkey2], 2)
        super(CoinSwapTX01, obj).__init__(utxo_ins=utxo_ins,
                                           output_address=addr,
                                           output_amount=output_amount,
                                           change_address=change_address,
                                           change_amount=change_amount,
                                           signing_redeem_scripts=signing_redeem_scripts,
                                           signing_pubkeys=signing_pubkeys,
                                           signatures=signatures)
        return obj

class CoinSwapSpend2_2(CoinSwapTX):
    """Generic class for any transaction that spends
    only from a single input scriptPubkey which is a 2 of 2
    multisig.
    """
    def sign_at_index(self, privkey, key_index):
        assert btc.privkey_to_pubkey(privkey) == self.signing_pubkeys[0][key_index]
        if len(self.signatures[0]) == 0:
            self.signatures[0] = [None, None]
        sigform = self.signature_form(0)
        sig = btc.ecdsa_tx_sign(sigform, privkey)
        assert btc.verify_tx_input(self.base_form, 0,
                                   self.signing_redeem_scripts[0], sig,
                                   self.signing_pubkeys[0][key_index])
        self.signatures[0][key_index] = sig
        if all([self.signatures[0][x] for x in [0,1]]):
            self.completed[0] = True

    def include_signature(self, key_index, sig):
        """If we possess 1 of the 2 needed signatures, validate
        it for the transaction; if valid, mark that index as completed,
        and return True. If invalid, return False.
        """
        if len(self.signatures[0]) == 0:
            self.signatures[0] = [None, None]
        sigform = self.signature_form(0)
        if not btc.verify_tx_input(self.base_form, 0,
                                   self.signing_redeem_scripts[0], sig,
                                   self.signing_pubkeys[0][key_index]):
            jlog.info("Error in include_signature: signature invalid: " + sig)
            return False
        else:
            self.signatures[0][key_index] = sig
            if all([self.signatures[0][x] for x in [0,1]]):
                self.completed[0] = True
            return True

    def attach_signatures(self):
        """A single 2 of 2 input
        """
        assert self.fully_signed()
        self.fully_signed_tx = btc.apply_multisignatures(self.base_form, 0,
                                  self.signing_redeem_scripts[0],
                                  self.signatures[0])

class CoinSwapTX45(CoinSwapSpend2_2):
    """Pays out from TX01 to a single specified output address.
    """
    def __init__(self):
            pass
    
    @classmethod
    def from_dict(cls, d):
        obj = cls()
        obj.deserialize(d)
        return obj

    @classmethod
    def from_params(cls,
                 pubkey1,
                 pubkey2,
                 utxo_in,
                 destination_address,
                 destination_amount):
        obj = cls()
        scr, addr = msig_data_from_pubkeys([pubkey1, pubkey2], 2)
        signatures = [[]]
        #The redeem script for the single input is that for the 2 of 2 case
        signing_redeem_scripts = [scr]
        super(CoinSwapTX45, obj).__init__(utxo_ins=[utxo_in],
                                           output_address=destination_address,
                                           output_amount=destination_amount,
                                           signing_pubkeys=[[pubkey1, pubkey2]],
                                    signing_redeem_scripts=signing_redeem_scripts)
        return obj

class CoinSwapTX23(CoinSwapSpend2_2):
    """Pays from 2of2 utxo (already broadcast), to
    a custom script: pay to (counterparty+secret reveal) or (me after timeout).
    """
    def __init__(self):
        pass

    @classmethod
    def from_dict(cls, d):
        obj = cls()
        obj.deserialize(d)
        return obj

    @classmethod
    def from_params(cls,
                 pubkey1,
                 pubkey2,
                 recipient_pubkey,
                 utxo_in,
                 recipient_amount,
                 hashed_secret,
                 absolutelocktime,
                 refund_pubkey):
        obj = cls()
        #Non-optional arguments are used to construct the 2of2 address:
        scr, addr = msig_data_from_pubkeys([pubkey1, pubkey2], 2)
        signatures = [[]]
        #The redeem script for the single input is that for the 2 of 2 case
        signing_redeem_scripts = [scr]
        #The destination address is created from the custom redeem script.
        obj.custom_redeem_script = generate_escrow_redeem_script(hashed_secret,
                                                  recipient_pubkey,
                                                  absolutelocktime,
                                                  refund_pubkey)
        output_address = btc.p2sh_scriptaddr(obj.custom_redeem_script,
                                             magicbyte=get_p2sh_vbyte())
        
        #Note that the locktime is *not* passed to the super constructor,
        #as it's the locktime applied to the output (with CLTV),
        #not this transaction.
        super(CoinSwapTX23, obj).__init__(utxo_ins=[utxo_in],
                                           output_address=output_address,
                                           output_amount=recipient_amount,
                                           signing_pubkeys=[[pubkey1, pubkey2]],
                                           signing_redeem_scripts=signing_redeem_scripts,
                                           signatures=signatures)
        return obj

class CoinSwapRedeemTX23Secret(CoinSwapTX):
    def __init__(self,
                 secret,
                 recipient_pubkey,
                 absolutelocktime,
                 refund_pubkey,
                 utxo_in,
                 recipient_amount,
                 destination_address):
        #Redeems have specific fee-handling (high prio usually)
        fee = estimate_tx_fee((1, 2, 2), 1, txtype='p2shMofN')
        self.secret = secret
        dummy, hashed_secret = get_coinswap_secret(raw_secret=self.secret)
        signing_redeem_scripts = [binascii.hexlify(generate_escrow_redeem_script(
            hashed_secret, recipient_pubkey, absolutelocktime, refund_pubkey))]

        super(CoinSwapRedeemTX23Secret, self).__init__(utxo_ins=[utxo_in],
                                           output_address=destination_address,
                                           output_amount=recipient_amount-fee,
                                           signing_pubkeys=[[recipient_pubkey]],
                                    signing_redeem_scripts=signing_redeem_scripts)

    def attach_signatures(self):
        """Redeeming the custom script via the secret
        """
        assert self.fully_signed()
        script_to_serialize = [binascii.unhexlify(self.signatures[0][0])]
        script_to_serialize += [binascii.unhexlify(self.secret)]
        script_to_serialize += [OP_TRUE,
                                binascii.unhexlify(self.signing_redeem_scripts[0])]
        rfs = btc.serialize_script(script_to_serialize)
        #Manually insert the customized refunding script
        txobj = btc.deserialize(self.base_form)
        txobj["ins"][0]["script"] = binascii.hexlify(rfs)
        signed_tx = btc.serialize(txobj)
        assert btc.verify_tx_input(signed_tx, 0,
                                   self.signing_redeem_scripts[0],
                                   self.signatures[0][0],
                                   self.signing_pubkeys[0][0])
        self.fully_signed_tx = signed_tx

class CoinSwapRedeemTX23Timeout(CoinSwapTX):
    """Redeems TX2 or TX3 via OP_CLTV timeout.
    This class does not require a from_dict constructor
    since it is only ever created on the fly in a backout execution.
    """
    def __init__(self,
                 recipient_pubkey,
                 hashed_secret,
                 absolutelocktime,
                 refund_pubkey,
                 utxo_in,
                 recipient_amount,
                 destination_address):
        #Redeems have specific fee-handling (high prio usually)
        fee = estimate_tx_fee((1, 2, 2), 1, txtype='p2shMofN')        
        signing_redeem_scripts = [binascii.hexlify(generate_escrow_redeem_script(
            hashed_secret, recipient_pubkey, absolutelocktime, refund_pubkey))]

        super(CoinSwapRedeemTX23Timeout, self).__init__(utxo_ins=[utxo_in],
                                           output_address=destination_address,
                                           output_amount=recipient_amount- fee,
                                           signing_pubkeys=[[refund_pubkey]],
                                           locktime=absolutelocktime,
                                    signing_redeem_scripts=signing_redeem_scripts)

    def attach_signatures(self):
        """Redeeming the custom script via the timeout
        """
        assert self.fully_signed()
        script_to_serialize = [binascii.unhexlify(self.signatures[0][0])]
        script_to_serialize += [None, self.signing_redeem_scripts[0]]
        rfs = btc.serialize_script(script_to_serialize)
        #Manually insert the customized refunding script
        txobj = btc.deserialize(self.base_form)
        txobj["ins"][0]["script"] = binascii.hexlify(rfs)
        #locktime and sequence already set by constructor.
        signed_tx = btc.serialize(txobj)
        assert btc.verify_tx_input(signed_tx, 0, self.signing_redeem_scripts[0],
                                         self.signatures[0][0],
                                         self.signing_pubkeys[0][0])
        self.fully_signed_tx = signed_tx

class CoinSwapParticipant(object):
    __metaclass__ = abc.ABCMeta

    def __init__(self, wallet, state_file, cpp=None):
        self.coinswap_parameters = cpp
        assert isinstance(self.coinswap_parameters, CoinSwapPublicParameters)
        self.generate_keys()
        assert isinstance(wallet, Wallet)
        self.state_file = state_file
        self.wallet = wallet
        self.state = -1
        self.tx0 = None
        self.tx1 = None
        self.tx2 = None
        self.tx3 = None
        self.tx4 = None
        self.tx5 = None
        self.secret = None
        self.hashed_secret = None
        #currently only used by Carol; TODO
        self.phase2_ready = False
        self.tx5_confirmed = False
        self.successful_tx3_redeem = False

    def generate_privkey(self):
        #always hex, with compressed flag
        return binascii.hexlify(os.urandom(32))+"01"

    def update(self, state):
        assert self.state == state - 1
        self.state = state
        if self.state > 0:
            self.persist()
            #for testing only
            self.load()

    def load(self):
        with open(self.state_file, "rb") as f:
            loaded_state = json.loads(f.read(), object_hook=_byteify)
        self.coinswap_parameters = CoinSwapPublicParameters()
        self.coinswap_parameters.deserialize(loaded_state['public_parameters'])
        self.state = loaded_state['current_state']
        self.keyset = loaded_state['keyset']
        self.secret = loaded_state['coinswap_secret_data']['preimage']
        self.hashed_secret = loaded_state['coinswap_secret_data']['hash']
        for n, t in zip(("TX0", "TX1", "TX2", "TX3", "TX4", "TX5"),
                        (CoinSwapTX01, CoinSwapTX01, CoinSwapTX23,
                         CoinSwapTX23, CoinSwapTX45, CoinSwapTX45)):
            if n in loaded_state:
                var = getattr(self, n.lower())
                var = t.from_dict(loaded_state[n])

    def persist(self):
        """In principle the following dataset is sufficient to recover to
        the current state: private keyset, public coinswap parameters,
        coinswap secret and or hash,
        and current state machine state (self.state).
        Additional information is realistically required however:
        transaction data for any transactions that are already broadcast.
        """
        persisted_state = {}
        persisted_state['public_parameters'] = self.coinswap_parameters.serialize()
        persisted_state['current_state'] = self.state
        persisted_state['keyset'] = self.keyset
        persisted_state['coinswap_secret_data'] = {'hash': self.hashed_secret,
                                                   'preimage': self.secret}
        for k, tx in {"TX0": self.tx0,
                      "TX1": self.tx1,
                      "TX2": self.tx2,
                      "TX3": self.tx3,
                      "TX4": self.tx4,
                      "TX5": self.tx5}.iteritems():
            if not tx:
                continue
            persisted_state[k] = tx.serialize()
        with open(self.state_file, "wb") as f:
            f.write(json.dumps(persisted_state, indent=4))
 
    def backout(self, msg):
        from .alice import CoinSwapAlice
        from .carol import CoinSwapCarol
        """Uses current state to decide backing out action.
        Note that program exits when actions are complete,
        thus this method tacitly assumes that only one of
        (Alice, Carol) is running in this executable. This
        point is relevant for testing only currently.
        """
        jlog.info('BACKOUT: ' + msg)
        jlog.info("Current state: " + str(self.state))
        jlog.info("I am: " + str(type(self)))
        if self.state == 0:
            #Failure in negotiation; nothing to do
            jlog.info("Failure in parameter negotiation; no action required; "
                     "ending.")
            reactor.stop()
        if (self.state in [-1, 0, 1, 2, 3]) or \
           (isinstance(self, CoinSwapCarol) and self.state == 4):
            #Alice/Carol created TX0/1 but didn't broadcast; no action required.
            #Alice/Carol may have sent signatures on spend-out transactions
            #but this is irrelevant as long as TX0/1 is not on the network.
            jlog.info("No funds have moved; no action required; ending.")
            reactor.stop()
        #Handling for later states depends on Alice/Carol
        if isinstance(self, CoinSwapAlice):
            if self.state == 4:
                #Alice has broadcast TX0 but has not released the secret;
                #therefore it's entirely safe to just wait for L0 and then
                #redeem on the lock branch.
                bh = get_current_blockheight()
                if bh < self.coinswap_parameters.timeouts["LOCK0"] + 1:
                    jlog.info("Not ready to redeem the funds, "
                             "waiting for block: " + str(
                                 self.coinswap_parameters.timeouts["LOCK0"]))
                    reactor.callLater(3.0, self.backout)
                msg, success = self.tx2.push()
                if not success:
                    jlog.info("RPC error message: ", msg)
                    jlog.info("Failed to broadcast TX2; here is raw form: ")
                    jlog.info(self.tx2.fully_signed_tx)
                    reactor.stop()
                tx23_redeem = CoinSwapRedeemTX23Timeout(
                    self.coinswap_parameters.pubkeys["key_TX2_secret"],
                    self.hashed_secret,
                    self.coinswap_parameters["timeouts"]["LOCK0"],
                    self.coinswap_parameters.pubkeys["key_TX2_lock"],
                    self.tx2.txid + ":0",
                    self.coinswap_parameters.tx4_amount,
                    self.coinswap_parameters.tx4_address)
                tx23_redeem.sign_at_index(self.keyset["key_TX2_lock"][0], 0)
                msg, success = tx23_redeem.push()
                if not success:
                    jlog.info("RPC error message: ", msg)
                    jlog.info("Failed to broadcast TX2 redeem; here is raw form: ")
                    jlog.info(tx23_redeem.fully_signed_tx)
                reactor.stop()
            elif self.state == 5:
                #Carol has received the secret. Immediately (before L1),
                #redeem TX3 using the secret.
                msg, success = self.tx3.push()
                if not success:
                    jlog.info("RPC error message: ", msg)
                    jlog.info("Failed to broadcast TX3; here is raw form: ")
                    jlog.info(self.tx3.fully_signed_tx)
                    reactor.stop()
                tx23_secret = CoinSwapRedeemTX23Secret(self.secret,
                            self.coinswap_parameters.pubkeys["key_TX3_secret"],
                            self.coinswap_parameters.timeouts["LOCK1"],
                            self.coinswap_parameters.pubkeys["key_TX3_lock"],
                            self.tx3.txid + ":0",
                            self.coinswap_parameters.tx3_recipient_amount,
                            self.coinswap_parameters.tx5_address)
                tx23_secret.sign_at_index(self.keyset["key_TX3_secret"][0], 0)
                msg, success = tx23_secret.push()
                if not success:
                    jlog.info("RPC error message: ", msg)
                    jlog.info("Failed to broadcast TX3 redeem; here is raw form: ")
                    jlog.info(tx23_secret.fully_signed_tx)
                else:
                    jlog.info("Redemption pushed successfully, txid: " + tx23_secret.txid)
                    jlog.info("Here it is: " + str(tx23_secret))
                reactor.stop()
            elif self.state in [6, 7]:
                #We are now in possession of a valid TX4 signature; either we
                #already broadcast it, or we do so now.
                if self.tx4.txid:
                    jlog.info("TX4 was already broadcast: " + self.tx4.txid)
                    jlog.info("Here is the raw form for re-broadcast: ")
                    jlog.info(self.tx4.fully_signed_tx)
                else:
                    self.tx4.sign_at_index(self.keyset["key_2_2_CB_1"][0], 1)
                    errmsg, success = self.tx4.push()
                    if not success:
                        self.backout("Failed to push TX4, errmsg: " + errmsg)
                reactor.stop()
            else:
                assert False
        elif isinstance(self, CoinSwapCarol):
            if self.state in [5, 6, 7]:
                #This is by far the trickiest case.
                #
                #We have valid signatures on TX3, we can broadcast and redeem it
                #via locktime after LOCK1.
                #However, since Alice knows the secret, she could double spend
                #the created outpoint (whose script pubkey is (Bob, Hash or Carol,
                #Lock)) using the secret. If she does so, we can instead redeem
                #TX2 using the same secret. This has to be done before the timeout
                #LOCK 0. Approach:
                #1. broadcast the lock1 TX3; wait for confirms.
                #2. broadcast a spend-out using the LOCK1 branch.
                #3. Wait for confirms. If seen, OK.
                #4. If outpoint is seen spent, but not with our expected hash:
                #5. Retrieve X from the scriptSig of the unexpected tx hash.
                #5. Sign and broadcast the TX2. wait for confirms.
                #6. Broadcast a spend-out using the secret branch for TX2.
                #Note, all this has to happen a reasonable safety buffer before
                #LOCK0.
                bh = get_current_blockheight()
                if bh < self.coinswap_parameters.timeouts["LOCK1"] + 1:
                    jlog.info("Not ready to redeem the funds, "
                             "waiting for block: " + str(
                                 self.coinswap_parameters.timeouts["LOCK1"]))
                    reactor.callLater(3.0, self.backout)
                if bh > self.coinswap_parameters.timeouts["LOCK0"]:
                    jlog.info("CRITICAL WARNING: Too late, counterparty may "
                             "be able to double spend our redemption; attempting "
                             "to claim funds anyway. Continuing...")
                #Broadcast TX3
                msg, success = self.tx3.push()
                if not success:
                    jlog.info("RPC error message: ", msg)
                    jlog.info("Failed to broadcast TX2; here is raw form: ")
                    jlog.info(self.tx3.fully_signed_tx)
                    reactor.stop()
                #**CONSTRUCT TX3-redeem-timeout
                tx23_redeem = CoinSwapRedeemTX23Timeout(
                    self.coinswap_parameters.pubkeys["key_TX3_secret"],
                    self.hashed_secret,
                    self.coinswap_parameters["timeouts"]["LOCK1"],
                    self.coinswap_parameters.pubkeys["key_TX3_lock"],
                    self.tx3.txid + ":0",
                    self.coinswap_parameters.tx5_amount,
                    self.coinswap_parameters.tx5_address)
                tx23_redeem.sign_at_index(self.keyset["key_TX3_lock"][0], 0)
                msg, success = tx23_redeem.push()
                if not success:
                    jlog.info("RPC error message: ", msg)
                    jlog.info("Failed to broadcast TX3 redeem; here is raw form: ")
                    jlog.info(tx23_redeem.fully_signed_tx)
                reactor.stop()
                #Now fire a waiting loop that triggers on one of 2 events: (1)
                #confirmation of above tx or (2) consumption of tx2 outpoint
                #without (1) occurring, and take action.
                self.carol_watcher_loop = task.LoopingCall(
                    self.watch_for_tx3_spends, self.tx3.txid)
                self.carol_watcher_loop.start(3.0)
                #Monitor for when the watching loop ends
                self.carol_waiting_loop = task.LoopingCall(
                    self.react_to_tx3_spend)
                self.carol_waiting_loop.start(3.0)
            elif self.state == 8:
                #We are now in possession of a valid TX5 signature; either we
                #already broadcast it, or we do so now.
                if self.tx5.txid:
                    jlog.info("TX5 was already broadcast: " + self.tx5.txid)
                    jlog.info("Here is the raw form for re-broadcast: ")
                    jlog.info(self.tx5.fully_signed_tx)
                else:
                    self.tx5.sign_at_index(self.keyset["key_2_2_AC_1"][0], 1)
                    errmsg, success = self.tx5.push()
                    if not success:
                        self.backout("Failed to push TX5, errmsg: " + errmsg)
                reactor.stop()
            else:
                assert False

    def check_for_phase1_utxos(self, utxos, callback, confs=1):
        """Any participant needs to wait for completion of phase 1 through
        seeing the utxos on the network. Pass callback for start of phase2
        (redemption phase), must have signature callback(utxolist).
        This should be fired by task looptask, which is stopped on success.
        """
        print('Type: ', type(self), " checking for utxos: ", utxos)
        result = jm_single().bc_interface.query_utxo_set(utxos,
                                                         includeconf=True)
        print('got this result:')
        print(result)
        if None in result:
            return
        for u in result:
            if u['confirms'] < confs:
                return
        callback(utxos)

    def generate_keys(self):
        """These are ephemeral keys required for redeeming various transactions.
        (Ephemeral in the sense that they must *not* be used for different runs,
        but must of course be persisted for the run).
        """
        self.keyset_keys = [self.generate_privkey() for _ in range(4)]
        self.keyset = {}
        for i, name in enumerate(self.required_key_names):
            self.keyset[name] = (self.keyset_keys[i],
                                 btc.privkey_to_pubkey(self.keyset_keys[i]))
        #keys will be stored on first persist, after parameters negotiated.

    def final_report(self):
        report_msg = ["Coinswap completed OK."]
        report_msg.append("**************")
        report_msg.append("Pay in transaction from Alice to 2-of-2:")
        report_msg.append("Txid: " + self.tx0.txid)
        report_msg.append("Amount: " + str(self.coinswap_parameters.tx0_amount))
        report_msg.append("Pay in transaction from Carol to 2-of-2:")
        report_msg.append("Txid: " + self.txid1)
        report_msg.append("Amount: " + str(self.coinswap_parameters.tx1_amount))
        report_msg.append("Pay out transaction from 2-of-2 to Alice:")
        report_msg.append("Txid: " + self.tx4.txid)
        report_msg.append("Receiving address: " + self.coinswap_parameters.tx4_address)
        report_msg.append("Amount: " + str(self.coinswap_parameters.tx4_amount))
        report_msg.append("Pay out transaction from 2-of-2 to Carol:")
        report_msg.append("Txid: " + self.txid5)
        report_msg.append("Receiving address: " + self.coinswap_parameters.tx5_address)
        report_msg.append("Amount: " + str(self.coinswap_parameters.tx5_amount))
        
        jlog.info("\n" + "\n".join(report_msg))

    @abc.abstractmethod
    def negotiate_coinswap_parameters(self):
        pass

class CoinSwapException(Exception):
    pass

class CoinSwapPublicParameters(object):
    required_key_names = ["key_2_2_AC_0", "key_2_2_AC_1", "key_2_2_CB_0",
                          "key_2_2_CB_1", "key_TX2_secret", "key_TX2_lock",
                          "key_TX3_secret", "key_TX3_lock"]
    def __init__(self,
                 tx01_amount=None,
                 tx24_recipient_amount=None,
                 tx35_recipient_amount=None,
                 timeoutdata=None,
                 addressdata=None,
                 pubkeydata=None):
        self.timeouts_complete = False
        self.pubkeys_complete = False
        self.addresses_complete = False
        self.tx4_address = None
        self.tx5_address = None
        self.timeouts = {}
        self.pubkeys = {}
        self.tx0_amount = tx01_amount
        self.tx1_amount = tx01_amount
        self.tx2_recipient_amount = tx24_recipient_amount
        self.tx3_recipient_amount = tx35_recipient_amount
        self.tx4_amount = tx24_recipient_amount
        self.tx5_amount = tx35_recipient_amount
        if timeoutdata:
            self.set_timeouts(*timeoutdata)
        if addressdata:
            self.set_addr_data(*addressdata)
        if pubkeydata:
            self.set_pubkey_data(pubkeydata)

    def serialize(self):
        """All data into a dict (for json persistence).
        Note that before this is complete, state machine
        processing does not start, so it doesn't need to be
        made available in that case.
        """
        assert self.is_complete()
        p = {}
        for v in ['tx0_amount', 'tx1_amount', 'tx2_recipient_amount',
                  'tx3_recipient_amount', 'tx4_amount', 'tx5_amount',
                  'tx4_address', 'tx5_address', 'timeouts', 'pubkeys']:
            p[v] = getattr(self, v)
        return p
    
    def deserialize(self, d):
        try:
            for v in ['tx0_amount', 'tx1_amount', 'tx2_recipient_amount',
                  'tx3_recipient_amount', 'tx4_amount', 'tx5_amount',
                  'tx4_address', 'tx5_address', 'timeouts', 'pubkeys']:
                setattr(self, v, d[v])
                self.addresses_complete = True
                self.pubkeys_complete = True
                self.timeouts_complete = True
            return True
        except:
            jlog.info("Failed to deserialize coinswap public parameters")
            return False
        
    def set_pubkey(self, key, pubkey):
        assert key in self.required_key_names
        self.pubkeys[key] = pubkey
        if set(self.pubkeys.keys()) == set(self.required_key_names):
            self.pubkeys_complete = True

    def set_tx4_address(self, addr):
        self.tx4_address = addr
        if self.tx5_address: self.addresses_complete = True

    def set_tx5_address(self, addr):
        self.tx5_address = addr
        if self.tx4_address: self.addresses_complete = True

    def set_addr_data(self, addr4, addr5):
        self.set_tx4_address(addr4)
        self.set_tx5_address(addr5)
        self.addresses_complete = True

    def set_pubkey_data(self, pubkeydata):
        for k, v in pubkeydata:
            self.set_pubkey(k, v)

    def is_complete(self):
        return self.pubkeys_complete and self.addresses_complete and self.timeouts_complete

    def set_timeout(self, key, blockheight):
        assert tx in ["LOCK0", "LOCK1"]
        self.timeouts[key] = blockheight
        if set(self.timeouts.keys()) == set(["LOCK0", "LOCK1"]):
            assert self.timeouts["LOCK0"] > self.timeouts["LOCK1"]

    def set_timeouts(self, blockheight1, blockheight2):
        assert blockheight1 > blockheight2
        self.timeouts["LOCK0"] = blockheight1
        self.timeouts["LOCK1"] = blockheight2
        self.timeouts_complete = True
