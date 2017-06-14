from __future__ import print_function
import jmbitcoin as btc
from jmclient import (Wallet, get_p2pk_vbyte, get_p2sh_vbyte, estimate_tx_fee)
from twisted.internet import reactor, task
from txjsonrpc.web.jsonrpc import Proxy
from txjsonrpc.web import jsonrpc
from twisted.web import server
from .btscript import *
from .configure import get_log, cs_single
from decimal import Decimal
import binascii
import time
import os
import random
import abc
import sys
from pprint import pformat
import json
from functools import wraps

COINSWAP_SECRET_ENTROPY_BYTES = 14

cslog = get_log()

def prepare_ecdsa_msg(nonce, method, *args):
    return nonce + json.dumps([method] + list(args))

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
    blockchainInfo = cs_single().bc_interface.jsonRpc.call("getblockchaininfo", [])
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

def read_length(x):
    bx = binascii.unhexlify(x)
    val = ord(bx[0])
    if val < 253:
        n = 1
    elif val == 253:
        val = btc.decode(bx[1:3][::-1], 256)
        n = 3
    elif val == 254:
        val = btc.decode(bx[1:5][::-1], 256)
        n = 5
    elif val == 255:
        val = btc.decode(bx[1:9][::-1], 256)
        n = 9
    else:
        assert False
    return (val, n)

def get_transactions_from_block(blockheight):
    block = cs_single().bc_interface.get_block(blockheight)
    txdata = block[160:]
    ntx, nbytes = read_length(txdata)
    txdata = txdata[nbytes*2:]
    found_txs = []
    for i in range(ntx):
        tx = btc.deserialize(txdata)
        if i != 0:
            found_txs.append(tx)
        len_tx = len(btc.serialize(tx))
        txdata = txdata[len_tx:]
    return found_txs

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
    the preimage and hash image, both as hex strings.
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
    """Takes a vin array as returned by jmbitcoin serialization,
    and extract the secret if at least one of the inputs was
    spending from the custom redeem script; otherwise return None
    """
    #extract scriptSig raw hex
    for vin in vins:
        scriptsig_serialized = vin["script"]
        #a match will start with (signature, secret, ...) so match only pos 1
        ss_deserialized = btc.deserialize_script(scriptsig_serialized)
        if len(ss_deserialized[1]) != 2*COINSWAP_SECRET_ENTROPY_BYTES:
            continue
        candidate_secret = get_coinswap_secret(raw_secret=ss_deserialized[1])
        if candidate_secret[1] == hashed_secret:
            cslog.info("Found secret in counterparty tx: " + candidate_secret[0])
            return candidate_secret[0]
        else:
            cslog.info("Candidate vin had entry of right length, but wrong secret.")
            cslog.info("Vin: ", vin)
    cslog.info("Found no secret in the spending transaction")
    return None
        
def create_hash_script(redeemer_pubkey, hashes):
    """Creates part of the redeem script that deals
        with the hashes
    """
    script = []
    for h in hashes:
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

class FeePolicy(object):
    """An object to encapsulate the fee policy of a server; it needs
    to serve two functions: (1) to express to a querier what the policy is
    with some serialization, (2) to be able to calculate the actual fee for
    a specific client request.
    """
    def __init__(self, cfg):
        #The cfg argument is of the type constructed in configure.py
        self.cfg = cfg
        self.minimum_fee = cfg.getint("SERVER", "minimum_coinswap_fee")
        #This can throw if invalid input, allowing that for now TODO
        self.percent = float(cfg.get("SERVER", "coinswap_fee_percent"))

    def get_policy(self):
        return {"minimum_fee": self.minimum_fee, "percent_fee": self.percent}

    def get_fee(self, amount):
        """Given a coinswap amount in satoshis, return
        the fee that we require corresponding to it (also in satoshis).
        """
        proposed_fee = amount * self.percent / 100.0
        if proposed_fee < self.minimum_fee:
            cslog.info("Calculated percentage fee less than minimum allowed, "
                       "bringing up to minimum: " + str(self.minimum_fee))
            return self.minimum_fee
        #Don't care about rounding errors here
        return int(proposed_fee)

class StateMachine(object):
    """A simple state machine that has integer states,
    incremented on successful execution of corresponding callbacks.
    """
    def __init__(self, init_state, backout, callbackdata):
        self.num_states = len(callbackdata)
        self.init_state = init_state
        self.state = init_state
        #this is set to True to indicate that further processing
        #is not allowed (when backing out)
        self.freeze = False
        self.default_timeout = float(cs_single().config.get("TIMEOUT",
                                                    "default_network_timeout"))
        #by default no pre- or post- processing
        self.setup = None
        self.finalize = None
        self.backout_callback = backout
        self.callbacks = []
        self.auto_continue = []
        self.timeouts = []
        for i,cbd in enumerate(callbackdata):
            self.callbacks.append(cbd[0])
            if cbd[1]:
                self.auto_continue.append(i)
            if cbd[2] > 0:
                self.timeouts.append(cbd[2])
            else:
                self.timeouts.append(self.default_timeout)

    def stallMonitor(self, state):
        """Wakes up a set timeout after state transition callback
        was called; if state has not been incremented, we backout.
        """
        if state < self.state or self.state == len(self.callbacks):
            return
        if not self.freeze:
            self.backout_callback('state transition timed out; backing out')
        self.freeze = True

    def tick_return(self, *args):
        """Must pass the callback name as the first argument;
        returns the return value from the first non-auto-continue
        callback.
        """
        if self.freeze:
            cslog.info("State machine is shut down, no longer receiving updates")
            return True
        cslog.info("starting server tick function, state is: " + str(self.state))
        if self.state == len(self.callbacks):
            cslog.info("State machine has completed.")
            return True
        requested_callback = args[0]
        args = args[1:]
        if requested_callback != self.callbacks[self.state].__name__:
            cslog.info('invalid callback name: ' + str(requested_callback))
            return False
        if self.setup:
            self.setup()
        if not args:
            retval, msg = self.execute_callback()
        else:
            retval, msg = self.execute_callback(*args)
        if not retval:
            cslog.info("Execution failed at step after: " + str(self.state) + \
                  ", backing out.")
            #state machine must lock and prevent update from counterparty
            #at point of backout.
            self.freeze = True
            reactor.callLater(0, self.backout_callback, msg)
            return (False, msg)
        if self.finalize:
            if self.state > 2:
                self.finalize()
        cslog.info("State: " + str(self.state -1) + " finished OK.")
        #create a monitor call that's woken up after timeout; if we didn't
        #update, something is wrong, so backout
        if self.state < len(self.callbacks):
            reactor.callLater(self.timeouts[self.state],
                              self.stallMonitor, self.state)
        if self.state in self.auto_continue:
            return self.tick_return(self.callbacks[self.state].__name__)

        return (retval, msg)

    def tick(self, *args):
        """Executes processing for each state with order enforced.
        Runs pre- and post-processing step if provided.
        Optionally provide arguments - for callbacks receiving data from
        counterparty, these are provided, otherwise not.
        Calls backout_callback on failure, to allow
        the caller to execute backout conditional on state.
        """
        if self.freeze:
            cslog.info("State machine is shut down, no longer receiving updates")
            return
        if self.state == len(self.callbacks):
            cslog.info("State machine has completed.")
            return
        cslog.info("starting client tick function, state is: " + str(self.state))
        if self.setup:
            self.setup()
        if not args:
            retval, msg = self.execute_callback()
        else:
            retval, msg = self.execute_callback(*args)
        if not retval:
            cslog.info("Execution failed at step after: " + str(self.state) + \
                  ", backing out.")
            cslog.info("Error message: " + msg)
            #state machine must lock and prevent update from counterparty
            #at point of backout.
            self.freeze = True
            reactor.callLater(0, self.backout_callback, msg)
            return False
        if self.finalize:
            if self.state > 2:
                self.finalize()
        cslog.info("State: " + str(self.state -1) + " finished OK.")
        #create a monitor call that's woken up after timeout; if we didn't
        #update, something is wrong, so backout
        if self.state < len(self.callbacks):
            reactor.callLater(self.timeouts[self.state],
                              self.stallMonitor, self.state)
        if self.state in self.auto_continue:
            self.tick()

    def execute_callback(self, *args):
        try:
            if args:
                retval, msg = self.callbacks[self.state](*args)
            else:
                retval, msg = self.callbacks[self.state]()
        except Exception as e:
            errormsg = "Failure to execute step after: " + str(self.state)
            errormsg += ", Exception: " + repr(e)
            cslog.info(errormsg)
            return (False, errormsg)
        if not retval:
            return (False, msg)
        #update to next state *only* on success.
        self.state += 1
        return (retval, "OK")

    def set_finalize(self, callback):
        self.finalize = callback

    def set_setup(self, callback):
        self.setup = callback
        
class CoinSwapTX(object):
    """A generic bitcoin transaction construct,
    currently limited to one output scriptPubKey
    and one (optional) change. "Change" here is notional, since
    this class is not encapsulating a wallet; so it can be an output
    to a different party (this is used in backouts here).
    Note that the positions of the pay, change outputs
    are automatically randomized; but inputs are not, so
    any randomization there must be implemented by the caller.

    Base class provides full signing functionality; subclasses
    must override at least the attach_signatures function
    for creation of valid signed transaction. Subclasses
    only need to override sign_at_index in case there is more
    than one input signing pubkey.
    """
    attr_list = ['utxo_ins', 'signing_pubkeys', 'signing_redeem_scripts',
                  'signatures', 'output_address', 'change_address',
                  'output_script', 'change_script', 'output_amount',
                  'change_amount', 'locktime', 'outs', 'pay_out_index',
                  'base_form', 'fully_signed_tx', 'completed', 'txid',
                  'is_spent', 'is_confirmed', 'is_broadcast', 'spending_tx']

    def __init__(self,
                 utxo_ins,
                 output_address,
                 change_address=None,
                 output_amount=None,
                 change_amount=None,
                 change_random=True,
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
            if (not change_random) or (random.random() < 0.5):
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
        self.is_broadcast = False
        self.is_confirmed = False
        self.is_spent = False
        self.spending_tx = None

    def unconfirm_update(self, txd, txid):
        """The is_broadcast flag is *only* set when
        the blockchain interface confirms arrival in mempool.
        Note this can occur due to other counterparty, not ourselves.
        """
        cslog.info("Triggered unconfirm update for txid: " + txid)

        if self.txid:
            if not txid == self.txid:
                cslog.info("WARNING: malleation detected.")
        self.is_broadcast = True

    def spent_update(self, txd, txid):
        self.is_spent = True
        cslog.info('found spending transaction: ' + str(txd))
        self.spending_tx = btc.serialize(txd)

    def confirm_update(self, txd, txid, confs):
        """Note this can occur due to other counterparty, not ourselves.
        """
        if self.txid:
            if not txid == self.txid:
                cslog.info("WARNING: malleation detected.")
        self.is_confirmed = True
        #Confirmed implies broadcast (this is used in backout logic)
        self.is_broadcast = True

    def signature_form(self, index):
        assert len(self.signing_redeem_scripts) >= index + 1
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
        if not cs_single().bc_interface.pushtx(self.fully_signed_tx):
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
            if self.txid:
                msg.append("Txid: " + self.txid)
            tx = self.fully_signed_tx
        dtx = btc.deserialize(tx)
        return pformat(dtx) + "\n" + "\n".join(msg)

    def serialize(self):
        p = {}
        for v in self.attr_list:
            p[v] = getattr(self, v)
        return p

    def deserialize(self, d):
        try:
            for v in self.attr_list:
                setattr(self, v, d[v])
            return True
        except:
            cslog.info("Failed to deserialize Coinswap TX object")
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
    multisig. Supports multiple outputs.
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
            cslog.info("Error in include_signature: signature invalid: " + sig)
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
                 destination_amount,
                 carol_change_address,
                 carol_change_amount):
        obj = cls()
        scr, addr = msig_data_from_pubkeys([pubkey1, pubkey2], 2)
        signatures = [[]]
        #The redeem script for the single input is that for the 2 of 2 case
        signing_redeem_scripts = [scr]
        super(CoinSwapTX45, obj).__init__(utxo_ins=[utxo_in],
                                           output_address=destination_address,
                                           output_amount=destination_amount,
                                           signing_pubkeys=[[pubkey1, pubkey2]],
                                    signing_redeem_scripts=signing_redeem_scripts,
                                    change_address=carol_change_address,
                                    change_amount=carol_change_amount,
                                    change_random=False)
        return obj

class CoinSwapTX23(CoinSwapSpend2_2):
    """Pays from 2of2 utxo (already broadcast), to
    (a) a custom script: pay to (counterparty+secret reveal) or (me after timeout).
    (b) an output to one party only ("Carol"); this uses "change" as noted in the
    CoinSwapTX class.
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
                 refund_pubkey,
                 carol_only_address,
                 carol_only_amount):
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
                                           signatures=signatures,
                                           change_address=carol_only_address,
                                           change_amount=carol_only_amount,
                                           change_random=False)
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
        script_to_serialize += [None,
                                binascii.unhexlify(self.signing_redeem_scripts[0])]
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

    def __init__(self, wallet, state_file, cpp=None, testing_mode=False,
                 fee_checker=None):
        self.testing_mode = testing_mode
        self.coinswap_parameters = cpp
        if self.coinswap_parameters:
            assert isinstance(self.coinswap_parameters, CoinSwapPublicParameters)
        self.generate_keys()
        assert isinstance(wallet, Wallet)
        if self.coinswap_parameters and self.coinswap_parameters.session_id:
            self.state_file = state_file + self.coinswap_parameters.session_id + '.json'
        else:
            #Note this MUST be updated immediately on handshake.
            self.state_file = state_file
        self.wallet = wallet
        self.state = 0
        self.tx0 = None
        self.tx1 = None
        self.tx2 = None
        self.tx3 = None
        self.tx4 = None
        self.tx5 = None
        #other-side txids may not be available if quitting at certain points
        self.txid0 = None
        self.txid1 = None
        self.txid4 = None
        self.txid5 = None
        self.secret = None
        self.hashed_secret = None
        #Created on the fly for redeeming a backout (same mixdepth as origin)
        self.backout_redeem_addr = None
        #Only used by Alice; fee check callback
        self.fee_checker = fee_checker
        #currently only used by Carol; TODO
        self.phase2_ready = False
        self.tx4_confirmed = False
        self.successful_tx3_redeem = None
        self.consumed_nonces = []
        self.completed = False
        #Carol must keep track of coins reserved for usage
        #so as to not select them to spend, twice, concurrently.
        #We only init with a fresh empty list if this is the first
        #Carol in the run (so check from program startup setting of None).
        #Otherwise we would be wiping the existing list.
        if self.wallet.used_coins is None:
            self.wallet.used_coins = []
        self.sm = StateMachine(self.state, self.backout,
                               self.get_state_machine_callbacks())
        self.sm.set_finalize(self.finalize)

    def import_address(self, address):
        """To support checking transactions, import
        backout addresses to local wallet.
        """
        wallet_name = cs_single().bc_interface.get_wallet_name(self.wallet)
        #It is safe here to import without rescan *if* the address is fresh.
        cs_single().bc_interface.import_addresses([address], wallet_name)

    def watch_for_tx(self, tx):
        """Use the blockchain interface to update
        state when a transaction is broadcast and confirmed
        """
        #TODO here assuming that we want to monitor spends from the payout index
        #only, and also that confirm_update should be triggered only by the 1st
        #confirm
        cs_single().bc_interface.add_tx_notify(
        btc.deserialize(tx.fully_signed_tx),
        tx.unconfirm_update,
        tx.confirm_update,
        tx.spent_update,
        tx.output_address,
        tx.pay_out_index)

    def generate_privkey(self):
        #always hex, with compressed flag
        return binascii.hexlify(os.urandom(32))+"01"

    def finalize(self):
        self.persist()

    def load(self, sessionid=None):
        sess_loc = os.path.join(cs_single().homedir,
                            cs_single().config.get("SESSIONS", "sessions_dir"))
        #If a sessionid was passed, we use that to temporarily recover the full
        #filename; if not, we assume that self.state_file is already correct.
        sf = self.state_file + sessionid + ".json" if sessionid else self.state_file
        with open(os.path.join(sess_loc, sf), "rb") as f:
            loaded_state = json.loads(f.read(), object_hook=_byteify)
        self.coinswap_parameters = CoinSwapPublicParameters()
        self.coinswap_parameters.deserialize(loaded_state['public_parameters'])
        self.state_file = sf
        self.sm.state = loaded_state['current_state']
        self.keyset = loaded_state['keyset']
        self.secret = loaded_state['coinswap_secret_data']['preimage']
        self.hashed_secret = loaded_state['coinswap_secret_data']['hash']
        #TODO: this less repetitive version doesn't work for some reason
        """
        for n, t, tt in zip(("TX0", "TX1", "TX2", "TX3", "TX4", "TX5"),
                        (CoinSwapTX01, CoinSwapTX01, CoinSwapTX23,
                         CoinSwapTX23, CoinSwapTX45, CoinSwapTX45),
                        (self.tx0, self.tx1, self.tx2,
                         self.tx3, self.tx4, self.tx5)):
            if n in loaded_state:
                tt = t.from_dict(loaded_state[n])
        """
        if "TX0" in loaded_state:
            self.tx0 = CoinSwapTX01.from_dict(loaded_state["TX0"])
        if "TX1" in loaded_state:
            self.tx1 = CoinSwapTX01.from_dict(loaded_state["TX1"])
        if "TX2" in loaded_state:
            self.tx2 = CoinSwapTX23.from_dict(loaded_state["TX2"])
        if "TX3" in loaded_state:
            self.tx3 = CoinSwapTX23.from_dict(loaded_state["TX3"])
        if "TX4" in loaded_state:
            self.tx4 = CoinSwapTX45.from_dict(loaded_state["TX4"])
        if "TX5" in loaded_state:
            self.tx5 = CoinSwapTX45.from_dict(loaded_state["TX5"])

    def persist(self):
        """In principle the following dataset is sufficient to recover to
        the current state: private keyset, public coinswap parameters,
        coinswap secret and or hash,
        and current state machine state (self.state).
        Additional information is realistically required however:
        transaction data for any transactions that are already prepared or
        broadcast.
        """
        persisted_state = {}
        persisted_state['public_parameters'] = self.coinswap_parameters.serialize()
        persisted_state['current_state'] = self.sm.state
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
        sess_loc = os.path.join(cs_single().homedir,
                            cs_single().config.get("SESSIONS", "sessions_dir"))
        if not os.path.exists(sess_loc):
            os.makedirs(sess_loc)
        with open(os.path.join(sess_loc, self.state_file), "wb") as f:
            f.write(json.dumps(persisted_state, indent=4))

    def quit(self, complete=True, failed=False):
        """A generic end-processing function.
        """
        #A small delay to account for updates to the mempool.
        reactor.callLater(1.0, self.final_report, complete, failed)

    def backout(self, backoutmsg):
        from .alice import CoinSwapAlice
        from .carol import CoinSwapCarol
        """Uses current state to decide backing out action.
        Note that program exits when actions are complete,
        thus this method tacitly assumes that only one of
        (Alice, Carol) is running in this executable. This
        point is relevant for testing only currently.
        """
        cslog.info('BACKOUT: ' + backoutmsg)
        me = "Alice" if isinstance(self, CoinSwapAlice) else "Carol"
        cslog.info("Current state: " + str(self.sm.state) + ", I am : " + me)
        if self.sm.state == 0:
            #Failure in negotiation; nothing to do
            cslog.info("Failure in parameter negotiation; no action required; "
                     "ending.")
            self.quit(False, False)
            return
        if (isinstance(self, CoinSwapAlice) and self.sm.state in range(7)) or \
           (isinstance(self, CoinSwapCarol) and self.sm.state in range(6)):
            #Alice/Carol created TX0/1 but didn't broadcast; no action required.
            #Alice/Carol may have sent signatures on spend-out transactions
            #but this is irrelevant as long as TX0/1 is not on the network.
            cslog.info("No funds have moved; no action required; ending.")
            #If Carol is backing out before TX1 broadcast, need to release
            #the lock on the input coins so they can be used in future runs.
            if isinstance(self, CoinSwapCarol) and self.tx1:
                cslog.info("Used coins was: " + str(self.wallet.used_coins))
                self.wallet.used_coins = [
            x for x in self.wallet.used_coins if x not in self.tx1.utxo_ins]
                cslog.info("We unlocked those for this run, it is now: " + \
                           str(self.wallet.used_coins))
            self.quit(False, False)
            return
        #Handling for later states depends on Alice/Carol
        if isinstance(self, CoinSwapAlice):
            #for redeeming, we get a new address on the fly (not pre-agreed)
            if not self.backout_redeem_addr:
                self.backout_redeem_addr = self.wallet.get_new_addr(0, 1, True)
            if self.sm.state in [7, 8, 9]:
                #Alice has broadcast TX0 but has not released the secret;
                #therefore it's entirely safe to just wait for L0 and then
                #redeem on the lock branch.
                bh = get_current_blockheight()
                if bh < self.coinswap_parameters.timeouts["LOCK0"] + 1:
                    cslog.info("Not ready to redeem the funds, "
                             "waiting for block: " + str(
                                 self.coinswap_parameters.timeouts["LOCK0"]) + \
                             ", current block: " + str(bh))
                    reactor.callLater(3.0, self.backout, backoutmsg)
                    return
                msg, success = self.tx2.push()
                if not success:
                    cslog.info("RPC error message: " + msg)
                    cslog.info("Failed to broadcast TX2; here is raw form: ")
                    cslog.info(self.tx2.fully_signed_tx)
                    return self.quit(False, True)
                tx23_redeem = CoinSwapRedeemTX23Timeout(
                    self.coinswap_parameters.pubkeys["key_TX2_secret"],
                    self.hashed_secret,
                    self.coinswap_parameters.timeouts["LOCK0"],
                    self.coinswap_parameters.pubkeys["key_TX2_lock"],
                    self.tx2.txid + ":0",
                    self.coinswap_parameters.tx2_amounts["script"],
                    self.backout_redeem_addr)
                tx23_redeem.sign_at_index(self.keyset["key_TX2_lock"][0], 0)
                msg, success = tx23_redeem.push()
                if not success:
                    cslog.info("RPC error message: ", msg)
                    cslog.info("Failed to broadcast TX2 redeem; here is raw form: ")
                    cslog.info(tx23_redeem.fully_signed_tx)
                else:
                    cslog.info("Successfully reclaimed funds via TX2, to address: " +\
                              self.backout_redeem_addr)
                return self.quit(False, not success)
            elif self.sm.state == 10:
                #Carol has received the secret, but we don't have the TX5 sig.
                #Immediately (before L1), broadcast TX3 with the secret.
                msg, success = self.tx3.push()
                if not success:
                    cslog.info("RPC error message: " + msg)
                    cslog.info("Failed to broadcast TX3; here is raw form: ")
                    cslog.info(self.tx3.fully_signed_tx)
                    return self.quit(False, True)
                tx23_secret = CoinSwapRedeemTX23Secret(self.secret,
                            self.coinswap_parameters.pubkeys["key_TX3_secret"],
                            self.coinswap_parameters.timeouts["LOCK1"],
                            self.coinswap_parameters.pubkeys["key_TX3_lock"],
                            self.tx3.txid + ":0",
                            self.coinswap_parameters.tx3_amounts["script"],
                            self.backout_redeem_addr)
                tx23_secret.sign_at_index(self.keyset["key_TX3_secret"][0], 0)
                cslog.info("Broadcasting TX3 redeem: ")
                msg, success = tx23_secret.push()
                cslog.info(tx23_secret)
                if not success:
                    cslog.info("RPC error message: ", msg)
                    cslog.info("Failed to broadcast TX3 redeem; here is raw form: ")
                    cslog.info(tx23_secret.fully_signed_tx)
                else:
                    cslog.info("Successfully reclaimed funds via TX3, to address: " +\
                              self.backout_redeem_addr)
                return self.quit(False, not success)
            elif self.sm.state in [11, 12, 13]:
                #We are now in possession of a valid TX5 signature; either we
                #already broadcast it, or we do so now.
                if self.tx5.txid:
                    cslog.info("TX5 was already broadcast: " + self.tx5.txid)
                    cslog.info("Here is the raw form for re-broadcast: ")
                    cslog.info(self.tx5.fully_signed_tx)
                else:
                    self.tx5.sign_at_index(self.keyset["key_2_2_CB_1"][0], 1)
                    errmsg, success = self.tx5.push()
                    if not success:
                        cslog.info("Failed to push TX5, errmsg: " + errmsg)
                        cslog.info("Raw form: ")
                        cslog.info(self.tx5.fully_signed_tx)
                        cslog.info("Readable form: ")
                        cslog.info(self.tx5)
                    else:
                        cslog.info("Successfully broadcast TX5, amount: " + \
                                  str(self.tx5.output_amount) + \
                                  " to address: " + self.tx5.output_address)
                return self.quit(True, False)
            elif self.sm.state == 14:
                #occasionally errors on polling for confirm TX4 if other
                #side is shut down; nothing needs to be done.
                return
            else:
                assert False
        elif isinstance(self, CoinSwapCarol):
            #for redeeming, we get a new address on the fly (not pre-agreed)
            if not self.backout_redeem_addr:
                self.backout_redeem_addr = self.wallet.get_new_addr(0, 1, True)
            if self.sm.state in [6, 7]:
                #This is by far the trickiest case.
                #
                #We have valid signatures on TX3, we can broadcast and redeem it
                #via locktime after LOCK1.
                #However, since Alice knows the secret, she could double spend
                #the created outpoint (whose script pubkey is (Bob, Hash or Carol,
                #Lock)) using the secret. If she does so, we can instead redeem
                #TX2 using the same secret. This has to be done before the timeout
                #LOCK 0. Approach:
                #0. Wait for LOCK 1.
                #1. broadcast the lock1 TX3.
                #1a. if broadcast fails, it's because Alice spent TX3;
                #1b. tx-notify has kept track of TX3 spending and recorded
                #    the redeeming transaction tx3-redeem.
                #1c. Read the secret from tx3-redeem,
                #    construct TX2 and redeem from it (same as 4-7).
                #2. TX3 broadcast succeeded. Broadcast a spend-out using the LOCK1 branch.
                #3. Wait for confirms. If seen, OK.
                #4. If outpoint is seen spent, but not with our expected hash:
                #5. Retrieve X from the scriptSig of the unexpected tx hash.
                #6. Sign and broadcast the TX2.
                #7. Broadcast a spend-out using the secret branch for TX2.
                #Note, all this has to happen a reasonable safety buffer before
                #LOCK0.
                bh = get_current_blockheight()
                if bh < self.coinswap_parameters.timeouts["LOCK1"] + 1:
                    cslog.info("Not ready to redeem the funds, "
                             "waiting for block: " + str(
                                 self.coinswap_parameters.timeouts["LOCK1"]) + \
                             ", current block: " + str(bh))
                    reactor.callLater(3.0, self.backout, backoutmsg)
                    return
                if bh > self.coinswap_parameters.timeouts["LOCK0"]:
                    cslog.info("CRITICAL WARNING: Too late, counterparty may "
                             "be able to double spend our redemption; attempting "
                             "to claim funds anyway. Continuing...")
                #Broadcast TX3
                cslog.info("Monitor records is_spent: " + str(self.tx3.is_spent))
                cslog.info("Monitor records is_broadcast: " + str(self.tx3.is_broadcast))
                cslog.info("Monitor records is_confirmed: " + str(self.tx3.is_confirmed))
                if not self.tx3.is_broadcast:
                    msg, success = self.tx3.push()
                    if not success:
                        #Failure to broadcast TX3 may be because it's already
                        #been broadcast and redeemed. Try scanning the blockchain
                        #to find the secret.
                        scan_success = self.scan_blockchain_for_secret()
                        if scan_success:
                            rt2s_success = self.redeem_tx2_with_secret()
                            self.quit(False, not rt2s_success)
                            return
                        #TODO: corner case: TX3 broadcast, but for some reason
                        #not recorded as broadcast (restart), but not redeemed.
                        cslog.info("Failed to broadcast TX3, "
                                  "RPC error message: " + msg)
                        cslog.info("Failed to broadcast TX3; here is raw form: ")
                        cslog.info(self.tx3.fully_signed_tx)
                        cslog.info("Readable form: ")
                        cslog.info(self.tx3)
                        return self.quit(False, True)
                if self.tx3.is_spent:
                    cslog.info("Detected TX3 already spent by Alice. "
                              "Extracting secret and then redeeming TX2.")
                    #find out if tx3:0 is unspent; if so, we can attempt to
                    #spend it, if not we  must extract the secret.
                    secret = self.find_secret_from_tx3_redeem()
                    if not secret:
                        cslog.info("CRITICAL ERROR: Failed to retrieve secret "
                                  "from TX3 broadcast by Alice.")
                        return self.quit(False, True)
                    rt2s_success = self.redeem_tx2_with_secret()
                    #tx2 redemption cannot be conflicted before L0, so
                    #safe to return
                    return self.quit(False, not rt2s_success)
                else:
                    if not self.redeem_tx3_with_lock():
                        return self.quit(False, True)
                    #need to monitor for state updates to this transaction
                    self.watch_for_tx(self.tx3redeem)
                    #If we reached this point, we have broadcast a TX3 redeem,
                    #and want to ensure it confirms, and take appropriate action
                    #if it is double spent.
                    #Fire a waiting loop that triggers on one of 2 events: (1)
                    #confirmation of tx3 redeem, or (2) consumption of tx3 outpoint
                    #without (1) occurring, and take action.
                    self.carol_watcher_loop = task.LoopingCall(
                        self.watch_for_tx3_spends, self.tx3redeem.txid)
                    self.carol_watcher_loop.start(3.0)
            elif self.sm.state == 8:
                #Alice did not provide TX4 sig but we already allowed
                #TX5 spend; we use X to redeem from TX2, before L0.
                #No wait needed.
                rt2s_success = self.redeem_tx2_with_secret()
                return self.quit(False, not rt2s_success)
            elif self.sm.state == 9:
                #We are now in possession of a valid TX4 signature; either we
                #already broadcast it, or we do so now.
                if self.tx4.txid:
                    cslog.info("TX4 was already broadcast: " + self.tx4.txid)
                    cslog.info("Here is the raw form for re-broadcast: ")
                    cslog.info(self.tx4.fully_signed_tx)
                    return self.quit(True, False)
                else:
                    self.tx4.sign_at_index(self.keyset["key_2_2_AC_1"][0], 1)
                    errmsg, success = self.tx4.push()
                    if not success:
                        cslog.info("Failed to push TX4, errmsg: " + errmsg)
                        cslog.info("Raw form: ")
                        cslog.info(self.tx4.fully_signed_tx)
                        cslog.info("Readable form: ")
                        cslog.info(self.tx4)
                    else:
                        cslog.info("Successfully pushed TX4: " + self.tx4.txid + \
                                  ", funds claimed OK, shutting down.")
                    return self.quit(False, not success)
            else:
                assert False

    def check_for_phase1_utxos(self, utxos, cb=None):
        """Any participant needs to wait for completion of phase 1 through
        seeing the utxos on the network. Optionally pass callback for start
        of phase2 (redemption phase), else default is state machine tick();
        must have signature callback(utxolist).
        Triggered on number of confirmations as set by config.
        This should be fired by task looptask, which is stopped on success.
        """
        result = cs_single().bc_interface.query_utxo_set(utxos,
                                                         includeconf=True)
        if None in result:
            return
        for u in result:
            if u['confirms'] < cs_single().config.getint(
                "TIMEOUT", "tx01_confirm_wait"):
                return
        self.loop.stop()
        if cb:
            cb()
        else:
            self.sm.tick()

    def generate_keys(self):
        """These are ephemeral keys required for redeeming various transactions.
        (Ephemeral in the sense that they must *not* be used for different runs,
        but must of course be persisted for the run).
        """
        self.keyset_keys = [self.generate_privkey() for _ in range(
            len(self.required_key_names))]
        self.keyset = {}
        for i, name in enumerate(self.required_key_names):
            self.keyset[name] = (self.keyset_keys[i],
                                 btc.privkey_to_pubkey(self.keyset_keys[i]))
        #keys will be stored on first persist, after parameters negotiated.

    def final_report(self, complete=True, failed=False):
        """Simple text summary of coinswap in co-operative and
        non-co-operative case, for both sides.
        """
        from .blockchaininterface import sync_wallet
        from .alice import CoinSwapAlice
        from .carol import CoinSwapCarol
        self.completed = True
        sync_wallet(self.wallet, fast=True)
        self.bbma = self.wallet.get_balance_by_mixdepth(verbose=False)
        cslog.info("Wallet before: ")
        cslog.info(pformat(self.bbmb))
        cslog.info("Wallet after: ")
        cslog.info(pformat(self.bbma))
        if complete:
            report_msg = ["Coinswap completed OK."]
            report_msg.append("**************")
            report_msg.append("Pay in transaction from Alice to 2-of-2:")
            rtxid0 = self.tx0.txid if self.tx0 else self.txid0
            report_msg.append("Txid: " + str(rtxid0))
            report_msg.append("Amount: " + str(self.coinswap_parameters.tx0_amount))
            report_msg.append("Pay in transaction from Carol to 2-of-2:")
            rtxid1 = self.tx1.txid if self.tx1 else self.txid1
            report_msg.append("Txid: " + str(rtxid1))
            report_msg.append("Amount: " + str(self.coinswap_parameters.tx1_amount))
            report_msg.append("Pay out transaction from 2-of-2 to Carol:")
            rtxid4 = self.tx4.txid if self.tx4 else self.txid4
            report_msg.append("Txid: " + str(rtxid4))
            report_msg.append("Receiving address: " + self.coinswap_parameters.output_addresses["tx4_address"])
            report_msg.append("Amount: " + str(self.coinswap_parameters.tx4_amounts["carol"]))
            report_msg.append("Pay out transaction from 2-of-2 to Alice:")
            rtxid5 = self.tx5.txid if self.tx5 else self.txid5
            report_msg.append("Txid: " + str(rtxid5))
            report_msg.append("Receiving address: " + self.coinswap_parameters.output_addresses["tx5_address"])
            report_msg.append("Amount: " + str(self.coinswap_parameters.tx5_amounts["alice"]))
        else:
            if not failed:
                report_msg = ["Coinswap is finished and funds reclaimed, but we "
                              "did not complete the protocol normally."]
            else:
                report_msg = ["Coinswap did NOT finish successfully. You may "
                              "need to take further action."]
            for t in [self.tx0, self.tx1, self.tx2, self.tx3, self.tx4, self.tx5]:
                #This does not give all relevant information (in particular, the
                #redeem transactions), TODO
                if t and t.txid:
                    report_msg += ["We pushed transaction: " + t.txid]
                    report_msg += ["Amount: " + str(t.output_amount)]
                    report_msg += ["To address: " + t.output_address]

        cslog.info("\n" + "\n".join(report_msg))

        if self.testing_mode:
            #In testing mode the order of finishing of Alice/Carol depends
            #on scenario; this uses a dumb global check to always finish on
            #the second try
            if cs_single().num_entities_running == 1:
                reactor.stop()
            else:
                cs_single().num_entities_running += 1
        else:
            #Reactor stop must be deferred until after the report is complete.
            #Carol (server) must not shutdown unless there was a failure; in which
            #case it's prudent to shutdown, as this is a serious failure.
            if isinstance(self, CoinSwapAlice) or (
                isinstance(self, CoinSwapCarol) and failed == True):
                reactor.stop()

    @abc.abstractmethod
    def negotiate_coinswap_parameters(self):
        pass
    @abc.abstractmethod
    def get_state_machine_callbacks(self):
        """Return a set of tuples for the callbacks for each state transition.
        First item is callback function, second is a boolean flag used to
        indicate whether it should be automatically triggered by the previous
        state transition completing, third is how long to wait for the next
        state update before timing out (and backing out). A negative value for
        this last item is interpreted to mean using the default timeout.
        """
        pass

class CoinSwapException(Exception):
    pass

class CoinSwapPublicParameters(object):
    required_key_names = ["key_2_2_AC_0", "key_2_2_AC_1", "key_2_2_CB_0",
                          "key_2_2_CB_1", "key_TX2_secret", "key_TX2_lock",
                          "key_TX3_secret", "key_TX3_lock", "key_session"]
    attr_list = ['tx0_amount', 'tx1_amount', 'tx2_amounts',
                  'tx3_amounts', 'tx4_amounts', 'tx5_amounts',
                  'output_addresses', 'timeouts', 'pubkeys',
                  'coinswap_fee', 'blinding_amount', 'bitcoin_fee']

    def trigger_complete(func):
        """triggers setting of all transaction amounts
        once the base data is set by caller.
        """
        @wraps(func)
        def func_wrapper(inst, *args, **kwargs):
            func(inst, *args, **kwargs)
            if all([inst.bitcoin_fee, inst.coinswap_fee,
                    inst.blinding_amount, inst.base_amount]):
                inst.set_amounts()
        return func_wrapper

    def __init__(self,
                 base_amount=None,
                 blinding_amount=None,
                 coinswap_fee=None,
                 bitcoin_fee=None,
                 timeoutdata=None,
                 addressdata=None,
                 pubkeydata=None):
        self.session_id = None
        self.timeouts_complete = False
        self.pubkeys_complete = False
        self.addresses_complete = False
        self.output_addresses = {}
        self.bitcoin_fee = None
        self.coinswap_fee = None
        self.base_amount = None
        self.blinding_amount = None
        self.set_coinswap_fee(coinswap_fee)
        self.set_bitcoin_fee(bitcoin_fee)
        self.set_blinding_amount(blinding_amount)
        self.set_base_amount(base_amount)
        self.timeouts = {}
        self.pubkeys = {}
        self.tx0_amount = None
        self.tx1_amount = None
        self.tx2_amounts = {}
        self.tx3_amounts = {}
        self.tx4_amounts = {}
        self.tx5_amounts = {}
        #only used by Carol
        self.fee_policy = None
        if timeoutdata:
            self.set_timeouts(*timeoutdata)
        else:
            #Client can set timeouts from config
            self.set_timeouts(None, None)
        if addressdata:
            self.set_addr_data(*addressdata)
        if pubkeydata:
            self.set_pubkey_data(pubkeydata)

    @trigger_complete
    def set_base_amount(self, amt):
        self.base_amount = amt

    @trigger_complete
    def set_bitcoin_fee(self, fee):
        self.bitcoin_fee = fee

    @trigger_complete
    def set_blinding_amount(self, amt):
        self.blinding_amount = amt

    def set_fee_policy(self, fp):
        """Note that the fee policy attribute is only
        for convenience of initial setup; it's not
        required for restart, and so not included in the list
        of attributes persisted.
        """
        assert isinstance(fp, FeePolicy)
        self.fee_policy = fp

    @trigger_complete
    def set_coinswap_fee(self, fee):
        """Unlike the fee policy, the actual fee itself
        produced by that policy is persisted, although
        theoretically it may not be necessary (since all the output
        amounts are fixed.
        """
        self.coinswap_fee = fee

    def set_amounts(self):
        self.set_tx0_amount()
        self.set_tx1_amount()
        self.set_tx2_amounts()
        self.set_tx3_amounts()
        self.set_tx4_amounts()
        self.set_tx5_amounts()

    def set_tx5_amounts(self):
        self.tx5_amounts["alice"] = self.base_amount
        self.tx5_amounts["carol"] = self.blinding_amount + self.coinswap_fee + \
            self.bitcoin_fee * 2

    def set_tx4_amounts(self):
        self.tx4_amounts["carol"] = self.base_amount + self.coinswap_fee + \
            self.bitcoin_fee * 2

    def set_tx0_amount(self):
        self.tx0_amount = self.base_amount + self.coinswap_fee + \
            self.bitcoin_fee * 4

    def set_tx1_amount(self):
        self.tx1_amount = self.blinding_amount + self.base_amount + \
            self.coinswap_fee + self.bitcoin_fee * 4

    def set_tx2_amounts(self):
        self.tx2_amounts["script"] = self.base_amount + self.bitcoin_fee
        self.tx2_amounts["carol"] = self.coinswap_fee + self.bitcoin_fee

    def set_tx3_amounts(self):
        self.tx3_amounts["script"] = self.base_amount + self.bitcoin_fee
        self.tx3_amounts["carol"] = self.blinding_amount + self.coinswap_fee + \
            self.bitcoin_fee

    def set_session_id(self, sid):
        self.session_id = sid

    def serialize(self):
        """All data into a dict (for json persistence).
        Note that before this is complete, state machine
        processing does not start, so it doesn't need to be
        made available in that case.
        """
        assert self.is_complete()
        p = {}
        for v in self.attr_list:
            p[v] = getattr(self, v)
        return p
    
    def deserialize(self, d):
        try:
            for v in self.attr_list:
                setattr(self, v, d[v])
            self.addresses_complete = True
            self.pubkeys_complete = True
            self.timeouts_complete = True
            return True
        except:
            cslog.info("Failed to deserialize coinswap public parameters")
            return False
        
    def set_pubkey(self, key, pubkey):
        assert key in self.required_key_names
        self.pubkeys[key] = pubkey
        if set(self.pubkeys.keys()) == set(self.required_key_names):
            self.pubkeys_complete = True

    def set_addr_data(self, addr4=None, addr5=None, addr_2_carol=None,
                      addr_3_carol=None, addr_5_carol=None):
        if addr4:
            self.output_addresses["tx4_address"] = addr4
        if addr5:
            self.output_addresses["tx5_address"] = addr5
        if addr_2_carol:
            self.output_addresses["tx2_carol_address"] = addr_2_carol
        if addr_3_carol:
            self.output_addresses["tx3_carol_address"] = addr_3_carol
        if addr_5_carol:
            self.output_addresses["tx5_carol_address"] = addr_5_carol
        if all([x in self.output_addresses for x in ["tx4_address", "tx5_address",
                                                     "tx2_carol_address",
                                                     "tx3_carol_address",
                                                     "tx5_carol_address"]]):
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
        if not blockheight1:
            cb = get_current_blockheight()
            blockheight1 = cb + cs_single().config.getint("TIMEOUT", "lock_client")
            blockheight2 = cb + cs_single().config.getint("TIMEOUT", "lock_server")
        assert blockheight1 > blockheight2
        self.timeouts["LOCK0"] = blockheight1
        self.timeouts["LOCK1"] = blockheight2
        self.timeouts_complete = True
