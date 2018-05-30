from __future__ import print_function
import jmbitcoin as btc
from jmclient import (Wallet, get_p2pk_vbyte, get_p2sh_vbyte, estimate_tx_fee)
from coinswap import (get_log, cs_single, get_coinswap_parser,
                      load_coinswap_config)
from decimal import Decimal
import binascii
import time
import os
import copy
import random
import sys
from pprint import pformat
import json
from functools import wraps

COIN = 100000000

cslog = get_log()

class TxParsingError(Exception):
    pass

def btc_to_satoshis(amt):
    return int(round(Decimal(1e8) * Decimal(amt)))

def satoshis_to_btc(amt):
    return float(Decimal(amt)/Decimal(1e8))

"""Simple parsing routines
"""
def parse_txid(txid):
    if len(txid) != 32:
        raise TxParsingError("Invalid txid length")
    try:
        binascii.unhexlify(txid)
    except:
        raise TxParsingError("Invalid txid hex")
    return txid

def parse_tx_index(index):
    assert isinstance(index, int)
    assert index < 256
    assert index > -1
    return index

def parse_amount(amount):
    assert isinstance(amount, int)
    assert amount > 0 and amount < COIN
    return amount

def msig_data_from_pubkeys(pubkeys, N):
    """Create a p2sh address for the list of pubkeys given, N signers required.
    Return both the multisig redeem script and the p2sh address created.
    """
    #todo: lexicographical ordering is better
    multisig_script = btc.mk_multisig_script(pubkeys, N)
    p2sh_address = btc.p2sh_scriptaddr(multisig_script, magicbyte=get_p2sh_vbyte())
    return (multisig_script, p2sh_address)

def NN_script_from_pubkeys(pubkeys):
    return msig_data_from_pubkeys(pubkeys, len(pubkeys))[0]

class OCCTx(object):
    """An OCCTx is a transaction in the graph.
    It is instantiated using the template version of the transaction,
    along with a wallet to provide keys.
    Additionally, counterparty keys are inserted via the function apply_keys.
    Signatures are attached separately/later.
    """
    attr_list = ['utxo_ins', 'signing_pubkeys', 'signing_redeem_scripts',
                 'signatures', 'output_address', 'change_address',
                 'output_script', 'change_script', 'output_amount',
                 'change_amount', 'locktime', 'outs', 'pay_out_index',
                 'base_form', 'fully_signed_tx', 'completed', 'txid',
                 'is_spent', 'is_confirmed', 'is_broadcast', 'spending_tx']

    def __init__(self, txtemplate, wallet, n_counterparties, n, locktime=None, keyset=None):
        """Instantiation will always require a template for the skeleton
        of the transaction (inputs and outputs amounts and counterparties),
        but will usually not have a full set of keys, nor usually any
        signatures produced. Locktime will be included in the template.
        Note that since the previous transaction may not yet have been fully
        specified at instantiation time (due to absence of keys), we may
        not have all input txids available at the start, either.
        Arguments:
        ==========
        1. txtemplate is of type OCCTemplateTx and specifies: nins, nouts,
        counterparties responsible for each outpoint, amounts of ins, amounts
        of outs (including of course shared ins/outs, NN).
        2. wallet of type jmclient.SegwitWallet
        3. n_counterparties: integer number of counterparties involved
           in the overall contract
        4. n: my counterparty index (from 0) in the template used
        5. optionally a locktime
        6. optionally a set of keys indexed by the in/outpoints:
         format: dict: {"ins": {0: {0: key1, 1: key2}, 1: {1: key3}},
         "outs": {0: {0: key4, 1: key5}, 1: {1: key6, 2: key7}}}
         Note: if it is provided, it must be complete.
        """
        assert isinstance(wallet, Wallet)
        assert isinstance(txtemplate, OCCTemplateTX)
        assert all([isinstance(x, int) for x in [n_counterparties, n]])

        #Total number of counterparties in this OCC
        self.n_counterparties = n_counterparties
        
        #My counterparty index as described in the transaction
        #template:
        self.n = n

        #Locktime applied to this transaction
        self.locktime = locktime

        self.wallet = wallet
        self.template = txtemplate

        #will take format: [("txid:vout", amount),..]
        self.ins = []

        #will take format: [(scriptpubkey, amount), ..]
        #with index implicit
        self.outs = []
        
        #A list of the redeem scripts used by each input,
        #which will be filled out when the requisite keys
        #are added to the keyset (see below)
        self.signing_redeem_scripts = [None]*len(self.template.ins)

        #A list of lists of signatures to be applied to each
        #input (either length 1, or length self.n_counterparties)
        self.signatures = [[]] * len(self.template.ins)

        #create the structure (dict) that will hold all the
        #pubkeys used for the input signing and output destination
        #address creation.
        if not keyset:
            self.keys = {"ins":{}, "outs":{}}
            for i in range(len(self.template.ins)):
                self.keys["ins"][i] = {}
            for i in range(len(self.template.outs)):
                self.keys["outs"][i] = {}
        else:
            self.keys = keyset

        #This data is set once the transaction is finalized.
        self.fully_signed_tx = None
        self.completed = [False]*len(self.template.ins)
        self.txid = None

    def build_ins_from_template(self):
        for i, t in enumerate(self.template.ins):
            if t.txid:
                txid = t.txid
            else:
                raise Exception("Couldn't find outpoint for input")
            utxo_in = txid + ":" + str(t.n)
            self.ins.append((utxo_in, t.amount))

    def build_outs_from_template(self):
        for i, t in enumerate(self.template.outs):
            if t.spk_type == "p2sh-p2wpkh":
                self.outs.append({"address": btc.pubkey_to_p2sh_p2wpkh_address(
                    self.keys["outs"][i][t.counterparty], get_p2sh_vbyte()),"value": t.amount})
            elif t.spk_type == "NN":
                #check if all the necessary keys are available
                if not all([j in self.keys["outs"][i] for j in range(
                    self.n_counterparties)]):
                    raise Exception("Incomplete key data to construct outputs")
                self.outs.append({"address":
                                  btc.pubkeys_to_p2wsh_address(
                                      self.keys["outs"][i].values(
                                          ), vbyte=100),
                                  "value": t.amount})

    def mktx(self):
        """First, construct input and output lists
        as for a normal transaction construction,
        using the OCCTemplateTx corresponding inputs
        and outputs as information.
        To do this completely requires txids for all inputs.
        Thus, this must be called for this OCCTx *after*
        it has been called for all parent txs.
        We ensure that the txid for this Tx is set here,
        and is attached to all the Outpoint objects for its
        outputs.
        """
        self.build_ins_from_template()
        self.build_outs_from_template()
        assert all([self.ins, self.outs])
        self.base_form = btc.mktx([x[0] for x in self.ins], self.outs)
        dtx = btc.deserialize(self.base_form)
        if self.locktime:
            dtx["ins"][0]["sequence"] = 0
            dtx["locktime"] = self.locktime
        #To set the txid, it's required that we set the
        #scriptSig and scriptPubkey objects. We don't yet
        #need to flag it segwit (we're not yet attaching
        #signatures) since we want txid not wtxid and the
        #former doesn't use segwit formatting anyway.
        for i, inp in enumerate(dtx["ins"]):
            sti = self.template.ins[i]
            if sti.spk_type == "p2sh-p2wpkh":
                inp["script"] = "16" + btc.pubkey_to_p2sh_p2wpkh_script(
                    self.keys["ins"][i][sti.counterparty])
            elif sti.spk_type == "NN":
                inp["script"] = ""
        self.txid = btc.txhash(btc.serialize(dtx))
        #by setting the txid of the outpoints, we allow child
        #transactions to know the outpoint references for their inputs.
        for to in self.template.outs:
            to.txid = self.txid

    def apply_key(self, key, insouts, idx, cpr):
        """This is the only way (apart from instantiating
        the object with all keys in the constructor) to
        specify the public keys used in the inputs and outputs
        of the transaction, so must be called once for each.
        Note that when all the required keys have been provided
        for a particular input, that input's redeem script will
        be automatically generated, ready for signing.
        """
        #print("Running apply key on this transaction: " + repr(self.template))
        #print("Current keyset is: ", self.keys)
        #print("Trying to apply key with insouts, idx, cpr: ", insouts, idx, cpr)
        self.keys[insouts][idx][cpr] = key
        if insouts == "ins":
            #if all keys are available for this input,
            #we can set the signing redeem script
            tp = self.template.ins[idx].spk_type
            if  tp == "p2sh-p2wpkh":
                #only one signer: apply immediately
                self.signing_redeem_scripts[
                    idx] = btc.pubkey_to_p2sh_p2wpkh_script(key)
            elif tp == "NN":
                #do we have N signers?
                if len(self.keys["ins"][idx].keys(
                    )) == self.n_counterparties:
                    self.signing_redeem_scripts[
                        idx] = NN_script_from_pubkeys(
                        self.keys["ins"][idx].values())

    def signature_form(self, index):
        assert self.signing_redeem_scripts[index]
        return btc.segwit_signature_form(btc.deserialize(self.base_form),
                                         index,
                                         self.signing_redeem_scripts[index],
                                         self.ins[index][1])

    def sign_at_index(self, in_index):
        """Signs with our one key corresponding to one input;
        either sole-owned (promise) or NN.
        Segwit assumed; uses only p2sh-p2wpkh for sole-owned,
        p2wsh for co-owned.
        """
        print("******STARTTING SIGNATINDEX*******")
        print("on transaction: ", str(self.template))
        print("for index: ", in_index)
        print("Working with self.keys: ", self.keys)
        #the pubkey we're signing against:
        pub = self.keys["ins"][in_index][self.n]
        #the wallet holds the keys for p2sh-p2wpkh addresses directly.
        #for p2wsh addresses, we must use the pubkey to construct
        #the corresponding p2sh-p2wpkh address in the wallet to extract
        #the key. This is obviously stupid for a real world design TODO        
        addr = self.wallet.pubkey_to_address(pub)
        privkey = self.wallet.get_key_from_addr(addr)         
        #check whether we are multi-signing or single-signing:
        tp = self.template.ins[in_index].spk_type
        if tp  == "p2sh-p2wpkh":
            #the main (non-multisig) signing algo(s) return a signed
            #tx, not a signature; extract from the temporary tx
            txwithsig = btc.deserialize(self.wallet.sign(self.base_form, in_index,
                                   privkey, self.ins[in_index][1]))
            #txinwitness field is [sig, pub]
            sig = txwithsig["ins"][in_index]["txinwitness"][0]
            #verification check
            scriptCode = "76a914"+btc.hash160(binascii.unhexlify(pub))+"88ac"
            assert btc.verify_tx_input(self.base_form, in_index,
                                           scriptCode,
                                           sig, pub,
                                           witness="deadbeef",
                                           amount=self.ins[in_index][1])
            self.signatures[in_index] = [sig]
            self.completed[in_index] = True
        elif tp == "NN":
            if len(self.signatures[in_index]) == 0:
                self.signatures[in_index] = [None] * self.n_counterparties
            sig = btc.p2wsh_multisign(self.base_form,
                                      in_index,
                                      self.signing_redeem_scripts[in_index],
                                      privkey,
                                      amount=self.ins[in_index][1])
            assert btc.verify_tx_input(self.base_form, in_index,
                                       self.signing_redeem_scripts[in_index],
                                       sig, pub, witness="deadbeef",
                                       amount=self.ins[in_index][1])
            #Note that it's OK to use self.n as the explicit list index
            #here, as we *always* do N of N multisig.
            self.signatures[in_index][self.n] = sig
            if all([self.signatures[in_index][x] for x in range(
                self.n_counterparties)]):
                self.completed[in_index] = True
        #in some cases, the sig is used by the caller (to send to counterparty)
        return sig

    def include_signature(self, in_index, cp, sig):
        """For receiving counterparty signatures, either
        on promise inputs or NN multisigs. If valid,
        mark that index as completed if appropriate,
        and return True. If invalid, return False.
        """
        tp = self.template.ins[in_index].spk_type
        pub = self.keys["ins"][in_index][cp]
        if tp == "NN":
            if len(self.signatures[in_index]) == 0:
                self.signatures[in_index] = [None] * self.n_counterparties
            sigform = self.signature_form(in_index)            
            if not btc.verify_tx_input(self.base_form, in_index,
                                       self.signing_redeem_scripts[in_index], sig,
                                       self.keys["ins"][in_index][cp],
                                       witness="deadbeef",
                                       amount=self.ins[in_index][1]):
                cslog.info("Error in include_signature: signature invalid: " + sig)
                return False
            else:
                self.signatures[in_index][cp] = sig
                if all([self.signatures[in_index][x] for x in range(self.n_counterparties)]):
                    self.completed[in_index] = True
                return True
        elif tp  == "p2sh-p2wpkh":
            #counterparty's promise signature
            #verification check
            scriptCode = "76a914"+btc.hash160(binascii.unhexlify(pub))+"88ac"
            if not btc.verify_tx_input(self.base_form, in_index, scriptCode,
                                       sig, pub, witness="deadbeef",
                                       amount=self.ins[in_index][1]):            
            #if not btc.verify_tx_input(self.base_form, in_index,
            #                           self.signing_redeem_scripts[in_index],
            #                           sig, self.keys["ins"][in_index][cp],
            #                           witness="deadbeef",
            #                           amount=self.ins[in_index][1]):
                cslog.info("Error in include_signature: signature invalid: " + sig)
                return False
            else:
                self.signatures[in_index] = [sig]
                self.completed[in_index] = True
                return True

    def fully_signed(self):
        if all([self.completed[x]==True for x in range(len(self.ins))]):
            return True
        else:
            return False

    def attach_signatures(self):
        """Once all signatures are available,
        they can be attached to construct a "fully_signed_tx"
        form of the transaction ready for broadcast (as distinct
        from the "base_form" without any signatures attached).
        """
        assert self.fully_signed()
        self.fully_signed_tx = copy.deepcopy(self.base_form)
        for idx in range(len(self.ins)):
            tp = self.template.ins[idx].spk_type
            assert tp in ["NN", "p2sh-p2wpkh"]
            if tp == "NN":
                self.fully_signed_tx = btc.apply_p2wsh_multisignatures(
                    self.fully_signed_tx, idx, self.signing_redeem_scripts[idx],
                    self.signatures[idx])
            else:
                k = self.keys["ins"][idx][self.keys["ins"][idx].keys()[0]]
                dtx = btc.deserialize(self.fully_signed_tx)
                dtx["ins"][idx]["script"] = "16" + btc.pubkey_to_p2sh_p2wpkh_script(k)
                dtx["ins"][idx]["txinwitness"] = [self.signatures[idx][0], k]
                self.fully_signed_tx = btc.serialize(dtx)

    def set_txid(self):
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
        msg.append(tx)
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
            cslog.info("Failed to deserialize OCCTx object")
            return False

class Outpoint(object):
    def __init__(self, n, counterparty, amount=None, txobj=None, txid=None):
        self.txobj = txobj
        self.n = n
        #used for pre-existing outpoints (inflows/promises)
        self.txid = txid
        if counterparty == -1:
            self.spk_type = "NN"
        else:
            self.spk_type = "p2sh-p2wpkh"
        self.counterparty = counterparty
        if isinstance(amount, float):
            self.amount = btc_to_satoshis(amount)
        else:
            self.amount = amount
    def __repr__(self):
        return "Outpoint: %s %s %s %s" % (str(self.n), str(self.counterparty),
                                          self.spk_type, str(self.amount))

#In the template model, the transactions *possess* their outputs.
#Inputs are back-links to outpoints of parent transactions.
class OCCTemplateTX(object):

    def __init__(self, outs_info, ins, pre_tx_balances, min_fee=10000, max_fee=100000):
        self.pre_tx_balances = pre_tx_balances
        self.min_fee = min_fee
        self.max_fee = max_fee
        #this will be a list of Outpoints
        self.ins = ins
        self.outs = []
        #this will create a new list of Outpoints
        self.generate_outpoints(outs_info)
        self.validate_balance()
        #calculate the assignment of coins to each counterparty after
        #this transaction has gone through
        self.calculate_post_tx_balance()

    def generate_outpoints(self, outs_info):
        """
        Txnumber, index, counterparty number, amount
        The info should take the form of a list of tuples,
        first item is the number of this tx,
        second is the outpoint index, third is the counterparty number,
        if this is -1, then this output will be NN co-owned.
        lastly the amount *fraction* of the output assigned (from which
        exact amounts are immediately calculated based on the input sum).
        """
        print("working with ins list: " + str(self.ins))
        total_input_amount = sum([x.amount for x in self.ins])
        self.total_payable = total_input_amount - self.min_fee #TODO
        #We allow explicit Outpoint insertion in case the caller
        #already calculated the correct exact amounts:
        if all([isinstance(x, Outpoint) for x in outs_info]):
            self.outs = outs_info
        else:
            for oi in outs_info:
                amt = int(round(Decimal(oi[3]) * Decimal(self.total_payable)))
                self.outs.append(Outpoint(oi[1], oi[2], amt, self))
        

    def validate_balance(self):
        #transaction level rules can be checked immediately
        #on creation: bitcoin coin creation consensus check,
        #and positive outputs.
        assert sum([a.amount for a in self.outs]) <= sum([a.amount for a in self.ins])
        assert all([a.amount>0 for a in self.outs])

    def calculate_post_tx_balance(self):
        self.post_tx_balances = []
        for i, pre in enumerate(self.pre_tx_balances):
            self.post_tx_balances.append(pre)
            for inp in self.ins:
                if inp.counterparty == i:
                    self.post_tx_balances[-1] -= inp.amount
            for o in self.outs:
                #for this particular output, we must subtract its value,
                #but also the amount of the fees for the transaction
                #that were assigned to it, pro-rata, with the other outputs.
                out_frac = Decimal(o.amount)/Decimal(self.total_payable)
                fee = int(round(out_frac * self.min_fee))
                if o.counterparty == i:
                    self.post_tx_balances[-1] += o.amount

    def contains_promise(self):
        return any([x.counterparty != -1 for x in self.ins])

    def co_owned_outputs(self):
        return [x for x in self.outs if x.counterparty == -1]

    def __repr__(self):
        return ('Transaction: pre-tx balances: %s\ninputs: %s, outputs '
               '%s\npost-tx balances: %s' % (self.pre_tx_balances, self.ins,
                                             self.outs, self.post_tx_balances))

class OCCTemplate(object):

    def __init__(self, template_data_set):
        #number of counterparties
        self.n = template_data_set["n"]
        #number of transactions
        self.N = template_data_set["N"]
        #This lists the output indices for each transaction which are to be
        #co-owned outputs and their relative proportions
        #(Tx number:index, Counterparty number, amount fraction)
        #-1 is used for counterparty number when the output is co-owned by all.
        self.out_list = template_data_set["out_list"]
        #list of items of type Inflow: [(txnumber, input number, Inflow object)]
        self.inflows = template_data_set["inflows"]
        #Process:
        #loop starting at 0 for N transactions
        #For 0 we construct a transaction with inputs all inflow objects for index 0.
        funding_ins = [Outpoint(x[4], x[1], x[2], None, x[3]) for x in self.inflows if x[0] == 0]
        print("Got funding ins: " + str(funding_ins))
        funding_tx = OCCTemplateTX([x for x in self.out_list if x[0] == 0], funding_ins, [0, 0])
        self.txs = [funding_tx]
        for i in range(self.N)[1:]:
            #source the inputs from: the inflow list, and the co-owned outpoints of the previous
            #tranasaction (TODO this is a restriction in the model)
            our_inflows = [Outpoint(x[4], x[1], x[2], None, x[3]) for x in self.inflows if x[0] == i]
            our_outputs_info = [x for x in self.out_list if x[0] == i]
            our_co_owned_inputs = [x for x in self.txs[i-1].outs if x.spk_type == "NN"]
            self.txs.append(OCCTemplateTX(our_outputs_info, our_co_owned_inputs + our_inflows,
                                          self.txs[i-1].post_tx_balances))

        #Automatically generate a second list of transactions: backout transactions
        #Find all txs in self.txs that have at least one outpoint that is not "NN".
        #Create a backout tx consuming the *previous* tx's NN outpoints.
        #Assign the balances in proportion to each party's owed coins.
        self.backout_txs = []
        for i, t in enumerate(self.txs[1:]):
            print("Starting for loop for tx: ", t)
            if t.contains_promise():
                backout_outs = []
                backout_ins = self.txs[i].co_owned_outputs()
                #outputs pay to each counterparty what they are owed.
                #Take the sum of the value of the outpoints being consumed.
                #Subtract the fee. -> X.
                #Take the proportions of what each party is owed.
                #For each party j, assign an outpoint of value X*proportion_j
                idx = 0
                X = sum([x.amount for x in backout_ins])
                total_owed = sum(self.txs[i].post_tx_balances)
                for j in range(self.n):
                    owed = self.txs[i].post_tx_balances[j]
                    prop = Decimal(owed)/Decimal(total_owed) #both negative, so positive
                    fee = int(round(Decimal(10000)/Decimal(self.n))) #TODO hardcoded fee
                    adjusted_X = X - fee
                    assigned_redemption = int(round(Decimal(adjusted_X) * prop))
                    if assigned_redemption > 0:
                        print("Creating an outpoint for the backout tx of value: ", assigned_redemption)
                        backout_outs.append(Outpoint(idx, j, assigned_redemption))
                        idx += 1
                self.backout_txs.append(OCCTemplateTX(backout_outs, backout_ins,
                                                 self.txs[i].post_tx_balances))

    def keys_needed(self, counterparty):
        """How many distinct public keys counterparty counterparty
        needs to provide to fill out the template, *NOT* including promises.
        """
        total = 0
        for t in self.txs:
            for to in t.outs:
                if to.spk_type == "p2sh-p2wpkh" and to.counterparty != counterparty:
                    continue
                #for NN type, exactly one will always be needed
                total += 1
        for t in self.backout_txs:
            for to in t.outs:
                #backout outpoints are never NN
                if to.counterparty == counterparty:
                    total += 1
        return total

    def __repr__(self):
        """Used for human readable presentation of
        the template.
        """
        return "Template:\n" + "\n".join([repr(x) for x in self.txs]) + \
            "\nBackout transactions:\n" + "\n".join([repr(x) for x in self.backout_txs])
        

def get_our_keys(wallet, N):
    """This will simply source N new addresses from mixdepth 1,
    external branch (the branch for receiving), and return the
    pubkeys with the addresses
    """
    our_addresses = [wallet.get_external_addr(1) for _ in range(N)]
    our_pubkeys = [btc.privkey_to_pubkey(wallet.get_key_from_addr(x)) for x in our_addresses]
    return our_pubkeys, our_addresses

def get_utxos_from_wallet(wallet, amtdata):
    """Retrieve utxos of specified range, from mixdepth 0 (source of funds)
    """
    utxos_available = wallet.get_utxos_by_mixdepth()[0]
    cslog.info("These utxos available: " + str(utxos_available))
    
    utxos_used = []
    for ad in amtdata:
        utxo_candidate = None
        for k, avd in utxos_available.iteritems():
            hsh, idx = k.split(':')
            idx = int(idx)
            val = satoshis_to_btc(avd['value'])
            if val >= ad[0] and val <= ad[1]:
                pub = btc.privkey_to_pubkey(
                    wallet.get_key_from_addr(avd['address']))
                if not utxo_candidate:
                    utxo_candidate = (hsh, val, pub, idx)
                else:
                    if abs(val - (ad[0]+ad[1])/2.0) < abs(
                        utxo_candidate[1] - (ad[0]+ad[1])/2.0):
                        utxo_candidate = (hsh, val, pub, idx)
        utxos_used.append(utxo_candidate)
    if len(utxos_used) < len(amtdata):
        return (False, "Could not find utxos in range")
    else:
        return (utxos_used, "OK")

def create_realtxs_from_template(wallet, template, ncp, cp, lt):
    realtxs = []
    realbackouttxs = []
    for tx in template.txs:
        realtxs.append(OCCTx(tx, wallet, ncp, cp))
    for tx in template.backout_txs:
        realbackouttxs.append(OCCTx(tx, wallet, ncp, cp, locktime=lt))
    return realtxs, realbackouttxs

def apply_keys_to_template(wallet, template, realtxs, realbackouttxs,
                           promise_ins, keys, ncp, cp):
    #Create tx instantiations for all txs in graph. Insert the keys
    #in the right (deterministic) order.
    #****The Determinstic Ordering of Keys****
    #1. template_ins: these keys are for promises; they can be applied first.
    #  (note here we are considering the funding inputs as "promises")
    #Counterparty_keys:
    #2. First set are for all NN outpoints created. The keys must be applied
    #   to those outputs, but also to the inputs where they are consumed.
    #2a. This also applies to the backout transactions where those same outputs
    #    are consumed.
    #3. After (2) keys are consumed, we must also supply keys for the single-owned
    #   outputs within non-backout txs.
    #4. Finally, the remaining keys are used for backout outs, which are
    #   always single-owned.
    #Step 1 as above
    promise_ins_c = copy.deepcopy(promise_ins)
    keys_c = copy.deepcopy(keys)
    for i, tx in enumerate(template.txs):
        #first apply the keys for promises
        for j, tin in enumerate(tx.ins):
            if tin.counterparty == cp:
                realtxs[i].apply_key(promise_ins_c.pop(0), "ins", j, cp)
    #Step 2 and 2a as above
    for i, tx in enumerate(template.txs):
        for j, to in enumerate(tx.outs):
            if to.spk_type == "NN":
                working_key = keys_c.pop(0)
                realtxs[i].apply_key(working_key, "outs", j, cp)
                #search for the inpoint of the *next* transaction(TODO: assumption)
                for k, tin in enumerate(template.txs[i+1].ins):
                    if tin.amount == to.amount and tin.spk_type == "NN":
                        realtxs[i+1].apply_key(working_key, "ins", k, cp)
                #do the same for any backout txs
                #TODO: stupid assumption of matching amount, as no other
                #current way of finding backout's parents
                for l, btx in enumerate(template.backout_txs):
                    for k, tin in enumerate(btx.ins):
                        if tin.amount == to.amount:
                            realbackouttxs[l].apply_key(working_key,
                                                        "ins", k, cp)
    #Step 3 above
    for i, tx in enumerate(template.txs):
        for j, to in enumerate(tx.outs):
            if to.spk_type == "p2sh-p2wpkh" and to.counterparty == cp:
                realtxs[i].apply_key(keys_c.pop(0), "outs", j, cp)
    #Step 4 above
    for i, btx in enumerate(template.backout_txs):
        for j, to in enumerate(btx.outs):
            if to.counterparty == cp:
                realbackouttxs[i].apply_key(keys_c.pop(0), "outs", j, cp)
    return realtxs, realbackouttxs

def get_counterparty_setup(serv, port, amtdata):
    sckt = create_sock(serv, int(port))
    #send Act One
    sckt.send(json.dumps(amtdata))
    rspns = recv_socket(sckt)
    print("Got response to get counterparty setup: ", rspns)
    return json.loads(rspns)

def get_counterparty_keys(serv, port, template_inputs,
                          our_keys, template_data_set):
    tosend = {"template_ins": template_inputs,
              "our_keys": our_keys,
              "template": template_data_set}
    sckt = create_sock(serv, int(port))
    sckt.send(json.dumps(tosend))
    rspns = recv_socket(sckt)
    print("Got response from get counterparty keys: ", rspns)
    return json.loads(rspns)

def get_counterparty_funding_sigs(serv, port, sigs_to_send):
    sckt = create_sock(serv, int(port))
    sckt.send(json.dumps(sigs_to_send))
    rspns = recv_socket(sckt)
    print("Got response from get counterparty funding sigs: ", rspns)
    return json.loads(rspns)

    