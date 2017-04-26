This was originally hosted [here](https://gist.githubusercontent.com/AdamISZ/350bb4038834019eb0c06ec69446aec9/raw/74af8368cd5d613d75f39a426384924ad3fe18da/Newcoinswap-backout.md)

These notes refer to the setup described in table and diagram form [here](coinswap_new.pdf).


### Why tweak the original Coinswap design.

The original design is explained in [the original CoinSwap post](https://bitcointalk.org/index.php?topic=321228.0).
The reason for attempting to come up with a modification is seen in the diagram line E:

```
E.Computes TX_2: TX_0>Carol+X |                            |                           | Phase 1
F.Send TX_2     ------------> 
```

At this step, in the process, Carol does not possess the secret X, so cannot spend *out* of the address
corresponding to `Carol+X`, but she can however simply spend *into* that address. By doing so, she has
locked up the funds originating in `TX_0`; the original timeout is now invalidated.
Even though she cannot claim those funds, this situation is unacceptable
(reverts to game-theory style MAD arguments as to whether she will cooperate).

### Broad outline of the tweak, in words.

Thus, the modification described here attempts to fold in the timeout from `TX_0` into the same transaction
as the atomically-released secret part. If either side is uncooperative, they are always defended by (a)
timeout, and (b) the atomic redeemability based on the secret. There is nothing particularly new about
this type of transaction, e.g. it is used in Tumblebit (and probably other places, perhaps it was in the
CLTV BIP as an example, I forget). Here is an example, see above imgur link for more details:

```
OP_IF OP_HASH160 H(X) OP_EQUALVERIFY <carol_pubkey>  OP_CHECKSIG
OP_ELSE <locktime-0> OP_CLTV OP_DROP <alice_pubkey> OP_CHECKSIG
OP_ENDIF
```

What's unchanged: both sides prepare a spend-in (TX-0, TX-1) to the 2 2-of-2 addresses, and pass over the txid.
Alice passes over the hash of X. Then both sides prepare the same TX-2 and TX-3 backout transactions, with 
scriptPubKeys as above (p2sh wrapped of course), and both sign and pass signatures, so
both sides have broadcast-able versions of these backouts in advance of publishing TX-0 and TX-1.

Then both sides broadcast TX-0, TX-1. Then Alice passes the secret X to Carol, enabling her backout path via
the secret in case Alice uses the secret to backout. Then both sides (as per original Coinswap) make "normal"
output transactions from TX-0, TX-1 to TX-4, TX-5, superceding the backout transactions, and broadcasting them.


### Iteration of defensive backout process in case of non-cooperation.

(Note all sigs on TX2 and TX3 are swapped and validated beforehand)

X = the coinswap secret

L0 = time lock on Alice pubkey redemption on TX2.

L1 = time lock on Carol pubkey redemption on TX3.

L1 < L0.

(Note all sigs on TX2 and TX3 are swapped and validated before funds committed.)

### Carol malicious, Alice defence

(1) Until TX0 is broadcast, no coins are committed, no action required.

(2) After TX0 broadcast, if TX1 is not broadcast: Since the X has not been revealed,
just wait until L0 to broadcast TX2 using timeout and then spend out of it.

(3) TX1 broadcast and X is sent to Carol.

-(a) If Carol is unresponsive, redeem and spend out of TX3, using X, before L1.

-(b) Carol spends TX2, same as (a).
 
(4) If TX5 sig received and valid, broadcast to receive funds (before L1).

### Alice malicious, Carol defence

(1) Until TX1 is broadcast, no coins are committed; no action required.

(2) If Alice does not send X after TX1 confirmed: wait until L1, monitor:

-(a) If at any time before L1 Alice spends TX3 using X, spend TX2 using X.

-(b) If Alice does not do (a), spend out of TX3 after L1 passed.

-(c) If Alice successfully double spends TX3 from (b), use X to spend TX2.
  
  As long as this all happens well before L0, Carol is safe.

(3) Alice receives TX5 sig and spends TX1->TX5 but does not return a TX4 sig:
Carol redeems and spends out of TX2 using the secret (safe before L0).

(4) If TX4 sig received and valid, broadcast to receive funds (before L0).
