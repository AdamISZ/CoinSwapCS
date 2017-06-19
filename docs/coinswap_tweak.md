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

This sequence of actions is shown in the high level design illustration [here](coinswap_new.pdf), as mentioned at the start of this doc.

The workflow for backing out in case each side fails to follow protocol are listed in the [backout document](backout.md).
