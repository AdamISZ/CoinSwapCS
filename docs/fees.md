(Edited form of [this issue comment](https://github.com/AdamISZ/CoinSwapCS/issues/8#issuecomment-299255003).

[Link to sketch diagram](http://imgur.com/a/m54m7), it may help to understand.

### Fees and amount obfuscation

The main goals:

* to prevent Carol losing any funds if Alice is malicious (first priority)
* Carol to receive a positive income for the service
* Prevent DOS attacks against the server (locking up coins, not network layer DOS)
* Obfuscate the amounts in the transactions to make it harder to link the two payment flows.

This design may well be updated in future if a better way to achieve all the above
goals is found.

##### Definition of terms:

* cf = coinswap fee
* bf = an amount representing the approximate cost of a bitcoin transaction with one input
* &#916; - an offset amount used by Carol for amount ambiguation
* x - the nominal amount of the swap in BTC
* '.' is used for multiplication (to disambiguate with 'x').

Remember that we don't know in advance which of TX2 or TX3 will be used by Alice in any backout; and moreover, Alice can choose which. So the TX2 and TX3 outputs more or less have to be the same, or at least, it's pointless to create a different one such that one is more advantageous to a malicious Alice, as she will always pick that one in that case.

The main idea is: **add a second output to the backout transactions TX2/TX3, redeemable by Carol only** (let's say p2pkh for simplicity). This allows Carol to always receive more from the backout than Alice, most importantly allowing Carol never to lose funds in case of backout/failure. 

The secondary idea is the use of a "blinding" &#916; amount by Carol, as already mentioned above.

### Structure of transactions:

Funding transactions; note the code already randomises the output order, for simplicity we assume output 0 is the 2/2 funding utxo:

TX0
====
Input | Input Value | -> | Output | Output value
--- | --- | --- | --- | --- 
(From wallet) | x + cf + bf.4 + (wallet selection) | | 2_2_AC | x + cf + bf.3
 | | | | (to wallet) | (change amount)

TX1
====
Input | Input Value | -> | Output | Output value
--- | --- | --- | --- | --- 
(From wallet) | &#916; + x + cf + bf,4 + (wallet selection) | | 2_2_CB | &#916; + x + cf + bf.3
 | | | | (to wallet) | (change amount)

Next pair are the cooperative outputs; TX4 goes to Carol, TX5 goes to Alice; note there is an open issue to add pseudo change address here, #17 . This could be additional to this basic structure.

TX4
====
Input | Input Value | -> | Output | Output value
--- | --- | --- | --- | --- 
TX0:0 | x + cf + bf.3 | | Carol only | x + cf + bf.2

TX5
====
Input | Input Value | -> | Output | Output value
--- | --- | --- | --- | --- 
TX1:0 | &#916; + x + cf + bf.3 | | Alice only | x
 | | | | Carol only | &#916; + cf + bf.2

The backout transactions; they must as mentioned above have the same output amounts, but here we add an additional Carol only output


TX2
====
Input | Input Value | -> | Output | Output value
--- | --- | --- | --- | --- 
TX0:0 | x + cf + bf.3 | | (Carol, secret) or (Alice, timeout) | x + bf
 | | | | Carol only | cf + bf

TX3
====
Input | Input Value | -> | Output | Output value
--- | --- | --- | --- | --- 
TX1:0 | &#916; + x + cf + bf.3 | | (Alice, secret) or (Carol, timeout) | x + bf
 | | | | Carol only | &#916; + cf + bf

#### Accounting

Carol inputs &#916; + x + cf + bf.3. In cooperative case she received back (&#916; + cf + bf.2 from TX5) + (x + cf + bf.2 from TX4), for a net gain of (cf + bf). In recovery case she receives back (x + bf from TX2 or TX3), and (&#916; + cf.2 + bf.2 from both), for a net gain of (cf). However she needs to redeem that backout, so it's actually (cf - bf) gain realistically.

Alice inputs x + cf + bf x 4. In cooperative case she received back (x from TX5) for a net payment of cf + bf.4. In recovery case she receives back (x + bf from TX2 or TX3) for a net payment of cf + bf.3; however she also needs to pay 1 bf to redeem the backout transaction (usually), so it's basically the same cost (cf + bf.4) (without the privacy boost).

#### Amount correlation, privacy issues

The use of a blinding &#916; is a help, but it needs investigation how much. The main TX4/TX5 outputs can be pretty obfuscated with the use of that; you could split them up with fake changes. You could also make &#916 whatever makes it most obfuscated.

The idea that TX5 can have an output to *both* Alice and Carol doesn't seem to be a problem; Alice can take that utxo knowing it has no connection to *her* history.

Carols cf + bf output from TX2 is going to be small; but by design should be spendable to an output of cf (doesn't have the time priority requirement that the other custom redeem script output has).

#### Anti-DOS feature, but also a drawback:

In the case that Carol is unresponsive after the broadcast of TX0, Alice must back
out via TX2, which still pays Carol cf + bf. In this case Alice will not be very
happy about paying an unresponsive server, but will not use it again.

Meanwhile, note that this enforces a cost on Alice, whatever the outcome;
so there is a cost to DOSing the server. If backout of TX0 was costless,
Alice could lock up the server's coins by starting but always backing out via TX2.