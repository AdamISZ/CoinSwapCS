### Iteration of defensive backout process in case of non-cooperation.

(Note all sigs on TX2 and TX3 are swapped and validated beforehand)

(As a reminder, Alice is the client and Carol the server in CoinSwapCS).

#### Definitions

X = the coinswap secret

L0 = time lock on Alice pubkey redemption on TX2.

L1 = time lock on Carol pubkey redemption on TX3.

L1 < L0.

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
