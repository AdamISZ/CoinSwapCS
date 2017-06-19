## State management in CoinSwapCS

Coinswap is a stateful protocol, in the sense that each side must take actions
contingent on the current state. The purpose of state tracking is to ensure that
each participant is always safe from losing funds (modulo a coinswap fee, on the
client side - see the [fees](fees.md) document for details on this), *no matter
what error occurs*. Errors here include:

* Code bugs (except for bugs in state management, of course!)
* Network failures of any type
* Hardware failures
* Power loss

Note that this list does not include:

* Invalid Bitcoin state (we assume that the blockchain access via Bitcoin Core is
doing its job correctly)
* User error - **but** the decision making requirement placed on the user is reduced
to the bare minimum. The most likely failure on the user side is failure to execute
a backout transaction (after some catastrophic failure e.g. a crash) before the
prescribed timeout; and this only creates the *risk* of loss of funds if the other
side is malicious.

The above failure modes were discussed a bit in the README for the project.

The state machine flow here is only identifying the transition of states that occur
for a **cooperative, successful** CoinSwap. If any state transition fails to occur
in the predetermined time window, then we go to backout, as documented [here](backout.md).

The state transitions are strictly forward-only, in a single flow.

Backout is currently designed to be 100% non-interactive, although theoretically it's
entirely possible to try to re-establish cooperation in certain scenarios. But that's
a lot more complicated design wise. Hence, entering 'backout' mode means the state
machine described here stops, and does not ever continue further.

The state machine is found in `coinswap/state_machine.py` and enforces the following
process:

* On starting the `tick` function, receive as argument a set of inputs, including
the proposed state transition function
* Check that the state transition process is not current running: if so, stop. If not,
set the state transition processing lock to True.
* Check that the state machine has not been "frozen" (if in backout mode, state
machine must not proceed).
* Execute the appropriate state transition function, wrapped for *all* exceptions.
* If error or exception is raised, move to backout mode, passing in the current state.
* If state transition function is successful, increment state (`self.state +=1`,
occurs in exactly one [place](https://github.com/AdamISZ/CoinSwapCS/blob/master/coinswap/state_machine.py#L111).
* Execute `self.finalize()` code: this means calling a `persist()` function which
persists the entirety of the current state to disk. The main objects `CoinSwapTx`,
`CoinSwapPublicParameters` and `CoinSwapParticipant` have `serialize()` methods
to support this. The data is stored in the unique session file in json format.
* Start the `self.stallMonitor()` function to wake up after the timeout for the
newly incremented state, and, in that function, check if the next state transition
has completed by examining the value of `self.state`; if not, go into backout mode.
* Set the state transition processing lock to False.
* If the just-completed state has flag `auto_continue`, automatically execute the next state
transition (in other cases, wait for a callback to fire `self.tick()` before doing so).
* Output of state transition function is returned to the caller.

The design enforces (a) always persisting state immediately after successful transition, (b)
catching any kind of error (including bugs) and moving to the appropriate backout
code in this case, (c) not allowing the completion of the next state to take longer
than the specified timeout (if it does, also backout), (d) locking access to state transition function so it is done in serial.

Since this design does not always automatically fire the next state transition (which
it cannot, since the protocol is interactive with a counterparty), the actual state
flow is like this:

1. Post-state N-1 = Pre-state N
2. State N started, transition N in process
3. Transition N completed = Post-state N = pre-state N + 1
4. State N+1 started, transition N + 1 in process
5. Post-state N+1 ...

In cases where `auto_continue` is set for state N, the entry 3 in the above list
would not occur.

### States / transitions

#### Alice (the client)

```
    State machine:
    State 0: pre-initialisation
    State 1: handshake complete
    State 2: Parameter negotiation initiated.
    State 3: Parameter negotiation complete.
    ========SETUP PHASE===============================
    State 4: TX0id, H(x), TX2sig sent to Carol.
    State 5: TX1id, TX2sig, TX3sig received from Carol.
    State 6: TX3 sent to Carol.
    State 7: TX0 broadcast.
    State 8: TX0, TX1 seen
    State 9: TX0, TX1 seen confirmed by Carol
    ==================================================
    
    ========REDEEM PHASE==============================
    State 10: X sent to Carol.
    State 11: TX5 sig received, validated
    State 12: TX5 broadcast.
    State 13: Sent TX4 sig. (complete)
    ==================================================
```

(this and the next table are lifted from the code, `coinswap/alice.py`).

From the point of view of the protocol, the only state transitions that really
matter are: 6 -> 7 (TX0 is on the network), 7->8 (TX1 is confirmed),
9 -> 10 (X is sent), 10 -> 11 (TX5 is valid), 12-> 13 (TX4 is valid). The others
are tracked for better keeping track of information. For example, although data
has been gathered up to state 6, no Bitcoin transactions have been broadcast, so
failure does not require action.


### Carol (the server)

```
    State machine:
    State 0: pre-initialisation
    State 1: handshake complete
    State 2: Parameter negotiation complete.
    ========SETUP PHASE===============================
    State 3: TX0id, H(x), TX2sig received from Alice.
    State 4: TX1id, TX2sig, TX3sig sent to Alice.
    State 5: TX3 sig received and TX0 seen confirmed.
    State 6: TX1 broadcast and confirmed.
    ==================================================
    
    ========REDEEM PHASE==============================
    State 7: X received.
    State 8: Sent TX5 sig.
    State 9: TX4 sig received valid from Alice.
    State 10: TX4 broadcast.
    ==================================================
```
