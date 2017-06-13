# CoinSwap-CS
A simple implementation of CoinSwap with Carol as server and Alice as client.

## Navigation

[What is CoinSwap](#coinswap-basics) ?

[More details on how it's done here](#coinswap-details).

[Is this ready to use](#project-readiness)?

[How to install it](#installation)?

[Risk factors](#risk-factors)

[What needs doing](#todo-list)

[Testing](#testing)

[More background on the ideas](#background)

### Coinswap basics

CoinSwap was [proposed](https://bitcointalk.org/index.php?topic=321228.0) in 2013
by Gregory Maxwell; I'd advise reading through the general outline in that post
first, even though you're unlikely to understand it all at once. It gives the main
motivation - break the history of the coins you own by "swapping" some of your
coins with someone else, but without having to trust them to *hold* your coins. It
also gives a lot of useful context, such as how it compares with CoinJoin.

Absolute brain-dead description: you pay in coins to a 2 of 2 address you agree
with your counterparty, and after a little time, you get out coins from a different
2 of 2 address, which *originally* came from your counterparty, so your new coins
have none of your old history. They're "disconnected". *You never have to trust the
other side with your coins*.

If you want more info about the general ideas without delving into code, jump to
[background](#background).

### Coinswap details

The original proposal contains a flaw; I have written up a brief description of
my own proposed fix [here](docs/coinswap_tweak.md),
and it's this version of the protocol that's implemented in this code. I would
welcome further peer review on this; there may be other tweaks possible to the
basic arrangement.

Critical to making it work is:
 * accurate and up to date blockchain information - hence this code assumes use of
 Bitcoin Core as a full node
 * Recovery in case of any malicious or accidental failure - hence the code
 persists the current state at every step to allow either party to recover and
 claim their coins, including if the code or machine crashes.

The "CS" in "CoinSwapCS" refers to "client-server"; this is a slightly squishy
point. The intention is not of course to have a "single server" that everyone
uses; this loses a lot of the value, and is dangerous. Rather, the intention is
to have long-lived participants serving clients, to make it easier to use. There
is no restriction on who can be such a server, other than having to stand it up
on a machine with a hot wallet. The exact way this is done is left open; it could
be on a hidden service over Tor for example, or communication could happen over IRC
etc. For now there is a simple HTTP server provided serving JSON-RPC requests, and
TLS will be added shortly.

##### Who are Alice and Carol?

There are references to Alice and Carol peppered around, this is an artifact of the
fact that the original proposal was for Alice to send coins to Bob via Carol, but
there is no requirement for 3 people to be involved. The more natural case is Alice
also acting as Bob (so Alice is the receiver as well as the sender), so that this
becomes a 2 party rather than 3 party protocol. Of course Alice could send Bob
coins using this, in that the recipient address might not be Alice's own (but bear
in mind since it's a little slow this use case is a bit impractical). So for now,
just treat "Alice" as "client" and "Carol" as "server", with the effect that the
two parties swap the history of their coins.

##### Should they really be "client" and "server"?

As you'll understand from reading more into the technical design of CoinSwap, it's
very undesirable for the protocol to fall into "backout" mode. You lose a small
amount of extra fees, you lose a *lot* of time in some cases (the most important),
and you are potentially losing privacy - instead of your transactions looking like
other P2SH transactions, they are now unambiguously CoinSwap style transactions,
and moreover, you may not end up getting disconnected coins, depending on the
specific backout that happens - then you'll have wasted money and time for nothing.

Avoiding this scenario if your counterparty is malicious is hard, so it makes sense
to be a bit less ambitious, and have a more client-server mode where the server can
still be anonymous, but more like pseudonymous - e.g. running the "service" via
Tor. That way a "client" can rely on the reputation of servers that he has some
vague confidence are unlikely to cause him annoyance by backing out. Now, of
course, if *everyone* uses one server, then that server has a ton of private
address-connecting information, which is not desirable. But it's a little like
VPNs - trusting them to never reveal logs is not very realistic, but imagine being
able to mix and match lots of different ones. You could use many different
"CoinSwap" servers, especially if they're easy to set up. And even if you didn't,
you've vastly changed what a snooper has to achieve in order to connect all your
coins.

### Project readiness

Is this ready to use? **NO**.

The status of this section will change. For now, there are still quite a bunch of
things not really quite complete; it isn't quite ready for testnet testing, even.
The open issues are listed in [What needs doing](#todo-list).

### Installation

This code uses Python 2.7. (Yes, I know!)

(TODO: not sure the exact apt-get dependencies for this).

Start by making and activating a virtualenv:

    sudo pip install virtualenv
    mkdir coinswapenv
    cd coinswapenv; virtualenv .; source bin/activate; cd ..
  
Follow the instructions to install Joinmarket client/bitcoin code from
[this](https://github.com/AdamISZ/joinmarket-clientserver) repo. The reason for
doing this is to pick up the bitcoin and wallet code from Joinmarket (this project
reuses that code, and so the wallets are compatible with Joinmarket).

The instructions are:

    git clone https://github.com/AdamISZ/joinmarket-clientserver
    cd joinmarket-clientserver
    python setupall.py --client-bitcoin
    cd ..

Then you need this repo

    git clone https://github.com/AdamISZ/CoinSwapCS; cd CoinSwapCS
    python setup.py install

To connect to a server you'll then need its hostname and port, then do a status check with
`python coinswap_run.py -s https://url:port -C` (the config file in `~/.CoinSwapCS/coinswapcs.cfg` will need edits after the first run).

If using a hidden service, install tor and instead use:
`torsocks python coinswap_run.py -s http://onionurl:port -C`

### Risk factors

Coinjoin is perfectly atomic in the sense that a single coinjoin transaction either
happens or it doesn't. Coinswap being a multi-transaction protocol, it requires a bit
more. Here are the things that can go wrong:

 * If your blockchain interface (to Bitcoin Core) is giving you wrong information,
 you may think that a transaction has happened when it hasn't. This could result
 in loss of funds. This is a very difficult attack for someone to pull off, if
 you're running a full node in a sensible way (Of course, this attack can be used
 against other things than CoinSwap too).
 * If your program crashes, or you lose power, or the other side crashes or gives
 wrong information, or there is a serious network failure: all of these cases are
 handled by the "backout" code, which will reclaim your funds - but if it was your
 side that crashed (if not, the backout happens in-run), you must restart
 before the timeout to be sure of keeping your funds. Hence, this is not a "set and
 forget" protocol. If all goes well, you will only need to wait for a couple of
 confirmations (by default) on the first transaction, plus a short amount of time
 afterwards, to be sure that the protocol completed OK and you're safe. But if during
 that time, something goes wrong, you may have to wait considerably longer - a few
 hours, to be *sure* of receiving the funds back.
 * Loss of files - if you remove or lose the session file
 (stored in `~/.CoinSwapCS/sessions` by default), *and* your own program crashed
 or stopped, the funds will be unrecoverable. Obviously this is highly unlikely.

Clearly it's the second of those three that is the most concern: CoinSwap is not
something you can start running and then go off on a journey. You should be *prepared*
to hang around for a few hours, although the vast majority of the time, you won't
have to. This could be greatly improved with more sophisticated code to restart,
but that won't help if there's a power outage, for example.

### TODO list

It goes without saying that help with this would be appreciated!

Using this repo's Issues list to track this.

You can find a list of [features](https://github.com/AdamISZ/CoinSwapCS/issues?q=is%3Aopen+is%3Aissue+label%3Aenhancement)
that are needed and [bugs](https://github.com/AdamISZ/CoinSwapCS/issues?q=is%3Aopen+is%3Aissue+label%3Abug) to fix.

### Testing

The instructions on how to test are in the [test README](test/)
### Background

Some background motivation might be in order here: this project is part of the
ongoing efforts to improve Bitcoin's fungibility. There are now a lot of different
approaches being taken to this, including: Coinjoin (see [Joinmarket](https://github.com/Joinmarket-Org),
see Coinshuffle, under development, plus other implementations like DarkWallet and SharedCoin which
are no longer active), there's also [Tumblebit](https://github.com/NTumbleBit),
currently in testing on testnet, stealth addresses, you could even add OpenDime,
plus projects with a broader scope but including fungibility/privacy like the Lightning
Network.

My first contact with CoinSwap was having Peter Todd point me to it in a half-derelict
building in Milan nearly 4 years ago (long story!). I didn't really understand it
except in very broad terms, but it was a class of ideas that people have been
mulling over for many years. See e.g. the idea [Atomic Cross Chain Swaps](https://bitcointalk.org/index.php?topic=193281.msg2224949#msg2224949)
, which is related but not the same. So lots of "mulling over" occurred, but as far
as I can see no one actually implemented CoinSwap in code anywhere in the last 4
years. And in the meantime other, more advanced "contracts" have been developed
which shared at least some aspect of this basic idea (see e.g. the "HTLC" or
"hash time locked contract", which forms a critical piece of the Lightning Network
design). And TumbleBit also uses a somewhat similar concept, but considerably
"souped up" by adding the cut-and-choose protocols allowing payment for Bitcoin
signatures (long story here too, but if you are interested in this stuff I *highly*
recommend taking the time to understand it). So CoinSwap in this broader context,
is almost like a kind of old curiosity - an idea that never really went very far. Why
is this?

I think a big part of the answer is inconvenience. Coinjoin is by nature a very
"lazy" protocol. It's very simple, because it's actually just Bitcoin - literally.
Any Bitcoin transaction is intrinsically a potential coinjoin, as long as it has
\> 1 input and \> 1 output. It requires no state management, because a Bitcoin
transaction is itself atomic. So people naturally started trying to include it
in Bitcoin software as early as 2013/14, shortly after it was proposed. CoinSwap,
on the other hand, needs state management and even in a cooperative case, requires
4 separate transactions to happen (in the form used here), and 6, usually, in the
non-cooperative case. That combined with the delays required (safe timeouts) likely
means that it takes ~ 30min-1hr if everything goes well, and likely to take several
hours in certain cases if something goes wrong. This combination (complexity of
coding, and delay in using) probably put people off.

But even considering these negatives, there still may be something quite valuable
here. First, there is the matter of fees. *Effective* use of coinjoin, to really
gain significant fungibility, requires a large-ish number of large Bitcoin transactions,
which means the fees really add up - see the notes I wrote on this point [here](https://github.com/JoinMarket-Org/joinmarket/wiki/Step-by-step-running-the-tumbler#before-going-further-a-few-words-on-fees).
(the situation has since got worse). Intrinsic to CoinSwap is the fact that it causes an actual break in the history of
owned coins, without requiring lots of counterparties or lots of transactions. For
these reasons, a similar (or better) level of fungibility can be achieved for *far*
lower fees. There is also the question of anonymity set: in the cooperative case,
CoinSwap involves transactions using p2sh addresses, which look in no way different
from typical, non-CoinSwap transactions. By contrast, a single CoinJoin, at least
in the Joinmarket model, and in most reasonable-to-propose others, has an anonymity
set of the participants in the join. Although that isn't the whole story, it
makes it a very tempting model on which to base fungibility efforts, in this time
when blockchain space commands a much higher premium.

So if you've got this far, you get the general overall view: it's potentially much more
effective than Coinjoin, almost certainly cheaper, but more complex and slower. At
the same time there are now other potential systems, not yet active - TumbleBit and
Lightning, in particular, that are far more complex still, but could well be, in the
long run, the best options. But they are not yet ready, and are not *unconditionally*
better than CoinSwap, in any case. CoinSwap *may* have a place in the fungibility
tapestry of Bitcoin.


