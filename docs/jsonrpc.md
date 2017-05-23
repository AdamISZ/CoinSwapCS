### JSON-RPC interface

The main goal of this document is to make it possible to rewrite either the client- or server- side of the CoinSwap transaction negotiation, so it is a (for now, a bit rough) specification.

#### Session management

The philosophy here was principally to not rely on the network layer. In theory TLS does what you need for a single session, but this would not be good enough for multiple network sessions.

So the concept here is:
Use an ephemeral bitcoin keypair (compressed pubkey). Alice sends the pubkey in hex encoding (along with several other ephemeral keys) in the initial handshake request. Carol responds with a unique 16 byte session id.

Future requests from Alice all have format:

    "method": "coinswap", "params": [session_id, {"nonce": nonce, "sig": sig}, method_name, args..]

The fields `nonce`, `session_id` and `sig` are all hex encoded. This is slightly inefficient but the data transfer rate here is tiny.

Some notes on this are in order:

* The json-rpc method is always `coinswap` to deal with the slightly funky nature of [txJSONRPC](https://github.com/oubiwann/txjsonrpc): python method names are fixed to `jsonrpc_methodname`, so to run code common to all methods it's easier to just have a single generic method, then defer to sub-methods as defined by `method_name` in the params list. So nonce and signature verification occur in the generic code (see `coinswap.csjson.CoinSwapCarolJSONServer.validate_sig_nonce`).

* The message to be signed is of form: `nonce || json.dumps([methodname] + list(arguments))` (`nonce` is hex-encoded).

* The only other two json-rpc methods are thus `status` (status check outside of a run, as before) and `handshake` (which cannot be encapsulated by the session as it starts it).

* Carol provides a 16 byte unique session id in the response to the first handshake call and it's stored in the CoinSwapPublicParameters object (as before) ( [generated here](https://github.com/AdamISZ/CoinSwapCS/blob/master/coinswap/csjson.py#L198)).

* The `CoinSwapCarolJSONServer` stores a dict of `CoinSwapCarol` objects keyed by the `sessionid`.
    Replay attacks are prevented by the fact that each new request must have a unique nonce (checked in `CoinSwapCarol.consume_nonce`).

For now, backout is strictly non-interactive, so there is no need to worry about how to "restart" after a network break. But in principle it should not be a problem if backout mode did revert to interactivity, since the session_id is stored in the parameters section of the state file, and the session bitcoin pubkey is likewise stored in the pubkeys session (`CoinSwapPublicParameters.keyset["key_session"]`), so it should still be possible to key into the same session and make valid signatures (and nonces rely only on computational infeasibility of repeats).

### Valid requests

#### `status`

* Request format:

```json
   { "method": "status", "params": null}
```
* Return format:

```json
   {
    "busy": true, 
    "source_chain": "BTC", 
    "fee_policy": {
        "percent_fee": 0.5, 
        "minimum_fee": 100000
    }, 
    "maximum_amount": -1, 
    "minimum_amount": 5000000, 
    "destination_chain": "BTC", 
    "cscs_version": 0.1
}
```

* Explanation of fields:

`cscs_version` - version of the software. If it is higher than that offered by the client, the server will refuse to continue.

`busy` - if true, the server is not currently ready to offer to take part in Coinswaps (usually because out of liquidity or doing too many concurrently).

`source_chain`, `destination_chain` - only BTC currently supported. **Note** this is still `BTC` in case of testnet/regtest.

`minimum_amount`, `maximum_amount` - in satoshis, specifiying what size of final output the server will accept for the coinswap. If `maximum_amount` is -1, it means the server does not have sufficient coins available.

`fee_policy` - a set of data specifying how the coinswap fee will be calculated. As of version 0.1, this only supports a minimum fee and a percentage fee (applied as long as it is higher than the minimum).

#### `handshake`

* Request format:

Note that the signature field in (nonce, sig) is not verified for this request by the server (it doesn't yet have the pubkey). The `session_id` field is `null` because it hasn't yet been assigned.

```json
{"params": 
[null,
{"nonce": "3d2b6869fc32c54b64ce27f1734326a8",
"sig":"MEUCIQCG05CclQpa//5KV8Bm2HpOsj5Ot3Iore+RMwvWCcAQIgCiTE70PNV65OOQTN7OaizZ2L6yWJ+bysNrY2WYACtTI="},
"handshake",
{"coinswapcs_version": 0.1,
"source_chain": "BTC",
"tx01_confirm_wait": 2,
"bitcoin_fee": 9150,
"amount": 10000000,
"destination_chain": "BTC",
"key_session": "02c3f260e626254af5a81754c740d5187db70f981ab4c5e6d3e98d0e9899e05335"}],
"method": "handshake"}
```

* Return format:

```json
["841c684e84be4443180e18ea38c29b5c", "OK"]
```
where the first item is the newly-assigned `session_id`, or

```json
[null, "Invalid parameters because reasons."]
```
#### `negotiate`

The next request from the client specifies the detailed public data set for the proposed CoinSwap; mainly ephemeral bitcoin public keys in hex:

* Request format:

```json
{"params":
["24ca0e5ab774925df50c825a83bc58a9",
{"nonce": "d7c33047b40b77cc86b7eeb81eaba2d4",
"sig": "MEUCIQCxmhsSpt4qJN8JBh/lO2lAukVAmuRp/obYHEfqwfI/6QIgWkKCcPKWRqhWhXowPy46oVjImvfKrNO2SeHimHEk/Kw="},
"negotiate",
"0309bbe7f60fac1464d30c6800e3e997b8a61b641d51a111af239a578b71165810",
"02533c4a170564958e8202cae7387e1be38cd8fd8407772a6a41d8d648c38eebc8",
"03f541bfaf6f9de86cb375cd0acccfc7a29033b7cdf3628c5e1a46b24f49cca59b",
"038e05e26566e66387984a2c934f4112179685658ca388469a71cd91a17a335334",
268,
258,
"mmUSAzNdoFRiDHGUGwaqonoWZmKi3VYyXZ"],
"method": "coinswap"}
```
 After the `method_name` value `negotiate`, the 7 subsequent arguments are, in order:
 - (public) key_2_2_AC_0
 - (public) key_2_2_CB_1
 - (public) key_TX2_lock
 - (public) key_TX3_secret
 - LOCK0 timeout as absolute block height
 - LOCK1 timeout as absolute block height
 - destination address for TX5 (client receipt address for successful swap)

As a reminder, all public keys must be compressed.

* Return format

```json
[true, 
"038b75eb55031a99fc09b0fcdeb926737b81d01f29cc4250971fc847f7e6acb3af", "0334b50bb96719ab534c47caf058a48e95b0220cb5700bee98c04193d4076eebbd", "02c3e50d87c753f9bf1dddd6809c464ae6d0e95627966838219a83812cc17d3cd7", "038f9067c2bf37e6a2003cd4ec97f1b3433eb448e4f5b96dc6ea2e46b054022d9d", "mzC9tM5TA7yCP7bcDGY7DbukD25EVhZdjf",
100000,
48832805,
"miwG7WLDx42cpzG7Vb6aLp9Kr8EAJTbYPk",
"moZ2QgkpBkYkrbXTGXDCQyV9waedAzQi9Z",
"mvGuBAFTxM8nnWiJBcBYifMncMhb5Jm1wy",
"24ca0e5ab774925df50c825a83bc58a9"]
```

If the first element of the array is `false`, the second element will be an error message, usually explaining the reason for the rejection of the parameters proposed. If it is `true` the remaining elements are as follows:

 - (public) key_2_2_AC_1
 - (public) key_2_2_CB_0
 - (public) key_TX2_secret
 - (public) key_TX3_lock
 - destination address for TX4
 - coinswap_fee (satoshis)
 - blinding_amount (satoshis)
 - destination address for the server for TX2
 - destination address for the server for TX3
 - destination address for the server for TX5
 - session id

#### `tx0id_hx_tx2sig`

* Request format

```json
{"params":
["24ca0e5ab774925df50c825a83bc58a9",
{"nonce": "9d5649b8cd5220372692be8aa2a59a22",
"sig":"MEUCIQDcfJpa0yGoDmBgg4ftmdz8zPXjiFOQSZs5kammQXO9SwIgEjdE2TZN2yCNn6TZjbc226oHH4gVgKB5lVccGICPV2Q="},
"tx0id_hx_tx2sig",
"90e662f70ce84dceae36f751d47cd11f2205d4953024d246734427e4ed5c40cb:0",
"8a45df126ed1afa23ab310b6ad8df418c37e6b8a",
"3044022003a968d759e2bd754b6fde25f12c1e01a30404b34d5c165e1eebad431d19c1fb0220222ac6
5d8cbecd58d6dfcf3456e6194104d7cad65d0626e6889a6cd212008bf01"],
"method": "coinswap"}
```

Note that this and all succeeding requests use the provided `session_id` (16 bytes hex encoded) as the first parameter.
After the `method_name` `tx0id_hx_tx2sig` is provided, the remaining arguments are:

 - utxo from the unpublished TX0 in format txid:N
 - 20 byte HASH160 hash image, hex encoded, of coinswap secret
 - Client's valid signature on TX2

* Return format

```json
["c727cb5096628abd3b5cd45d7f291ff8e413d53fb9f2d277954a583bc8dfc259:0",
"3044022003a968d759e2bd754b6fde25f12c1e01a30404b34d5c165e1eebad431d19c1fb0220222ac6c5d8cbecd58d6dfcf3456e6194104d7cad65d0626e6889a6cd212008bf01",
"3044022006de3ee4981d1da5fe257d5290fbae28440d84cc508d4548cdb942469fe1a0d002206df6d56605445721adc84b4f3e9f49c8dcd012946a1b34083e858dd6bfdc1ddb01"]
```

These are, in order:

 - The utxo of the server's constructed TX1 in format txid:N
 - The server's signature on TX2
 - The server's signature on TX3

#### `sigtx3`

* Request format

```json
{"params":
["24ca0e5ab774925df50c825a83bc58a9",
{"nonce": "fb53c04673965a698d5de80a8978289a",
"sig": "MEQCIB4Bz5cTMKUt/b3eRlnc5T2XxY4/5HvzTYOreSW4+XeYAiA8CDQ/KQuhEtLKb3pluqSUA+9cfb70Ulh5KOpxSQgNQ=="},
"sigtx3", "304402201e7ca9916f285c8a9926d9b8b8501aefb70d5342d2cd8c95d068f5921f8c532b02203a81de96423d4b8aaa68041d267408b201b0492d12bcfb7e6ff799f0ddd8cc9501"],
"method": "coinswap"}
```

* Response format

```json
[true, "Received TX3 sig OK"]
```
or
```json
[false, "TX3 sig received is invalid"]
```

This request's response does not return data, only accept/reject. The server waits to see TX0 confirmed before proceeding to update state further.

#### `phase2_ready`

This is a stateless polling request to check whether the server agrees with the client that we are ready to continue to "2nd phase" of the CoinSwap protocol (in which the client will pass the coinswap secret thus defending both sides against funds loss, and then swapping ordinary non-backout redemptions). The client can pass this as often as they like (within DOS limits).

* Request format

```json
{"params":
["24ca0e5ab774925df50c825a83bc58a9",
{"nonce": "15afb5330e3bf8e393b35de23e21830f",
"sig": "MEQCIBkxGRnfwC38XPg138S7dM6N40mgL8J0IeOAIS5KOjQ4AiAIh5w7JUaiLu9eBJeWKPl5EytVG9TReqEWMWIJYdSJ9w=="},
"phase2_ready"],
"method": "coinswap"}
```

As you can see, there are no arguments other than the `method_name` field.

* Response format

The response is `true` once the server has seen TX1 and TX0 with the requisite number of confirmations on the network, and `false` before that. The client should use the switch to `true` as a trigger that the server is ready to proceed onto the next phase:

#### `secret`

* Request format

```json
{"params":
["24ca0e5ab774925df50c825a83bc58a9",
{"nonce": "f48ccd7abc5389054da4ae610a87729d",
"sig": "MEQCIAliGOE1jRze/lenOeBLuhMvy5RN+t8jEZBL/RCC4UV3AiAj9x0DObMtN57rhNGTfOceIw00cPcyFAPrMqvnXo+OjA=="},
"secret", "7382b361921d03c859ec4716a764"],
"method": "coinswap"}
```

* Response format

```json
["3045022100b856817c6e50798f05471303f17b35a1526c940b9fd3741e8de605b2f16d6da202200fc2118b8428268afaf399e251a17e0d36e36cbd785a778cfa6e8fc16c965cb301", "OK"]
```
or
```json
[false, "Received invalid coinswap secret."]
```

The server checks if the secret is a valid preimage for the earlier provided hash; if not returns rejection message above, otherwise it returns a signature on TX5.

*Note; from this point, the client is pushing TX5 to the network and theoretically is safe from further problems, so in a sense the remainder is optional, but the next step at least (the `sigtx4` call) is required to avoid forcing the server to back out their transaction, which at minimum is highly unsociable!*

#### `sigtx4`

* Request format

```json
{"params":
["24ca0e5ab774925df50c825a83bc58a9",
{"nonce": "8b1ae85c795947109519f905a828393a",
"sig": "MEQCIGkiZNW/+cz5g2pHurbvnz6VL4qM/zKfzthD/HX9GgVPAiA2FhDpUQ0Drmb02Kos9LC8m3ium8swM1QM2oCVO6JjZw=="},
"sigtx4", "3044022052780916fbbe202a2adebc98731f3a28f2a781877c76a53919f03062d06b5d7b02202617f9614213ebd99a5c4e3848eaf511fd4b1c2785e4883c8c673e9c8656bac101",
"1edaa62fd7bbc8624db5ba7517d1e97c4b0701e9e7a68388d2354b6c59975ee8"],
"method": "coinswap"}
```

This provides a TX4 signature to the server and a txid for TX5 for convenience.

* Response format

Either
```json
[false, "Received invalid TX4 signature"]
```
or
```json
[true, "OK"]
```

#### `confirm_tx4`

This call is strictly optional, but useful for the client to know that the CoinSwap is fully complete on both sides (both sides have received the intended funds via TX4 and TX5).

* Request format

```json
{"params":
["24ca0e5ab774925df50c825a83bc58a9",
{"nonce": "eebe4e4a51b51c2fca455bbcdbfdb530",
"sig": "MEQCIA4DmuTIBcjDOk9kUsGOr0Dl1e2xDiNEcm4FHVeoH4xTAiAyuqu3vlJ3osiXNDpTowoLApZbd8tdSsTUss6EkC57aA=="},
"confirm_tx4"],
"method": "coinswap"}
```

As you can see this request has no arguments apart from its `method_name`. Like `phase2_ready`, it is also a stateless polling call and can be called as often as required.

* Response format

The response is similarly simple - `true` if TX4 is confirmed, `false` otherwise.