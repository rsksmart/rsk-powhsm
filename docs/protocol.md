# FedHM protocol definition v2.x

## Definitions

- `xxxxx`: String
- `hhhh`: Hex string
- `i`: Integer
- `b`: Boolean

## Commands

### Get version

#### Request
```
{
    "command": "version"
}
```

#### Response
```
{
    "version": 2,
    "errorcode": i
}
```

**Error codes:**
This operation can return `0` and generic errors. See the error codes section for details.

### Sign

#### Request

For this operation, depending on the `keyId` parameter, there's two possible formats: the authorized and the non-authorized. Details follow.

##### Authorized format

This format is only valid for the BTC and tBTC key ids (see corresponding section for details).

```
{
    "command": "sign",
    "keyId": "xxxxx", // (*)
    "message": {
        tx: "hhhh", // (**)
        input: i // (***)
    },
    "auth": {
        receipt: "hhhh",
        receipt_merkle_proof: [
            "hhhh", "hhhh", ..., "hhhh"
        ]
    },
    "version": 2
}

// (*) the given string must be the
// BIP44 path of the key to use for signing.
// See valid BIP44 paths below (BTC and tBTC for this format).
// (**) the fully serialized BTC transaction
// that needs to be signed.
// (***) the input index of the BTC transaction
// that needs to be signed.
//
// For the signing process to be successful, the computed receipts trie root
// must match the device's current 'ancestor_receipts_root'.
// This can be updated using the 'updateAncestorBlock' operation
// (see details below).
```

##### Non-authorized format

This format is only valid for the RSK, MST, tRSK and tMST key ids (see corresponding section for details).

```
{
    "command": "sign",
    "keyId": "xxxxx", // (*)
    "message": {
        hash: "hhhh", // (**)
    },
    "version": 2
}

// (*) the given string must be the
// BIP44 path of the key to use for signing.
// See valid BIP44 paths below (RSK, MST, tBTC and tMST for this format).
// (**) the hash that needs to be signed.
```

#### Response
```
{
    "signature": {
        "r": "hhhh",
        "s": "hhhh"
    },
    "errorcode": i
}
```

**Error codes:**
This operation can return `0`, `-101`, `-102`, `-103`, and generic errors. See the error codes section for details.

### Get public key

#### Request
```
{
    "command": "getPubKey",
    "keyId": "xxxxx", // (*)
    "version": 2
}

// (*) the given string must be the
// BIP44 path of the key of which to retrieve
// the public key. See valid BIP44 paths below.
```

#### Response
```
{
    "pubKey": "hhhh",
    "errorcode": i
}
```

**Error codes:**
This operation can return `0`, `-103`, and generic errors. See the error codes section for details.

### Advance Blockchain

#### Request
```
{
    "command": "advanceBlockchain",
    "blocks": [
        "hhhh", "hhhh", ..., "hhhh" // (*)
    ],
    "version": 2
}

// (*) each element must be the binary serialization of a block header as
// defined by the RSK protocol (it must include the bitcoin merged mining
// header, the bitcoin coinbase transaction and the bitcoin merged mining
// merkle proof).
```

#### Response
```
{
    "errorcode": i
}
```

**Error codes:**
This operation can return `0`, `1`, `-201`, `-202`, `-204`, and generic errors. See the error codes section for details.

### Reset Advance Blockchain

#### Request
```
{
    "command": "resetAdvanceBlockchain",
    "version": 2
}
```

#### Response
```
{
    "errorcode": i
}
```

**Error codes:**
This operation can return `0` and generic errors. See the error codes section for details.

### Get Blockchain State

#### Request
```
{
    "command": "blockchainState",
    "version": 2
}
```

#### Response
```
{
    "errorcode": i,
    "state": {
        "best_block": "hhhh", // (*)
        "newest_valid_block": "hhhh", // (*)
        "ancestor_block": "hhhh", // (*)
        "ancestor_receipts_root": "hhhh", // (**)
        "updating": {
            "in_progress": b,
            "already_validated": b,
            "next_expected_block": "hhhh", // (*)
            "total_difficulty": "hhhh", // (***)
            "found_best_block": b,
            "best_block": "hhhh", // (*)
            "newest_valid_block": "hhhh" // (*)
        }
    }
}

// (*) Value corresponds to an RSK block hash (32 bytes)
// (**) Value corresponds to a hash (32 bytes)
// (***) Value corresponds to a big-endian unsigned integer (36 bytes)
```

**Error codes:**
This operation can return `0` and generic errors. See the error codes section for details.

### Update ancestor block

#### Request
```
{
    "command": "updateAncestorBlock",
    "blocks": [
        "hhhh", "hhhh", ..., "hhhh" // (*)
    ],
    "version": 2
}

// (*) each element must be the binary serialization of a block header as
// defined by the RSK protocol (it does not need to include the bitcoin coinbase
// transaction and the bitcoin merged mining merkle proof).
```

#### Response
```
{
    "errorcode": i
}
```

**Error codes:**
This operation can return `0`, `-201`, `-203`, `-204`, and generic errors. See the error codes section for details.

### Error and success codes

The following are all the possible error and success codes:

#### Success codes (`xx`)
- `0`: Ok
- `1`: Partial success. Need the next blocks

#### Authorization-related errors (`1xx`)
- `-101`: Wrong authorization
- `-102`: Invalid message
- `-103`: Invalid or unauthorized key ID

#### Blockchain bookkeeping-related errors (`2xx`)
- `-201`: Chaining mismatch
- `-202`: PoW validation failed
- `-203`: Tip mismatch
- `-204`: Invalid or not enough input blocks

#### Generic errors (`9xx`).

These errors can be returned by all operations.

-`-901`: Format error
-`-902`: Invalid request
-`-903`: Command unknown
-`-904`: Wrong version
-`-905`: Device error (unspecified)
-`-906`: Unknown/unexpected error

### Valid BIP44 paths

For any operation that requires a `keyId` parameter, the following are the
only accepted BIP44 paths:

- BTC key id - `m/44'/0'/0'/0/0`
- RSK key id - `m/44'/137'/0'/0/0` (\*)
- MST key id - `m/44'/137'/1'/0/0` (\*)
- MST key id - `m/44'/137'/0'/0/1` (\*) (\*\*)
- tBTC key id - `m/44'/1'/0'/0/0`
- tRSK key id - `m/44'/1'/1'/0/0` (\*)
- tRSK key id - `m/44'/1'/0'/0/1` (\*) (\*\*)
- tMST key id - `m/44'/1'/2'/0/0` (\*)
- tMST key id - `m/44'/1'/0'/0/2` (\*) (\*\*)

(\*) Sign operations using these keys don't require authorization.
(\*\*) These keys are deprecated and will be removed in a future version.
