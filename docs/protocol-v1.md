# FedHM protocol definition v1.x

## About

This document describes the legacy protocol used in version 1 of the HSM. The purpose is to provide a reference for the usage of the legacy mode in the manager and TCP manager (with modifier `--version-one`).

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
    "version": 1,
    "errorcode": i
}
```

**Error codes:**
This operation can return `0` and generic errors. See the error codes section for details.

### Sign

#### Request

This command will only work with the authorized key ids (see corresponding section for details).

```
{
    "command": "sign",
    "keyId": "xxxxx", // (*)
    "message": "hhhh", // (**)
    "version": 1
}

// (*) the given string must be the
// BIP44 path of the key to use for signing.
// See valid BIP44 paths below.
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

### Get public key

#### Request
```
{
    "command": "getPubKey",
    "keyId": "xxxxx", // (*)
    "version": 1
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

### Error and success codes

The following are all the possible error and success codes:

#### Success codes
- `0`: Ok

#### Error codes

These errors can be returned by all operations.

-`-2`: General error in operation
-`-666`: Invalid version

### Valid BIP44 paths

For any operation that requires a `keyId` parameter, the following are the
only accepted BIP44 paths:

- RSK key id - `m/44'/137'/0'/0/0` (\*)
- MST key id - `m/44'/137'/1'/0/0` (\*)
- tRSK key id - `m/44'/1'/1'/0/0` (\*)
- tMST key id - `m/44'/1'/2'/0/0` (\*)

(\*) Sign operations using these keys don't require authorization.
