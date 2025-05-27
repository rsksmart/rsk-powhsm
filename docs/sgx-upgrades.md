# SGX powHSM firmware upgrades

## Foreword

The feature described in this document was designed exlusively for the SGX version of powHSM. Therefore, all the information contained herein must be interpreted as
applying exclusively to this implementation.

The only other implementation of powHSM, written for the Ledger Nano S, has got its own independent firmware upgrade process, described in [this document](./signer-authorization.md).

## Abstract

This document describes the mechanisms by which an existing SGX powHSM installation can be upgraded to a newer firmware version. This mechanism is essentially composed of a DB migration from the existing installation to the newer enclave binary, plus a few scripts that replace the existing artifacts with the new ones, including the resulting migrated DB. The migration itself requires an authorization process that is based on the existing Ledger firmware upgrades feature: an "N of M" signatures scheme for the authorization of any specific migration, that includes signing both the exporter and importer mrenclave values in a single message. This prevents unauthorised existing installation database migrations and, therefore, potential seed and password leaks.

## Motivation

Up to version 5.4 of the SGX powHSM, each new version of the firmware required a fresh onboarding, which in turn forced updating the RSK PowPeg composition -- an expensive process in terms of effort and, especially, time. Counting on a mechanism that allows for upgrading the firmware without the need for losing the existing seed and private keys becomes paramount.

## Solution

The SGX powHSM firmware uses sealing in order to protect non-volatile information such as the seed. In particular, the type of sealing used (`SEAL_POLICY_UNIQUE`) implies that only the exact version of an enclave (i.e., with a matching `mrenclave`) running on the same physical SGX server is ever allowed to read back previosly written secrets. This has the (somewhat arguable) advantage of avoiding the use of a unique `mrsigner`, that would otherwise allow for secret sharing amongst authorised codebases. This represents an advantage due to the fact that having to safekeep an `mrsigner` private key is a challenge in itself, and, most importantly, a heavy centralization point. An obvious disadvantage of using this type of sealing policy is, of course, the inability of a different firmware version to function with a database created by a codebase different than its own. Therefore, the solution must be that of secret sharing between two enclaves of different codebases. This is where the migration feature comes in.

In order to migrate an existing database without leaking the secrets to any other party, we leverage SGX local attestation (see [this document](./attestation.md#local-and-remote-attestation) for details) to implement a communication channel that is both authenticated and encrypted. Roughly, the migration process is composed of the following steps:
- Both importer and exporter receive a migration spec that specifies both parties' mrenclaves, and has been signed by a precompiled N of M wallet that both enclaves share.
- Upon validation of said migration spec, each party leverages local attestation to identify and validate itself and its peer, while at the same time exchanging a pair of ephemeral ECDSA public keys.
- The exporter party exports the encrypted database using a shared secret computed using ECDH with the ephemeral keypair. The importer party imports the received database using the same secret, and the process is finished.

## Implementation

The firmware upgrade is implemented by means of:

- An N of M wallet, implemented by means of a hardcoded set of M public keys in each enclave codebase. Please note that a minimum of N keys must be shared between exporter and importer enclaves for a migration to be possible. This also gives room for incremental updates to this N of M wallet.
- A middleware toolset that allows for the generation of the N of M signatures.
- A middleware tool that allows for the migration of a DB between two running instances.
- An upgrade process that performs the migration and also replaces the running service and its artifacts with the new ones and the migrated DB.

### Authorizing a migration

In order to simplify and standardize the authorization of firmware versions by holders of
the authorising private keys, we use [EIP-712](https://eips.ethereum.org/EIPS/eip-712)'s
encoding of bytestrings in order to generate the digests to be signed. Therefore, any user
of e.g. MetaMask can act as an authoriser for a given firmware version without the need for additional hardware or software. The message to be signed is as follows:

```
RSK_powHSM_SGX_upgrade_from_<EXPORTER_MRENCLAVE>_to_<IMPORTER_MRENCLAVE>
```

where `<EXPORTER_MRENCLAVE>` and `<IMPORTER_MRENCLAVE>` correspond to the ASCII-encoded, hex-encoded 32-byte mrenclave values of the exporter and importer enclaves, respectively.
For example, if we had to authorize a signer version with mrenclaves
`2c29a879ea2d4cf2a3cd11d70147b3a8c4672ea796480419457ba208bc11b05b` and `389a7298a8affc05acfd261f7048e5be87589f44a42c03cc63d3500c21ff4d42`, the message would be:

```
RSK_powHSM_SGX_upgrade_from_2c29a879ea2d4cf2a3cd11d70147b3a8c4672ea796480419457ba208bc11b05b_to_389a7298a8affc05acfd261f7048e5be87589f44a42c03cc63d3500c21ff4d42
```

When signing with e.g. MetaMask for the Ethereum network, EIP-712's encoding is applied
automatically, whereas if we had to manually sign the message, we'd have to manually apply
said encoding before signing. That is, the digest to sign would be the `keccak256` hash
of:

```
\x19Ethereum Signed Message:\n160RSK_powHSM_SGX_upgrade_from_2c29a879ea2d4cf2a3cd11d70147b3a8c4672ea796480419457ba208bc11b05b_to_389a7298a8affc05acfd261f7048e5be87589f44a42c03cc63d3500c21ff4d42
```
