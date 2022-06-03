# powHSM signer authorization and upgrade

## Abstract

This document describes the mechanisms by which the UI component authorizes versions of
the Signer component to run on a device. It is an improvement to the authorization scheme
present up to version 2.3 in that it introduces an "N of M" signatures requirement for the
authorization of any given Signer version, enhancing security and decentralization of the
powHSM solution as a whole. It is also an improvement over the "downgrade prevention"
mechanism (also present up to version 2.3), in that it removes the limit present in the
feature up to then.

## Motivation

Up to version 2.3 of the UI, each new version of the Signer component is authorized using
the Ledger Nano S's custom certificate authority (CCA for short), represented by a unique
ECDSA pair. If lost or stolen, there would be a need to generate a new pair, reset the
existing devices and update the RSK federation in order to issue new Signer versions.
Moreover, the downgrade prevention mechanism, which is based on a finite blacklist of
previous signer versions, rolls over after 100 versions, which also implies the need to
reset existing devices, the CCA and update the RSK federation in order to clear said list
and move past the 100 signer version mark. Even though at the time of writing the 100
signer version mark is very far away, it would eventually become an issue.

## Solution

In order to solve the aforementioned problems, we replace the CCA-based authorization step
for the signer: every signer version needs to be signed by at least N of M authorizers,
represented by M SECP256k1 keypairs. This step is now the entire signer authorization,
replacing the CCA signature in its entirety. In spite of this, the UI still needs a single
signature from the CCA to be considered authentic, but as it turns out, there is no real
need for a CCA apart from this. Therefore, the device setup process generates a random
keypair, signs the UI with it and then drops the private key. The public key and signature
are then used to set the device CCA and install the UI, respectively. Now, since the CCA
has no real use beyond the device setup, a scenario where the user tampers with the setup
process and uses a CCA of his choosing would have no real impact on the device's security.
The UI and Signer are still protected from counterfeiting by the [attestation
process](./attestation.md), which is the ultimate source of truth when it comes to
determining RSK's federation members.

## Implementation

The signer authorization is implemented by means of:

- A hardcoded set of M public keys in the UI.
- An `authorized_signer_hash` (32 bytes) and `authorized_signer_iteration` (2 bytes)
  values in the UI NVM, with default values (`000...000` for the hash and initially `0000`
  for the iteration).
- An `authorize_signer` operation in the UI bootloader, that changes the
  `authorized_signer_hash` and `authorized_signer_iteration` in the UI NVM iff:
  - N of M signatures for the concatenation of a given hash and iteration are given.
  - The given iteration is strictly greater than the current stored iteration (downgrade
    prevention).
- A Signer pre-run test that replaces the 2.3 downgrade prevention logic entirely, and
  allows the installed Signer to run iff its hash matches the `authorized_signer_hash`.
- An app pre-installation test that allows an app to be installed iff its hash matches the `authorized_signer_hash`.
- An updated UI attestation, including the values for `authorized_signer_hash` and
  `authorized_signer_iteration`, and removing the CCA present up to version 2.3 entirely.
- A middleware toolset that allows for the generation of the aforementioned signatures.
- An updated upgrade process that includes the Signer authorization step.

### Authorizing a signer

In order to simplify and standardize the authorization of signer versions by holders of
the authorising private keys, we use [EIP-712](https://eips.ethereum.org/EIPS/eip-712)'s
encoding of bytestrings in order to generate the digests to be signed. Therefore, any user
of e.g. MetaMask can act as an authoriser for a given signer version without the need for
additional hardware or software. The message to be signed is as follows:

```
RSK_powHSM_signer_<HASH>_iteration_<ITERATION>
```

where `<HASH>` corresponds to the ASCII-encoded, hex-encoded 32-byte hash of the signer,
and `<ITERATION>` corresponds to the ASCII-encoded decimal value for the signer iteration.
For example, if we had to authorize a signer version with hash
`e1baa18564fc0c2c70ac4019609c6db643adbf12711c8b319f838e6a74b0da2c` and iteration `45`, the
message would be:

```
RSK_powHSM_signer_e1baa18564fc0c2c70ac4019609c6db643adbf12711c8b319f838e6a74b0da2c_iteration_45
```

When signing with e.g. MetaMask for the Ethereum network, EIP-712's encoding is applied
automatically, whereas if we had to manually sign the message, we'd have to manually apply
said encoding before signing. That is, the digest to sign would be the `keccak256` hash
of:

```
\x19Ethereum Signed Message:\n95RSK_powHSM_signer_e1baa18564fc0c2c70ac4019609c6db643adbf12711c8b319f838e6a74b0da2c_iteration_45
```

### Considerations

It is important to mention that, when distributing UI and Signer for a new federation
member, the UI should be built with the `authorized_signer_iteration` corresponding to the
current Signer version, preventing the installation of older Signers using old
authorization witnesses.

## Future work

With the current implementation, the M keypairs in the N of M authorization scheme are
fixed. An improvement worth considering is implementing an operation that allows for the
updating of said keypairs.

The potential implementations and consequent security implications of this and other proposed changes should be analysed carefully before actually moving forwards.