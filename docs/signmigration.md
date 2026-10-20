# powHSM SGX migration authorization tool

## Foreword

The tool described in this document is designed exclusively for the SGX version of
powHSM. Therefore, all the information contained herein must be interpreted as applying
exclusively to this implementation.

The Ledger version of powHSM has got its own independent authorization tool, described in
[this document](./signapp.md).

## Abstract

This document describes the usage of `signmigration.py`, the middleware tool that serves
the purpose of generating and signing authorization files for SGX powHSM database
migrations. For details on the SGX firmware upgrade and migration process itself (i.e.,
the "N of M" signatures requirement, the message format and the encoding used for the
digests to be signed), please refer to the [SGX firmware upgrades
documentation](./sgx-upgrades.md).

The tool supports four operations, which can be split into two groups, depending on their
intended use:

- Testing operations:
  - `key`: signs an authorization with a manually input private key. *This operation is
    intended for testing purposes only and must never be used in production.*
- Production operations:
  - `message`: computes the message to be signed for a given migration, and optionally
    generates an unsigned authorization file for it.
  - `eth`: signs an authorization with a Ledger device running the Ethereum app.
  - `manual`: adds an externally generated signature (e.g., one obtained from MetaMask or
    MyEtherWallet) to an authorization file.

Unlike its [Ledger counterpart](./signapp.md), this tool has no operation to compute
an enclave's hash, since the enclave's `mrenclave` value is reported by the firmware
build process (see [the firmware build documentation](../firmware/build/README.md) for
details). The `message` operation is, however, also used by the distribution build
process, in order to generate the unsigned authorization file included in every
distribution.

## Running the tool

The tool can be run from within a middleware development environment terminal (see [the
middleware documentation](../middleware/README.md) for details on setting one up), by
means of the `signmigration.py` script within the `middleware` directory.

A binary build of the tool, `signmigration`, is also included in every SGX
distribution. The binary accepts the exact same operations and options as the script.
Throughout the rest of the document, we will use an example binary for the examples,
located at `tools/signmigration`. For instance, to print the tool's built-in help, issue:

```
> tools/signmigration --help
```

## Options

The following is the complete list of options. Note that each option is only meaningful
for some of the operations (see each operation's section for details):

- `-e`, `--exporter`: the 32-byte hex-encoded `mrenclave` of the exporter enclave, i.e.,
  the enclave of the existing installation (`message` operation only).
- `-i`, `--importer`: the 32-byte hex-encoded `mrenclave` of the importer enclave, i.e.,
  the enclave to which the installation is to be upgraded (`message` operation only).
- `-f`, `--file`: an existing SGX migration authorization file from which to read the
  migration (`message` operation only). Cannot be combined with `-e` or `-i`.
- `-o`, `--output`: the SGX migration authorization file to create or update (or, for the
  `eth` operation together with `-b`, the file to which to save the public key).
- `-k`, `--key`: a 32-byte hex-encoded private key (`key` operation only).
- `-p`, `--path`: the BIP32 derivation path of the signing key (`eth` operation only).
  Defaults to `m/44'/60'/0'/0/0`.
- `-b`, `--pubkey`: retrieve and save the device's public key instead of signing (`eth`
  operation only).
- `-g`, `--signature`: the externally generated signature to add (`manual` operation
  only). See [supported signature formats](#supported-signature-formats).
- `-s`, `--signer`: the expected signer of the given signature, either as a hex-encoded
  address or public key (`manual` operation only).
- `-v`, `--verbose`: enable verbose mode (useful for debugging the communication with a
  Ledger device).

## The SGX migration authorization file

All of the signing operations read from and write to an SGX migration authorization file.
This is a JSON file that specifies the migration being authorized (the exporter and
importer `mrenclave` values) along with the signatures collected so far. For example:

```json
{
  "version": 1,
  "hashes": {
    "exporter": "2c29a879ea2d4cf2a3cd11d70147b3a8c4672ea796480419457ba208bc11b05b",
    "importer": "389a7298a8affc05acfd261f7048e5be87589f44a42c03cc63d3500c21ff4d42"
  },
  "signatures": [
    "3045022100cbd7...",
    "3044022057a1..."
  ]
}
```

Unlike the signing operations of its [Ledger counterpart](./signapp.md), the `key`, `eth`
and `manual` operations of this tool never create the authorization file: it must always
be generated beforehand with the `message` operation.

Every SGX distribution includes an unsigned SGX migration authorization file under
`hsm/migration_auth.json`. Since the exporter enclave depends on the version of each
existing installation, and is therefore unknown at build time, this file is generated with
the `mrenclave` of the distribution's enclave as the importer, and a default exporter
value of `00...00`. *Said file must be regenerated with the actual exporter `mrenclave`
before gathering any signatures*, as explained in [the corresponding
section](#computing-the-authorization-message-message).

The fully signed file is then needed to upgrade an existing installation (see the [SGX
distribution documentation](../dist/sgx/README.md) for details on the upgrade process).
The minimum number of signatures needed is the threshold (N/2+1) for the total number of
authorizers (N) in the authorizers header file specified at build time. Please also note
that a minimum of N authorizers must be shared between the exporter and importer enclaves
for a migration to be possible.

Signatures are always stored DER-encoded and normalized to their low-S form, irrespective
of the format in which they were given. Also, each authorizer is counted at most once:
attempting to add a second signature by an authorizer that has already signed (be it an
exact copy, a different encoding of the same signature or a brand new signature) is
rejected.

## Testing operations

### Signing with a private key (`key`)

**This operation is not to be used in production under any circumstances.** It requires
the private key of an authorizer to be input in plain text on the command line, which
defeats the entire purpose of safekeeping said key. Its sole intended use is for testing,
e.g., to sign migrations between enclaves built with a set of test authorizers whose
private keys are known.

The `key` operation signs an SGX migration authorization with a given private key and
adds the resulting signature to the existing SGX migration authorization file given. To
sign with a private key, issue:

```
> tools/signmigration key -o /path/to/migration_auth.json -k <private_key>
```

where `<private_key>` is the 32-byte hex-encoded private key (with or without the `0x`
prefix). The operation can be repeated with each of the test authorizers' keys until the
signature threshold is met.

## Production operations

The production operations are designed so that holders of the authorizing private keys
can sign a migration by any of the following means, without ever exposing said keys:

- With a Ledger device running the Ethereum app, connected to the machine running the tool
  (`eth` operation).
- With any third-party wallet that supports Ethereum's standard message signing (e.g.,
  MetaMask, MyEtherWallet, MyCrypto, Etherscan), on any machine. The message to sign is
  obtained with the `message` operation, and the resulting signature is then added to
  the authorization file with the `manual` operation.

Both means can be freely combined to gather the signatures for a single authorization.

### Signing with a Ledger device (`eth`)

The `eth` operation signs an SGX migration authorization with a Ledger device running the
Ethereum app and adds the resulting signature to the existing SGX migration authorization
file given.

Before starting, connect the device to the machine running the tool, unlock it and open
the Ethereum app. Then, issue:

```
> tools/signmigration eth -o /path/to/migration_auth.json
```

or, to sign with a key other than the one corresponding to the default derivation path
(`m/44'/60'/0'/0/0`):

```
> tools/signmigration eth -o /path/to/migration_auth.json -p "<path>"
```

The tool first outputs the address and public key corresponding to the derivation path
used, so that the authorizer can verify that the expected address is being used for
signing. It then sends the message to the device for signing and outputs the message along
with its digests:

```
Check that the device shows the following message (or one of the digests):
    Message:

    RSK_powHSM_SGX_upgrade_from_2c29a879ea2d4cf2a3cd11d70147b3a8c4672ea796480419457ba208bc11b05b_to_389a7298a8affc05acfd261f7048e5be87589f44a42c03cc63d3500c21ff4d42

    Digest (app >= 1.22.3, if hash display enabled):  0x0db6275d18e36976775cf77994d0285e6db08c986005d15f0cffa1c2ca82203f
    Digest (app <= 1.9.19):                           91EC9E0FA8BAE9AE8FE256285128E91870A31E9C2E97CF5335F22367A805DC04
```

The authorizer must check that the device displays either the message or the digest that
corresponds to the Ethereum app version installed, and only then approve the signature on
the device. The tool verifies the signature obtained from the device against the
retrieved public key before adding it to the SGX migration authorization file.

#### Retrieving the public key

Authorizers can also use the `eth` operation to retrieve the public key corresponding to
their signing key, e.g., in order to include it in the authorizers header file. To do
this, issue:

```
> tools/signmigration eth -b -o /path/to/pubkey.txt
```

optionally specifying a derivation path with `-p`. The tool outputs the address and
public key, and saves the hex-encoded public key to the given output file. No signing
takes place, and therefore no existing SGX migration authorization file is needed.

### Computing the authorization message (`message`)

The `message` operation computes the message that authorizers must sign for a given
migration. The migration can be specified either by means of the exporter and importer
`mrenclave` values, or by means of an existing SGX migration authorization file. The
exporter `mrenclave` is that of the existing installation, which can be obtained from its
attestation (see [the attestation documentation](./attestation.md) for details). The
importer `mrenclave` is that of the enclave to which the installation is to be upgraded,
which is reported by the distribution build process (and is also the `importer` value in
the distribution's `hsm/migration_auth.json` file).

To compute the message from the exporter and importer `mrenclave` values, issue:

```
> tools/signmigration message -e <exporter_mrenclave> -i <importer_mrenclave>
```

or, to compute it from an existing SGX migration authorization file, issue:

```
> tools/signmigration message -f /path/to/migration_auth.json
```

The output should look like the following:

```
Message to sign: copy and paste exactly, as a single line, into your
wallet's 'sign message' feature - e.g., MyEtherWallet, MetaMask:

    RSK_powHSM_SGX_upgrade_from_2c29a879ea2d4cf2a3cd11d70147b3a8c4672ea796480419457ba208bc11b05b_to_389a7298a8affc05acfd261f7048e5be87589f44a42c03cc63d3500c21ff4d42

Your wallet automatically adds the standard Ethereum signed message prefix.
Do NOT include it yourself.


For reference only (do NOT paste these into your wallet):

    Full message: \x19Ethereum Signed Message:\n160RSK_powHSM_SGX_upgrade_from_2c29a879ea2d4cf2a3cd11d70147b3a8c4672ea796480419457ba208bc11b05b_to_389a7298a8affc05acfd261f7048e5be87589f44a42c03cc63d3500c21ff4d42
    Digest (keccak256):        0x0db6275d18e36976775cf77994d0285e6db08c986005d15f0cffa1c2ca82203f
```

The message under "Message to sign" is the one that must be pasted, verbatim, into the
third-party wallet. The full message and digest are given for reference only, e.g., to
compare against the digest a wallet or hardware device displays before signing.

Alternatively, if an output path is given, then instead of printing the message, the
operation writes a new, unsigned SGX migration authorization file for the given
migration. This is how the distribution build process generates the unsigned
`hsm/migration_auth.json` file, and also how said file must be regenerated with the
actual exporter `mrenclave` prior to gathering signatures. For example:

```
> tools/signmigration message -e <exporter_mrenclave> -i <importer_mrenclave> -o /path/to/dist/hsm/migration_auth.json
```

*Important*: the output file is always overwritten with an unsigned authorization. In
particular, issuing the operation with `-f` and `-o` pointing to the same file discards
any signatures collected so far.

### Adding an external signature (`manual`)

The `manual` operation adds an externally generated signature to an existing SGX
migration authorization file. The typical flow for an authorizer using a third-party
wallet is as follows:

1. Obtain the message to sign using the `message` operation (see [the corresponding
   section](#computing-the-authorization-message-message)).
2. Sign the message using the wallet's "sign message" feature.
3. Add the resulting signature to the signer authorization file using the `manual`
   operation.

To add a signature, issue:

```
> tools/signmigration manual -o /path/to/migration_auth.json -g <signature> -s <expected_signer>
```

where `<signature>` is the signature (see the supported formats below) and
`<expected_signer>` is the address or public key of the authorizer that is supposed to
have produced it.

The tool verifies the given signature against the authorization message for the migration
in the SGX migration authorization file, and outputs the detected signature format and
signer address. For example:

```
Opening SGX migration authorization file /path/to/migration_auth.json...
Verifying signature...
Signature format: r||s||v
Signer address: 0x1563915e194D8CfBA1943570603F7606A3115508
Signer matches the expected signer
Adding signature...
SGX migration authorization saved to /path/to/migration_auth.json
```

#### Supported signature formats

The signature can be given in any of the following formats:

- A hex-encoded, DER-encoded signature.
- A hex-encoded 65-byte `r||s||v` signature, with `v` being either `27`/`28` or `0`/`1`.
  This is the format output by e.g. MetaMask, MyEtherWallet and Ledger.
- A signed message JSON, as output by e.g. MyEtherWallet, MyCrypto or Etherscan. This
  is an object containing at least a `msg` field with the signed message (either as plain
  text or hex-encoded) and a `sig` field with a 65-byte `r||s||v` signature. If the
  object also contains an `address` field, it must match the signature's signer. The
  signed message must match the authorization message exactly.

Any of the above can be given either inline or as a path to a file containing it. Giving
a path to a file is especially convenient for signed message JSONs, which would otherwise
need to be quoted on the command line.

#### Verifying the signer

Giving the expected signer with `-s` is optional, but strongly recommended. When given,
the signature is rejected unless it was produced by that signer. When not given, the
tool still outputs the signer address along with a warning, and it is up to the operator
to check that address against the expected authorizer.

Please note that a DER-encoded signature does not, by itself, identify a single signer:
up to two candidate addresses can be recovered from it, and the tool outputs both. Using
the `r||s||v` or signed message JSON formats is therefore preferable whenever available.
