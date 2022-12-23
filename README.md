# powHSM

![Tests](https://github.com/rsksmart/rsk-powhsm/actions/workflows/run-tests.yml/badge.svg)
![Python linter](https://github.com/rsksmart/rsk-powhsm/actions/workflows/lint-python.yml/badge.svg)
![C linter](https://github.com/rsksmart/rsk-powhsm/actions/workflows/lint-c.yml/badge.svg)

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](./LICENSE)

## About

The RSK Powpeg protects private keys stored in special purpose PowHSMs based on tamper-proof secure elements (SE). The PowHSM runs an RSK node in SPV mode, and signatures can only be commanded by chain cumulative proof of work.

This repository hosts the powHSM firmware. The stable versions are the tags published in the [releases tab](https://github.com/rsksmart/rsk-powhsm/releases).

## Notation

Throughout the repository READMEs, the prompt `~/repo>` is used to denote a `bash` terminal cded to the repository's root. Likewise, the prompt `~/repo/another/path>` is used to denote a `bash` terminal cded to the repository's `another/path` directory. Finally, the prompt `/this/is/a/path>` is used to denote a `bash` terminal cded to the absolute path `/this/is/a/path`.

## Quickstart

Refer to our [quickstart guide](./QUICKSTART.md) to learn about environment setup and common tasks without further ado.

## Supported platforms

Unless otherwise stated, only x86 platforms are supported for building this project and running the tools provided. It is possible, however, to build and run the [TCPSigner bundle](./utils/tcpsigner-bundle/README.md) on arm64 platforms. This is provided for development and testing purposes.

## Concepts overview

powHSM is a solution designed specifically for the [RSK network](https://www.rsk.co/) powPeg. Its main role is to safekeep and prevent the unauthorized usage of each of the powPeg's members' private keys. powHSM is implemented as a pair of applications for the [Ledger Nano S](https://shop.ledger.com/products/ledger-nano-s), namely a UI and a Signer, and it strongly depends on the device's security features to implement the aforementioned safekeeping.

Each powPeg member runs an individual physical device on which a transparent installation and onboarding process is carried. Amongst other things, this process safely generates the root key, that never leaves the device. There is an [attestation process](./docs/attestation.md) that serves the purpose of testifying and guaranteeing this key generation process, and ultimately the fact that the key is only ever known to the device.

After onboarding, each device is physically connected to and interacts with its corresponding powPeg node by means of a middleware layer that exposes a [high-level protocol](./docs/protocol.md) for its operation.

The signer application running within each device enables the usage of two sets of keypairs by its owner powPeg node: an _unauthorized_ and an _authorized_ set. These keys are generated from the root key using a standard [BIP32](https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki) derivation path (following [BIP44](https://github.com/bitcoin/bips/blob/master/bip-0044.mediawiki)).

The _unauthorized_ keyset can be used to sign arbitrary hashes, and its security scheme relies solely on the knowledge of the device's pin (akin to owning a Ledger Nano S for personal usage). This keyset is used by the powPeg members for non critical operations (e.g., signing powPeg-only transactions within the RSK network).

The _authorized_ keyset is the main security focus of the solution. It can _only_ ever be used to sign BTC transactions that correspond to pegOuts within the RSK network, i.e., the release of Bitcoin funds held within RSK's bridge mechanism. This authorization is enforced by means of events that the [Bridge contract](https://explorer.rsk.co/address/0x0000000000000000000000000000000001000006) emits whenever a pegOut request is generated, and that are included in RSK's blocks by means of transaction receipts, and ultimately mined and secured by actual Bitcoin miners. This implies that without a mined pegOut request with a minimum amount of hashing power on top, the device emits no signature. This powerful feature gives the project its name: _powHSM_ - Proof of Work Hardware Security Module.

## Digging deeper

Refer to the following documents for details on specifics:

- [powHSM manager protocol specification](./docs/protocol.md)
- [Blockchain bookkeeping documentation](./docs/blockchain-bookkeeping.md)
- [Attestation documentation](./docs/attestation.md)
- [Heartbeat documentation](./docs/heartbeat.md)
- [Ledger apps](./ledger/README.md)
- [Middleware](./middleware/README.md)
- [Distribution](./dist/README.md)

## Report Security Vulnerabilities

To report a vulnerability, please use the [vulnerability reporting guideline](./SECURITY.md) for details on how to do it.

## License

powHSM is licensed under the MIT License, included in our repository in the [LICENSE](./LICENSE) file.

## Your Pledge

PowHSM has been developed with the intention of fostering the progress of society. By using PowHSM, you make a pledge not to use it to incur in:
- Any kind of illegal or criminal act, activity or business;
- Any kind of act, activity or business that requires any kind of governmental authorization or license to legally occur or exist, without previously obtaining such authorization or license;
- Any kind of act, activity or business that is expected to infringe upon intellectual property rights belonging to other people;
- Any kind of act, activity or business involving dangerous or controlled goods or substances, including stolen goods, firearms, radioactive materials or drugs.
Something will be considered illegal, criminal, or requiring any kind of governmental authorization or license, when either the laws or regulations of the country in which you reside, or the laws or regulations of the country from which you use PowHSM, consider it illegal, criminal, or requiring any kind of governmental authorization or license.
