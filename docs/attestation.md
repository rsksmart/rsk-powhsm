# powHSM attestation

## Abstract

This document describes the mechanisms through which a powHSM installation can prove to an end user that it is actually installed on an authentic physical Ledger device with a specific UI and Signer versions, along with its currently authorized signer version and generated public keys.

## Preliminaries, native support and assumptions

Each device currently used to run powHSM on, namely Ledger Nano S, ships with a mechanism to prove its authenticity and that also enables and leverages some basic additional support for user application attestation. For powHSM attestation we make extensive use of these mechanisms, assuming it is robust enough for our purpose.

## Device key and authenticity

The mechanism used by Ledger Nano S devices to prove their authenticity can be better understood from [the ledger documentation](https://developers.ledger.com/docs/nano-app/bolos-features/#attestation):

_"When all Ledger devices are provisioned in the factory, they first generate a unique Device public-private keypair. The Device’s public key is then signed by Ledger’s Issuer key to create an Issuer Certificate which is stored in the device. This certificate is a digital seal of authenticity of the Ledger device. By providing the Device’s public key and Issuer Certificate, the device can prove that it is a genuine Ledger device."_

We use the device public key and issuer certificate as the basis for the powHSM attestation mechanism.

## Application attestation and powHSM

Ledger Nano S user applications can make indirect use of the aforementioned device keypair to provide attestation mechanisms. This can be better understood from [the ledger documentation](https://developers.ledger.com/docs/nano-app/bolos-features/#attestation):

_"The device generates a new attestation keypair and signs it using the Device private key to create a Device Certificate. The device then returns the attestation public key, the Device Certificate, and the Issuer Certificate..."_

and

_"The attestation keys are not accessible to apps directly, instead BOLOS provides attestation functionality to userspace applications through cryptographic primitives available as system calls. There are two different Endorsement Schemes available to applications (Endorsement Scheme One and Endorsement Scheme Two). When creating an attestation keypair, the user must choose which scheme the keypair shall belong to."_

For powHSM, we use Endorsement Scheme Two, which provides a primitive to _"Sign a message using a private key derived from the attestation private key and the hash of the running application"_. In this way, installed applications can endorse specific messages, and that endorsement constitutes _proof_ of those messages being generated on that specific running code on an authentic Ledger Nano S. This is the basis for the powHSM attestation.

## Attestation goal

The main goal of the powHSM attestation mechanism is enabling the end user(s) to have proof of a specific powHSM with a given UI and Signer running on an authentic Ledger Nano S with a specific authorized signer version and having control over a given set of generated public keys. Given the constraints specifically implemented on the powHSM UI (more on this later), proof of the aforementioned would also guarantee that the holder of the powHSM device will not ever be able to alter the installed UI; and that upgrades for the Signer application will need the explicit authorization of a minimum number of predefined authorizers (currently hardcoded within the UI, and decided at compile time). Attempts to bypass these restrictions would result in the keypairs being lost forever.

## Attestation gathering

The attestation gathering process is actually a three step process: first, the attestation keypair is setup; second, the UI provides attestation for itself; last, the Signer provides an attestation for itself. Together, these three pieces form the powHSM attestation.

### Attestation keypair setup

The attestation keypair setup takes place right after the onboarding is complete (any attestation keypairs generated before that are wiped). In this part of the process, also known as endorsement setup, the device generates a new keypair, which will be known as the attestation keypair. Then, it signs its public key with its device key, and then outputs the attestation public key, the aforementioned signature and the issuer's certificate of the device's keypair. This two-step certification chain can be used to prove that the generated attestation keypair was generated in an authentic ledger device and is under its control. It is important to mention that the _endorsement scheme number two_ is used for the attestation setup. This then implies that applications using the attestation key to sign messages actually use a derived key obtained from this key plus the running application hash. Therefore, a valid signature under this scheme is also proof of it being generated from a specific application.

### UI Attestation

Before diving into the UI attestation, it is important to recall a few relevant UI features:

- At onboarding, the user-entered pin is required to contain at least one non-numeric character, and the recovery screen for the Ledger device only allows for the manual input of a fully numeric pin. This in turn implies that the only way of accessing the recovery screen after the UI is installed and the device is onboarded is by entering an invalid pin three times, which would wipe the device - including any generated keys.
- An application is only allowed to run if it's hash is exactly that of the currently authorized signer version's hash.
- The authorized signer version can only be changed with explicit authorization from a set of predefined authorizers (see the [signer authorization documentation](./signer-authorization.md) for details on this).
- The attestation keypair cannot be regenerated or changed.
- The UI does not backup the keys that it generates during the onboarding process.

To generate the attestation, the UI uses the configured attestation scheme to sign a message generated by the concatenation of:

- A predefined header (`HSM:UI:4.0`).
- A 32 byte user-defined value. By default, the attestation generation client supplies the latest RSK block hash as this value, so it can then be used as a minimum timestamp reference for the attestation generation.
- The compressed public key corresponding to the private key obtained by deriving the generated seed with the BIP32 path `m/44'/0'/0'/0/0` (normally used as the BTC key by the Signer application).
- The hash of the currently authorized Signer version.
- The iteration of the currently authorized Signer version (used for downgrade prevention).

As a consequence of the aforementioned features, this message guarantees that the device is running a specific version of the UI with a specific seed and authorized signer version, and also that this cannot be changed without wiping the device, therefore losing the keys forever. The RSK best block hash also consitutes proof of a minimum date/time on which the attestation was generated.

### Signer attestation

To generate the attestation, the Signer uses the configured attestation scheme to sign a message containing a predefined header (`HSM:SIGNER:4.0`) and the `sha256sum` of the concatenation of the authorized public keys (see the [protocol](./protocol.md) for details on this) lexicographically ordered by their UTF-encoded derivation path. This message guarantees that the device is running a specific version of the Signer and that those keys are in control of the ledger device.

## Attestation file format

The output of the attestation process is a JSON file with a proprietary structure that allows for the validation of each of the attestation components (UI and Signer) all the way to the issuer's public key (Ledger), and also validating the generated attestation keypair as a byproduct. A sample attestation file is shown below:

```json
{
  "version": 1,
  "targets": [
    "ui",
    "signer"
  ],
  "elements": [
    {
      "name": "attestation",
      "message": "ff04a4fa2b3f2efa63635011ba09980d13db35d70576b32a191a5517a223146f4477783ab9354e75b81861b5fd2148d42ebaff2d36d18e3f41be6b72cb83eebd00fd",
      "signature": "3044022002db0c43131697d6b3a8b84996651cb7c68fddd57fd97d9eedaddf5ff991abe80220748c8f43b5e5dc6e83450857a7eb2f092cb6924edc75f24d5b3fa158a4aea167",
      "signed_by": "device"
    },
    {
      "name": "device",
      "message": "0210b48081be20280434a28e4185e735964a36b5cd8817cbdde534f2839f04c5f998927a36f08343726de175327fa5272e3929b9c357f36f2128c92e14af359ce0e00734d2c93f4c07",
      "signature": "30440220181d61b12165b0dd0548cb574577d9f9419a894da56e5b1323375c3b9435622a0220290a29b2a06bbd481b0d0587abadddee39c002ed7f269ac11b23917e7c5c615e",
      "signed_by": "root"
    },
    {
      "name": "ui",
      "message": "48534d3a55493a332e30c4207b260c5b6964190568e528ec0b212a70e512ed6bdcef5e192362852a383903198eb60255fefc3478d0a78c11f5124c938f66fdaa62f9e9c543c6ced031ef37e1baa18564fc0c2c70ac4019609c6db643adbf12711c8b319f838e6a74b0da2c0001",
      "signature": "3044022058bb00fb47f1ba25e840e179ea705e1a9c42f75bc2e63775c91f6547661b9afb022074b769bb4815b16c86503da37a5db8e16933606ddd25ee5bb65aebe5d9a53155",
      "signed_by": "attestation",
      "tweak": "17f2129265b071e3d8658a549cd60720c86e34c7a6b81d517ffef123c8425f19"
    },
    {
      "name": "signer",
      "message": "48534d3a5349474e45523a332e30a2316e4c4e07e77ae65c74574452f330ed62752ba4c66f9c2101836d7b36cef2",
      "signature": "30440220154bb544fe00df5635c03618ee9614d50933fe7c9226d8efce55f1a40832681402206289dab7b8d6700e048b602ac03516e0e6a1609796fc27c440848d072af71c2a",
      "signed_by": "attestation",
      "tweak": "e1baa18564fc0c2c70ac4019609c6db643adbf12711c8b319f838e6a74b0da2c"
    }
  ]
}
```

Following is an explanation of the different components in the example:

- The `version` field just indicates the version of the format (`1`), which determines the semantics of the rest of the file.
- The `targets` field is a string array indicating which elements are to be validated. In this case, both `ui` and `signer` are to be independently validated.
- The `elements` is an array containing each of the elements of the certificate. The role of each of the elements' fields is explained below:
  - The `name` field is a unique identifier for the element throughout the file. It allows for referencing from the `targets` and `elements.signed_by` fields. The only allowed values for this field are `device`, `attestation`, `ui` and `signer`.
  - The `message` contains the hex-encoded message signed in that element.
  - The `signature` contains the hex-encoded signature for that element's `message`.
  - The `signed_by` contains either the name of another element within the file (e.g., `attestation` for the `signer` element), or the value `root`. It is used to find the public key of the signer of the element at hand. In the case of referencing an element, that element's `message` (combined with its `extract` field) is used as the public key. In the case of `root`, the root issuer's public key (normally Ledger) is to be used for validation. This public key can be fed manually through e.g. tooling.
  - The optional `tweak` element is a hex-encoded hash that indicates whether the signer public key should be tweaked for validation (see [the implementation](../middleware/admin/certificate.py) for details).

Additionally, we define a function `extract` that takes an element and returns the `value` portion of its `message` component. This `value` will then serve as either a validator public key for a child element, or for end-user validation purposes if at a leaf - e.g., the hash of the public keys in the case of the `signer` element. The definition uses _a la python_ slicing notation, and general python-like code, and is:

```
def extract(element):
  message = decode_hex_string(element.message)

  if element.name == "device":
    return message[-65:]

  if element.name == "attestation":
    return message[1:]
  
  if element.name == "ui" or element.name == "signer":
    return message

  raise "Invalid element"
```

The validation process _for each of the targets_ is fairly straightforward, and can even be done manually with the aid of basic ECDSA and hashing tools: walk the element chain "upwards" until the element signed by `root` is found. Then start by validating that element's signature against the root public key and extracting that element's public key. Repeat the process walking the chain "downwards" until the target is reached. Fail if at any point an element's signature is invalid. Otherwise the target is valid and its value can be extracted from its `message` field and interpreted accordingly (in the case of the `ui` element, the user-defined value, public key and custom certification authority; in the case of the `signer`, the hash of the authorized public keys).

## Tooling

For completion's sake, a validation tool is provided within the administration toolset. So, for example, if the file depicted above was at `/a/path/to/the/attestation.json`, the JSON-formatted public keys generated at onboarding time were at `/a/path/to/the/public-keys.json` and we knew the issuer public key was `0490f5c9d15a0134bb019d2afd0bf297149738459706e7ac5be4abc350a1f818057224fce12ec9a65de18ec34d6e8c24db927835ea1692b14c32e9836a75dad609` (the actual ledger issuer public key, found in [ledger's endorsement setup tooling](https://github.com/LedgerHQ/blue-loader-python/blob/0.1.31/ledgerblue/endorsementSetup.py#L138)), we could issue:

```bash
middleware/term> python adm.py verify_attestation -t /a/path/to/the/attestation.json -r 0490f5c9d15a0134bb019d2afd0bf297149738459706e7ac5be4abc350a1f818057224fce12ec9a65de18ec34d6e8c24db927835ea1692b14c32e9836a75dad609 -b /a/path/to/the/public-keys.json
```

to then obtain the following sample output:

```
########################################
### -> Verify UI and Signer attestations
########################################
Using 0490f5c9d15a0134bb019d2afd0bf297149738459706e7ac5be4abc350a1f818057224fce12ec9a65de18ec34d6e8c24db927835ea1692b14c32e9836a75dad609 as root authority
--------------------------------------------------------------------------------------------------------
UI verified with:
UD value: c4207b260c5b6964190568e528ec0b212a70e512ed6bdcef5e192362852a3839
Derived public key (m/44'/0'/0'/0/0): 03198eb60255fefc3478d0a78c11f5124c938f66fdaa62f9e9c543c6ced031ef37
Authorized signer hash: e1baa18564fc0c2c70ac4019609c6db643adbf12711c8b319f838e6a74b0da2c
Authorized signer iteration: 1
Installed UI hash: 17f2129265b071e3d8658a549cd60720c86e34c7a6b81d517ffef123c8425f19
--------------------------------------------------------------------------------------------------------
---------------------------------------------------------------------------------------
Signer verified with public keys:
m/44'/0'/0'/0/0:   03198eb60255fefc3478d0a78c11f5124c938f66fdaa62f9e9c543c6ced031ef37
m/44'/1'/0'/0/0:   0309fe4c9a803658c1d1c0c19f2d841e34306d172f0bb092431ace7bbda334e902
m/44'/1'/1'/0/0:   023ac8c77507fdcb7581ce3ee366a7b09791b54377af67f75e1a159737f4f77fe7
m/44'/1'/2'/0/0:   02583d0dec06114cc0a19883398652d8f87af0175f7d7c2c97417622341e06560c
m/44'/137'/0'/0/0: 03458e7f8f7885f0b0648a8e2e899fe838a7f93da0028634689438e460d3ba614f
m/44'/137'/1'/0/0: 03e27a65c9e6ff0d3fc4085aa84f8d7ec467edf6ae6b30ed40d96d4344b516f4c6

Hash: a2316e4c4e07e77ae65c74574452f330ed62752ba4c66f9c2101836d7b36cef2
Installed Signer hash: e1baa18564fc0c2c70ac4019609c6db643adbf12711c8b319f838e6a74b0da2c
---------------------------------------------------------------------------------------
```

and verify that the reported custom CA and UI and Signer hashes match the expected values.