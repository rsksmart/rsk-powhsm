# powHSM attestation

## Abstract

This document describes the mechanisms through which a powHSM installation can prove to an end user that it is actually installed on an authentic physical Ledger device with a specific UI and Signer versions, along with its installed Certification Authority (usually RSK) and generated public keys.

## Preliminaries, native support and assumptions

Each device currently used to run powHSM on, namely Ledger Nano S, ships with a mechanism to prove its authenticity and that also enables and leverages some basic additional support for user application attestation. For powHSM attestation we make extensive use of these mechanisms, assuming it is robust enough for our purpose.

## Device key and authenticity

The mechanism use by Ledger Nano S devices to prove their authenticity can be better understood from [the ledger documentation](https://ledger.readthedocs.io/en/latest/bolos/features.html#attestation):

_"When all Ledger devices are provisioned in the factory, they first generate a unique Device public-private keypair. The Device’s public key is then signed by Ledger’s Issuer key to create an Issuer Certificate which is stored in the device. This certificate is a digital seal of authenticity of the Ledger device. By providing the Device’s public key and Issuer Certificate, the device can prove that it is a genuine Ledger device."_

We use the device public key and issuer certificate as the basis for the powHSM attestation mechanism.

## Application attestation and powHSM

Ledger Nano S user applications can make indirect use of the aforementioned device keypair to provide attestation mechanisms. This can be better understood from [the ledger documentation](https://ledger.readthedocs.io/en/latest/bolos/features.html#attestation):

_"The device generates a new attestation keypair and signs it using the Device private key to create a Device Certificate. The device then returns the attestation public key, the Device Certificate, and the Issuer Certificate..."_

and

_"The attestation keys are not accessible to apps directly, instead BOLOS provides attestation functionality to userspace applications through cryptographic primitives available as system calls. There are two different Endorsement Schemes available to applications (Endorsement Scheme One and Endorsement Scheme Two). When creating an attestation keypair, the user must choose which scheme the keypair shall belong to."_

For powHSM, we use Endorsement Scheme #2, which provides a primitive to _"Sign a message using a private key derived from the attestation private key and the hash of the running application"_. In this way, installed applications can endorse specific messages, and that endorsement constitutes _proof_ of those messages being generated on that specific running code on an authentic Ledger Nano S. This is the basis for the powHSM attestation.

## Attestation goal

The main goal of the powHSM attestation mechanism is enabling the end user(s) to have proof of a specific powHSM with a given UI and Signer running on an authentic Ledger Nano S with a specific custom certification authority (CA) and having control over a given set of generated public keys. Given the constraints specifically implemented on the powHSM UI (more on this later), proof of the aforementioned would also guarantee that the holder of the powHSM device will not be able to alter the installed UI and/or Signer applications without the explicit authorization of the custom certification authority (namely, RSK). An attempt to do so would result in the keypairs being lost forever.

## Attestation gathering

The attestation gathering process is actually a three step process: first, the attestation keypair is setup; second, the UI provides attestation for itself; last, the Signer provides an attestation for itself. Together, these three pieces form the powHSM attestation.

### Attestation keypair setup

The attestation keypair setup takes place right after the onboarding is complete (any attestation keypairs generated before that are wiped). In this part of the process, also known as endorsement setup, the device generates a new keypair, which will be known as the attestation keypair. Then, it signs its public key with its device key, and then outputs the attestation public key, the aforementioned signature and the issuer's certificate of the device's keypair. This two-step certification chain can be used to prove that the generated attestation keypair was generated in an authentic ledger device and is under its control. It is important to mention that the _endorsement scheme number two_ is used for the attestation setup. This then implies that applications using the attestation key to sign messages actually use a derived key obtained from this key plus the running application hash. Therefore, a valid signature under this scheme is also proof of it being generated from a specific application.

### UI Attestation

Before diving into the UI attestation, it is important to recall a few relevant UI features:

- At onboarding, the user-entered pin is required to contain at least one non-numeric character, and the recovery screen for the Ledger device only allows for the manual input of a fully numeric pin. This in turn implies that the only way of accessing the recovery screen after the UI is installed and the device is onboarded is by entering an invalid pin three times, which would wipe the device - including any generated keys.
- An application is only allowed to run if it is signed by the custom certification authority.
- The custom certification authority cannot be changed.
- The attestation keypair cannot be regenerated or changed.
- The UI does not backup the keys that it generates during the onboarding process.

To generate the attestation, the UI uses the configured attestation scheme to sign a message generated by the concatenation of:

- A predefined header (`RSK:HSM:UI:`).
- A 32 byte user-defined value. By default, the attestation generation client supplies the latest RSK block hash as this value, so it can then be used as a minimum timestamp reference for the attestation generation.
- The compressed public key of the private key obtained by deriving the generated seed with the BIP32 path `m/44'/0'/0'/0/0` (normally used as the BTC key).
- The compressed custom certification authority's public key. 

As a consequence of the aforementioned features, this message guarantees that the device is running a specific version of the UI with a specific seed and custom certification authority, and also that this cannot be changed without wiping the device, therefore losing the keys forever. The RSK best block hash also consitutes proof of a minimum date/time on which the attestation was generated.

### Signer attestation

To generate the attestation, the Signer uses the configured attestation scheme to sign a message containing a predefined header (`RSK:HSM:SIGNER:`) and the `sha256sum` of the concatenation of the authorized public keys (see the [protocol](./protocol.md) for details on this) lexicographically ordered by their UTF-encoded derivation path. This message guarantees that the device is running a specific version of the Signer and that those keys are in control of the ledger device.

## Attestation file format

The output of the attestation process is a JSON file with a proprietary structure that allows for the validation of each of the attestation components (UI and Signer) all the way to the issuer's public key(Ledger), and also validating the generated attestation keypair as a byproduct. A sample attestation file is shown below:

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
      "message": "ff043bc81f42c85b1cafb66f2af7ba29c61aac0357ae0228ea479d775c908ee412ca857f892c38c300c7e7283298dea535723955448fe6edb906a4dc4738cbb61e86",
      "digest": "none",
      "extract": "1:",
      "signature": "3045022100cb411ef6771105a8eb71c85295450fac36edd8abfca7bfcf55dbca0fe9842a0f022056055f6f34f4f0c0bfe6620611b18139fc816b8c64447452ea31d2551c0dcff2",
      "signed_by": "device"
    },
    {
      "name": "device",
      "message": "0210b48081be20280434a28e4185e735964a36b5cd8817cbdde534f2839f04c5f998927a36f08343726de175327fa5272e3929b9c357f36f2128c92e14af359ce0e00734d2c93f4c07",
      "digest": "none",
      "extract": "-65:",
      "signature": "30440220181d61b12165b0dd0548cb574577d9f9419a894da56e5b1323375c3b9435622a0220290a29b2a06bbd481b0d0587abadddee39c002ed7f269ac11b23917e7c5c615e",
      "signed_by": "root"
    },
    {
      "name": "ui",
      "message": "52534b3a48534d3a55493a045993ce2195967539196548251c78d1b75b73cc39424dc2570f73c1f89fd55f8eb96538377f31ee0a68799d151b56e3bc539995e61206b09a30878560702c1157",
      "digest": "none",
      "extract": ":",
      "signature": "304402207744f1f7080766b560d83e35a33bd624a5cabf3ae0b63545e3b42cbbca7fe1f002207d476d3c0fb55c19aeca8e186cd40ba5f6c8957e297cab1dea364e6a94c180a2",
      "signed_by": "attestation",
      "tweak": "4b73dc1bdd565dd2c7af9587ae33b7db65fbb95fc174fd701d45c70df8bb4f51"
    },
    {
      "name": "signer",
      "message": "52534b3a48534d3a5349474e45523aaed652b48a8306bfc023c19be3a5273a284feaf381f115bcd5450552319a9320",
      "digest": "none",
      "extract": ":",
      "signature": "304402202ebb12c6a780eedb8f3f9e811cea3e920f06308a91e527cc2b24ed1923d1d1110220576bcaa97e0042e1c3e4da7d6f735155078a7c8c55b7c745f9e474fadd176dd9",
      "signed_by": "attestation",
      "tweak": "26ec706760ea301358d40fe669edc4422dc8ec3cdfe898a4332b7d33b6ba2e96"
    }
  ]
}
```

Following is an explanation of the different components in the example:

- The `version` field just indicates the version of the format (`1`), which determines the semantics of the rest of the file.
- The `targets` field is a string array indicating which elements are to be validated. In this case, both `ui` and `signer` are to be independently validated.
- The `elements` is an array containing each of the elements of the certificate. The role of each of the elements' fields is explained below:
  - The `name` field is a unique identifier for the element throughout the file. It allows for referencing from the `targets` and `elements.signed_by` fields.
  - The `message` contains the hex-encoded message signed in that element.
  - The `signature` contains the hex-encoded signature for that element's `message`.
  - The `digest` indicates whether the `message` needs to be digested for validation against the `signature`. Possible values in version 1 are `none` and `sha256`.
  - The `signed_by` contains either the name of another element within the file (e.g., `attestation` for the `signer` element), or the value `root`. It is used to find the public key of the signer of the element at hand. In the case of referencing an element, that element's `message` (combined with its `extract` field) is used as the public key. In the case of `root`, the root issuer's public key (normally Ledger) is to be used for validation. This public key can be fed manually through e.g. tooling.
  - The `extract` element is a reduced _a la python_ array slice specifier with no striding (see [the documentation](https://docs.python.org/3.8/reference/expressions.html?highlight=slice#slicings) for details). It indicates which part of the `message` constitutes the `value` of the element at hand (which could serve as a validator public key for another element, or could have a different use if at the top of the chain - e.g., the hash of the public keys in the case of the `signer` element).
  - The optional `tweak` element is a hex-encoded hash that indicates whether the signer public key should be tweaked for validation (see [the implementation](../middleware/admin/certificate.py) for details).

The validation process _for each of the targets_ is fairly straightforward, and can even be done manually with the aid of basic ECDSA and hashing tools: walk the element chain "upwards" until the element signed by `root` is found. Then start by validating that element's signature against the root public key and extracting that element's public key. Repeat the process walking the chain "downwards" until the target is reached. Fail if at any point an element's signature is invalid. Otherwise the target is valid and its value can be extracted from its `message` field and interpreted accordingly (in the case of the `ui` element, the custom certification authority; in the case of the `signer`, the hash of the authorized public keys).

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
----------------------------------------------------------------------------------------------------------------------------------
UI verified with CA:
045993ce2195967539196548251c78d1b75b73cc39424dc2570f73c1f89fd55f8eb96538377f31ee0a68799d151b56e3bc539995e61206b09a30878560702c1157
Installed UI hash: 4b73dc1bdd565dd2c7af9587ae33b7db65fbb95fc174fd701d45c70df8bb4f51
----------------------------------------------------------------------------------------------------------------------------------
---------------------------------------------------------------------------------------
Signer verified with public keys:
m/44'/0'/0'/0/0:   035e3676f3d262be05a1a7c03b6c22b1a26bef4bdbda5272d9dd3b3f90326508e8
m/44'/1'/0'/0/0:   031927f8ae5f174d91fac7f189a64eec3c349a91076579300ab8ddbd59500752b4
m/44'/1'/0'/0/1:   032ff72bdd81e7cdad25ba8329ed12cb38dd3cf1574af3a60e9b89091b889a57f0
m/44'/1'/0'/0/2:   02ed8e973f1dc8756bd69bc470bb983340b95972442674cc43a9f954fef376f63b
m/44'/1'/1'/0/0:   032400a32487c34dbb49a8c29191e1a2f8ac7efe1dfd130a232aa3f848ab905577
m/44'/1'/2'/0/0:   03757a42eebe2e2221e8106fd6b3996c7d039b0edb7b0e399030a43e34b503d219
m/44'/137'/0'/0/0: 039e620ab2fb9b68c28e44f13e9b29c9ba07871f4aaa4bb4762aa730f2372b44e8
m/44'/137'/0'/0/1: 0342b155b3dd7d61842f4bdedf72bd10a8f1b13a829561beb7fd0f58edcfcfa5ea
m/44'/137'/1'/0/0: 0369b1413bcba7eb04a42e8fc8a55c093da4f123e262ec90584dccfd10f85f58bc

Hash: aed652b48a8306bfc023c19be3a5273a284feaf381f115bcd5450552319a9320
Installed Signer hash: 26ec706760ea301358d40fe669edc4422dc8ec3cdfe898a4332b7d33b6ba2e96
---------------------------------------------------------------------------------------
```

and verify that the reported custom CA and UI and Signer hashes match the expected values.