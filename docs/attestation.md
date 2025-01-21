# powHSM attestation

## Abstract

This document describes the mechanisms through which a powHSM installation can prove to an end user that either:

- It is actually installed an authentic physical Ledger Nano S device with specific UI and Signer versions, along with its currently authorized signer version and generated public keys; or
- It is running in an authentic Intel SGX environment, within an SGX enclave with a specific codebase, along with its safely generated and stored public keys.

## Attestation for the Ledger-based powHSM

### Preliminaries, native support and assumptions

Each Ledger device currently used to run powHSM on, namely Ledger Nano S, ships with a mechanism to prove its authenticity and that also enables and leverages some basic additional support for user application attestation. For powHSM attestation we make extensive use of these mechanisms, assuming it is robust enough for our purpose.

### Device key and authenticity

The mechanism used by Ledger Nano S devices to prove their authenticity can be better understood from [the ledger documentation](https://developers.ledger.com/docs/nano-app/bolos-features/#attestation):

_"When all Ledger devices are provisioned in the factory, they first generate a unique Device public-private keypair. The Device’s public key is then signed by Ledger’s Issuer key to create an Issuer Certificate which is stored in the device. This certificate is a digital seal of authenticity of the Ledger device. By providing the Device’s public key and Issuer Certificate, the device can prove that it is a genuine Ledger device."_

We use the device public key and issuer certificate as the basis for the powHSM attestation mechanism.

### Application attestation and powHSM

Ledger Nano S user applications can make indirect use of the aforementioned device keypair to provide attestation mechanisms. This can be better understood from [the ledger documentation](https://developers.ledger.com/docs/nano-app/bolos-features/#attestation):

_"The device generates a new attestation keypair and signs it using the Device private key to create a Device Certificate. The device then returns the attestation public key, the Device Certificate, and the Issuer Certificate..."_

and

_"The attestation keys are not accessible to apps directly, instead BOLOS provides attestation functionality to userspace applications through cryptographic primitives available as system calls. There are two different Endorsement Schemes available to applications (Endorsement Scheme One and Endorsement Scheme Two). When creating an attestation keypair, the user must choose which scheme the keypair shall belong to."_

For powHSM, we use Endorsement Scheme Two, which provides a primitive to _"Sign a message using a private key derived from the attestation private key and the hash of the running application"_. In this way, installed applications can endorse specific messages, and that endorsement constitutes _proof_ of those messages being generated on that specific running code on an authentic Ledger Nano S. This is the basis for the powHSM attestation.

### Attestation goal

The main goal of the Ledger-based powHSM attestation mechanism is enabling the end user(s) to have proof of a specific powHSM with a given UI and Signer running on an authentic Ledger Nano S with a specific authorized signer version and having control over a given set of generated public keys. Given the constraints specifically implemented on the powHSM UI (more on this later), proof of the aforementioned would also guarantee that the holder of the powHSM device will not ever be able to alter the installed UI; and that upgrades for the Signer application will need the explicit authorization of a minimum number of predefined authorizers (currently hardcoded within the UI, and decided at compile time). Attempts to bypass these restrictions would result in the keypairs being lost forever.

### Attestation gathering

The attestation gathering process is actually a three step process: first, the attestation keypair is setup; second, the UI provides attestation for itself; last, the Signer provides an attestation for itself. Together, these three pieces form the powHSM attestation. Intermediate software layers unify these pieces into a user-friendly format that can be used for transmission and verification.

#### Attestation keypair setup

The attestation keypair setup takes place right after the onboarding is complete (any attestation keypairs generated before that are wiped). In this part of the process, also known as endorsement setup, the device generates a new keypair, which will be known as the attestation keypair. Then, it signs its public key with its device key, and then outputs the attestation public key, the aforementioned signature and the issuer's certificate of the device's keypair. This two-step certification chain can be used to prove that the generated attestation keypair was generated in an authentic ledger device and is under its control. It is important to mention that the _endorsement scheme number two_ is used for the attestation setup. This then implies that applications using the attestation key to sign messages actually use a derived key obtained from this key plus the running application hash. Therefore, a valid signature under this scheme is also proof of it being generated from a specific application.

#### UI Attestation

Before diving into the UI attestation, it is important to recall a few relevant UI features:

- At onboarding, the user-entered pin is required to contain at least one non-numeric character, and the recovery screen for the Ledger device only allows for the manual input of a fully numeric pin. This in turn implies that the only way of accessing the recovery screen after the UI is installed and the device is onboarded is by entering an invalid pin three times, which would wipe the device - including any generated keys.
- An application is only allowed to run if it's hash is exactly that of the currently authorized signer version's hash.
- The authorized signer version can only be changed with explicit authorization from a set of predefined authorizers (see the [signer authorization documentation](./signer-authorization.md) for details on this).
- The attestation keypair cannot be regenerated or changed.
- The UI does not backup the keys that it generates during the onboarding process.

To generate the attestation, the UI uses the configured attestation scheme to sign a message generated by the concatenation of:

- A predefined header (`HSM:UI:5.3`).
- A 32 byte user-defined value. By default, the attestation generation client supplies the latest RSK block hash as this value, so it can then be used as a minimum timestamp reference for the attestation generation.
- The compressed public key corresponding to the private key obtained by deriving the generated seed with the BIP32 path `m/44'/0'/0'/0/0` (normally used as the BTC key by the Signer application).
- The hash of the currently authorized Signer version.
- The iteration of the currently authorized Signer version (used for downgrade prevention).

As a consequence of the aforementioned features, this message guarantees that the device is running a specific version of the UI with a specific seed and authorized signer version, and also that this cannot be changed without wiping the device, therefore losing the keys forever. The RSK best block hash also consitutes proof of a minimum date/time on which the attestation was generated.

#### Signer attestation

To generate the attestation, the Signer uses the configured attestation scheme to sign a message that guarantees that the device is running a specific version of the Signer and that those keys are in control of the Ledger device. Additional fields aid in auditing a device's state at the time the attestation is gathered (e.g., for firmware updates). For details on the specific message signed, refer to the [powHSM attestation contents](#powhsm-attestation-contents) section.

## Attestation for the Intel SGX-based powHSM

### Preliminaries, native support and assumptions

The Intel Software Guard Extensions (SGX) architecture features an advanced mechanism that allows a combination of hardware and software to gain a remote party's trust. This mechanism, known as remote attestation, gives the relying party the ability to check that the intended software is
securely running within an enclave on a system with Intel SGX enabled. For the Intel SGX-based powHSM attestation we make use of remote attestation, assuming it is robust enough for our purpose. In particular, we use ECDSA-based attestation using Intel SGX Data Center Attestation Primitives (DCAP), explained below.

### Local and remote attestation

Local attestation is a native Intel SGX process that can be by used by an enclave to verify the integrity and authenticity of another enclave running on the same physical platform. It enables the "verifier" enclave to confirm the identity, code, and state of the target enclave by exchanging a secure report, natively and securely generated using Intel SGX primitives. This report can additionally include arbitrary information generated by the target enclave, whose source the verifier enclave can deem trustworthy.

Remote attestation extends local attestation to enable trust verification between an SGX enclave and a verifier outside the platform. In Intel SGX DCAP remote attestation, the target enclave generates a local attestation report, which is then sent to a specialized system enclave that transforms the local report into a "quote" by signing it with a platform-specific attestation key. This quote, along with a certificate that chains back to Intel's root of trust, is sent to the remote verifier. The verifier uses the certificate chain to validate the quote and, by extension, the enclave’s identity and platform security, enabling the remote party to trust the enclave.

### Attestation goal

The main goal of the SGX-based powHSM attestation mechanism is enabling the end user(s) to have proof of a powHSM with a given trusted codebase running within an authentic Intel SGX enclave and having control over a given set of generated public keys. Given the constraints specifically implemented on the powHSM enclave business layer alongside the specific primitives leveraged to encrypt/decrypt secrets within the SGX enclave (namely, the use of the enclave identity for the encryption key derivation functions), it is guaranteed that all enclave secrets (and, in particular, the master seed) will only ever be known to the powHSM enclave. Any attempts to modify the code (even having access to the enclave signer private key) will result in a different enclave identity and, thus, in an invalid set of derived keys that will make it impossible for the modified enclave to access the original enclave's secrets.

### Attestation gathering

As opposed to what happens with the Ledger-based powHSM, the attestation gathering process for the SGX-based powHSM is straightforward: upon request, the powHSM enclave produces a quote. This quote is, in itself, the entire attestation, but is then transformed by intermediate software layers into a user-friendly format that can be used for transmission and verification.

## powHSM attestation contents

Under both Ledger and SGX, the powHSM business layer includes an arbitrary message that is part of the final attestation produced, and that can also be verified and trusted by the interested parties. This message is generated by the concatenation of:

- A predefined header (`POWHSM:5.4::`).
- A 3-byte platform identifier, which for Ledger and SGX are exactly the ASCII characters `led` or `sgx`, respectively.
- A 32 byte user-defined value, given by the requesting party. By default, the attestation generation client supplies the latest RSK block hash as this value, so it can then be used as a minimum timestamp reference for the attestation generation.
- A 32 byte value that is generated by computing the `sha256sum` of the concatenation of the authorized public keys (see the [protocol](./protocol.md) for details on this) lexicographically ordered by their UTF-encoded derivation path.
- A 32 byte value denoting the powHSM's current known best block hash for the Rootstock network.
- An 8 byte value denoting the leading bytes of the latest authorised signed Bitcoin transaction hash.
- An 8 byte value denoting a big-endian unix timestamp. For both Ledger and SGX, this is currently always zero.

This message guarantees that the device is running a specific powHSM version and that the keys are in control of the Ledger device or SGX enclave. The additional fields aid in auditing a powHSM's state at the time the attestation is gathered.

## Attestation file formats

The output of the attestation process is a JSON file with a proprietary structure that allows for the validation of each of the attestation components all the way to the root of trust (Ledger or Intel, depending on the platform used). Currently, there's two versions of the attestation file used: version one is used in the Ledger-based implementation, and version two is used for the Intel SGX-based implementation. In the future, the idea is unifying everything into a single version in order to simplify the generation and verification process both from a software implementation and end-user perspective.

### Attestation version one

A sample attestation version one file is shown below:

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
      "message": "504f5748534d3a352e343a3a6c656413c3581aa97c8169d3994e9369c11ebd63bcf123d0671634f21b568983d3291687fd9b1f4aa83e348906e2efd6cbed98e39d17aea4c03d73f30e99d602d67633bdcb3c17c7aee714cec8ad900341bfd987b452280220dcbd6e7191f67ea4209b659a04529d6811dd0000000000000000",
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

### Attestation version two

A sample attestation version two file is shown below:

```json
{
  "version": 2,
  "targets": [
    "quote"
  ],
  "elements": [
    {
      "name": "quote",
      "type": "sgx_quote",
      "message": "03000200000000000a000f00939a7233f79c4ca9940a0db3957f0607ceae3549bc7273eb34d562f4564fc182000000000e0e100fffff01000000000000000000010000000000000000000000000000000000000000000000000000000000000005000000000000000700000000000000d32688d3c1f3dfcc8b0b36eac7c89d49af331800bd56248044166fa6699442c10000000000000000000000000000000000000000000000000000000000000000718c2f1a0efbd513e016fafd6cf62a624442f2d83708d4b33ab5a8d8c1cd4dd000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000064000100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000b1fcb9087762c10418e2a0e9e0791f9fdfe1e123b00416a477cf0875f98e44070000000000000000000000000000000000000000000000000000000000000000",
      "custom_data": "504f5748534d3a352e343a3a7367788d5dbf3ca886a9d849228e154693cdbab15d109f6327a71b5ef5860a9b828bef0c4d091913d39750dc8975adbdd261bd10c1c2e110faa47cfbe30e740895552bbdcb3c17c7aee714cec8ad900341bfd987b452280220dcbd6e7191f67ea4209b00000000000000000000000000000000",
      "signature": "3046022100a4ec02ec2714b7c5c23cf6ff85ea45a4cff357199ed093212488ec4efead26d602210094d383e55f079ad3a66dcbfc2962b006b8d98c7a872721a4d54644096dc21bd3",
      "signed_by": "attestation"
    },
    {
      "name": "attestation",
      "type": "sgx_attestation_key",
      "message": "0e0e100fffff0100000000000000000000000000000000000000000000000000000000000000000000000000000000001500000000000000e70000000000000096b347a64e5a045e27369c26e6dcda51fd7c850e9b3a3a79e718f43261dee1e400000000000000000000000000000000000000000000000000000000000000008c4f5775d796503e96137f77c68a829a0056ac8ded70140b081b094490c57bff00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001000a000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001fe721d0322954821589237fd27efb8fef1acb3ecd6b0352c31271550fc70f940000000000000000000000000000000000000000000000000000000000000000",
      "key": "04a024cb34c90ea6a8f9f2181c9020cbcc7c073e69981733c8deed6f6c451822aa08376350ff7da01f842bb40c631cbb711f8b6f7a4fae398320a3884774d250ad",
      "auth_data": "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
      "signature": "304502201f14d532274c4385fc0019ca2a21e53e17143cb62377ca4fcdd97fa9fef8fb2502210095d4ee272cf3c512e36779de67dc7814982f1160d981d138a32b265e928a0562",
      "signed_by": "quoting_enclave"
    },
    {
      "name": "quoting_enclave",
      "type": "x509_pem",
      "message": "MIIE8zCCBJigAwIBAgIUfr2dlwN42DBUA9CXIkBlGP2vV3AwCgYIKoZIzj0EAwIw\ncDEiMCAGA1UEAwwZSW50ZWwgU0dYIFBDSyBQbGF0Zm9ybSBDQTEaMBgGA1UECgwR\nSW50ZWwgQ29ycG9yYXRpb24xFDASBgNVBAcMC1NhbnRhIENsYXJhMQswCQYDVQQI\nDAJDQTELMAkGA1UEBhMCVVMwHhcNMjQwMzIzMDQ0NjIxWhcNMzEwMzIzMDQ0NjIx\nWjBwMSIwIAYDVQQDDBlJbnRlbCBTR1ggUENLIENlcnRpZmljYXRlMRowGAYDVQQK\nDBFJbnRlbCBDb3Jwb3JhdGlvbjEUMBIGA1UEBwwLU2FudGEgQ2xhcmExCzAJBgNV\nBAgMAkNBMQswCQYDVQQGEwJVUzBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABKl7\nRDNlsZKkEtAcW7SfCX1JegbvGq4O0rRUt0z/G6fZJsNlpmRwTB4DYkrgkm1t+9Rp\nLwxFX9/kghxiDQm0jqmjggMOMIIDCjAfBgNVHSMEGDAWgBSVb13NvRvh6UBJydT0\nM84BVwveVDBrBgNVHR8EZDBiMGCgXqBchlpodHRwczovL2FwaS50cnVzdGVkc2Vy\ndmljZXMuaW50ZWwuY29tL3NneC9jZXJ0aWZpY2F0aW9uL3Y0L3Bja2NybD9jYT1w\nbGF0Zm9ybSZlbmNvZGluZz1kZXIwHQYDVR0OBBYEFALKV5DF16KnEbSW5QM9ecDq\nBZaHMA4GA1UdDwEB/wQEAwIGwDAMBgNVHRMBAf8EAjAAMIICOwYJKoZIhvhNAQ0B\nBIICLDCCAigwHgYKKoZIhvhNAQ0BAQQQttJXuiQVwqM4s74g+HxfKTCCAWUGCiqG\nSIb4TQENAQIwggFVMBAGCyqGSIb4TQENAQIBAgEOMBAGCyqGSIb4TQENAQICAgEO\nMBAGCyqGSIb4TQENAQIDAgEDMBAGCyqGSIb4TQENAQIEAgEDMBEGCyqGSIb4TQEN\nAQIFAgIA/zARBgsqhkiG+E0BDQECBgICAP8wEAYLKoZIhvhNAQ0BAgcCAQEwEAYL\nKoZIhvhNAQ0BAggCAQAwEAYLKoZIhvhNAQ0BAgkCAQAwEAYLKoZIhvhNAQ0BAgoC\nAQAwEAYLKoZIhvhNAQ0BAgsCAQAwEAYLKoZIhvhNAQ0BAgwCAQAwEAYLKoZIhvhN\nAQ0BAg0CAQAwEAYLKoZIhvhNAQ0BAg4CAQAwEAYLKoZIhvhNAQ0BAg8CAQAwEAYL\nKoZIhvhNAQ0BAhACAQAwEAYLKoZIhvhNAQ0BAhECAQ0wHwYLKoZIhvhNAQ0BAhIE\nEA4OAwP//wEAAAAAAAAAAAAwEAYKKoZIhvhNAQ0BAwQCAAAwFAYKKoZIhvhNAQ0B\nBAQGAGBqAAAAMA8GCiqGSIb4TQENAQUKAQEwHgYKKoZIhvhNAQ0BBgQQDVe/DXUV\nE4gemtgO5uBpvDBEBgoqhkiG+E0BDQEHMDYwEAYLKoZIhvhNAQ0BBwEBAf8wEAYL\nKoZIhvhNAQ0BBwIBAQAwEAYLKoZIhvhNAQ0BBwMBAQAwCgYIKoZIzj0EAwIDSQAw\nRgIhAJFgf78HggTBtvQPXZJx/3Fm71vCOmt82pce91M2ZAI0AiEAiZMPBbZZmvR2\nv+1mrs76JeglDQ+pK/SLN94l4+jM5DA=",
      "signed_by": "platform_ca"
    },
    {
      "name": "platform_ca",
      "type": "x509_pem",
      "message": "MIICljCCAj2gAwIBAgIVAJVvXc29G+HpQEnJ1PQzzgFXC95UMAoGCCqGSM49BAMC\nMGgxGjAYBgNVBAMMEUludGVsIFNHWCBSb290IENBMRowGAYDVQQKDBFJbnRlbCBD\nb3Jwb3JhdGlvbjEUMBIGA1UEBwwLU2FudGEgQ2xhcmExCzAJBgNVBAgMAkNBMQsw\nCQYDVQQGEwJVUzAeFw0xODA1MjExMDUwMTBaFw0zMzA1MjExMDUwMTBaMHAxIjAg\nBgNVBAMMGUludGVsIFNHWCBQQ0sgUGxhdGZvcm0gQ0ExGjAYBgNVBAoMEUludGVs\nIENvcnBvcmF0aW9uMRQwEgYDVQQHDAtTYW50YSBDbGFyYTELMAkGA1UECAwCQ0Ex\nCzAJBgNVBAYTAlVTMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAENSB/7t21lXSO\n2Cuzpxw74eJB72EyDGgW5rXCtx2tVTLq6hKk6z+UiRZCnqR7psOvgqFeSxlmTlJl\neTmi2WYz3qOBuzCBuDAfBgNVHSMEGDAWgBQiZQzWWp00ifODtJVSv1AbOScGrDBS\nBgNVHR8ESzBJMEegRaBDhkFodHRwczovL2NlcnRpZmljYXRlcy50cnVzdGVkc2Vy\ndmljZXMuaW50ZWwuY29tL0ludGVsU0dYUm9vdENBLmRlcjAdBgNVHQ4EFgQUlW9d\nzb0b4elAScnU9DPOAVcL3lQwDgYDVR0PAQH/BAQDAgEGMBIGA1UdEwEB/wQIMAYB\nAf8CAQAwCgYIKoZIzj0EAwIDRwAwRAIgXsVki0w+i6VYGW3UF/22uaXe0YJDj1Ue\nnA+TjD1ai5cCICYb1SAmD5xkfTVpvo4UoyiSYxrDWLmUR4CI9NKyfPN+",
      "signed_by": "sgx_root"
    }
  ]
}
```

Following is an explanation of the different components in the example:

- The `version` field just indicates the version of the format (`2`), which determines the semantics of the rest of the file.
- The `targets` field is a string array indicating which elements are to be validated. In this case, only the `quote` element is to be validated.
- The `elements` is an array containing each of the elements of the certificate. The role of each of the elements' mandatory fields is explained below:
  - The `name` field is a unique identifier for the element throughout the file. It allows for referencing from the `targets` and `elements.signed_by` fields. As opposed to what happens in version 1, arbitrary names are allowed here.
  - The `type` field indicates the type of element being described, and dictates which other attributes should also be present. Currently, there are three element types allowed: `sgx_quote`, `sgx_attestation_key` and `x509_pem`.
  - The `signed_by` contains either the name of another element within the file (e.g., `platform_ca` for the `quoting_enclave` element), or the value `sgx_root`. It is used to find the certifier for the element at hand. In the case of referencing an element, that element's public key is used for validation of the current element. In the case of `sgx_root`, the root of trust certificate (normally Intel) is to be used for validation. This certificate can be fed manually through e.g. tooling.
  - The `message` contains:
    - For the `sgx_quote` type, the hex-encoded message signed in that element, that corresponds to a `sgx_quote_t` struct, without the `signature_len` component (see [the source](https://github.com/openenclave/openenclave/blob/master/include/openenclave/bits/sgx/sgxtypes.h) for details).
    - For the `sgx_attestation_key` type, the hex-encoded message signed in that element, that corresponds to a `sgx_report_body_t` struct (see [the source](https://github.com/openenclave/openenclave/blob/master/include/openenclave/bits/sgx/sgxtypes.h) for details).
    - For the `x509_pem` type, the base64-encoded x509 certificate (same as what a `.pem` file would contain, without the begin and end markers).
  - For the `sgx_quote` and `sgx_attestation_key` types, the `signature` contains the hex-encoded DER signature for that element's `message`.
  - Additionally, for the `sgx_quote` type, the `custom_data` field contains the hex-encoded custom message given by the powHSM enclave. Its hash is contained within the `message` field.
  - Additionally, for the `sgx_attestation_key` type:
    - The `key` field contains the hex-encoded uncompressed NIST P-256 attestation public key that is used to validate other elements.
    - The `auth_data` field contains hex-encoded additional data that, SHA-256 hashed alongside the aforementioned public key, is contained within the signed `message`.

The validation process _for each of the targets_ is fairly straightforward, and very similar in spirit to that of the version one certificate shown before. It can also be done manually with the aid of basic ECDSA, hashing and x509 tools: walk the element chain "upwards" until the element signed by `sgx_root` is found. Then, if the element is of `x509_type`, validate it using an x509 parser and validator, retrieving the root of trust accordingly. Otherwise, validate that element's `signature` and `message` against the public key of the `signed_by` element. Additionally, validate that all remaining attributes are contained within the `message` according to its type. Repeat the process walking the chain "downwards" until the target is reached. Fail if at any point an element is deemed invalid. Otherwise the target is valid. Normally the target should be of `sgx_quote` type, and the custom message signed by the powHSM enclave is exactly the `custom_data` field. The individual fields contained within can now be extracted, analysed and validated accordingly.

## Tooling

For completion's sake, validation tools are provided within the administration toolset. So, for example, if the JSON attestation file was at `/a/path/to/the/attestation.json`, the JSON-formatted public keys generated at onboarding time were at `/a/path/to/the/public-keys.json`, then we could issue the following commands depending on the platform.

### Ledger

Assuming we knew the issuer public key was `0490f5c9d15a0134bb019d2afd0bf297149738459706e7ac5be4abc350a1f818057224fce12ec9a65de18ec34d6e8c24db927835ea1692b14c32e9836a75dad609` (the actual ledger issuer public key, found in [ledger's endorsement setup tooling](https://github.com/LedgerHQ/blue-loader-python/blob/0.1.31/ledgerblue/endorsementSetup.py#L138)), we could issue:

```bash
middleware/term> python adm_ledger.py verify_attestation -t /a/path/to/the/attestation.json -r 0490f5c9d15a0134bb019d2afd0bf297149738459706e7ac5be4abc350a1f818057224fce12ec9a65de18ec34d6e8c24db927835ea1692b14c32e9836a75dad609 -b /a/path/to/the/public-keys.json
```

to then obtain the following sample output:

```
########################################
### -> Verify UI and Signer attestations
########################################
Using 0490f5c9d15a0134bb019d2afd0bf297149738459706e7ac5be4abc350a1f818057224fce12ec9a65de18ec34d6e8c24db927835ea1692b14c32e9836a75dad609 as root authority
--------------------------------------------------------------------------------------------------------
UI verified with:
UD value: 13c3581aa97c8169d3994e9369c11ebd63bcf123d0671634f21b568983d32916
Derived public key (m/44'/0'/0'/0/0): 0254464d36eaa08a2c31a80eb902e7400563f403c85ef51dd73aaadb57967b61e8
Authorized signer hash: cc3c55563a4fa50d973faf704d7ef4f272b99ed7e0e0848457dd60be7d3df4b5
Authorized signer iteration: 1
Installed UI hash: 7674c4870ff06ace61d468df8af521be6cc40e86ca6a6b732453801e6b7adf9d
Installed UI version: 5.4
--------------------------------------------------------------------------------------------------------
---------------------------------------------------------------------------------------
Signer verified with public keys:
m/44'/0'/0'/0/0:   0254464d36eaa08a2c31a80eb902e7400563f403c85ef51dd73aaadb57967b61e8
m/44'/1'/0'/0/0:   02a7171ba5fcdf9ae8a32b733cbe748b6007b4633939ba1c8baca074e9358a281a
m/44'/1'/1'/0/0:   022e777db5856568da55947c1a60df4ec28b8fb27ea182de54575b3aadc4559932
m/44'/1'/2'/0/0:   0307455520c1b365436741c98ddc987c8ed7adddf67b8b69e5763f930c0131727e
m/44'/137'/0'/0/0: 02ecdf31ca81e7c5a2949dad38536676eee2647ec2e41c0771cd4e918b5c2fc4f8
m/44'/137'/1'/0/0: 0345ac500d260c1f6794b21fad8acce66548fee7a463befd5a0ec5bb73b9ae4df1
Hash: 72237ee55064aebd5ab13d179c61bfb41c5b1d2ed7e018f8de46a7262c8cf1ec

Installed Signer hash: cc3c55563a4fa50d973faf704d7ef4f272b99ed7e0e0848457dd60be7d3df4b5
Installed Signer version: 5.4
Platform: led
UD value: 13c3581aa97c8169d3994e9369c11ebd63bcf123d0671634f21b568983d32916
Best block: bdcb3c17c7aee714cec8ad900341bfd987b452280220dcbd6e7191f67ea4209b
Last transaction signed: 659a04529d6811dd
Timestamp: 0
---------------------------------------------------------------------------------------
```

and verify that the reported UI and Signer application hashes match the expected value. The user should also check that each additional reported value corresponds with an expected or reasonable value (e.g., verify that the UD value corresponds to an RSK block header hash that was mined on or after the time of setup/update; or that in the case of an update, the public keys correspond to those of the PowPeg member and have not been altered from the values obtained at setup).

### SGX

Assuming we knew Intel SGX Root CA certificate could be downloaded from `https://certificates.trustedservices.intel.com/Intel_SGX_Provisioning_Certification_RootCA.pem` (the actual certificate, that can be found [in Intel's API documentation](https://api.portal.trustedservices.intel.com/content/documentation.html#pcs)), we could issue:

```bash
middleware/term> python adm_sgx.py verify_attestation -t /a/path/to/the/attestation.json -r https://certificates.trustedservices.intel.com/Intel_SGX_Provisioning_Certification_RootCA.pem -b /a/path/to/the/public-keys.json
```

to then obtain the following sample output:

```
################################
### -> Verify powHSM attestation
################################
Attempting to gather root authority from https://certificates.trustedservices.intel.com/Intel_SGX_Provisioning_Certification_RootCA.pem...
Attempting to validate self-signed root authority...
Using https://certificates.trustedservices.intel.com/Intel_SGX_Provisioning_Certification_RootCA.pem as root authority
--------------------------------------------------------------------------------------------
powHSM verified with public keys:
m/44'/0'/0'/0/0:   03d2c1ab7245b1676e7aa66ef7588c3925ff972cce19756e6c030ad8ad22634fa4
m/44'/1'/0'/0/0:   03c9b0dac136c1651e75456f768c6ed3a424500af139905710882f7821c5810ffe
m/44'/1'/1'/0/0:   03b70f79eb845c76bb3c51e0b6c6b58a67ec84bb1fb48871127960f0cfe41dc359
m/44'/1'/2'/0/0:   031df2601f232cbf1fd8bb5e3dd1fe0bc5c4952b41716546f7c48823dffaa055dc
m/44'/137'/0'/0/0: 0238ad6df3f4023502860c46fab39a64e4ff76225782321eb19be87008606175c4
m/44'/137'/1'/0/0: 03d4b5cef399724fa0bb27f3e46d83b4f7c3ce69abfebd6afa25f8aa3078a3ac72
Hash: 0c4d091913d39750dc8975adbdd261bd10c1c2e110faa47cfbe30e740895552b

Installed powHSM MRENCLAVE: d32688d3c1f3dfcc8b0b36eac7c89d49af331800bd56248044166fa6699442c1
Installed powHSM MRSIGNER: 718c2f1a0efbd513e016fafd6cf62a624442f2d83708d4b33ab5a8d8c1cd4dd0
Installed powHSM version: 5.4
Platform: sgx
UD value: 13c3581aa97c8169d3994e9369c11ebd63bcf123d0671634f21b568983d32916
Best block: bdcb3c17c7aee714cec8ad900341bfd987b452280220dcbd6e7191f67ea4209b
Last transaction signed: 659a04529d6811dd
Timestamp: 0
--------------------------------------------------------------------------------------------
```

and verify that the reported MRENCLAVE and MRSIGNER application hashes match the expected values (for completion, this can be obtained from the Rootstocklabs publicly available enclave binary for the corresponding version, and then its digest verified against a local build). The user should also check that each additional reported value corresponds with an expected or reasonable value (e.g., verify that the UD value corresponds to an RSK block header hash that was mined on or after the time of setup and that the public keys correspond to those that will be used to define the PowPeg member and have not been altered).