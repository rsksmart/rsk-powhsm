# powHSM Firmware

## Overview and source code

By firmware, we collectively refer to the group of applications that comprise the main powHSM logic and its different implementations (currently and namely, powHSM for Ledger Nano S, powHSM for Intel SGX and powHSM for x86 -- codenamed TCPSigner). The source code under this document's directory is located within the `src` directory, and is organised as follows:

- `hal`: contains header and source files for the Hardware Abstraction Layer, on top of which the powHSM logic is built. Currently implemented for Ledger Nano S, Intel SGX and x86.
- `powhsm`: contains the powHSM logic.
- `ledger`: contains the Ledger Nano S apps.
- `sgx`: contains the Intel SGX implementation of powHSM (host and enclave).
- `tcpsigner`: contains the x86 implementation of powHSM.
- `common`: contains some common headers used both in powHSM, the Ledger Nano S apps and the Intel SGX host and enclave.

## powHSM for Ledger Nano S

### Apps

There are two ledger apps, both of them targeted for running on a Ledger Nano S with a 1.3.1 firmware.

- UI: this is the modified 1.3.1 UI with a nonblocking behavior to allow the device to run uninterruptedly without human interaction. It is essentially the RSK version of the Ledger Nano S User Interface which can be loaded as a specific application - it can be used to personalize most generic parts of the user experience. This version also modifies the onboarding process to reflect RSK needs. Modified UIs display a warning at boot time to let you know whether you're running a certified version. This application shall be installed in Recovery mode. Find the source code under `firmware/src/ledger/ui`.

- Signer: this is the main app that implements the signing and authorization logic for powHSM. It is intended to be used alongside the UI. Find the source code under `firmware/src/powhsm`.

### Prerequisites

Before starting, you must have the following installed on your system:

- Docker

The first time, you must build the docker image that will serve as the ledger build environment, as well as the docker image for the middleware, which will serve as the basis for deploying built apps to a physical ledger. Issue:

```
~/repo> docker/ledger/build
```

and

```
~/repo> docker/mware/build
```

that should build (or rebuild in case any of the `Dockerfile`s have changed) the corresponding docker images.

### Common tasks and documentation

Refer to [firmware/build/README.md](./build/README.md) for instructions on building and to [firmware/deploy/README.md](./deploy/README.md) for instructions on deploying.

See [Ledger's documentation](http://ledger.readthedocs.io) to get a reference on developing for the platform.

## powHSM for Intel SGX

### Host and Enclave

There are two parts to the Intel SGX powHSM implementation: a host and an enclave. The enclave is responsible for hosting the core powHSM business logic, as well as for managing all secrets (e.g., private keys). This enclave runs in a reserved memory area and cannot be tampered with or accessed by any other entities than itself. Its only link with the outside world is the host, with which it shares a limited, well defined, communication protocol. The host, then, is responsible for managing the enclave creation, destruction, and all its interactions with the outside world -- including, but not limited to, disk and network access. Once built, both host and enclave take the form of binaries that must be deployed together to the Intel SGX server on which they are set to run.

### Prerequisites

Before starting, you must have the following installed on your system:

- Docker

The first time, you must build the docker image that will serve as the SGX build environment. Issue:

```
~/repo> docker/sgx/build
```

that should build (or rebuild in case any of the `Dockerfile`s have changed) the corresponding docker image.

### Common tasks and documentation

Refer to [firmware/build/README.md](./build/README.md) for instructions on building.

See [Open Enclave](https://openenclave.io/sdk/) for development documentation and reference, and [Intel SGX](https://www.intel.com/content/www/us/en/products/docs/accelerator-engines/software-guard-extensions.html) for information about the underlying platform.

## powHSM for x86

Besides the Ledger implementation, there is also an x86 based implementation of the powHSM, which we call _TCPSigner_. This is used to smoke test, fuzz (see [the fuzzing documentation](./fuzz/README.md) for details) and debug & test new features on before we jump onto testing on a physical Ledger Nano S device. With the exception of fuzzing, this component creates a TCP/IP server that serves the purpose of enabling the otherwise USB-based interactions with a given client.

## Tests

There is a test framework written in Python with a rather large set of tests that serve the purpose of smoke testing the main powHSM signing business logic when either installed and running on a Ledger Nano S, an Intel SGX server or via a fresh TCPSigner build. Refer to [the firmware testing documentation](./test/README.md) for details on how to run these tests on each supported platform.

## Troubleshooting

### Enable user access to Ledger Nano USB

If under GNU linux and your Ledger Nano S can't be found (`No dongle found` errors), then try downloading and running the following script with `sudo`:

https://github.com/LedgerHQ/udev-rules/blob/master/add_udev_rules.sh
