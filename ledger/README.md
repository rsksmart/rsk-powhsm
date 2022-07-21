# powHSM Ledger Nano S apps

There are two ledger apps, both of them targeted for running on a Ledger Nano S with a 1.3.1 firmware.

- UI: this is the modified 1.3.1 UI with a nonblocking behavior to allow the device to run uninterruptedly without human interaction. It is essentially the RSK version of the Ledger Nano S User Interface which can be loaded as a specific application - it can be used to personalize most generic parts of the user experience. This version also modifies the onboarding process to reflect RSK needs. Modified UIs display a warning at boot time to let you know whether you're running a certified version. This application shall be installed in Recovery mode. Find the source code under `ledger/src/ui`.

- Signer: this is the main app that implements the signing and authorization logic for powHSM. It is intended to be used alongside the UI. Find the source code under `ledger/src/signer`.


There exists also an x86 implementation of the _Signer_ component, which we call TCPSigner, that we use to smoke test, fuzz (see [the fuzzing documentation](./fuzz/README.md) for details) and debug & test new features on before we jump onto testing on a physical device. With the exception of fuzzing, this component creates a TCP/IP server that serves the purpose of enabling the otherwise USB-based interactions with a given client.

## Prerequisites

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

## Common tasks and documentation

Refer to [ledger/build/README.md](./build/README.md) for instructions on building and to [ledger/deploy/README.md](./deploy/README.md) for instructions on deploying.

See [Ledger's documentation](http://ledger.readthedocs.io) to get a reference on developing for the platform.

## Tests

There are some tests written in Python that serve the purpose of smoke testing the powHSM signer when either installed and running on a Ledger Nano S or via a fresh TCPSigner build. To run them against a TCPSigner, issue:

```
~/repo/ledger/test> ./test-all
```

To run them against a Ledger Nano S, issue:

```
~/repo/ledger/test> ./test-all dongle
```

Make sure that the Ledger is unlocked and with the signer app running for the tests to run correctly.

## Troubleshooting

### Enable user access to Ledger Nano USB

If under GNU linux and your Ledger Nano S can't be found (`No dongle found` errors), then try downloading and running the following script with `sudo`:

https://github.com/LedgerHQ/udev-rules/blob/master/add_udev_rules.sh
