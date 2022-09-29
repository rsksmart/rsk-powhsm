# powHSM middleware

All of the powHSM middleware is written in Python 3. Here you will find guidelines on setting up and using an environment for developing, running and building binaries.

## Prerequisites

Before starting, you must have the following installed on your system:

- Docker

The first time, you must build the docker image that will serve as the middleware development and execution environment. Within the root directory of the repository, issue:

```
~/repo> docker/mware/build
```

that should build (or rebuild in case the `Dockerfile` has changed) the corresponding docker image.

## Environment

For developing, testing and building middleware binaries, you can use the docker image. To gather a development terminal, issue:

```
~/repo> middleware/term
```

or within the `middleware` directory, just:

```
~/repo/middleware> ./term
```

Within that terminal, you will have a `python` binary with all the required dependencies for developing, running, testing and building binaries of the middleware. You can also use the `middleware/term` script to run single commands without having to gather an environment terminal first, like so:

```
~/repo/middleware> ./term "python -m unittest tests.ledger.test_hsm2dongle"
```

Throughout the rest of the document, we will refer to a middleware development environment terminal with the `(mware)>` prefix.

## Middleware breakdown

### Manager

The manager is the main middleware component. Its role is to provide a high-level abstraction layer over the low-level powHSM dongle USB interface. It does this by starting a TCP service in a certain interface and port and implementing the [protocol](../docs/protocol.md) on top by means of interactions with the connected powHSM dongle. The entrypoint to the powHSM manager is the `manager.py` script. In order to start it, issue:

```
(mware)> python manager.py
```

Hit CTRL-C at any time to stop it.

### TCP Manager

This is an implementation of the Manager that connects to a dongle via a TCP/IP connection. Its main use is along the TCPSigner (an x86 implementation of the Signer component) for integration tests and the like. It's important to mention that Manager and TCP Manager share most of the code, and that the main difference lies in the dongle proxy used and available user options. The entrypoint to the TCP manager is the `manager-tcp.py` script. In order to start it, issue:

```
(mware)> python manager-tcp.py
```

Hit CTRL-C at any time to stop it.

### Administrative utilities

Aside from the main `manager.py` and `manager-tcp.py` scripts, there are other three scripts to consider:

- `adm.py`: administrative utility for a powHSM dongle. It provides common utilities that can be performed on a powHSM dongle.
- `lbutils.py`: common frontend to some of the `ledgerblue` modules. In particular, it ultimately serves the purpose of being able to build a binary for these utilities.
- `signapp.py`: signer authorization generator. Serves the purpose of generating authorization files for Signer versions (see [the signer authorization documentation](../docs/signer-authorization.md) for details). It can be used to sign with a powHSM Certificate Signer Ledger app (see [the ledger readme](../ledger/README.md) for details), to add manually fed signatures (externally generated), or to sign with a manually input key (for testing purposes). It can also be used to calculate the message to be signed to authorize a specific signer version (so that then the signature can be generated on a third-party application, e.g., MetaMask). Last, it has an option to calculate and output a ledger app's hash.
- `signonetime.py`: ledger app signer. Serves the purpose of signing firmware builds with a securely generated random one-time key. It is used in the distribution building process targeting the initial device setup process.

The remaining `client.py` is a shorthand client utility for manually testing communication with a running manager or TCP manager.

## Unit tests

To run the unit tests, issue:

```
(mware)> python -m unittest discover
```

Or, from outside the development environment:

```
~/repo/middleware> ./test-all
```

As the middleware evolves, unit tests should be maintained and augmented in order to keep code coverage to a sensible minimum. The unit testing style follows a "mock dependencies" pattern: all nontrivial dependencies *must* be mocked in order to generate and consider the possible execution scenarios of the unit of code being tested. Testing more than one nontrivial unit of code at the same time is strongly discouraged.

## Building middleware binaries

### Prerequisites

The first time, you must build a second docker image that will serve as the packer for the binary files. Within the root directory of the repository, issue:

```
~/repo> docker/packer/build
```

that should build (or rebuild in case the `Dockerfile` has changed) the corresponding docker image.

### Building

Distribution of the middleware is done in the form of `.tgz` archives containing the binaries - main file and dependencies -, which are first built using the python tool [pyinstaller](https://www.pyinstaller.org/) and then packed for distribution. Scripts for building binaries for each main tool can be found under the `middleware/build` directory. These scripts place the output under the `middleware/bin` directory. There are also two scripts that are shorthand for serial building:

- `middleware/build/all`: builds all the tools.
- `middleware/build/dist`: builds all the tools that are meant for distribution.

Within the same docker image, utility builds are bytewise reproducible.
