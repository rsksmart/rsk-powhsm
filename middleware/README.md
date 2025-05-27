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

### Ledger Manager

The Ledger manager is the main middleware component for the Ledger powHSM implementation. Its role is to provide a high-level abstraction layer over the low-level powHSM dongle USB interface. It does this by starting a TCP service in a certain interface and port and implementing the [protocol](../docs/protocol.md) on top by means of interactions with the connected powHSM dongle. The entrypoint to the Ledger powHSM manager is the `manager_ledger.py` script. In order to start it, issue:

```
(mware)> python manager_ledger.py
```

Hit CTRL-C at any time to stop it.

### SGX Manager

The SGX manager is the main middleware component for the SGX powHSM implementation. It is essentially an implementation of the Ledger manager that connects to an SGX powHSM by means of a TCP/IP connection. The entrypoint to the SGX powHSM manager is the `manager_sgx.py` script. You can use the SGX manager to run against a real SGX instance in an Intel SGX enabled server, or against an SGX simulation build on your local. For the former, make sure you build a `manager_sgx` binary package (see the corresponding section below for details) and then copy it over to the SGX server in order to run it there alongside the SGX powHSM. For the latter, and assuming an SGX simulation build is running in the same container, you can just issue:

```
(mware)> python manager_sgx.py
```

Hit CTRL-C at any time to stop it.

### TCP Manager

This is an implementation of the Manager that connects to a powHSM via a TCP/IP connection. Its main use is along the TCPSigner (an x86 implementation of the Signer component) for integration tests and the like. It's important to mention that Ledger, SGX and TCP Manager share most of the code, and that the main difference lies in the powHSM proxy used and available user options. The entrypoint to the TCP manager is the `manager_tcp.py` script. In order to start it, issue:

```
(mware)> python manager_tcp.py
```

Hit CTRL-C at any time to stop it.

### Administrative utilities

Aside from the main `manager_ledger.py`, `manager_sgx.py` and `manager_tcp.py` scripts, there are other scripts to consider:

- `adm_ledger.py`: administrative utility for a Ledger powHSM dongle. It provides common utilities that can be performed on a powHSM dongle.
- `adm_sgx.py`: administrative utility for an SGX powHSM. It provides common utilities that can be performed on a running SGX powHSM instance.
- `lbutils.py`: common frontend to some of the `ledgerblue` modules. In particular, it ultimately serves the purpose of being able to build a binary for these utilities. This is used for Ledger exclusively.
- `signapp.py`: signer authorization generator. Serves the purpose of generating authorization files for Signer versions (see [the signer authorization documentation](../docs/signer-authorization.md) for details). It can be used to add externally generated signatures, or to sign with a manually input key (intended for testing purposes only). It can also be used to calculate the message to be signed to authorize a specific signer version (so that then the signature can be generated on a third-party application, e.g., MetaMask). Last, it has an option to calculate and output a Ledger app's hash. This is used for Ledger exclusively.
- `signmigration.py`: SGX migration authorization generator. Serves the purpose of generating authorization files for SGX database migrations. See [the SGX firmware upgrades documentation](../docs/sgx-upgrades.md) for details.
- `signonetime.py`: ledger app signer. Serves the purpose of signing Ledger Nano S firmware builds with a securely generated random one-time key. It is used in the distribution building process targeting the initial device setup process. This is used for Ledger exclusively.

The remaining `client.py` is a shorthand client utility for manually testing communication with a running Ledger, SGX or TCP manager.

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

Distribution of the middleware is done in the form of `.tgz` archives containing the binaries - main file and dependencies -, which are first built using the python tool [pyinstaller](https://www.pyinstaller.org/) and then packed for distribution. Scripts for building binaries for each main tool can be found under the `middleware/build` directory. These scripts place the output under the `middleware/bin` directory. There are also three scripts that are shorthand for serial building:

- `middleware/build/all`: builds all the tools.
- `middleware/build/dist_ledger`: builds all the tools that are meant for Ledger distribution.
- `middleware/build/dist_sgx`: builds all the tools that are meant for SGX distribution.

Within the same docker image, utility builds are bytewise reproducible.
