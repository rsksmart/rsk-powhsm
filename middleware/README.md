# HSM 2.0 middleware

All of the HSM 2.0 middleware is written in Python 3. Here you will find guidelines on setting up and using an  environment for developing, running and building binaries.

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

The manager is the main middleware component. Its role is to provide a high-level abstraction layer over the low-level HSM 2 dongle USB interface. It does this by starting a TCP service in a certain interface and port and implementing the [protocol](../docs/protocol.md) on top by means of interactions with the connected HSM 2 dongle. The entrypoint to the manager is the `manager.py` script. In order to start the HSM 2 manager, issue:

```
(mware)> python manager.py
```

Hit CTRL-C at any time to stop it.

### Simulator

The simulator is a middleware component that implements both the manager and the HSM 2 dongle at the same time, meaning that there's no need for an actual physical HSM device to be present. That is, it simulates an HSM 2 dongle and all its supported operations. This piece of software should be updated alongside the manager as the middleware evolves. The entrypoint to the simulator is the `sim.py` script. In order to start the HSM 2 simulator, issue:

```
(mware)> python sim.py
```

Hit CTRL-C at any time to stop it.

### Administrative utilities

Aside from the main `manager.py` and `sim.py` scripts, there are other four scripts to consider:

- `adm.py`: administrative utility for an HSM 2 dongle. It provides common utilities that can be performed on an HSM 2 dongle.
- `lbutils.py`: common frontend to some of the `ledgerblue` modules. In particular, it ultimately serves the purpose of being able to build a binary for these utilities.
- `signapp.py`: ledger app signer. Serves the purpose of signing firmware builds. Can be used to sign with an HSM Certificate Signer Ledger app (see [the ledger readme](`../ledger/README.md`) for details) or with a manually input key (for testing purposes).
- `restore.py`: HSM 2 onboarding backup restorer. It takes an HSM 2 backup (one of the byproducts of the onboarding process) as input and produces a mnemonic as output. This mnemonic can then be used to restore the keys of the ledger. It is intended for emergencies only.

The remaining `client.py` is a shorthand client utility for manually testing communication with a running manager or simulator.

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

Distribution of the middleware is done in the form of amd64 binaries, which are built using the python tool [pyinstaller](https://www.pyinstaller.org/). Scripts for building binaries for each main script can be found under the `middleware/build` directory. These scripts place the binary output under the `middleware/bin` directory. There are also two scripts that are shorthand for serial building:

- `middleware/build/all`: builds all the tools.
- `middleware/build/dist`: builds all the tools that are meant for distribution (i.e., all but `sim.py` and `restore.py`).

Within the same docker image, utility builds are bytewise reproducible.
