# powHSM for SGX distribution

This document describes the artifacts provided to build a distributable version of the powHSM software for Intel SGX. This distributable version includes both SGX apps and middleware binaries, as well as scripts for setting up and onboarding a brand new installation.

## Prerequisites

You will need all of the docker images built (see the [quickstart guide](../QUICKSTART.md) for details on this).

## Generating a distribution

To generate a full distribution into a fresh directory, issue:

```
~/repo> ./build-dist-sgx <destination path> <checkpoint> <minimum difficulty> <network>
```

where `<destination path>` is the target directory (which must not exist); `<checkpoint>`, `<minimum difficulty>` and `<network>` are the build parameters for the SGX enclave application. The script will build the SGX apps (host and enclave) as well as the required middleware. Then it will output all of the necessary distribution artifacts, including the aforementioned builds, to the destination path given.

For example, to build a distribution with checkpoint `0x00f06dcff26ec8b4d373fbd53ee770e9348d9bd6a247ad4c86e82ceb3c2130ac`, minimum cumulative difficulty of `0x7c50933098` and `testnet` network, issue:

```
~/repo> ./build-dist-sgx /path/to/output 0x00f06dcff26ec8b4d373fbd53ee770e9348d9bd6a247ad4c86e82ceb3c2130ac 0x7c50933098 testnet
```

## Using a distribution

### Prerequisites

The computer on which the distrbution is to be used needs the following installed:

- Docker

### Scripts

As mentioned, a distribution can be used to setup a new device. To setup a brand new installation, within the `/path/to/dist` directory, issue:

```
/path/to/dist> ./setup-new-powhsm
```

and follow the instructions.
