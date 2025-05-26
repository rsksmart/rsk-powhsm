# powHSM for SGX distribution

This document describes the artifacts provided to build a distributable version of the powHSM software for Intel SGX. This distributable version includes both SGX apps and middleware binaries, as well as scripts for setting up and onboarding a brand new   installation; and also to upgrade an existing powHSM SGX installation to a newer firmware version.

## Prerequisites

You will need all of the docker images built (see the [quickstart guide](../QUICKSTART.md) for details on this).

## Generating a distribution

To generate a full distribution into a fresh directory, issue:

```
~/repo> ./build-dist-sgx <destination path> <checkpoint> <minimum difficulty> <network> <signers_file>
```

where `<destination path>` is the target directory (which must not exist); `<checkpoint>`, `<minimum difficulty>` and `<network>` are the build parameters for the SGX enclave application; and `<signers_file>` is the basename of the upgrade signer authorizers header file. The script will build the SGX apps (host and enclave) as well as the required middleware. Then it will output all of the necessary distribution artifacts, including the aforementioned builds, to the destination path given.

For example, to build a distribution with checkpoint `0x00f06dcff26ec8b4d373fbd53ee770e9348d9bd6a247ad4c86e82ceb3c2130ac`, minimum cumulative difficulty of `0x7c50933098`, `testnet` network and authorizers header file `testing`, issue:

```
~/repo> ./build-dist-sgx /path/to/output 0x00f06dcff26ec8b4d373fbd53ee770e9348d9bd6a247ad4c86e82ceb3c2130ac 0x7c50933098 testnet testing
```

## Using a distribution

### Prerequisites

The computer on which the distrbution is to be used needs the following installed:

- Docker

### Scripts

As mentioned, a distribution can be used to setup a new device as well as to upgrade an existing SGX powHSM installation to a newer firmware version. To setup a brand new installation, within the `/path/to/dist` directory, issue:

```
/path/to/dist> ./setup-new-powhsm
```

and follow the instructions.

To upgrade an existing SGX powHSM installation, you will first need:

- A file `/path/to/dist/pin.txt` with the current installation's pin.
- A fully signed `/path/to/dist/hsm/migration_auth.json`, authorising the firmware versions from and to which the installation is to be upgraded. The `signmigration.py` middleware tool aids in the generation of the signatures needed (the file is generated when the distribution is built, but with no signatures and a default `exporter` value of `00...00`). The minimum number of signatures needed will be the threshold (N/2+1) for the total number of authorizers (N) in the authorizers headers file specified at build time.

Then, to execute the upgrade process, within the `/path/to/dist` directory, issue:

```
/path/to/dist> ./upgrade-existing-powhsm
```

and follow any instructions on screen. Please note that the actual upgrade process should require no interaction if all the prerequisites are met.
