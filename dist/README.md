# powHSM distribution

This document describes the artifacts provided to build a distributable version of the powHSM software. This distributable version includes both ledger apps and middleware binaries, as well as scripts for both setting up and onboarding a brand new Ledger Nano S; and also for upgrading an existing Ledger Nano S with powHSM to a newer Signer version.

## Prerequisites

You will need all of the docker images built (see the [quickstart guide](../QUICKSTART.md) for details on this).

## Generating a distribution

To generate a full distribution into a fresh directory, issue:

```
~/repo> ./build-dist <destination path> <checkpoint> <minimum difficulty> <network> <ui_iteration> <ui_authorizers>
```

where `<destination path>` is the target directory (which must not exist); `<checkpoint>`, `<minimum difficulty>` and `<network>` are the build parameters for the signer app; `<ui_iteration>` is the signer version iteration with which the UI must be built; and `<ui_authorizers>` is the basename of the authorizers header file. The script will build the ledger apps (signer and UI) as well as the required middleware. Then it will output all of the necessary distribution artifacts, including the aforementioned builds, to the destination path given.

For example, to build a distribution with checkpoint `0x00f06dcff26ec8b4d373fbd53ee770e9348d9bd6a247ad4c86e82ceb3c2130ac`, minimum cumulative difficulty of `0x7c50933098`, `testnet` network, signer iteration `43` and authorizers header file `testing`, issue:

```
~/repo> ./build-dist /path/to/output 0x00f06dcff26ec8b4d373fbd53ee770e9348d9bd6a247ad4c86e82ceb3c2130ac 0x7c50933098 testnet 43 testing
```

## Using a distribution

### Prerequisites

The computer on which the distrbution is to be used needs the following installed:

- Docker

### Scripts

As mentioned, a distribution can be used to setup a new device as well as to upgrade a device with powHSM to a newer Signer version. To setup a brand new device, within the `/path/to/dist` directory, issue:

```
/path/to/dist> ./setup-new-device
```

and follow the instructions.

To upgrade an existing powHSM device, you will first need:

- A file `/path/to/dist/pin.txt` with the current device's pin.
- A file `/path/to/dist/device_attestation.json` corresponding to the attestation generated at setup.
- A fully signed `/path/to/dist/firmware/signer_auth.json`, authorising the signer version to which the device is to be upgraded. The `signapp.py` middleware tool aids in the generation of the signatures needed (the file is generated when the distribution is built, but with no signatures). The minimum number of signatures needed will be the threshold (N/2+1) for the total number of authorizers (N) in the UI authorizers headers file specified at build time.

Then, to execute the upgrade process, within the `/path/to/dist` directory, issue:

```
/path/to/dist> ./upgrade-existing-device
```

and follow the instructions.
