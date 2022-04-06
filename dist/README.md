# powHSM distribution

This document describes the artifacts provided to build a distributable version of the powHSM software. This distributable version includes both ledger apps and middleware binaries, as well as scripts for both setting up and onboarding a brand new Ledger Nano S; and also for upgrading an existing legacy Ledger Nano S with HSM 1.x to powHSM.

## Prerequisites

You will need both of the ledger and middleware docker images built (see the [ledger](../ledger/README.md) and [middleware](../middleware/README.md) readmes for details on this).

## Generating a distribution

To generate a full distribution into a fresh directory, issue:

```
~/repo> ./build-dist <destination path> <checkpoint> <minimum difficulty> <network>
```

where `<destination path>` is the target directory (which must not exist); and `<checkpoint>`, `<minimum difficulty>` and `<network>` are the build parameters for the signer app. The script will build the ledger apps (signer and UI) as well as the required middleware. Then it will output all of the necessary distribution artifacts, including the aforementioned builds, to the destination path given.

For example, to build a distribution with checkpoint `0x00f06dcff26ec8b4d373fbd53ee770e9348d9bd6a247ad4c86e82ceb3c2130ac`, minimum cumulative difficulty of `0x7c50933098` and for the `testnet` network, issue:

```
~/repo> ./build-dist /path/to/output 0x00f06dcff26ec8b4d373fbd53ee770e9348d9bd6a247ad4c86e82ceb3c2130ac 0x7c50933098 testnet
```

## Using a distribution

### Prerequisites

The computer on which the distrbution is to be used needs the following installed:

- Docker

### Scripts

As mentioned, a distribution can be used to setup a new device as well as to upgrade a device from a legacy HSM 1.x to powHSM. To setup a brand new device, you will first need:

- Certification of both of the ledger applications (UI and Signer) by means of generating signatures for them using the ledger with the public key corresponding to `/path/to/dist/scripts/rsk-ca.txt` with the `signapp` utility (see [the middleware readme](../middleware/README.md) for details on this). Files expected to be present at the end of this process are `/path/to/dist/firmware/signer.hex.sig` and `/path/to/dist/firmware/ui.hex.sig`.

Then, to execute the setup process, within the `/path/to/dist` directory, issue:

```
/path/to/dist> ./setup-new-device
```

and follow the instructions.

As mentioned, a distribution can be used to setup a new device as well as to upgrade a device from a legacy HSM 1.x to powHSM or to upgrade an existing powHSM to a newer firmware version. 

To upgrade an existing legacy HSM 1.x device, you will first need:

- A file `/path/to/dist/pin.txt` with the current device's pin.
- Certifications of both of the ledger applications (UI and Signer) exactly as in the setup process (see above).

Then, to execute the upgrade process, within the `/path/to/dist` directory, issue:

```
/path/to/dist> ./upgrade-v1-device
```

and follow the instructions.

To upgrade an existing powHSM device, you will first need:

- A file `/path/to/dist/pin.txt` with the current device's pin.
- A file `/path/to/dist/device_attestation.json` with the device attestation generated upon setup.
- Certification of the ledger signer exactly as in the setup process (see above).

Then, to execute the upgrade process, within the `/path/to/dist` directory, issue:

```
/path/to/dist> ./upgrade-v2-device
```

and follow the instructions.
