# powHSM Setup and onboarding

## Prerequisites

The computer on which the powHSM setup and onboarding is to be executed needs the following installed:

- Docker

## Scripts

This can be used to setup a new device as well as to upgrade a device with powHSM to a newer Signer version.

### Setup

To setup a brand new device, within the `/path/to/dist` directory, issue:

```
/path/to/dist> ./setup-new-device
```

and follow the instructions.

### Upgrade a powHSM

To upgrade an existing powHSM device to a newer firmware version, you will first need:

- A file `/path/to/dist/pin.txt` with the current device's pin.
- A file `/path/to/dist/device_attestation.json` with the device attestation generated upon setup.

Then, to execute the upgrade process, within the `/path/to/dist` directory, issue:

```
/path/to/dist> ./upgrade-existing-device
```

and follow the instructions.
