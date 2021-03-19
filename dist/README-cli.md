# HSM 2 Setup and onboarding

## Prerequisites

The computer on which the HSM 2 setup and onboarding is to be executed needs the following installed:

- Docker

## Scripts

This can be used to setup a new device as well as to upgrade a device from HSM 1.x to HSM 2. 

### Setup

To setup a brand new device, within the `/path/to/dist` directory, issue:

```
/path/to/dist> ./setup-new-device
```

and follow the instructions.

### Upgrade HSM 1.x to HSM 2

To upgrade an existing HSM 1.x device, you will first need:

- A file `/path/to/dist/pin.txt` with the current device's pin.

Then, to execute the upgrade process, within the `/path/to/dist` directory, issue:

```
/path/to/dist> ./upgrade-v1-device
```

and follow the instructions.

### Upgrade an HSM 2

To upgrade an existing HSM 2 device to a newer firmware version, you will first need:

- A file `/path/to/dist/pin.txt` with the current device's pin.
- A file `/path/to/dist/device_attestation.json` with the device attestation generated upon setup _(only if initially setup with HSM 2.1+)_.

Then, to execute the upgrade process, within the `/path/to/dist` directory, issue:

If initially setup with HSM 2.1+:
```
/path/to/dist> ./upgrade-v2-device
```

If initially setup with HSM 2.0:
```
/path/to/dist> ./upgrade-v2-device-noatt
```

and follow the instructions.
