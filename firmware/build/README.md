# powHSM building

## Building the Ledger Nano S apps

The following instructions indicate how to build both the Signer and UI applications for
Ledger Nano S. The Docker image for ledger builds (see [the ledger readme](../README.md)) provides an environment suitable to build Ledger Nano S applications on 1.3.1 firmware. This way new developers don't have to struggle setting up the build toolchain, and all of them will have exactly the same toolchain (no different compiler versions and related nuisances). Overall, we have an infrastructure enabling repeatable and bytewise reproducible builds. This image must be built beforehand.

### Building the UI

To build the UI, just issue:

```bash
~/repo> firmware/build/build-ledger-ui <signer_hash> <signer_iteration> <signers_file>
```

where `<signer_hash>` is the hash of the authorized signer version (only this signer can be opened in the UI once running), `<signer_iteration>` is the iteration of the authorized signer version (used for downgrade prevention) and `<signers_file>` is the basename of the signer authorizers header file (the file to be included for the build process should be at `~/firmware/src/ledger/ui/src/signer_authorization_signers/<signers_file>.h`).

There is also a *debug* version of the UI, which disables disallowing PINs with no alpha characters, therefore allowing for testing UI (and Signer) builds granting access to recovery mode without the need for wiping the device each time. This debug version is intended for development purposes only, and to build it, just issue:

```bash
~/repo> firmware/build/build-ledger-ui-debug <signer_hash> <signer_iteration> <signers_file>
```

### Building the Signer

To build the signer, just issue:

```bash
~/repo> firmware/build/build-ledger-signer <checkpoint> <minimum_difficulty> <network>
```

where `<checkpoint>` is the desired blockchain checkpoint hash, `<minimum_difficulty>` is the minimum required difficulty (can be specified as a decimal number or as a hexadecimal - prefixed with `0x`), and `<network>` is the desired network the build is to target (one of `mainnet`, `testnet` or `regtest`).

For example, to build the signer with checkpoint `0x00f06dcff26ec8b4d373fbd53ee770e9348d9bd6a247ad4c86e82ceb3c2130ac`, minimum cumulative difficulty of `0x7c50933098` and the `testnet` network, issue:

```bash
~/repo> firmware/build/build-ledger-signer 0x00f06dcff26ec8b4d373fbd53ee770e9348d9bd6a247ad4c86e82ceb3c2130ac 0x7c50933098 testnet
```

Once the build is complete, you will get the hash of the build as output, and the actual build output will be in `<HSM_PROJECT_ROOT>/firmware/src/ledger/signer/bin/app.hex` (for the signer) and `<HSM_PROJECT_ROOT>/firmware/src/ledger/ui/bin/token.hex` (for the UI).

### Reproducible builds

It is *very important* to mention that both the Signer and the UI builds are bitwise reproducible. That is, two independent builds of the same code will yield the exact same hex files (and thus, the same app hashes). This is of remarkable importance for the [attestation process](../../docs/attestation.md).

## Building the TCPSigner

The Docker image for the middleware (see [the middleware readme](../../middleware/README.md)) provides a suitable environment to build, run and test the TCPSigner. This image must be built beforehand. To then build the TCPSigner, just issue:

```bash
~/repo> firmware/build/build-tcpsigner
```

Happy building!
