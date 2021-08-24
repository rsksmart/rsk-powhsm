# Ledger app building

The Docker image for ledger builds (see [the ledger readme](../README.md)) provides a environment suitable to build Ledger Nano S applications on 1.3.1 firmware. This way new developers don't have to struggle setting up the build toolchain, and all of them will have exactly the same toolchain (no different compiler versions and related nuisances). Overall, we have an infrastructure enabling repeatable and bytewise reproducible builds.

### Building signer and UI

To build the UI, just issue:

```bash
~/repo> ledger/build/build-ui
```

There is also a *debug* version of the UI, which disables downgrade prevention. That is, it disables three features: disallowing running of blacklisted applications, disallowing running of non-certified applications and disallowing PINs with no alpha characters. This debug version is intended for debugging purposes only, and to build it, just issue:

```bash
~/repo> ledger/build/build-ui-debug
```

To build the signer, just do:

```bash
~/repo> ledger/build/build-signer <checkpoint> <minimum_difficulty> <network> [<docker_image>]
```

where `<checkpoint>` is the desired blockchain checkpoint hash, `<minimum_difficulty>` is the minimum required difficulty (can be specified as a decimal number or as a hexadecimal - prefixed with `0x`), and `<network>` is the desired network the build is to target (one of `mainnet`, `testnet` or `regtest`). If your docker image has a different tag than `hsm:latest`, you can specify that as the last parameter.

For example, to build the signer with checkpoint `0x00f06dcff26ec8b4d373fbd53ee770e9348d9bd6a247ad4c86e82ceb3c2130ac`, minimum cumulative difficulty of `0x7c50933098` and the `testnet` network, issue:

```bash
~/repo> ledger/build/build-signer 0x00f06dcff26ec8b4d373fbd53ee770e9348d9bd6a247ad4c86e82ceb3c2130ac 0x7c50933098 testnet
```

Once the build is complete, you will get the hash of the build as output, and the actual build output will be in `<HSM_PROJECT_ROOT>/ledger/src/signer/bin/app.hex` (for the signer) and `<HSM_PROJECT_ROOT>/ledger/src/ui/bin/token.hex` (for the UI).

### Building the certificate signer

To build the certificate signer, just do:

```bash
~/repo> ledger/build/build-signer-certificate
```

### Building the simulator

```bash
~/repo> ledger/build/builder-term [<docker_image>]
cd ledger/src/simul
make
```

Happy building!
