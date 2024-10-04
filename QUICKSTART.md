# powHSM quickstart guide

Whether new to the project or just wanting to quickly get an environment up and running to e.g. verify binary hashes or run tests, here is a checklist that will get you sorted in no time:

## Prerequisites

- Make sure you have [Docker](https://www.docker.com/get-started/) installed.
- If running MacOS, make sure you have also got [coreutils](https://formulae.brew.sh/formula/coreutils) installed (link using [homebrew](https://brew.sh/)).
- Build all required docker images:
```
~/repo> docker/mware/build # Middleware image
~/repo> docker/ledger/build # Ledger image
~/repo> docker/sgx/build # SGX image
~/repo> docker/packer/build # Middleware binary packer image
```

## Supported platforms

Unless otherwise stated, only x86 platforms are supported for building this project and running the tools provided. The only exception is the [TCPSigner bundle](./utils/tcpsigner-bundle/README.md), which can be built and ran in x86 and arm64 platforms.

## Common tasks

- Run tests:
```
~/repo> middleware/test-all # Middleware unit tests
~/repo> firmware/test/test-all # Firmware tests
~/repo> firmware/src/ledger/ui/test/run-all.sh # Ledger UI application unit tests
~/repo> firmware/src/ledger/signer/test/run-all.sh # Ledger Signer application unit tests
~/repo> firmware/src/common/test/run-all.sh # Common code unit tests
~/repo> firmware/src/powhsm/test/run-all.sh # powHSM logic unit tests
~/repo> firmware/src/hal/common/test/run-all.sh # HAL common code unit tests
~/repo> firmware/src/hal/x86/test/run-all.sh # HAL x86 implementation unit tests
```

- Build Ledger Nano S application binaries:
```
~/repo> firmware/build/build-ledger-signer <checkpoint> <difficulty> <network> # Build signer
~/repo> firmware/build/build-ledger-ui <signer_hash> <signer_iteration> <signers_file> # Build UI
```

- Build SGX binaries (both host and enclave):
```
~/repo> firmware/build/build-sgx <checkpoint> <difficulty> <network>
```

- Build middleware binaries:
```
~/repo> middleware/build/all
```

- Build a complete Ledger powHSM distribution:
```
~/repo> ./build-dist-ledger <destination path> <checkpoint> <minimum difficulty> <network> <ui_iteration> <ui_authorizers>
```

- Build a complete SGX powHSM distribution:
```
~/repo> ./build-dist-sgx <destination path> <checkpoint> <minimum difficulty> <network>
```

- Build the TCPSigner:
```
~/repo> firmware/build/build-tcpsigner
```

- Build the SGX simulator:
```
~/repo> firmware/build/build-sgx-sim <checkpoint> <minimum difficulty> <network>
```
