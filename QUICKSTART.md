# powHSM quickstart guide

Whether new to the project or just wanting to quickly get an environment up and running to e.g. verify binary hashes or run tests, here is a checklist that will get you sorted in no time:

## Prerequisites

- Make sure you have [Docker](https://www.docker.com/get-started/) installed.
- If running MacOS, make sure you have also got [coreutils](https://formulae.brew.sh/formula/coreutils) installed (link using [homebrew](https://brew.sh/)).
- Build all required docker images:
```
~/repo> docker/mware/build # Middleware image
~/repo> docker/ledger/build # Ledger image
~/repo> docker/packer/build # Middleware binary packer image
```

## Common tasks

- Run tests:
```
~/repo> middleware/test-all # Middleware unit tests
~/repo> ledger/test/test-all # Ledger signer application tests
~/repo/ledger/src/signer/test/*> make test # Run ledger signer application unit tests
~/repo/ledger/src/common/test/*> make test # Run ledger common libraries unit tests
```

- Build firmware binaries:
```
~/repo> ledger/build/build-signer <checkpoint> <difficulty> <network> # Build signer
~/repo> ledger/build/build-ui # Build UI
```

- Build middleware binaries:
```
~/repo> middleware/build/all
```

- Build a complete powHSM distribution (will need an [additional certification step](./dist/README.md#using-a-distribution)):
```
~/repo> ./build-dist <destination-dir> <checkpoint> <difficulty> <network>
```
