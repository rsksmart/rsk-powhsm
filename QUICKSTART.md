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

### Additional note for M1 computers

Building this project, in addition to the Docker images listed in the [Prerequisites](#prerequisites) section, is currently not supported on M1 computers. However, we provide a special Dockerfile suited for running the middleware Docker image with limited functionality on M1 computers. Refer to [middleware/README.md](./middleware/README.md) for instructions on running that.

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
~/repo> ledger/build/build-ui <signer_hash> <signer_iteration> <signers_file> # Build UI
```

- Build middleware binaries:
```
~/repo> middleware/build/all
```

- Build a complete powHSM distribution:
```
~/repo> ./build-dist <destination path> <checkpoint> <minimum difficulty> <network> <ui_iteration> <ui_authorizers>
```
