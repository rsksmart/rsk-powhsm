# powHSM dockerized TCPSigner bundle

## Usage

### Prerequisites

- Docker
- Middleware and Packer docker images

### Required images

To build the required docker images, in the root of the repository, issue:

```
docker/mware/build
```

then

```
docker/packer/build
```

### Building and bundling

Before using the TCPSigner bundle (i.e., TCPSigner + Manager combo), both the TCPSigner
and the TCPManager binaries must be built. In order to do that, within this document's
directory, issue:

```
./build.sh
```

and wait for the process to finish. Once this is done, the `dist` directory will contain
the standalone bundle that can be copied and ran on any system with Docker installed.

### Running

To run the TCPSigner bundle, from within the distribution directory (built in the previous section), issue:

```
./run.sh [-h]
```

Refer to the help (`-h`) command for options.

### Supported Platforms

The TCPSigner bundle can be built and ran in x86 and arm64 platforms. The steps for building and running the TCPSigner bundle are the same for both platforms.
