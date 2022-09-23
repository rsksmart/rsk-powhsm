# Building and running the powHSM dockerized TCPSigner on M1 computers

## Prerequisites

- Docker
- M1 specific Middleware image (refer to [middleware/README.md](../../middleware/README.md) for details)

## Required image

Refer to [middleware/README.md](../../middleware/README.md) for instructions on building the Middleware image on M1.

## Building and running the TCPSigner

After building the Middleware image, issue the following command from the root of the repository to run the container and access the terminal:

```
middleware/term
```

Access the tcpsigner directory:
```
cd /hsm2/ledger/src/tcpsigner
```

Build the TCPSigner:
```
make
```

Run the TCPSigner:
```
./tcpsigner
```
Refer to the help (`--help`) command for options.

You should see the following messages when the TCPSigner is running:
```
[TCPSIGNER] ECDSA initialized.
[TCPSIGNER] ADMIN: Init OK.
[TCPSIGNER] Starting TCP server on 127.0.0.1:8888
[TCPSIGNER] Server listening...
```

## Running the Manager

Open a second instance of the same container:
```
docker exec -it hsm-mware bash
```

Run manager-tcp:
```
python3 manager-tcp.py
```
Refer to the help (`-h`) command for options.
