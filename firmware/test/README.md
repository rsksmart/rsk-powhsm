# powHSM firmware test suite

## Blockchain parameters to run the tests on any implementation (i.e., Ledger, SGX, TCPSigner, etc)

*Checkpoint:* 0xbdcb3c17c7aee714cec8ad900341bfd987b452280220dcbd6e7191f67ea4209b
*Difficulty:* 0x32 (50)
*Network:* regtest

### Example command to build a ledger signer to run the tests against

```bash
~/repo> firmware/build/build-ledger-signer 0xbdcb3c17c7aee714cec8ad900341bfd987b452280220dcbd6e7191f67ea4209b 50 regtest
```

## Running the tests

To test using the TCPSigner, issue:

```bash
~/repo> firmware/test/test-all
```

To test against a physical dongle, issue:

```bash
~/repo> firmware/test/test-all dongle
```

To test against an SGX instance, there are a few more steps involved, since normally the
instance will be running in an SGX-enabled server elsewhere. Therefore, there are some
prerequisites for this:

- Your server must have Docker installed
- Have a running SGX powHSM instance on your server
- Said instance MUST be already onboarded
- The instance MUST be running with the server bound to `0.0.0.0`
- We'll assume that the instance is listening on port `7777`

To run the tests, follow these steps:
- Package the tests:

```bash
~/repo> firmware/test/package/generate
```

- Copy the generated `firmware/test/package/bundle.tgx` to the server on which the SGX
  powHSM instance is running
- On the server, decompress the bundle to a directory of your choice (say
  `~/powhsm-tests`)
- Run the tests:

```bash
~/powhsm-tests> ./run-with-docker -dsgx -p7777 -shost.docker.internal -m
```

The above command will run the tests in "manual unlocking" mode. You can change this to
automatic unlocking replacing the `-m` option with `-P <PIN>`. Also, to see the test
runner options, issue:

```bash
~/powhsm-tests> ./run-with-docker --help
```
