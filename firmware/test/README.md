# powHSM firmware test suite

## Build parameters for a physical Ledger Nano S

*Checkpoint:* 0xbdcb3c17c7aee714cec8ad900341bfd987b452280220dcbd6e7191f67ea4209b
*Difficulty:* 0x32 (50)
*Network:* regtest

### Example command to build a signer to run the tests against

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
