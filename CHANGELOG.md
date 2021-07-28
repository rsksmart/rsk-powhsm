# Changelog
All notable changes to this project will be documented in this file.

## [2.0.1] - 10/12/2020

### Features/enhancements

- Binary builds are no longer one file bundles, but compressed .tgz(s)
- Added docker image rebuild scripts
- Added client distribution README
- Setup and upgrade scripts now expand and clean binary bundles

### Fixes

- Fixed middleware's Dockerfile apt package versions
- Fixed middleware reproducible build

## [2.1.0] - 08/03/2021

### Features/enhancements

- UI and Signer attestation is now part of the output of the setup (and upgrade) process
- Signer is now Iris-aware
- Signer now supports arbitrarily large merge mining merkle proofs - hard size limit set to 960 from Iris onwards
- Signer and simulator now support three additional unauthorized derivation paths that deprecate the old MST, tRSK and tMST paths
- Added upgrade process for 2.x => 2.y

### Fixes

- Ledger compatibility: simulator now unsigns BTC transactions before computing the sighash 
- Middleware builds are now compatible with older glibc versions (2.24+)
- Fixed unused symbols reported in 2.0.0 security audit
- Fixed private key cleaning issues reported in 2.0.0 security audit
- Restricted public key gathering to only authorized paths in signer

## [2.1.1] - 31/05/2021

### Features/enhancements

- Implements recommendations from Coinspect 2.1 Security Audit v210405
- Upgrade process (2.x => 2.y) now supports devices with a UI >= 2.0

### Fixes

- Implements fixes to reported issues on Coinspect 2.1 Security Audit v210405
- Implements fixes to reported issues on Coinspect 2.1 Second Security Audit v20210430
- Manager is now backwards compatible with older versions of the firmware (>= 2.0)
- Fixed outdated ledger docker image build
- Signer: fixed assigning a wrong value to expectedRXBytes on S_CMD_FINISHED state
- Signer: fixed RLP parser behavior when handling inconsistent length encodings
- Signer now verifies BTC transactions are either version 1 or 2
- Simulator now verifies BTC transactions are either version 1 or 2

## [2.1.2] - 17/06/2021

### Fixes

- Fixed SIGHASH calculation bug in BTC transactions with scriptSigs larger than 256 bytes
- Implements fixes to reported issues on Coinspect 2.1 Second Security Audit fixes v20210611

## [2.1.3] - 08/07/2021

### Features/enhancements

- Set Iris activation block numbers for mainnet and testnet

## [2.1.4] - 27/07/2021

### Features/enhancements

- Set Iris activation block numbers for mainnet and testnet (reviewed)

### Fixes

- Implements fixes to reported issues on HSM2 July Review Security Report v210723