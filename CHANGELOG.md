# Changelog
All notable changes to this project will be documented in this file.

## [alpha-0.0.1] - 5/9/2020

### Features/enhancements

- HSM 2 signer firmware.
- HSM 2 UI firmware.
- HSM 2 manager middleware.
- HSM 2 simulator.
- Firmware build toolchain.
- Middleware build toolchain.
- Old HSM 1.1 python2 scripts and utilities.

## [alpha-0.0.2] - 11/11/2020

### Features/enhancements

- Implemented signer blacklist in UI firmware.
- Disallowed running unsigned apps in UI firmware.
- Only allowing 8-character pins and with at least one alpha character in UI firmware.
- Manager's pin source is pin.txt file first, then environment variable.
- Enforcing pin restrictions within all applicable middleware.
- Unified administration tooling into a single script for unlocking, onboarding, exiting, gathering public keys and pin changing.
- Added backup restoration script.
- Added app signer script.
- Added unified ledgerblue utils script with app load & delete, setup & reset CA, CA generation.
- Added building scripts for all middleware.
- Added distribution setup and upgrade scripts.
- Added full distribution building script (firmware + middleware + setup & upgrade scripts).
- Unified python scripts (middleware, firmware deployment and firmware tests) for python3. 
- Unified and dockerized python development and execution environment.
- Automatically deploying signed apps within dev deployment scripts if signatures exist.
- Removed old and/or unused scripts and directories.
- Restructured the solution's directory tree.
- Updated READMEs project-wide to reflect the current state of the solution.

### Fixes

- Fixed bug in merkle proof parsing within the firmware signer.
- Fixed post signer updating crash in UI firmware.
- Fixed bug in UI onboarding backup generation.
- Command 'blockchainState' response protocol incompatibility fix in manager.
- Fixed 'tip mismatch' error handling in command 'updateAncestorBlock' in manager.
- Fixed dongle timeout issues in manager.
- Added hash to sign type and length validation in unauthorized signing command for both manager and simulator.
- Added top-level request type (JSON object) validation to both manager and simulator.
- Removed verbatim pin logging upon pin change in manager.

## [2.0.0] - 27/11/2020

### Features/enhancements

- Manager HSM 1 protocol implementation on HSM 2 firmware (and simulator).
- Removed backup generation from UI firmware.
- Removed backup gathering in onboarding tool.
- Removed backup encryption in setup script.

### Fixes

- Resetting CA before setting up new CA in setup script.
- Fixing 'updateAncestorBlock' border case failure in parsing when removing MM fields.

## [2.0.1] - 10/12/2020

### Features/enhancements

- Binary builds are no longer one file bundles, but compressed .tgz(s)
- Added docker image rebuild scripts
- Added client distribution README
- Setup and upgrade scripts now expand and clean binary bundles

### Fixes

- Fixed middleware's Dockerfile apt package versions
- Fixed middleware reproducible build

## [2.0.2] - 03/05/2021

### Features/enhancements

- Middleware now using Python 3.7
- Middleware builds are now compatible with older GLIBC versions (2.24+)

### Fixes

- Fixed broken ledger docker image build
- Fixed broken middleware docker image build

## [2.0.3] - 04/06/2021

### Features/enhancements

- Added upgrade process for 2.x => 2.y

### Fixes

- Signer now verifies BTC transactions are either version 1 or 2
- Simulator now verifies BTC transactions are either version 1 or 2
- Fixed broken firmware simulator build

## [2.0.4] - 15/06/2021

### Fixes

- Fixed SIGHASH calculation bug in BTC transactions with scriptSigs larger than 256 bytes
