# Changelog

## [5.2.2] - 20/01/2025

### Features/enhancements

- Implemented OSSF scorecard on CI

### Fixes

- Fixed middleware docker image build
- Fixed minor scorecard findings
- Bumped debian, aflplusplus docker images
- Bumpled GH actions codeql, upload-artifact

## [5.2.1] - 14/11/2024

### Fixes

- Removed compilation products from repository
- Fixed failing middleware docker image build

## [5.2.0] - 09/09/2024

### Features/enhancements

- Added "screen saver" mode to signer app to extend display lifetime
- Decoupled business and I/O (aka communication) layers in preparation for multiple platforms
- Improved HAL directory structure to accomodate for testing different platform implementations

### Fixes

- Fixed middleware docker image build
- Fixed verify_attestaion.py to allow distinct versions for UI and Signer
- Incidentally bumped urllib3, certifi to address dependabot findings

## [5.1.0] - 01/07/2024

### Features/enhancements

- Decoupled business and hardware layers in preparation for multiple platforms
- Upgraded Python to version 3.12
- Upgraded Python dependencies

### Fixes

- Removed unnecessary requirements file for middleware docker image
- Fixed post-upgrade failing middleware docker image build
- Incidentally bumped idna, pillow to address dependabot findings

## [5.0.0] - 09/04/2024

### Features/enhancements

- Implemented authorised segwit transaction signing
- Added firmware static analysis to CI
- Middleware and Firmware code coverage
- Unified wa_store function into unique WA_STORE macro
- Updated bug bounty program handler, domains and program response time

### Fixes

- Brother validation on advance blockchain payload
- Bumped pyinstaller, pycryptodome, pycryptodomex to address dependabot findings

## [4.0.2] - 01/12/2023

### Features/enhancements

- New signer upgrades wallet (Alpha)
- Periodic unit and integration tests workflow run (every 24hs)

### Fixes

- Fixed failing middleware docker image build
- Bumped certifi, urllib3 to address dependabot findings

## [4.0.1] - 14/06/2023

### Features/enhancements

- Using Nanos SDK fork version 2

## [4.0.0] - 30/05/2023

### Features/enhancements

- New Signer and UI heartbeat operations
- Factored out UI into independent and unit tested modules
- Removed all human interactivity from the UI
- Preventing re-onboarding
- Removed deprecated derivations paths
- Moving partial advance blockchain state to an independent RAM area
- TCPSigner: added command-line customisation of block difficulty cap and network upgrade
  activation block numbers
- Added support for building and running the TCPSigner bundle on arm64
- Added a binary build for signapp as part of the distribution build
- Unified APDU and error definitions within the Signer and UI
- Renamed upgrade scripts
- Documented ledger apps' deployment flags
- Added C static code analysis script for the Signer and UI codebases
- Added CodeQL workflow for Python codebase
- Using Nanos SDK fork instead of local patches for Docker image build
- Reduce USB max endpoints

### Fixes

- Changed signapp command-line parameter for backwards compatibility
- Removed unused sample generator
- Bumped altgraph, certifi, future, macholib, Pillow, protobuf and requests to address findings
- Updated GH actions to use node16 versions
- Fixed varint handling on btc tx parser and rsk trie parser
- Preventing manager shutdown upon unknown request errors
- Zeroing out sRLP context when initialising the parser
- Removed unused signer memory #defines
- Fixed varint handling on btc tx parser and rsk trie parser
- Fixed failing middleware docker image build

## [3.0.1] - 11/08/2022

### Features/enhancements

- Standard ledger Ethereum app support in signer authorization generator
- Supporting VM environments
- Added compile-time check to number of signer authorizers
- Optimized NVM usage within the advance blockchain operation
- Improved blockchain bookkeeping documentation to align with implementation
- Covered all mpAdd possible return values for completeness' sake
- Unified generic error codes into definitions within UI and Signer
- Signer operations don't run if device is not onboarded or has been wiped
- Possibility of simulating a non-onboarded device on the TCPSigner
- Unified pin buffers in UI
- Compilation warnings now treated as errors both in UI and Signer
- Removed deprecated signer-certificate ledger app
- Additional NVM test cases in Signer
- Additional middleware unit tests covering admin utilities

### Fixes

- Removed unused open app consent dialog if app is not signed
- Additional output overflow checks on APDU
- Signer authorizaton process ignores order of signatures
- Added volatile modifiers where missing
- Removed unused case statement in UI
- Fixed inconsistent usage of SAFE_MEMMOVE
- Onboarding flag is now reset at the start of the onboarding process
- Removed compilation warnings both in UI and Signer
- Persistence issue with blockchain state initialization flag
- Fixed attestation documentation broken links
- Fixed CHANGELOG 3.0.0 version and release date

## [3.0.0] - 04/06/2022

### Features/enhancements

- Considering uncles difficulty in "advanceBlockchain" operation
- Implemented N of M signer upgrade authorization scheme
- Authorized signing operation parsers rewritten from scratch
- Added new "blockchainParameters" command
- Added unit tests to middleware admin tooling
- Fuzzing improvements
- General best practices related improvements and fixes
- Removed old/unused code

### Fixes

- Fixed failing middleware docker image build
