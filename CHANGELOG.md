# Changelog

## [4.0.0] - 08/02/2023

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

### Fixes

- Changed signapp command-line parameter for backwards compatibility
- Removed unused sample generator
- Bumped altgraph, certifi, future, macholib, Pillow and protobuf to address findings
- Updated GH actions to use node16 versions
- Fixed varint handling on btc tx parser and rsk trie parser

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
