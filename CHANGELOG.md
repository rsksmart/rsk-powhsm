# Changelog

## [5.6.1] - 10/11/2025

### Features/enhancements

- Unit tested powHSM main APDU processor
- Unit tested powHSM path authorization policy
- Unit tested powHSM attestation
- Unit tested powHSM heartbeat
- Achieved 90%+ coverage on firmware codebase

### Fixes

- Fixed potential integer underflow and uninitialized OP read in meta_bc operation
- Fixed potential infinite loop on meta_bc operation in case underlying op stalls
- Added missing firmware directories to C linting and formatting script
- Bumped CI dependencies: `actions/dependency-review-action`, `github/codeql-action`, `actions/upload-artifact`

## [5.6.0] - 09/10/2025

### Features/enhancements

- Improved performance on SGX powHSM's advance blockchain and update ancestor operations
- Firmware tests now support running on SGX simulator
- Removed unnecessary port exposure in SGX powHSM service
- Unit tested SGX trusted ecall and sync modules
- Unit tested SGX HAL trusted access and hash modules
- Unit tested SGX untrusted enclave_provider and enclave_proxy modules
- Unit tested common_linked communication, hash and exception modules
- Unit tested Ledger HAL endorsement, hash, nvmem and seed modules
- Unit tested common bigdigits module
- Ensuring temporary powHSM docker container is stopped upon a failed SGX upgrade
- SGX setup and upgrade: make sure the service is running before proceeding
- Added SGX static analysis
- Enforced static analysis on CI for both Ledger and SGX codebase
- Added return value checks for `secp256k1_ecdsa_sign` and `secp256k1_ecdsa_signature_serialize_der` in SGX HAL seed module
- Using secp256k1 context randomisation throughout SGX HAL
- Added input checks on der_encode_uint
- Failsafe verification of the custom claims hash when verifying evidence
- Added checks for the return value of oe_malloc throughout the SGX implementation
- Added output pointer size parameter and check to hmac_sha512
- SGX attestation validation improvements: validate CRLs, verify TCB and QE identity

### Fixes

- Fixed broken format-python script
- Fixed broken firmware and middleware coverage badges
- Added missing unit tests to coverage report
- Fixed SGX I/O protocol desynchronisation issue
- Fixed file ownership after an SGX upgrade
- Fixed exception library for Ledger, SGX and x86
- Fixed middleware docker image build
- Fixed all static analysis findings, both for Ledger and SGX codebases
- Fixed missing SGX build documentation
- Removed usage of deprecated secp256k1_context_create specific context parameter
- Fixed potential integer underflow in P1_BTC and P1_RECEIPT
- Fixed potential dangling pointers in main SGX upgrade function
- Fixed SGX evidence claim deallocation to prevent potential memory leaks
- Fixed incorrect deallocation of format settings throughout the SGX implementation
- Bumped python libraries: `requests`, `urllib3`, `ledgerblue`, `protobuf`
- Bumped CI dependencies: `actions/checkout`, `aws-actions/configure-aws-credentials`, `actions/dependency-review-action`, `github/codeql-action`, `ossf/scorecard-action`

## [5.5.1] - 02/06/2025

### Fixes

- Fixed middleware docker image build
- Bumped `ossf/scorecard-action`

## [5.5.0] - 27/05/2025

### Features/enhancements

- Introduced SGX firmware upgrades
- Added SGX uninstall script
- Improved SGX setup scripts
- Use `mbedtls` for `hmac_sha512` and non-midstate `sha256` implementation on SGX HAL
- Enhanced Ledger setup and upgrade script to use tput for specific colors in user-facing messages
- Automatically deleting all pre-installed apps on Ledger before onboarding
- Added "Troubleshooting" section to distribution docs
- Ledger screen now shows current signer version

### Fixes

- Fixed mistimed log message in middleware server component
- Ignoring SGX tool-generated files for C linting
- Moved `oeedger8r` generated sources to their own directory
- Destination size check in `der_encode_signature`
- Fixed potential buffer overflow in `der_encode_uint`
- Updated Ubuntu image on GH workflows
- Bumped `libudev-dev`, `ossf/scorecard-action`, `actions/upload-artifact`, 
  `cryptography`, `github/codeql-action`, `aws-actions/configure-aws-credentials`, 
  `actions/dependency-review-action` and `setuptools`

## [5.4.1] - 07/02/2025

### Features/enhancements

- Unified pin/password policy across platforms
- Disabled CapturePFGPExceptions on non-debug and non-simulator builds
- Added key-based headers and header checks to secrets
- Moved bip32_derive_private and dependent libraries to SGX's HAL only
- Moved bip32_parse_path to x86 only

### Fixes

- Increased pip install socket timeout for middleware Dockerfile
- Fixed potential memory leak on SGX's NVmem module
- Pinned all actions/checkout by hash
- Pinned SGX Dockerfile base image by hash
- Pinned firmware test package Dockerfile base image by hash
- Pinned middleware's docker cython-hidapi package by commit hash
- Removed self.expected overwriting from RawCommand test command
- Using cls for class variable name in all class methods
- Fixed unused import warnings
- Removed unwanted comma from regexp in attestation verification
- Made string concatenation explicit in lists
- Added output buffer size validation in bip32_derive_private
- Bumped aws-actions/configure-aws-credentials, github/codeql-action

## [5.4.0] - 27/01/2025

### Features/enhancements

- Enhanced Ledger attestation scheme with additional information
- SGX powHSM implementation
- SGX middleware manager
- SGX middleware admin tooling
- SGX distribution scripts and installation as a service
- SGX reproducible builds
- SGX attestation gathering, saving and verification
- SGX simulation build
- SGX tests
- SGX documentation
- Enhanced distribution documentation

### Fixes

- Added max APDU buffer size checks
- Common modules linking approach change to aid in ease of code auditing
- Bumped actions/checkout from 3 to 4
- Bumped github/codeql-action from 3.28.1 to 3.28.5

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
