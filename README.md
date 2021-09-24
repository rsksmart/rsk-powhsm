# HSM 2.X

![Tests](https://github.com/rsksmart/rsk-powhsm/actions/workflows/run-tests.yml/badge.svg)
![Python linter](https://github.com/rsksmart/rsk-powhsm/actions/workflows/lint-python.yml/badge.svg)
![C linter](https://github.com/rsksmart/rsk-powhsm/actions/workflows/lint-c.yml/badge.svg)

This repository hosts the HSM 2 project. Refer to the following documents for details on specifics:

- Documentation:
  - [Protocol specification](./docs/protocol.md)
  - [Blockchain bookkeeping documentation](./docs/blockchain-bookkeeping.md)
- [Ledger apps](./ledger/README.md)
- [Middleware](./middleware/README.md)
- [Distribution](./dist/README.md)

## General considerations

Throughout the repository READMEs, the prompt `~/repo>` is used to denote a `bash` terminal cded to the repository's root. Likewise, the prompt `~/repo/another/path>` is used to denote a `bash` terminal cded to the repository's `another/path` directory. Finally, the prompt `/this/is/a/path>` is used to denote a `bash` terminal cded to the absolute path `/this/is/a/path`.

## Report Security Vulnerabilities

To report a vulnerability, please use the [vulnerability reporting guideline](./SECURITY.md) for details on how to do it.
