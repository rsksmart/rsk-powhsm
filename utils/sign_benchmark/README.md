# powHSM signing benchmark

Measures the end-to-end latency of unauthorised `sign` requests sent to a running powHSM
manager, and compares results across different runs. Use it to check the performance
impact of firmware changes, such as additional validations on produced signatures.

## How it works

- The `run` subcommand sends a fixed sequence of unauthorised `sign` requests to the
  manager. By default it alternates two of the keys that need no authorisation,
  `m/44'/137'/0'/0/0` (RSK) and `m/44'/137'/1'/0/0` (MST). It times each request from
  connection to response, verifies every returned signature against the key's public key,
  and writes the raw timings and metadata to `results/<label>_<timestamp>.json`.
- The `compare` subcommand groups results files by label. It reports:
  - statistics for each run and for each label;
  - the run-to-run noise of each label (the spread of its run medians);
  - for each label, the difference of medians against a baseline label, with a 95%
    bootstrap confidence interval.

## Prerequisites

- Docker
- The middleware docker image built (`docker/mware/build`).

## Usage

For each individual benchmark, start the manager within a middleware container (`middleware/term`), and then within the same container (acquire a terminal with `docker exec -ti hsm-mware bash`), issue:

```
cd /hsm2/utils/sign_benchmark
python run_benchmark.py run --label <label> [--notes "<signer hash, device, etc>"]
```

Then compare:

```
utils/sign_benchmark/run_benchmark.py compare utils/sign_benchmark/results/*.json --baseline <baseline label>
```

Run `run_benchmark.py run --help` and `run_benchmark.py compare --help` for all options (sample count, warmup, keys, seed, output directory).

## Getting meaningful results

- **Alternate builds and repeat runs, e.g. A, B, A, B.** Each label needs at least two runs. Without them, `compare` can't tell a real difference from run-to-run variation (USB, host load, temperature), and reports differences as inconclusive.
- **Keep the seed, keys and sample count the same across runs.** `compare` warns if they differ.
- **Keep everything else fixed:** same host, same manager logging configuration, and nothing else talking to the manager while a run is in progress.
- **Small firmware costs may not show.** A change of a few microseconds on the device is far below the variation of a request that includes USB and manager round trips. A difference reported as "no significant difference" or "within run-to-run noise" means the change is not measurable at this level.
