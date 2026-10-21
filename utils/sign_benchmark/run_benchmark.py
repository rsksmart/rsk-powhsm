# The MIT License (MIT)
#
# Copyright (c) 2021 RSK Labs Ltd
#
# Permission is hereby granted, free of charge, to any person obtaining a copy of
# this software and associated documentation files (the "Software"), to deal in
# the Software without restriction, including without limitation the rights to
# use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies
# of the Software, and to permit persons to whom the Software is furnished to do
# so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.
"""
Benchmark unauthorised signing through a running powHSM manager.

Two subcommands:

  run      sends a fixed, seeded sequence of unauthorised "sign" requests to the
           manager, times each one end to end and writes the raw timings plus
           metadata to a JSON results file.
  compare  loads two or more results files, groups them by label and reports
           per-run and per-label statistics, the run-to-run noise within each
           label and the difference of each label against a baseline.

Requests use RFC6979-deterministic signing on the device, so the same seed yields
exactly the same signing work across firmware builds.
"""

from argparse import ArgumentParser
from datetime import datetime, timezone
import hashlib
import json
import os
import platform
import random
import socket
import statistics
import sys
import time

DEFAULT_HOST = "localhost"
DEFAULT_PORT = 9999
DEFAULT_SAMPLES = 500
DEFAULT_WARMUP = 20
DEFAULT_SEED = "powhsm-sign-benchmark"
DEFAULT_KEYS = ["m/44'/137'/0'/0/0", "m/44'/137'/1'/0/0"]
DEFAULT_OUTPUT_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "results")
DEFAULT_BOOTSTRAP_ITERATIONS = 2000

PROTOCOL_VERSION = 5
ERROR_CODE_OK = 0
SOCKET_TIMEOUT = 60
PROGRESS_EVERY = 50


class BenchmarkError(RuntimeError):
    pass


# Manager communication
# (protocol is in the HTTP/1.0 style - one command per connection)
def send_request(host, port, request):
    with socket.create_connection((host, port), timeout=SOCKET_TIMEOUT) as sock:
        sock.sendall((json.dumps(request) + "\n").encode("utf-8"))
        received = b""
        while not received.endswith(b"\n"):
            chunk = sock.recv(4096)
            if not chunk:
                break
            received += chunk
    if not received:
        raise BenchmarkError("Empty response from manager")
    return json.loads(received.decode("utf-8"))


def check_ok(response, what):
    if response.get("errorcode") != ERROR_CODE_OK:
        raise BenchmarkError(f"{what} failed: {response}")
    return response


def get_manager_version(host, port):
    return check_ok(send_request(host, port, {"command": "version"}),
                    "Version request")["version"]


def get_pubkey(host, port, key_id):
    return check_ok(
        send_request(
            host, port, {
                "command": "getPubKey",
                "keyId": key_id,
                "version": PROTOCOL_VERSION,
            }
        ), f"getPubKey for {key_id}"
    )["pubKey"]


def sign_request(key_id, hash_hex):
    return {
        "command": "sign",
        "keyId": key_id,
        "message": {
            "hash": hash_hex
        },
        "version": PROTOCOL_VERSION,
    }


# Deterministic inputs
def build_inputs(seed, count, keys, offset=0):
    inputs = []
    for i in range(offset, offset + count):
        hash_hex = hashlib.sha256(f"{seed}:{i}".encode("utf-8")).hexdigest()
        inputs.append((keys[i % len(keys)], hash_hex))
    return inputs


# Signature verification
class Verifier:

    def __init__(self, pubkeys):
        import ecdsa
        self._ecdsa = ecdsa
        self._keys = {
            key_id:
            ecdsa.VerifyingKey.from_string(bytes.fromhex(pubkey), curve=ecdsa.SECP256k1)
            for key_id, pubkey in pubkeys.items()
        }

    def verify(self, key_id, hash_hex, signature):
        r = int(signature["r"], 16)
        s = int(signature["s"], 16)
        order = self._ecdsa.SECP256k1.order
        sig = self._ecdsa.util.sigencode_strings(r, s, order)
        try:
            return self._keys[key_id].verify_digest(
                sig,
                bytes.fromhex(hash_hex),
                sigdecode=self._ecdsa.util.sigdecode_strings
            )
        except self._ecdsa.BadSignatureError:
            return False


def build_verifier(pubkeys, enabled):
    if not enabled:
        return None
    try:
        return Verifier(pubkeys)
    except ImportError:
        raise BenchmarkError(
            "Signature verification requires the 'ecdsa' python package "
            "(available in the hsm:mware docker image). Install it or use --no-verify"
        )


def timed_sign(host, port, key_id, hash_hex):
    start = time.perf_counter_ns()
    response = send_request(host, port, sign_request(key_id, hash_hex))
    elapsed = time.perf_counter_ns() - start
    check_ok(response, f"Signing {hash_hex} with {key_id}")
    if "signature" not in response:
        raise BenchmarkError(f"No signature in response: {response}")
    return elapsed, response["signature"]


# Statistics
def percentile(sorted_values, pct):
    if not sorted_values:
        return None
    k = (len(sorted_values) - 1) * pct / 100
    lo = int(k)
    hi = min(lo + 1, len(sorted_values) - 1)
    return sorted_values[lo] + (sorted_values[hi] - sorted_values[lo]) * (k - lo)


def summarize(values_ms):
    ordered = sorted(values_ms)
    return {
        "count": len(ordered),
        "mean_ms": statistics.mean(ordered),
        "median_ms": statistics.median(ordered),
        "stdev_ms": statistics.stdev(ordered) if len(ordered) > 1 else 0.0,
        "min_ms": ordered[0],
        "p5_ms": percentile(ordered, 5),
        "p95_ms": percentile(ordered, 95),
        "max_ms": ordered[-1],
    }


def bootstrap_median_diff_ci(base, other, iterations, rng):
    diffs = []
    for _ in range(iterations):
        b = statistics.median(rng.choices(base, k=len(base)))
        o = statistics.median(rng.choices(other, k=len(other)))
        diffs.append(o - b)
    diffs.sort()
    return percentile(diffs, 2.5), percentile(diffs, 97.5)


# Subcommands
def run(options):
    if options.samples < 1 or options.warmup < 0:
        raise BenchmarkError("Samples must be positive and warmup non-negative")

    host, port = options.host, options.port
    print(f"Manager:  {host}:{port}")
    manager_version = get_manager_version(host, port)
    print(f"Protocol: v{manager_version}")
    if manager_version != PROTOCOL_VERSION:
        raise BenchmarkError(
            f"Unsupported manager protocol version {manager_version} "
            f"(expected {PROTOCOL_VERSION})"
        )

    pubkeys = {key_id: get_pubkey(host, port, key_id) for key_id in options.keys}
    verifier = build_verifier(pubkeys, not options.no_verify)

    # Warmup uses its own inputs so that the measured sequence is identical
    # regardless of the warmup size
    warmup_inputs = build_inputs(f"{options.seed}:warmup", options.warmup, options.keys)
    inputs = build_inputs(options.seed, options.samples, options.keys)

    print(f"Warming up with {options.warmup} requests...")
    for key_id, hash_hex in warmup_inputs:
        timed_sign(host, port, key_id, hash_hex)

    print(f"Measuring {options.samples} requests...")
    samples = []
    started_at = datetime.now(timezone.utc)
    wall_start = time.perf_counter_ns()
    for i, (key_id, hash_hex) in enumerate(inputs):
        elapsed, signature = timed_sign(host, port, key_id, hash_hex)
        if verifier is not None and not verifier.verify(key_id, hash_hex, signature):
            raise BenchmarkError(
                f"Invalid signature for {hash_hex} with {key_id}: "
                f"{signature}"
            )
        samples.append({
            "keyId": key_id,
            "hash": hash_hex,
            "elapsed_ns": elapsed,
        })
        if (i + 1) % PROGRESS_EVERY == 0 or i + 1 == len(inputs):
            print(f"  {i + 1}/{len(inputs)}")
    wall_elapsed = time.perf_counter_ns() - wall_start
    finished_at = datetime.now(timezone.utc)

    summary = summarize([s["elapsed_ns"] / 1e6 for s in samples])
    summary["throughput_rps"] = len(samples) / (wall_elapsed / 1e9)

    result = {
        "metadata": {
            "label": options.label,
            "notes": options.notes,
            "manager": f"{host}:{port}",
            "protocol_version": manager_version,
            "keys": options.keys,
            "pubkeys": pubkeys,
            "seed": options.seed,
            "samples": options.samples,
            "warmup": options.warmup,
            "verified": verifier is not None,
            "started_at": started_at.isoformat(),
            "finished_at": finished_at.isoformat(),
            "client_host": platform.node(),
            "python": platform.python_version(),
        },
        "summary": summary,
        "samples": samples,
    }

    os.makedirs(options.output_dir, exist_ok=True)
    timestamp = started_at.strftime("%Y%m%dT%H%M%SZ")
    path = os.path.join(options.output_dir, f"{options.label}_{timestamp}.json")
    with open(path, "w") as f:
        json.dump(result, f, indent=2)

    print_summary(f"Run '{options.label}'", summary)
    print(f"Results written to {path}")


def print_summary(title, summary):
    print(f"{title}:")
    print(
        f"  n={summary['count']}  median={summary['median_ms']:.3f}ms  "
        f"mean={summary['mean_ms']:.3f}ms  stdev={summary['stdev_ms']:.3f}ms"
    )
    print(
        f"  min={summary['min_ms']:.3f}ms  p5={summary['p5_ms']:.3f}ms  "
        f"p95={summary['p95_ms']:.3f}ms  max={summary['max_ms']:.3f}ms"
    )
    if "throughput_rps" in summary:
        print(f"  throughput={summary['throughput_rps']:.2f} req/s")


def load_results(paths):
    runs = []
    for path in paths:
        with open(path, "r") as f:
            result = json.load(f)
        values = [s["elapsed_ns"] / 1e6 for s in result["samples"]]
        runs.append({
            "path": path,
            "label": result["metadata"]["label"],
            "seed": result["metadata"]["seed"],
            "keys": result["metadata"]["keys"],
            "values": values,
            "summary": result["summary"],
        })
    return runs


def compare(options):
    runs = load_results(options.files)
    if len(runs) < 2:
        raise BenchmarkError("At least two results files are needed to compare")

    # All runs must have performed the same signing work
    if len({(r["seed"], tuple(r["keys"]), len(r["values"])) for r in runs}) != 1:
        print(
            "WARNING: runs differ in seed, keys or sample count. "
            "Their signing work is not identical."
        )

    labels = []
    for r in runs:
        if r["label"] not in labels:
            labels.append(r["label"])
    baseline = options.baseline or labels[0]
    if baseline not in labels:
        raise BenchmarkError(f"Baseline label '{baseline}' not found in the results")

    print("Per run:")
    for r in runs:
        print_summary(f"- [{r['label']}] {os.path.basename(r['path'])}", r["summary"])

    print()
    print("Per label (all runs pooled):")
    pooled = {}
    noise = {}
    for label in labels:
        label_runs = [r for r in runs if r["label"] == label]
        pooled[label] = [v for r in label_runs for v in r["values"]]
        medians = [statistics.median(r["values"]) for r in label_runs]
        noise[label] = max(medians) - min(medians) if len(medians) > 1 else None
        print_summary(f"- [{label}] {len(label_runs)} run(s)", summarize(pooled[label]))
        if noise[label] is None:
            print("  run-to-run noise: unknown (single run, repeat it to measure noise)")
        else:
            print(f"  run-to-run noise (spread of run medians): {noise[label]:.3f}ms")

    print()
    print(
        f"Against baseline '{baseline}' (difference of medians, "
        f"95% bootstrap CI over {options.iterations} iterations):"
    )
    rng = random.Random(options.seed)
    base_values = pooled[baseline]
    base_median = statistics.median(base_values)
    for label in labels:
        if label == baseline:
            continue
        diff = statistics.median(pooled[label]) - base_median
        lo, hi = bootstrap_median_diff_ci(
            base_values, pooled[label], options.iterations, rng
        )
        relative = diff / base_median * 100
        # Noise is only known when both labels have been run more than once
        if noise[baseline] is None or noise[label] is None:
            noise_floor = None
        else:
            noise_floor = max(noise[baseline], noise[label])
        if lo <= 0 <= hi:
            verdict = "no significant difference (CI includes 0)"
        elif noise_floor is not None and abs(diff) <= noise_floor:
            verdict = "within run-to-run noise"
        elif noise_floor is None:
            verdict = "inconclusive, noise unknown (repeat runs for both labels)"
        else:
            verdict = "SLOWER" if diff > 0 else "FASTER"
        print(
            f"- [{label}] {diff:+.3f}ms ({relative:+.2f}%)  "
            f"CI [{lo:+.3f}ms, {hi:+.3f}ms]  -> {verdict}"
        )


def main():
    parser = ArgumentParser(
        description="Benchmark unauthorised signing through a running powHSM manager"
    )
    subparsers = parser.add_subparsers(dest="operation", required=True)

    run_parser = subparsers.add_parser("run", help="run a benchmark and save results")
    run_parser.add_argument(
        "-l",
        "--label",
        required=True,
        help="label for this run (e.g., the firmware variant)"
    )
    run_parser.add_argument(
        "-a",
        "--host",
        default=DEFAULT_HOST,
        help=f"manager host (default {DEFAULT_HOST})"
    )
    run_parser.add_argument(
        "-p",
        "--port",
        type=int,
        default=DEFAULT_PORT,
        help=f"manager port (default {DEFAULT_PORT})"
    )
    run_parser.add_argument(
        "-n",
        "--samples",
        type=int,
        default=DEFAULT_SAMPLES,
        help=f"measured requests (default {DEFAULT_SAMPLES})"
    )
    run_parser.add_argument(
        "-w",
        "--warmup",
        type=int,
        default=DEFAULT_WARMUP,
        help=f"unmeasured warmup requests (default {DEFAULT_WARMUP})"
    )
    run_parser.add_argument(
        "-s",
        "--seed",
        default=DEFAULT_SEED,
        help="seed for the hashes to sign (default "
        f"'{DEFAULT_SEED}'). Keep it fixed across runs"
    )
    run_parser.add_argument(
        "-k",
        "--key",
        dest="keys",
        action="append",
        help="key id to sign with, can be repeated (default: "
        f"{', '.join(DEFAULT_KEYS)})"
    )
    run_parser.add_argument(
        "-o",
        "--output-dir",
        default=DEFAULT_OUTPUT_DIR,
        help="directory for results files (default: "
        "results/ next to this script)"
    )
    run_parser.add_argument(
        "--notes",
        default="",
        help="free-form notes to store (e.g., signer hash, device)"
    )
    run_parser.add_argument(
        "--no-verify", action="store_true", help="skip verifying returned signatures"
    )

    compare_parser = subparsers.add_parser(
        "compare", help="compare two or more results files"
    )
    compare_parser.add_argument("files", nargs="+", help="results files to compare")
    compare_parser.add_argument(
        "-b", "--baseline", help="baseline label (default: label of the first file)"
    )
    compare_parser.add_argument(
        "-i",
        "--iterations",
        type=int,
        default=DEFAULT_BOOTSTRAP_ITERATIONS,
        help="bootstrap iterations (default "
        f"{DEFAULT_BOOTSTRAP_ITERATIONS})"
    )
    compare_parser.add_argument(
        "--seed", type=int, default=0, help="bootstrap random seed (default 0)"
    )

    options = parser.parse_args()
    try:
        if options.operation == "run":
            options.keys = options.keys or DEFAULT_KEYS
            run(options)
        else:
            compare(options)
    except (BenchmarkError, OSError) as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
