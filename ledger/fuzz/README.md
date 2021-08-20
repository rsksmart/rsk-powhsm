# Fuzzing

This folder contains fuzzing scripts for the TCPSigner. Right now everything 
is geared towards (AFL++)[https://github.com/aflplusplus].

Most of the scripts here require a working `hsm:afl` Docker image which you
can build using the `~/repo/docker/afl/build` script.

# Building a fuzzable TCPSinger 

You can build the TCPSigner with the AFL++ compilers with the 
`~/repo/ledger/build/build-tcpsigner-afl` script, which uses the 
`~/repo/docker/afl/Dockerfile` instructions to build a `tcpsigner` 
binary which you can then fuzz using the `fuzz` script in this folder.

You should always at least one primary fuzzer (`./fuzz primary`) and as
many secondary fuzzers as you want (`./fuzz secondary`). Running the `./fuzz` script 
with only `primary` or `secondary` arguments works. If you want to specify
input and output folders, you should know that all fuzzers are required
to share the output folder. Read more on the AFL++ docs.

# Generating coverage
To know how much coverage the fuzzer has, you can run the `./coverage` script. 
The `./coverage` script needs to be run _before_ the fuzzer starts. Its defaults 
match the defaults arguments of the `./fuzz` script, but if you will run 
the fuzzer with a different output location, you should let the `./coverage` script
know.

The `coverage-build` parameter is an unfortunate technicality. Coverage needs
a copy of the source files, and we must put it somewhere. The default is `./.coverage-build`.
You can mostly ignore this folder. But whatever you specify as the coverage build folder
**will get deleted** by the script, so be careful.

# Generating testcases

You can run `./generate-testcases` to generate the testcases,
make them unique and minimize them. This is recommended but takes
a good while.

The longest step by far is to minimize them. You can skip this step
by running `./generate-testcases big`, but this will obviously 
result in bigger testcases and a slower fuzzing.

If you want to run only some steps of the process, you can run the
helper scripts `extract-inputs-from-tests`, `unique-testcases` and 
`min-testcases` one by one.

# Creating new entries in the dictionary

The `./fuzz` script will read from the dictionary at `./dict/`. To easily add 
entries to the dictionary, you can use the helper python script `hex_to_dict.py` like this:

```python3
python3 hex_to_dict.py <hex data, no 0x prefix> <name>
```

# Modifying run parameters
The `~/repo/ledger/fuzz/env` file specifies the difficulty, network and checkpoint to be
used both by the fuzzer and the coverage script.
