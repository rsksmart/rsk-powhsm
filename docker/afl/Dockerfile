# First step is to actaully compile AFL++.
# The image for some reason compiles it and
# then removes the binaries, so let's compile it again.

# unfortunately no cool tags provided, so let's go with a digest.
FROM aflplusplus/aflplusplus@sha256:6ad555201c6c3065dd95ad1fbee46c7011848970519e81729a8d32604c036077 as afl

# Need to install GCC7 because signer / tcpsigner are compiled with
# GCC6 and GCC9 respectively. AFL++ image comes with GCC10 which
# just breaks everything between the two.
RUN apt-get update && apt-get install -y -q gcc-7 gcc-7-plugin-dev g++-7 build-essential libsecp256k1-dev gcc

# Need to rebuild AFL++ with gcc-7. Source-only
# builds what we need to isntrument a binary
# and all the main AFL binaries.
RUN CC=gcc-7 make source-only all install

# Make GCOV point to the same version as GCC
RUN ln -sf /usr/bin/gcov-7 /usr/bin/gcov
RUN ln -sf /usr/bin/gcov-tool-7 /usr/bin/gcov-tool
RUN ln -sf /usr/bin/gcov-dump-7 /usr/bin/gcov-dump
