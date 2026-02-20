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

import json
from comm.bip32 import BIP32Path


class TestCase:
    OPERATION_KEY = "operation"

    RUN_ON_KEY = "runOn"
    RUN_ON_VALUE_ALL = "all"
    RUN_ON_VALUE_LEDGER = "ledger"
    RUN_ON_VALUE_SGX = "sgx"
    RUN_ON_VALUE_TCPSIGNER = "tcpsigner"
    RUN_ON_VALUE_SGX_SIM = "sgxsim"
    RUN_ON_VALUES = [
        RUN_ON_VALUE_ALL,
        RUN_ON_VALUE_LEDGER,
        RUN_ON_VALUE_SGX,
        RUN_ON_VALUE_TCPSIGNER,
        RUN_ON_VALUE_SGX_SIM,
    ]

    RUN_ARGS_PIN_KEY = "pin"
    RUN_ARGS_MANUAL_KEY = "manual"
    RUN_ARGS_DEVICE_KIND_KEY = "deviceKind"

    op_mapping = None
    PATHS = None

    @classmethod
    def op_name(cls):
        pass

    @classmethod
    def from_json_file(cls, path):
        try:
            with open(path, "r") as f:
                return cls.create(json.load(f))
        except Exception as e:
            raise RuntimeError(f"While loading test case from {path}: {e}")

    @classmethod
    def create(cls, spec):
        # Build the mapping from op names
        # to classes
        if not cls.op_mapping:
            cls.op_mapping = {}
            for k in cls.__subclasses__():
                if k.op_name():
                    cls.op_mapping[k.op_name()] = k

        if (type(spec) != dict or cls.OPERATION_KEY not in spec
                or spec[cls.OPERATION_KEY] not in cls.op_mapping):
            raise RuntimeError(f"Invalid spec: {str(spec)}")

        return cls.op_mapping[spec[cls.OPERATION_KEY]](spec)

    def __init__(self, spec):
        self.name = spec["name"]
        self.run_on = spec.get(self.RUN_ON_KEY, [self.RUN_ON_VALUE_ALL])

        # Normalize run on value
        if type(self.run_on) == str:
            self.run_on = [self.run_on]

        # Validate run on value
        if type(self.run_on) != list or \
           any(map(lambda ro: ro not in self.RUN_ON_VALUES, self.run_on)):
            raise RuntimeError(f"Invalid run_on specified for test case {self.name}: "
                               f"{self.run_on}")

        # Test case expectation
        self.expected = spec.get("expected", True)
        self.expected_desc = self.expected
        if type(self.expected) == str:
            self.expected = self._parse_int(self.expected)

        # Paths to test (for signing and related cases)
        self.paths = spec.get("paths", None)
        if self.paths:
            paths = {}
            for p in self.paths:
                paths[p] = BIP32Path(p, nelements=None)
            self.paths = paths
        else:
            self.paths = self.PATHS

    def runs_on(self, run_on):
        return run_on in self.run_on or self.RUN_ON_VALUE_ALL in self.run_on

    def run(self, dongle, debug, run_args):
        raise RuntimeError(f"Unable to run generic test case {self.name}")

    def _parse_int(self, s):
        if s.startswith("0x"):
            return int(s, 16)
        return int(s, 10)


class TestCaseError(RuntimeError):
    pass
