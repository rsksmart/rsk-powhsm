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

import os
import output
from .case import TestCase, TestCaseError


def noop(s):
    pass


def debug(s):
    output.debug(f"\n{s}")


class TestSuite:
    @classmethod
    def load_from_path(cls, path, flt):
        prefixes = flt.split(",")
        cases_paths = filter(lambda p: os.path.splitext(p)[1] == ".json",
                             os.listdir(path))
        cases_paths = list(
            filter(
                lambda p: len(prefixes) == 0 or any(
                    map(lambda prefix: p.startswith(prefix), prefixes)),
                cases_paths,
            ))
        cases_paths.sort()
        return cls(
            list(map(
                lambda case_path: TestCase.from_json_file(os.path.join(path, case_path)),
                cases_paths,
            )))

    def __init__(self, cases):
        self.cases = cases
        self.debug = False

    def run(self, dongle, run_on, run_args):
        debug_fn = debug if self.debug else noop
        self._passed = 0
        self._failed = 0
        self._skipped = 0
        try:
            for case in self.cases:
                output.info(case.name)
                if case.runs_on(run_on):
                    case.run(dongle, debug_fn, run_args)
                    output.ok()
                    self._passed += 1
                else:
                    output.skipped()
                    self._skipped += 1
            return True
        except TestCaseError as e:
            output.error(str(e))
            self._failed += 1
            return False

    def get_stats(self):
        return {
            "passed": self._passed,
            "failed": self._failed,
            "skipped": self._skipped,
        }
