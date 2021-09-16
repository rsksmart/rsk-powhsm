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
            map(
                lambda case_path: TestCase.from_json_file(os.path.join(path, case_path)),
                cases_paths,
            ))

    def __init__(self, cases):
        self.cases = cases
        self.debug = False

    def run(self, dongle, version):
        debug_fn = debug if self.debug else noop
        try:
            for case in self.cases:
                output.info(case.name)
                case.run(dongle, version, debug_fn)
                output.ok()
            return True
        except TestCaseError as e:
            output.error(str(e))
            return False
