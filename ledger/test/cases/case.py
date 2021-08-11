import json
from comm.bip32 import BIP32Path

class TestCase:
    OPERATION_KEY = 'operation'
    op_mapping = None
    PATHS = None

    @classmethod
    def op_name(cls):
        pass

    @classmethod
    def from_json_file(cls, path):
        with open(path, 'r') as f:
            return cls.create(json.load(f))

    @classmethod
    def create(cls, spec):
        # Build the mapping from op names
        # to classes
        if not cls.op_mapping:
            cls.op_mapping = {}
            for k in cls.__subclasses__():
                if k.op_name():
                    cls.op_mapping[k.op_name()] = k

        if type(spec) != dict or \
           cls.OPERATION_KEY not in spec or \
           spec[cls.OPERATION_KEY] not in cls.op_mapping:
            raise RuntimeError(f"Invalid spec: {str(spec)}")

        return cls.op_mapping[spec[cls.OPERATION_KEY]](spec)

    def __init__(self, spec):
        self.name = spec['name']
        
        # Test case expectation
        self.expected = spec.get('expected', True)
        if type(self.expected) == str:
            self.expected = self._parse_int(self.expected)

        # Paths to test (for signing and related cases)
        self.paths = spec.get('paths', None)
        if self.paths:
            paths = {}
            for p in self.paths:
                paths[p] = BIP32Path(p, nelements=None)
            self.paths = paths
        else:
            self.paths = self.PATHS

    def run(self, dongle, version, debug):
        raise RuntimeError(f"Unable to run generic test case {self.name}")

    def _parse_int(self, s):
        if s.startswith('0x'):
            return int(s, 16)
        return int(s, 10)

class TestCaseError(RuntimeError):
    pass