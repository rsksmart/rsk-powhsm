from .case import TestCase, TestCaseError

class GetBlockchainState(TestCase):
    @classmethod
    def op_name(cls):
        return "getState"

    def __init__(self, spec):
        return super().__init__(spec)

    def run(self, dongle, version, debug):
        try:
            state = dongle.get_blockchain_state()
            debug(f"State: {state}")
            # Expectations on the retrieved state (optional)
            if type(self.expected) == dict:
                for key in self.expected:
                    if state.get(key) != self.expected[key]:
                        raise TestCaseError(f"Expected {key} to be {self.expected[key]} but got {state.get(key)}")
        except RuntimeError as e:
            raise TestCaseError(str(e))