from .case import TestCase, TestCaseError


class ResetAdvanceBlockchain(TestCase):
    @classmethod
    def op_name(cls):
        return "resetAdvanceBlockchain"

    def __init__(self, spec):
        return super().__init__(spec)

    def run(self, dongle, version, debug):
        try:
            dongle.reset_advance_blockchain()
        except RuntimeError as e:
            raise TestCaseError(str(e))
