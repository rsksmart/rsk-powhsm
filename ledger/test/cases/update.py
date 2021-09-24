from .case import TestCase, TestCaseError


class UpdateAncestor(TestCase):
    @classmethod
    def op_name(cls):
        return "updateAncestor"

    def __init__(self, spec):
        self.blocks = spec["blocks"]
        self.chunk_size = spec.get("chunkSize", len(self.blocks))
        return super().__init__(spec)

    def run(self, dongle, version, debug):
        try:
            debug(f"About to send {len(self.blocks)} blocks")
            offset = 0
            while offset < len(self.blocks):
                chunk = self.blocks[offset:offset + self.chunk_size]

                debug(f"Sending blocks {offset} to {offset+len(chunk)-1} "
                      f"({len(chunk)} blocks)...")
                result = dongle.update_ancestor(chunk, version)
                debug(f"Dongle replied with {result}")

                offset += self.chunk_size

                error_code = (dongle.last_comm_exception.sw
                              if dongle.last_comm_exception is not None else result[1])

                if self.expected is True:
                    if not result[0]:
                        raise TestCaseError(
                            f"Expected success but got failure with code {error_code}")
                    elif error_code != dongle.RESPONSE.UPD_ANCESTOR.OK_TOTAL:
                        raise TestCaseError(
                            f"Expected {dongle.RESPONSE.UPD_ANCESTOR.OK_TOTAL} (success) "
                            f"but got {error_code}")
                else:
                    if result[0]:
                        raise TestCaseError(
                            f"Expected failure but got success with code {error_code}")
                    elif error_code != self.expected:
                        raise TestCaseError(
                            f"Expected failure with code {self.expected} but got failure "
                            f"with code {error_code}")

        except RuntimeError as e:
            raise TestCaseError(str(e))
