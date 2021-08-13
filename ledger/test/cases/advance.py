from .case import TestCase, TestCaseError
import ledger.hsm2dongle

class AdvanceBlockchain(TestCase):
    @classmethod
    def op_name(cls):
        return "advanceBlockchain"

    def __init__(self, spec):
        self.blocks = spec['blocks']
        self.chunk_size = spec.get('chunkSize', len(self.blocks))
        self.partial = spec.get('partial', False)

        # listLength applies to all blocks 
        # (will usually be used to test a single block that fails to validate)
        self.list_length = spec.get('listLength', None)
        if self.list_length:
            if self.list_length.startswith('0x'):
                self.list_length = self.list_length[2:]
            self.list_length = bytes.fromhex(self.list_length)

        return super().__init__(spec)
    
    def _change_rlp_list_length(self, block_hex):
        bs = bytes.fromhex(block_hex)
        bs = bs[:1] + self.list_length + bs[len(self.list_length)+1:]
        return bs.hex()

    def run(self, dongle, version, debug):
        try:
            debug(f"About to send {len(self.blocks)} blocks")
            offset = 0
            while offset < len(self.blocks):
                chunk = self.blocks[offset:offset+self.chunk_size]

                if self.list_length:
                    # Mock RLP payload size and coinbase tx getters
                    old_rlp_mm_payload_size = ledger.hsm2dongle.rlp_mm_payload_size
                    first_block_rlp_mm_payload_size = old_rlp_mm_payload_size(chunk[0])
                    ledger.hsm2dongle.rlp_mm_payload_size = lambda h: first_block_rlp_mm_payload_size
                    old_get_coinbase_txn = ledger.hsm2dongle.get_coinbase_txn
                    first_block_coinbase_txn = old_get_coinbase_txn(chunk[0])
                    ledger.hsm2dongle.get_coinbase_txn = lambda h: first_block_coinbase_txn
                    # Change list lengths
                    chunk = list(map(self._change_rlp_list_length, chunk))

                debug(f"Sending blocks {offset} to {offset+len(chunk)-1} ({len(chunk)} blocks)...")
                result = dongle.advance_blockchain(chunk, version)
                debug(f"Dongle replied with {result}")
                
                offset += self.chunk_size

                if self.list_length:
                    # Change mocks back
                    ledger.hsm2dongle.rlp_mm_payload_size = old_rlp_mm_payload_size
                    ledger.hsm2dongle.get_coinbase_txn = old_get_coinbase_txn
                    
                error_code = dongle.last_comm_exception.sw if dongle.last_comm_exception is not None else result[1]
                if self.expected == True:
                    if not(result[0]):
                        raise TestCaseError(f"Expected success but got failure with code {error_code}")
                    elif offset < len(self.blocks) and error_code != dongle.RESPONSE.ADVANCE.OK_PARTIAL:
                        raise TestCaseError(f"Expected {dongle.RESPONSE.ADVANCE.OK_PARTIAL} (partial success) but got {error_code}")
                    elif offset >= len(self.blocks) and not(self.partial) and error_code != dongle.RESPONSE.ADVANCE.OK_TOTAL:
                        raise TestCaseError(f"Expected {dongle.RESPONSE.ADVANCE.OK_TOTAL} (total success) but got {error_code}")
                    elif offset >= len(self.blocks) and self.partial and error_code != dongle.RESPONSE.ADVANCE.OK_PARTIAL:
                        raise TestCaseError(f"Expected {dongle.RESPONSE.ADVANCE.OK_PARTIAL} (partial success) but got {error_code}")
                else:
                    if result[0]:
                        raise TestCaseError(f"Expected failure but got success with code {error_code}")
                    elif error_code != self.expected:
                        raise TestCaseError(f"Expected failure with code {self.expected} but got failure with code {error_code}")
                
        except RuntimeError as e:
            raise TestCaseError(str(e))