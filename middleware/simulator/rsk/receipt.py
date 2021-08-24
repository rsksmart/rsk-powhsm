import sha3
from .utils import rlp_decode_list_of_expected_length
import logging

class RskTransactionReceipt:
    def __init__(self, raw_hex_string):
        self.logger = logging.getLogger("rsktransactionreceipt")
        self.__raw = bytes.fromhex(raw_hex_string)
        self.__decode()

    def __decode(self):
        # An RSK transaction receipt is encoded in RLP.
        # The top-level list has 6 elements, of which its 3rd element corresponds
        # to the receipt logs, which is itself another list.
        self.logger.debug("Decoding from %s", self.__raw.hex())

        rlp_items = rlp_decode_list_of_expected_length(self.__raw, 6, "transaction receipt")

        self.__logs = list(map(lambda raw_log: RskReceiptLog(raw_log), rlp_items[3]))

        self.logger.debug("Hash 0x%s", self.hash)
        self.logger.debug("# of logs: %d", len(self.logs))

    @property
    def logs(self):
        return self.__logs

    @property
    def hash(self):
        return sha3.keccak_256(self.__raw).digest().hex()

    def __str__(self):
        return "<RskTransactionReceipt hash=0x%s>" % self.hash

    def __repr__(self):
        return str(self)

class RskReceiptLog:
    def __init__(self, rlp_items):
        # An RSK transaction receipt log is expected to be given as a list of 3 elements.
        # The first element is the log emitter's address (a byte array)
        # The second element is another list, containing the log's topics
        # (each of the elements is a byte array)
        # The third element is the log's data (a byte array)
        self.logger = logging.getLogger("rskreceiptlog")

        EXPECTED_ITEMS = 3

        if len(rlp_items) != EXPECTED_ITEMS:
            message = "Invalid list length (expected %d got %d)" % (EXPECTED_ITEMS, len(rlp_items))
            self.logger.debug(message)
            raise ValueError("Error building an RskReceiptLog: %s", message)

        self.__address = rlp_items[0].hex()
        self.__topics = list(map(lambda b: b.hex(), rlp_items[1]))
        self.__data = rlp_items[2].hex()

        self.logger.debug("Address 0x%s", self.address)
        self.logger.debug("Topics %s", list(map(lambda t: "0x%s" % t, self.topics)))
        self.logger.debug("Data 0x%s", self.data)

    @property
    def address(self):
        return self.__address

    @property
    def topics(self):
        return self.__topics

    @property
    def signature(self):
        # In solidity-emitted events, the first topic corresponds to
        # the event signature. If no topics are present, then
        # there's no signature.
        if len(self.__topics) == 0:
            return None

        return self.__topics[0]

    @property
    def data(self):
        return self.__data

    def __str__(self):
        return "<RskReceiptLog signature=0x%s>" % self.signature

    def __repr__(self):
        return str(self)
