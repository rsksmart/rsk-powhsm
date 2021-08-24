import sha3
import math
import logging

class RskTrieError(RuntimeError):
    pass

# Represents a (binary) trie, of the kind
# used in RSK. Each trie consists of a mandatory key,
# a shared prefix (potentially empty),
# a parent (optional), a value (optional) and
# left and right subtries (also optional).
class RskTrie:
    ENCODING_VERSION = 0b01
    MAX_EMBEDDED_SIZE = 40

    # Given a list of encoded nodes that start with the leaf node
    # and traverse to the root (i.e., a partial binary tree)
    # this generates a Trie instance representing that structure.
    @staticmethod
    def from_proof(merkle_proof):
        if type(merkle_proof) != list or len(merkle_proof) == 0:
            raise RskTrieError("Empty or invalid encoded merkle proof given")

        parent_node = None
        for encoded_node in reversed(merkle_proof):
            node = RskTrie(encoded_node, parent_node)
            parent_node = node

        return node.get_root()


    def __init__(self, encoded, parent):
        self.logger = logging.getLogger("rsktrie")
        self._encoded = encoded
        self._parent = parent

        # Hexadecimal string?
        # Get bytes from hexadecimal value
        if type(self._encoded) == str:
            self._encoded = bytes.fromhex(self._encoded)

        # Encoded should be bytes now
        if type(self._encoded) != bytes:
            raise RskTrieError("Cannot decode type %s. Must provide either bytes or hex-encoded string" % type(self._encoded))

        # Calculate hash
        self._hash = sha3.keccak_256(self._encoded).digest().hex()

        # Decode
        self.__decode()

        # After decoding, try to match this node against either the left or right
        # nodes from its parent (if any)
        if self.parent is not None:
            self.logger.debug("Linking %s to parent %s", self, self.parent)
            self.parent.link_child(self)

    def link_child(self, child):
        # Is the child our left node?
        if child.hash == self.left.hash:
            self._left = child
            return

        # Is the child our right node?
        if child.hash == self.right.hash:
            self._right = child
            return

        # No match!
        raise RskTrieError("%s is neither the left or right node of %s" % (child, self))

    def __decode(self):
        bs = self._encoded

        if len(bs) == 0:
            raise RskTrieError("Cannot deserialize a trie from a zero-length message")

        # Parse flags
        flags = bs[0]
        node_version           = (flags & 0b11000000) >> 6
        has_long_value         = (flags & 0b00100000) > 0
        shared_prefix_present  = (flags & 0b00010000) > 0
        node_present_left      = (flags & 0b00001000) > 0
        node_present_right     = (flags & 0b00000100) > 0
        node_is_embedded_left  = (flags & 0b00000010) > 0
        node_is_embedded_right = (flags & 0b00000001) > 0
        bs = bs[1:]

        # Only supporting a specific encoding version
        if node_version != self.ENCODING_VERSION:
            raise RskTrieError("Version %d not supported" % node_version)

        # Shared prefix
        self._shared_prefix = None
        if shared_prefix_present:
            try:
                (self._shared_prefix, read_length) = _read_shared_prefix(bs)
            except ValueError as e:
                raise RskTrieError("Can't read shared prefix", e)
            bs = bs[read_length:]

        # Left node
        self._left = None
        if node_present_left:
            (self._left, read_length) = self.__read_node(bs, node_is_embedded_left)
            bs = bs[read_length:]

        # Right node
        self._right = None
        if node_present_right:
            (self._right, read_length) = self.__read_node(bs, node_is_embedded_right)
            bs = bs[read_length:]

        # Children size
        if node_present_left or node_present_right:
            try:
                (children_size, read_length) = _read_var_int(bs)
            except ValueError as e:
                raise RskTrieError("Can't read children size")
            bs = bs[read_length:]

        # Value
        self._has_value = False
        self._value = None
        self._value_hash = None
        self._value_length = 0

        if has_long_value:
            self._has_value = True
            self._value = None
            self._value_hash = bs[0:32].hex()
            bs = bs[32:]
            try:
                (self._value_length, read_length) = _read_uint24(bs)
            except ValueError as e:
                raise RskTrieError("Can't read value length", e)
            bs = bs[read_length:]
            # There should be no remaining bytes to read
            if len(bs) > 0:
                raise RskTrieError("The message had more data than expected")
        elif len(bs) > 0:
            self._has_value = True
            self._value = bs[:].hex()
            self._value_hash = sha3.keccak_256(bytes.fromhex(self._value)).digest().hex()
            self._value_length = len(bs)

        self.logger.debug("Parsed encoded node: %s", self.encoded)
        self.logger.debug("Node version: %d", node_version)
        self.logger.debug("Has long value: %s", has_long_value)
        self.logger.debug("Shared prefix present: %s", shared_prefix_present)
        self.logger.debug("Node present left: %s", node_present_left)
        self.logger.debug("Node embedded left: %s", node_is_embedded_left)
        self.logger.debug("Node present right: %s", node_present_right)
        self.logger.debug("Node embedded right: %s", node_is_embedded_right)
        self.logger.debug("Shared prefix: %s", self.shared_prefix)
        self.logger.debug("Left: %s", self.left)
        self.logger.debug("Right: %s", self.right)
        self.logger.debug("Value: %s", self.value)
        self.logger.debug("Value length: %d", self.value_length)
        self.logger.debug("Value hash: %s", self.value_hash)

    # Reads a node, whether embedded
    # or not (i.e., just the hash of the node)
    # In every case we're interested in calculating (or just reading)
    # the node hash. That is, we don't recursively parse the embedded node.
    # That is enough for our use case since we always have the whole tree
    # available.
    def __read_node(self, bs, embedded):
        if len(bs) == 0:
            raise RskTrieError("Can't read node from empty bytes")

        if not embedded:
            if len(bs) < 32:
                raise RskTrieError("Node hash size smaller than 32 bytes")
            read_bytes = 32
            hash = bs[0:32].hex()
        else:
            size = min(self.MAX_EMBEDDED_SIZE, bs[0], len(bs)-1)
            hash = sha3.keccak_256(bs[1:1+size]).digest().hex()
            read_bytes = size+1

        return (RskTrieHash(hash), read_bytes)

    @property
    def parent(self):
        return self._parent

    @property
    def shared_prefix(self):
        return self._shared_prefix

    @property
    def has_value(self):
        return self._has_value

    @property
    def value(self):
        if self._value is not None:
            return self._value

        return None

    @property
    def value_hash(self):
        if self.has_value:
            return self._value_hash

        return None

    @property
    def value_length(self):
        return self._value_length

    @property
    def is_leaf(self):
        return self._left is None and self._right is None

    @property
    def left(self):
        return self._left

    @property
    def right(self):
        return self._right

    @property
    def encoded(self):
        return self._encoded.hex()

    @property
    def hash(self):
        return self._hash

    # Get the root of the trie
    def get_root(self):
        current = self
        while current.parent is not None:
            current = current.parent
        return current

    # Find the first full leaf (i.e., not a hash)
    # from this node and return it
    # This is useful in the case in which the trie has only
    # got one leaf (e.g., partial merkle proof)
    def get_first_leaf(self):
        current = self
        while not current.is_leaf:
            if type(current.left) == RskTrie:
                current = current.left
            elif type(current.right) == RskTrie:
                current = current.right
            else:
                raise RskTrieError("Cannot find a leaf. Missing either full left or right trie node")
        return current

    def __str__(self):
        return "RskTrie <0x%s>" % self.hash

    def __repr__(self):
        return str(self)

class RskTrieHash:
    def __init__(self, hash):
        self._hash = hash

    @property
    def hash(self):
        return self._hash

    def __str__(self):
        return "RskTrieHash <0x%s>" % self.hash

    def __repr__(self):
        return str(self)

# *** Utility functions *** #

# Reads a variable-length integer
# Returns a tuple (V, L) where V is the read
# integer and L the length in bytes of what
# was read
def _read_var_int(bs):
    if len(bs) == 0:
        raise ValueError("Not enough bytes to read var int")

    first_byte = bs[0]

    if first_byte < 0xfd:
        value = int(first_byte)
        read_bytes = 1
    elif first_byte == 0xfd:
        if len(bs) < 3:
            raise ValueError("Not enough bytes to read var int")
        value = int(bs[1]) + (int(bs[2]) << 8)
        read_bytes = 3
    elif first_byte == 0xfe:
        if len(bs) < 5:
            raise ValueError("Not enough bytes to read var int")
        value = int(bs[1]) + (int(bs[2]) << 8) + (int(bs[3]) << 16) + (int(bs[4]) << 24)
        read_bytes = 5
    else:
        if len(bs) < 9:
            raise ValueError("Not enough bytes to read var int")
        value = int(bs[1]      ) + (int(bs[2]) << 8 ) + (int(bs[3]) << 16) + (int(bs[4]) << 24) + \
                int(bs[5] << 32) + (int(bs[6]) << 40) + (int(bs[7]) << 48) + (int(bs[8]) << 56)
        read_bytes = 9

    return (value, read_bytes)

# Reads an unsigned 24-bit integer
# stored in big-endian
def _read_uint24(bs):
    if len(bs) < 3:
        raise ValueError("Not enough bytes to read uint24")
    value = int(bs[0] << 16) + (int(bs[1]) << 8) + int(bs[2])
    return (value, 3)

# Reads a shared prefix serialized as per
# this RSKIP: https://github.com/rsksmart/RSKIPs/blob/master/IPs/RSKIP107.md
# This includes the shared path prefix and its length compression
def _read_shared_prefix(bs):
    if len(bs) == 0:
        raise ValueError("Cannot read shared prefix from empty bytes")

    # Length
    first_byte = bs[0]
    offset = 1

    if first_byte >= 0 and first_byte <= 31:
        length = first_byte + 1
    elif first_byte >= 32 and first_byte <= 254:
        length = first_byte + 128
    else:
        (length, read_length) = _read_var_int(bs[1:])
        offset += read_length

    # Actual path
    shared_prefix = []
    size_bytes = 0

    if length > 0:
        size_bytes = length//8 + 1
        if len(bs[offset:]) < size_bytes:
            raise ValueError("Not enough bytes to read in shared prefix")
        encoded_path = bs[offset:offset+size_bytes]
        # First bit is most significant
        for index in range(0, length):
            byte = index//8
            bit = 7 - index
            shared_prefix.append((encoded_path[byte] & (1 << bit)) >> bit)

    return (shared_prefix, offset+size_bytes)
