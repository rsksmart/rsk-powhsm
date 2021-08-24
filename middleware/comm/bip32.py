import struct
import logging

_logger = logging.getLogger("bip44")

class BIP32Element:
    def __init__(self, spec):
        if type(spec) != str or len(spec) == 0:
            message = "BIP32Element spec must be a nonempty string"
            _logger.debug(message)
            raise ValueError(message)

        index = 0
        sindex = spec
        if spec[-1] == "'":
            index = (1<<31)
            sindex = spec[:-1]

        if not str.isdecimal(sindex):
            message = "BIP32Element must be a decimal number optionally followed by a single quote (got %s)" % sindex
            _logger.debug(message)
            raise ValueError(message)

        val = int(sindex)
        if val >= (1<<31):
            message = "BIP32Element must be specified with an integer between 0 and 2^31"
            _logger.debug(message)
            raise ValueError(message)

        index += val

        if index < 0 or index > (1<<32):
            message = "Invalid index for BIP32 element"
            _logger.debug(message)
            raise ValueError(message)

        self._index = index

    @property
    def is_hardened(self):
        return self._index >= (1<<31)

    @property
    def spec_index(self):
        if self.is_hardened:
            return self._index - (1<<31)
        return self._index

    @property
    def index(self):
        return self._index

    def __str__(self):
        return "%d%s" % (self.spec_index, "'" if self.is_hardened else "")

    def __repr__(self):
        return "<BIP32Element \"%s\">" % str(self)

class BIP32Path:
    def __init__(self, spec):
        if type(spec) != str or len(spec) == 0:
            message = "BIP32Path spec must be a nonempty string"
            _logger.debug(message)
            raise ValueError(message)

        if spec[:2] != "m/":
            message = "BIP32Path spec must start with 'm/', instead got %s" % spec
            _logger.debug(message)
            raise ValueError(message)

        self._elements = list(map(lambda s: BIP32Element(s), spec[2:].split('/')))

        if len(self._elements) != 5:
            message = "BIP32Path spec must have exactly 5 elements, got %d" % len(self._elements)
            _logger.debug(message)
            raise ValueError(message)

    @property
    def elements(self):
        return self._elements

    def to_binary(self):
        binary = struct.pack('<B', len(self._elements))
        for element in self.elements:
            binary += struct.pack('<I', element.index)
        return binary

    def __str__(self):
        return 'm/%s' % "/".join(map(lambda e: str(e), self._elements))

    def __repr__(self):
        return "<BIP32Path \"%s\">" % str(self)

    def __eq__(self, other):
        return str(self) == str(other)
