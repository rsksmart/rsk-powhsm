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


import struct
import re


class CStruct:
    MAP = {
        "uint8_t": ["B", "s"],
        "uint16_t": "H",
        "uint32_t": "I",
        "uint64_t": "Q",
    }
    SPEC = None
    TYPENAME = None

    @classmethod
    def _spec(cls, little=True):
        if cls.SPEC is None or little not in cls.SPEC:
            fmt = "<" if little else ">"
            atrmap = {}
            names = []
            types = []
            index = 0
            typename = None
            for line in cls.__doc__.split("\n")[1:]:
                line = re.sub(r"\s+", " ", line.strip())
                if line == "":
                    continue
                if typename is None:
                    typename = line
                    continue
                tspec = line.split(" ")

                length = "" if len(tspec) < 3 else str(int(tspec[2].strip(), 10))

                typ = tspec[0].strip()
                actual_type = None
                derived_type = None
                if typ not in cls.MAP.keys():
                    for kls in cls.__base__.__subclasses__():
                        if cls != kls:
                            if typ == kls._typename():
                                actual_type = kls
                                derived_type = kls
                    if derived_type is None:
                        raise ValueError(f"Invalid type: {typ}")
                else:
                    actual_type = cls.MAP[typ]

                if length != "" and not isinstance(actual_type, list):
                    raise ValueError(f"Invalid type spec: {line}")

                name = tspec[1].strip()

                if isinstance(actual_type, list):
                    actual_type = actual_type[0] if length == "" else actual_type[1]
                elif not isinstance(actual_type, str) and \
                        issubclass(actual_type, cls.__base__):
                    actual_type = str(actual_type.get_bytelength(little)) + "s"

                fmt += length + actual_type
                names.append(name)
                types.append(derived_type)
                atrmap[name] = index
                index += 1
            if cls.SPEC is None:
                cls.SPEC = {}
            cls.SPEC[little] = (struct.Struct(fmt), atrmap, names, types, typename)

        return cls.SPEC[little]

    @classmethod
    def _struct(cls, little=True):
        return cls._spec(little)[0]

    @classmethod
    def _atrmap(cls, little=True):
        return cls._spec(little)[1]

    @classmethod
    def _names(cls, little=True):
        return cls._spec(little)[2]

    @classmethod
    def _types(cls, little=True):
        return cls._spec(little)[3]

    @classmethod
    def _typename(cls):
        if cls.TYPENAME is None:
            for line in cls.__doc__.split("\n"):
                line = re.sub(r"\s+", " ", line.strip())
                if line == "":
                    continue
                cls.TYPENAME = line
                break

        return cls.TYPENAME

    @classmethod
    def get_bytelength(cls, little=True):
        return cls._struct(little).size

    def __init__(self, value, offset=0, little=True):
        self._offset = offset
        self._little = little
        self._raw_value = value

        try:
            self._parsed = list(self._struct(little).unpack_from(value, offset))
        except Exception as e:
            raise ValueError(f"While parsing: {e}")

        for index, derived_type in enumerate(self._types(little)):
            if derived_type is not None:
                self._parsed[index] = derived_type(self._parsed[index], little=little)

    def _value(self, name):
        amap = self._atrmap(self._little)
        if name in amap:
            return self._parsed[amap[name]]
        raise NameError(f"Property {name} does not exist")

    def __getattr__(self, name):
        return self._value(name)

    def get_raw_data(self):
        return self._raw_value[
            self._offset:self._offset+self.get_bytelength(self._little)]

    def to_dict(self):
        result = {}
        for name in self._names(self._little):
            value = self._value(name)
            if isinstance(value, bytes):
                value = value.hex()
            result[name] = value.to_dict() if isinstance(value, CStruct) else value
        return result

    def __repr__(self):
        return f"<{self.__class__.__name__}: {self.to_dict()}>"
