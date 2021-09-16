import re


def bitwise_and_bytes(bs1, bs2):
    return bytes(x & y for (x, y) in zip(bs1, bs2))


def assert_int(obj, key):
    _assert_key_present(obj, key)
    if type(obj[key]) != int:
        raise ValueError("%s is not an integer" % _name_from_key(key))


def assert_bool(obj, key):
    _assert_key_present(obj, key)
    if type(obj[key]) != bool:
        raise ValueError("%s is not a boolean value" % _name_from_key(key))


def assert_dict(obj, key):
    _assert_key_present(obj, key)
    if type(obj[key]) != dict:
        raise ValueError("%s is not an object" % _name_from_key(key))


def assert_hex_hash(obj, key):
    _assert_key_present(obj, key)
    if not is_hex_string_of_length(obj[key], 32):
        raise ValueError(
            "%s is not a hexadecimal value representing a block hash"
            % _name_from_key(key)
        )


def _assert_keys_present(obj, keys):
    for key in keys:
        _assert_key_present(obj, key)


def _assert_key_present(obj, key):
    if key not in obj:
        raise ValueError("%s not present" % _name_from_key(key))


def _name_from_key(key):
    name = key.split("_")
    name[0] = name[0].capitalize()
    name = " ".join(name)
    return name


def is_hex_string_of_length(value, num_bytes, allow_prefix=False):
    try:
        if allow_prefix and value.startswith("0x"):
            value = value[2:]
        bs = bytes.fromhex(value)

        return len(bs) == num_bytes
    except Exception:
        return False


def is_nonempty_hex_string(value):
    try:
        bs = bytes.fromhex(value)
        return len(bs) > 0
    except Exception:
        return False


def hex_or_decimal_string_to_int(value):
    if value.startswith("0x"):
        return int(value, 16)

    return int(value, 10)


def normalize_hex_string(value):
    if value.startswith("0x"):
        return value[2:]

    return value


# Utility functions to parse and use a list slice
# from a string (in the python fashion [nn:mm])
_SLICE_REGEXP = re.compile("^(-?\\d*):(-?\\d*)$", re.ASCII)


def is_slice_str(s):
    return _SLICE_REGEXP.match(s) is not None


def slice_from_str(s):
    m = _SLICE_REGEXP.match(s)

    if m is None:
        raise ValueError(f'Invalid slice str "{s}"')

    gs = m.groups()
    start = 0 if gs[0] == "" else int(gs[0])
    stop = None if gs[1] == "" else int(gs[1])

    return slice(start, stop, 1)
