import struct

# Parse bip44 path, convert to binary representation [len][int][int][int]...


def bip44tobin(path):
    path = path[2:]
    elements = path.split("/")
    result = b""
    result = result + struct.pack(">B", len(elements))
    for pathElement in elements:
        element = pathElement.split("'")
        if len(element) == 1:
            result = result + struct.pack("<I", int(element[0]))
        else:
            result = result + struct.pack("<I", 0x80000000 | int(element[0]))
    return result


keyIds = [
    "m/44'/0'/0'/0/0",
    "m/44'/1'/0'/0/0",
    "m/44'/137'/0'/0/0",
    "m/44'/137'/0'/0/1",
    "m/44'/1'/0'/0/1",
    "m/44'/1'/0'/0/2",
]

for i in keyIds:
    msg = ""
    path = bip44tobin(i)
    for c in path:
        msg += "\\x%02x" % c
    print(msg)
