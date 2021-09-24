import sys

HASH_LENGTH = 32  # Bytes

if len(sys.argv) < 2:
    print("No hash specified")
    sys.exit(1)

hash_arg = sys.argv[1]

offset = 2 if hash_arg.startswith("0x") else 0
hash_plain = hash_arg[offset:]

try:
    int(hash_plain, 16)
    if len(hash_plain) != HASH_LENGTH*2:
        raise ValueError("Expected a %d-byte hexadecimal hash" % HASH_LENGTH)
except Exception as e:
    print("Invalid hash: %s" % str(e))
    sys.exit(1)

# Convert to C-const definition
result_hexes = []
for i in range(HASH_LENGTH):
    result_hexes.append("0x%s" % hash_plain[i*2:i*2+2])

print("{ %s }" % ", ".join(result_hexes))
