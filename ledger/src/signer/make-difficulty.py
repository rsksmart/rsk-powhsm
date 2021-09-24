import sys

DIGIT_SIZE = 4  # In bytes
NUM_DIGITS = 9
MAX_BYTES = NUM_DIGITS*DIGIT_SIZE  # Difficulty length is in terms of number of ints

if len(sys.argv) < 2:
    print("No difficulty specified")
    sys.exit(1)

dif_str = sys.argv[1]

base = 10
offset = 0
if dif_str.startswith("0x"):
    base = 16
    offset = 2

try:
    dif = int(sys.argv[1][offset:], base)
except Exception as e:
    print("Invalid hex difficulty: %s" % str(e))
    sys.exit(1)

num_bytes = -(-dif.bit_length()//8)

if num_bytes > MAX_BYTES:
    print("Difficulty too big (max %d bytes but got %d)" % (MAX_BYTES, num_bytes))

# Convert to C-const definition in the bigint representation used by the signer
# (ints are big-endian, but between different ints, little-endianess is used)
result_ints = []
remaining = dif
digit_bits = DIGIT_SIZE*8
mask = (1 << digit_bits)-1
for i in range(NUM_DIGITS):
    result_ints.append(int(remaining & mask))
    remaining = remaining >> digit_bits

print("{ %s }" % ", ".join(list(map(hex, result_ints))))
