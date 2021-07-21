import rlp

# Compute the given block's top-level RLP encoding list payload length in bytes,
# but excluding all merge mining fields.
#
# This is used by the ledger to compute the merge-mining
# hash of a block to be validated without having to transmit
# the block information twice (or having to save the block information
# elsewhere -- which wouldn't be possible given the lack of memory).
def rlp_mm_payload_size(raw_block_hex):
    return rlp_first_element_list_payload_length(
        remove_mm_fields_if_present(raw_block_hex, leave_btcblock=False, hex=False)
    )

# Exclude a given block's merge mining fields (either leaving or not the
# BTC merge mining header, depending on parameter).
# That is, parse the header, exclude the last one (none) or three (two) fields
# (depending on which mm fields it originally includes) and re-encode it
def remove_mm_fields_if_present(raw_block_hex, leave_btcblock=True, hex=True):
    # Decode
    try:
        block = rlp.decode(bytes.fromhex(raw_block_hex))
    except Exception as e:
        raise ValueError(e)
    # Sanity validation: list length (w/wo/umm_root and/or mm fields)
    num_fields = len(block)
    if num_fields not in [17, 18, 19, 20]:
        raise ValueError("Block header must have 17, 18, 19 or 20 elements, got %d", num_fields)

    # Exclude merge mining fields and re-encode
    if num_fields in [19, 20]:
        block_without_mm_fields = block[:-2] if leave_btcblock else block[:-3]
    else:
        block_without_mm_fields = block if leave_btcblock else block[:-1]

    block_without_mm_fields_rlp = rlp.encode(block_without_mm_fields)

    if not hex:
        return block_without_mm_fields_rlp

    return block_without_mm_fields_rlp.hex()

# Given a bytes object that represents an RLP-encoded list,
# compute the top level list's payload length.
def rlp_first_element_list_payload_length(bs):
    # Infer length L of payload of the first element of the given RLP-encoded bytes
    # First element *MUST* be a list. Validate that.

    # Encoding corresponds to a list, so first byte b will be one of:
    #   1. anything in the range 0xc0..0xf7: L = b - 0xc0
    #   2. anything in the range 0xf8..0xff:
    #     N = b - 0xf7
    #     length follows, encoded as a bigendian integer of length N
    b = bs[0]
    if b >= 0xc0 and b <= 0xf7:
        L = b - 0xc0
    elif b >= 0xf8 and b <= 0xff:
        N = b - 0xf7
        L = 0
        for i in range(N):
            L = (L << 8) | bs[1 + i]
    else:
        raise ValueError("Invalid RLP encoded list - got %s as first byte" % hex(b))
    return L
