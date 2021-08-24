import rlp

def rlp_decode_list_of_expected_length(encoded, expected_length, item_description):
    try:
        rlp_items = rlp.decode(encoded)
    except rlp.exceptions.DecodingError as de:
        raise ValueError("Error decoding %s data" % item_description, de)

    if not((type(expected_length) == list and len(rlp_items) in expected_length) or\
        (type(expected_length) == int and len(rlp_items) == expected_length)):
        raise ValueError("Error decoding %s data: invalid list length (expected %s got %d)" % \
                         (item_description, str(expected_length), len(rlp_items)))

    return rlp_items
