# Assorted test util functions

def flatten_list(ls):
    return [item for sublist in ls for item in sublist]

def list_product(ls1, ls2):
    return flatten_list(map(lambda i2: list(map(lambda i1: i1 + i2, ls1)), ls2))

