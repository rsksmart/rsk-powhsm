import sys

BYTES_PER_LINE = 20


def chunks(lst, n):
    """Yield successive n-sized chunks from lst."""
    for i in range(0, len(lst), n):
        yield lst[i:i + n]


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <HEX_STR>")
        sys.exit(1)

    try:
        cbs = list(chunks(bytes.fromhex(sys.argv[1]), BYTES_PER_LINE))
        lines = map(lambda l: "".join(map(lambda b: "\\x" + hex(b)[2:].rjust(2, "0"), l)),
                    cbs)
        lines = map(lambda l: f'"{l}"', lines)
        print("\n".join(lines))
        # print("".join(cv))
    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)
