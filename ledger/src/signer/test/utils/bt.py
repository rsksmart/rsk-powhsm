import sys


def translate(file_name):
    with open(file_name, 'r') as f:
        contents = f.read()

    out_name = file_name.replace('.txt', '.rlp')
    with open(out_name, 'wb') as out:
        buffer = []
        for i in range(0, len(contents), 2):
            buffer.append(int(contents[i:i+2], 16))
        out.write(bytes(buffer))


if __name__ == '__main__':
    if len(sys.argv) == 1:
        print(f'Usage: {sys.argv[0]} <block-file>')
        sys.exit(1)
    block_file = sys.argv[1]
    translate(block_file)
    sys.exit(0)
