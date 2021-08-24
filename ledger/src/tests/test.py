import binascii
import click
import json
import os
import rlp
import struct
import sys

from secp256k1 import PublicKey
from enum import IntEnum, auto
from operator import setitem
from ledgerblue.comm import getDongle
from ledgerblue.commTCP import getDongle as getDongleTCP
from ledgerblue.commException import CommException


# Utilities to send colored output to a TTY
def _ansi_log(msg, cat, color):
    print(f"\033[{color}m", f"[{cat}]", msg, "\033[0m")

def info(msg):
    _ansi_log(msg, cat="INFO", color=33)

def succ(msg):
    _ansi_log(msg, cat="INFO", color=32)

def error(msg):
    _ansi_log(msg, cat="ERROR", color=31)

# ------------------------------------------------------------------------
# Convenience protocol constants. These must be kepy in synch with
# the blockchain protocol specifications.
# ------------------------------------------------------------------------
CLA = 0x80
TXLEN = 3

# Exit signer app
INS_EXIT = 0xff

#Common instructions
RSK_IS_ONBOARD = 0x06
RSK_MODE_CMD = 0x43
RSK_MODE_APP = 0x03
RSK_MODE_BOOTLOADER=0x02
INS_GET_PUBLIC_KEY = 0x04

#Receipt Sign constants
INS_SIGN = 0x02
P1_PATH=0x01
P1_BTC=0x02
P1_RECEIPT=0x04
P1_MERKLEPROOF=0x08
P1_LAST=0x80
P1_SUCCESS=0x81

# Get blockchain state
INS_GET_STATE = 0x20
OP_GET_IDLE = 0x00
OP_GET_HASH = 0x01
OP_GET_DIFF = 0x02
OP_GET_FLAGS = 0x03

# Reset blockchain state
INS_RESET_STATE = 0x21
OP_RESET_INIT = 0x01
OP_RESET_DONE = 0x02

# Advance blockchain
INS_ADVANCE = 0x10
OP_ADVANCE_IDLE = 0x01
OP_ADVANCE_INIT = 0x02
OP_ADVANCE_HEADER_META = 0x03
OP_ADVANCE_HEADER_CHUNK = 0x04
OP_ADVANCE_PARTIAL = 0x05
OP_ADVANCE_SUCCESS = 0x06

# Update ancestor
INS_UPD_ANCESTOR = 0x30
OP_UPD_ANCESTOR_IDLE = 0x01
OP_UPD_ANCESTOR_INIT = 0x02
OP_UPD_ANCESTOR_HEADER_META = 0x03
OP_UPD_ANCESTOR_HEADER_CHUNK = 0x04
OP_UPD_ANCESTOR_SUCCESS = 0x05


class Error(IntEnum):
    APP_NOT_STARTED = 0x6e00
    PROT_INVALID = 0x6b87
    RLP_INVALID = auto()
    BLOCK_TOO_OLD = auto()
    BLOCK_TOO_SHORT = auto()
    PARENT_HASH_INVALID = auto()
    RECEIPT_ROOT_INVALID = auto()
    BLOCK_NUM_INVALID = auto()
    BLOCK_DIFF_INVALID = auto()
    UMM_ROOT_INVALID = auto()
    BTC_HEADER_INVALID = auto()
    MERKLE_PROOF_INVALID = auto()
    BTC_CB_TXN_INVALID = auto()
    MM_RLP_LEN_MISMATCH = auto()
    BTC_DIFF_MISMATCH = auto()
    MERKLE_PROOF_MISMATCH = auto()
    MM_HASH_MISMATCH = auto()
    MERKLE_PROOF_OVERFLOW = auto()
    CB_TXN_OVERFLOW = auto()
    BUFFER_OVERFLOW = auto()
    CHAIN_MISMATCH = auto()
    TOTAL_DIFF_OVERFLOW = auto()
    ANCESTOR_TIP_MISMATCH = auto()

_errors = {
    Error.APP_NOT_STARTED: "Signer app has not been started",
    Error.PROT_INVALID: "Invalid or unexpected message",
    Error.RLP_INVALID: "Invalid RLP",
    Error.BLOCK_TOO_OLD: "Block too old",
    Error.BLOCK_TOO_SHORT: "Block too short",
    Error.PARENT_HASH_INVALID: "Invalid parent hash",
    Error.RECEIPT_ROOT_INVALID: "Invalid receipt root",
    Error.BLOCK_NUM_INVALID: "Block number longer than 4 bytes",
    Error.BLOCK_DIFF_INVALID: "Block difficulty longer than 32 bytes",
    Error.UMM_ROOT_INVALID: "Invalid UMM root",
    Error.BTC_HEADER_INVALID: "Invalid BTC merge mining header",
    Error.MERKLE_PROOF_INVALID: "Invalid Merkle proof",
    Error.BTC_CB_TXN_INVALID: "Invalid coinbase transaction",
    Error.MM_RLP_LEN_MISMATCH: "Merge mining RLP lengths don't match",
    Error.BTC_DIFF_MISMATCH: "BTC mm header doesn't match block difficulty",
    Error.MERKLE_PROOF_MISMATCH: "Merkle proof doesn't match merkle root",
    Error.MM_HASH_MISMATCH: "Merge mining hashes don't match",
    Error.MERKLE_PROOF_OVERFLOW: "Merkle proof exceeds maximum size",
    Error.CB_TXN_OVERFLOW: "Coinbase transactione exceeds maximum size",
    Error.BUFFER_OVERFLOW: "Work area buffer overflow",
    Error.CHAIN_MISMATCH: "Block is not parent of previous block",
    Error.TOTAL_DIFF_OVERFLOW: "Total difficulty overflow",
    Error.ANCESTOR_TIP_MISMATCH: "Ancestor tip mismatch"
}


# ------------------------------------------------------------------------
# Interact with a Ledger
# ------------------------------------------------------------------------
def connect(args):
    if args['use_proxy']:
        return getDongleTCP(server=args['proxy_addr'], port=args['proxy_port'], debug=True)
    else:
        return getDongle(debug=True)

def send(dongle, ins, op, *payload):
    try:
        if (not op):
            b = bytearray([CLA, ins])
        else:
            b = bytearray([CLA, ins, op])
        for p in payload:
            b.extend(p)
        return dongle.exchange(b)
    except CommException as e:
        msg = _errors.get(e.sw, "Unknown error - missing entry in _errors table?")
        error(f"\U0001F4A5 Invalid status {hex(e.sw)}: {msg}")
        sys.exit(1)


# ------------------------------------------------------------------------
# Infer Block metadata from is RLP serializarion
# ------------------------------------------------------------------------
def block_metadata(network, block_rlp):
    block = rlp.decode(block_rlp)
    return len(block_rlp), rlp_mm_payload_size(block)

# Compute the length that *would* have the RLP encoding of the given
# block, *if* the last three fields (BTC MM header, MM Merkle proof,
# and BTC MM coinbase txn) where excluded form the block.
#
# This is used by the ledger to efficiently compute the merge-mining
# hash of a block to be validated.
def rlp_mm_payload_size(block):
    # Fields to exclude:
    #  1. BTC MM header (decoded[-3])
    #  2. MM Merkle Proof (decoded[-2])
    #  3. BTC MM coinbase txn (decoded[-1])
    if len(block) >= 19:
        block_without_mm_fields = block[:-3]
    else:
        block_without_mm_fields = block[:-1]
    block_without_mm_fields_rlp = rlp.encode(block_without_mm_fields)

    # Infer length L of RLP payload of block without MM fields.
    # Encoding corresponds to a list, so first byte b will be one of:
    #   1. anything in the range 0xc0..0xf7: L = b - 0xc0
    #   2. anything in the range 0xf8..0xff:
    #     N = b - 0xf7
    #     length follows, encoded as a bigendian integer of length N
    b = block_without_mm_fields_rlp[0]
    if b >= 0xc0 and b <= 0xf7:
        L = b - 0xc0
    elif b >= 0xf8 and b <= 0xff:
        N = b - 0xf7
        L = 0
        for i in range(N):
            L = (L << 8) | block_without_mm_fields_rlp[1 + i]
    else:
        assert False, "Invalid RLP encoding for block without MM fields"
    return L


# ------------------------------------------------------------------------
# Advance blockchain for all blocks in a given file.
# ------------------------------------------------------------------------
def advance_blockchain(args, blocks_file, network):
    with open(blocks_file, 'r') as f:
        blocks = [bytes.fromhex(b) for b in json.load(f)]

    dongle = connect(args)

    # 1. Send OP_ADVANCE_INIT
    n_blocks = len(blocks)
    info(f"Initialize advance blockchain for {n_blocks} {'block' if n_blocks == 1 else 'blocks'}")
    r = send(dongle, INS_ADVANCE, OP_ADVANCE_INIT, struct.pack('>L', n_blocks))
    assert r[2] == OP_ADVANCE_HEADER_META, f"Unexpected response: {r[2]}"

    for n, block_rlp in enumerate(blocks):
        block_size, mm_payload_len = block_metadata(network, block_rlp)

        # 2. Send OP_ADVANCE_HEADER_META for current block
        info(f"\U0001F381 Send metadata for block #{n}")
        r = send(dongle, INS_ADVANCE, OP_ADVANCE_HEADER_META, struct.pack('>H', mm_payload_len))
        assert r[2] == OP_ADVANCE_HEADER_CHUNK, f"Unexpected response: {r[2]}"

        # 3. Send chunks for current block until ledger asks for next one
        total_read = 0
        while r[2] == OP_ADVANCE_HEADER_CHUNK:
            chunk_size = r[3]
            buf = block_rlp[total_read:total_read + chunk_size]
            total_read += chunk_size
            info(f'Send chunk [{total_read - len(buf):04d}-{total_read - 1:04d}] (block size = {block_size:04d})')
            r = send(dongle, INS_ADVANCE, OP_ADVANCE_HEADER_CHUNK, buf)

        # Ledger asked for next block
        if r[2] == OP_ADVANCE_HEADER_META:
            if total_read == block_size:
                info(f'Consumed block #{n}')
            else:
                info(f'Skipped block #{n}')
            continue

        # Ledger advanced blockchain
        if r[2] == OP_ADVANCE_SUCCESS:
            succ("Blockchain fully advanced! \U0001F389")
            return

        # Ledger partially advanced blockchain
        if r[2] == OP_ADVANCE_PARTIAL:
            assert n + 1 == len(blocks), "Partial success before trying all blocks"
            succ("Blockchain partially advanced! \U0001F389")
            return


# ------------------------------------------------------------------------
# Update ancestor block
# ------------------------------------------------------------------------
def update_ancestor(args, blocks_file, network):
    with open(blocks_file, 'r') as f:
        blocks = [bytes.fromhex(b) for b in json.load(f)]

    dongle = connect(args)

    # 1. Send OP_UPD_ANCESTOR_INIT
    n_blocks = len(blocks)
    info(f"Initialize update ancestor for {n_blocks} {'block' if n_blocks == 1 else 'blocks'}")
    r = send(dongle, INS_UPD_ANCESTOR, OP_UPD_ANCESTOR_INIT, struct.pack('>L', n_blocks))
    assert r[2] == OP_UPD_ANCESTOR_HEADER_META, f"Unexpected response: {r[2]}"

    for n, block_rlp in enumerate(blocks):
        block_size, mm_payload_len = block_metadata(network, block_rlp)

        # Don't send merkle proof and cb txn for some blocks
        if n % 2 == 0 and len(rlp.decode(block_rlp)) >= 19:
            block_rlp = rlp.encode(rlp.decode(block_rlp)[:-2])

        # 2. Send OP_UPD_ANCESTOR_HEADER_META for current block
        info(f"\U0001F381 Send metadata for block #{n}")
        r = send(dongle, INS_UPD_ANCESTOR, OP_UPD_ANCESTOR_HEADER_META, struct.pack('>H', mm_payload_len))
        assert r[2] == OP_UPD_ANCESTOR_HEADER_CHUNK, f"Unexpected response: {r[2]}"

        # 3. Send chunks for current block until ledger asks for next one
        total_read = 0
        while r[2] == OP_UPD_ANCESTOR_HEADER_CHUNK:
            chunk_size = r[3]
            buf = block_rlp[total_read:total_read + chunk_size]
            total_read += chunk_size
            info(f'Send chunk [{total_read - len(buf):04d}-{total_read - 1:04d}] (block size = {block_size:04d})')
            r = send(dongle, INS_UPD_ANCESTOR, OP_UPD_ANCESTOR_HEADER_CHUNK, buf)

        # Ledger asked for next block
        if r[2] == OP_UPD_ANCESTOR_HEADER_META:
            info(f'Moving to block #{n+1}')
            continue

        # Ledger successfully updated ancestor
        if r[2] == OP_UPD_ANCESTOR_SUCCESS:
            succ("Successfully updated ancestor! \U0001F389")
            return

# ------------------------------------------------------------------------
# Get/Reset blockchain state
# ------------------------------------------------------------------------

class Hashes(IntEnum):
    BEST_BLOCK = 0x01
    NEWEST_VALID_BLOCK = 0x02
    ANCESTOR_BLOCK = 0x03
    ANCESTOR_RECEIPT_ROOT = 0x05
    U_BEST_BLOCK = 0x81
    U_NEWEST_VALID_BLOCK = 0x82
    U_NEXT_EXPECTED_BLOCK = 0x84

_hash_transformers = {
    Hashes.BEST_BLOCK: lambda st, h: setitem(st, 'best_block', h),
    Hashes.NEWEST_VALID_BLOCK: lambda st, h: setitem(st, 'newest_valid_block', h),
    Hashes.ANCESTOR_BLOCK: lambda st, h: setitem(st, 'ancestor_block', h),
    Hashes.ANCESTOR_RECEIPT_ROOT: lambda st, h: setitem(st, 'ancestor_receipt_root', h),
    Hashes.U_BEST_BLOCK: lambda st, h: setitem(st['updating'], 'best_block', h),
    Hashes.U_NEWEST_VALID_BLOCK: lambda st, h: setitem(st['updating'], 'newest_valid_block', h),
    Hashes.U_NEXT_EXPECTED_BLOCK: lambda st, h: setitem(st['updating'], 'next_expected_block', h),
}

def get_blockchain_state(args):
    bc_state = {'updating': {}}
    dongle = connect(args)

    # Get hashes
    for h in Hashes.__members__.values():
        r = send(dongle, INS_GET_STATE, OP_GET_HASH, struct.pack('B', h.value))
        assert(len(r) == 36)
        assert(r[2] == OP_GET_HASH)
        assert(r[3] == h.value)
        _hash_transformers[h](bc_state, r[4:].hex())

    # Get difficulty
    r = send(dongle, INS_GET_STATE, OP_GET_DIFF)
    assert(r[2] == OP_GET_DIFF)
    bc_state['updating']['total_difficulty'] = int.from_bytes(r[3:], byteorder='big', signed=False)

    # Get flags
    r = send(dongle, INS_GET_STATE, OP_GET_FLAGS)
    assert(len(r) == 6)
    assert(r[2] == OP_GET_FLAGS)
    bc_state['updating']['in_progress'] = bool(r[3])
    bc_state['updating']['already_validated'] = bool(r[4])
    bc_state['updating']['found_best_block'] = bool(r[5])
    return bc_state

def reset_blockchain_state(args):
    dongle = connect(args)
    r = send(dongle, INS_RESET_STATE, OP_RESET_INIT)
    assert(len(r) == 3)
    assert(r[2] == OP_RESET_DONE)

# ------------------------------------------------------------------------
# Parse and sign receipt
# ------------------------------------------------------------------------


## Parse bip44 path, convert to binary representation [len][int][int][int]...
def bip44tobin(path):
    path=path[2:]
    elements = path.split('/')
    #result=""
    result = struct.pack('>B', len(elements))
    for pathElement in elements:
        element = pathElement.split('\'')
        if len(element) == 1:
            result = result + struct.pack("<I", int(element[0]))
        else:
            result = result + struct.pack("<I", 0x80000000 | int(element[0]))
    return result

## Sign transaction and check receipt PoC
def signTX(dongle, keyId,BTCTran,receipt,MP_tree,input_index):
        argToSend=P1_PATH
        receiptPtr=0
        TXPtr=0
        MPPtr=0
        BTCTran=struct.pack("<I",len(BTCTran)+4)+BTCTran
        while(True):
                # send first message (Path+input index)
            if argToSend==P1_PATH:
                input_index = struct.pack("<I",input_index)
                message=bytearray([P1_PATH])
                message+=bip44tobin(keyId)
                message+=input_index
                # send receipt
            if argToSend==P1_RECEIPT:
                if (receiptPtr+txSize>len(receipt)):
                    argToSend|=P1_LAST
                message=bytearray([argToSend])+receipt[receiptPtr:receiptPtr+txSize]
                receiptPtr+=txSize
                # send BTC TX
            if argToSend==P1_BTC:
                message=bytearray([argToSend])+BTCTran[TXPtr:TXPtr+txSize]
                TXPtr+=txSize
                # send MP TX
            if argToSend==P1_MERKLEPROOF:
                message=bytearray([argToSend])+MP_tree[MPPtr:MPPtr+txSize]
                MPPtr+=txSize
            response = send(dongle, INS_SIGN, "", message)
            argToSend=response[2]
            txSize=response[TXLEN]
            if response[2]==P1_SUCCESS:
                return response[3:]

def sign_json(args, sign_file):
    try:
        data=json.load(open(sign_file,'r'))
    except FileNotFoundError as e:
        error("File %s not found." % sign_file)
        return
    dongle = connect(args)
    #Check Dongle status
    info("Get Dongle Report")
    result=send(dongle,RSK_IS_ONBOARD,op="")
    if result[1]==1:
        info("Dongle report is onboard...")
    else:
        error("Dongle report is NOT onboard...")
        return
    info("Get Dongle Report mode")
    result=send(dongle,RSK_MODE_CMD,op="")
    info("Dongle report mode %d..." % result[1])

    # Generate merkle tree message
    # MP tree message format: [nodeCount][[[nodeLen][nodeBytes]]*nodeCount]
    mp=data["receipt_merkle_proof"]
    #Node count
    MP_msg=bytearray([len(mp)])
    #Node length+node
    for p in mp:
        stra=""
        MP_msg+=bytearray([int(len(p)/2)])
        MP_msg+=binascii.unhexlify(p)

    # this is signature hash to verify that this signature is correct. This value is not available to the
    # end use as it's an internal value calculated from the receipt
    textToSign=binascii.unhexlify(data["sigHashToVerify"]) # signatureHash

    # Test keys that need authentication using Receipt and Trie Merkle Proof
    for keyId in data["keyIds"]:
        info("--------------------- Key Path: %s" % keyId )
        #get public key
        publicKey = send(dongle,INS_GET_PUBLIC_KEY, "",bip44tobin(keyId))
        info("Public Key: %s" % binascii.hexlify(publicKey))
        try:
            pubKey = PublicKey(bytes(publicKey), raw=True)
        except:
            error("Can't read public Key")
            return
        info('\033[92m' + "PubKey" + '\x1b[0m')

        for BTCTran in data["BTCTrans"]:
                info("--------------------- Transaction len: %s" % len(BTCTran))
                signature=signTX(dongle,keyId,binascii.unhexlify(BTCTran),binascii.unhexlify(data["receipt"]),MP_msg,0)
                signature=bytearray([0x30])+signature[1:] ### Why Ledger returns 0x31 instead of 0x30?
                info("Signature (%d): %s" % (len(signature),repr(signature)))
                signatureDeserialized = pubKey.ecdsa_deserialize(bytes(signature))
                info("Deserialized Signature: " + str(signatureDeserialized))
                info("Verified Sigature: " + '\033[92m' + str(pubKey.ecdsa_verify(bytes(textToSign), signatureDeserialized,raw=True)) + '\x1b[0m')

    # Test keys that do not need authentication
    textToSign=binascii.unhexlify("AA"*32) # signatureHash
    for keyId in data["keyIdsNoAuth"]:
        info("--------------------- Key Path: %s" % keyId )
        #get public key
        publicKey = send(dongle,INS_GET_PUBLIC_KEY, "",bip44tobin(keyId))
        info("Public Key: %s" % binascii.hexlify(publicKey))
        try:
            pubKey = PublicKey(bytes(publicKey), raw=True)
        except:
            error("Can't read public Key")
            return
        info('\033[92m' + "PubKey" + '\x1b[0m')
        #message=bytearray([P1_PATH])
        message=bip44tobin(keyId)
        message+=textToSign
        try:
            response = send(dongle,INS_SIGN, P1_PATH,message)
        except:
            error("Error signing (Last unauth signature is a test and must fail)")
            return
        info('\033[92m' + "PubKey" + '\x1b[0m')
        signature=response[3:]
        signature=bytearray([0x30])+signature[1:] ### Why Ledger returns 0x31 instead of 0x30?
        info("Signature (%d): %s" % (len(signature),repr(signature)))
        signatureDeserialized = pubKey.ecdsa_deserialize(bytes(signature))
        info("Deserialized Signature: " + str(signatureDeserialized))
        info("Verified Sigature: " + '\033[92m' + str(pubKey.ecdsa_verify(bytes(textToSign), signatureDeserialized,raw=True)) + '\x1b[0m')


# ------------------------------------------------------------------------
# Command line entry points
# ------------------------------------------------------------------------
exit_help = 'Exit RSK signer application'
get_help = 'Get blockchain state'
reset_help = 'Reset blockchain state'
advance_help = 'Advance blockchain'
update_help = 'Update ancestor block'
sign_help = 'Sign receipt'

@click.group()
@click.option('--proxy/--no-proxy', '-p/ ', 'use_proxy',
    default=False, help='Connect to a Legder through a proxy')
@click.option('--proxy-addr', default='127.0.0.1', help='Ledger proxy address', show_default=True)
@click.option('--proxy-port', default=9999, help='Ledger proxy port', type=int, show_default=True)
@click.pass_context
def cli(ctx, use_proxy, proxy_addr, proxy_port):
    ctx.ensure_object(dict)
    ctx.obj['use_proxy'] = use_proxy
    ctx.obj['proxy_addr'] = proxy_addr
    ctx.obj['proxy_port'] = proxy_port

@cli.command(short_help=exit_help, help=exit_help)
@click.pass_context
def exit(ctx):
    try:
        dongle = connect(ctx.obj)
        send(dongle,INS_EXIT,op="")
    except CommException as e:
        msg = _errors.get(e.sw, "Unknown error - missing entry in _errors table?")
        error(f"\U0001F4A5 Invalid status {hex(e.sw)}: {msg}")
    except OSError:
        # This is expected, ignore (we're leaving anyway)
        pass

@cli.command(short_help=get_help, help=get_help)
@click.pass_context
def get(ctx):
    bc_state = get_blockchain_state(ctx.obj)
    bc_state['updating']['total_difficulty'] = hex(bc_state['updating']['total_difficulty'])
    #Send bc_state to stdout
    print(json.dumps(bc_state, indent=2))

@cli.command(short_help=reset_help, help=reset_help)
@click.pass_context
def reset(ctx):
    reset_blockchain_state(ctx.obj)

@cli.command(short_help=advance_help, help=advance_help)
@click.option('-b', '--blocks', 'blocks_file', required=True, help='Json blocks file')
@click.option('-n', '--network', default='mainnet', help='Network name',
    type=click.Choice(['mainnet', 'testnet'], case_sensitive=False))
@click.pass_context
def advance(ctx, blocks_file, network):
    advance_blockchain(ctx.obj, blocks_file, network)

@cli.command(short_help=update_help, help=update_help)
@click.option('-b', '--blocks', 'blocks_file', required=True, help='Json blocks file')
@click.option('-n', '--network', default='mainnet', help='Network name',
    type=click.Choice(['mainnet', 'testnet'], case_sensitive=False))
@click.pass_context

def update(ctx, blocks_file, network):
    update_ancestor(ctx.obj, blocks_file, network)

@cli.command(short_help=sign_help, help=sign_help)
@click.option('-d', '--data', 'sign_file', required=True, help='Json sign file')
@click.pass_context
def sign(ctx, sign_file):
    sign_json(ctx.obj, sign_file)

if __name__ == '__main__':
    # pylint: disable=E1123, E1120
    cli(obj={})
