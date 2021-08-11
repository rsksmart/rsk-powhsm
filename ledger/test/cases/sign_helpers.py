from ecdsa import VerifyingKey, SECP256k1, BadSignatureError
from .case import TestCaseError

def assert_signature(pubkey, message, signature):
    if pubkey is None:
        raise TestCaseError("Could not determine the public key")
        
    # Validate the signature
    vkey = VerifyingKey.from_string(bytes.fromhex(pubkey), curve=SECP256k1)
    try:
        tuple_sig = to_tuple(signature)
        vkey.verify_digest(tuple_sig, bytes.fromhex(message), sigdecode=lambda x,_: x)
    except BadSignatureError:
        raise TestCaseError(f"Got bad signature {tuple_sig} for message {message} and public key {pubkey}")

def to_tuple(signature):
    return (
        int.from_bytes(bytes.fromhex(signature.r), byteorder='big', signed=False), 
        int.from_bytes(bytes.fromhex(signature.s), byteorder='big', signed=False)
    )