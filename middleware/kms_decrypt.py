import base64
from asn1crypto import cms
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP, AES
from Crypto.Hash import SHA256
from Crypto.Util.Padding import unpad

def load_rsa_key(keyhex):
    return RSA.import_key(keyhex)

def decrypt_kms_ct_for_recipient(ct, private_key):
    # ct can be base64 text or raw DER bytes
    if isinstance(ct, str):
        try:
            der = base64.b64decode(ct, validate=True)
        except Exception:
            der = ct.encode()
    elif isinstance(ct, (bytes, bytearray)):
        try:
            der = base64.b64decode(ct, validate=True)
        except Exception:
            der = bytes(ct)
    else:
        raise TypeError("ct must be str/bytes")

    ci = cms.ContentInfo.load(der)
    ed = ci["content"]

    ri = ed["recipient_infos"][0].chosen
    wrapped_cek = ri["encrypted_key"].native

    cek = PKCS1_OAEP.new(
        private_key,
        hashAlgo=SHA256,
    ).decrypt(wrapped_cek)

    eci = ed["encrypted_content_info"]

    # For aes256_cbc, CMS algorithm parameters carry the IV
    iv = eci["content_encryption_algorithm"]["parameters"].native

    # IMPORTANT: use .native here, not .dump() or .contents
    encrypted_content = eci["encrypted_content"].native

    cipher = AES.new(cek, AES.MODE_CBC, iv)
    padded_plaintext = cipher.decrypt(encrypted_content)
    plaintext = unpad(padded_plaintext, 16)

    return plaintext
