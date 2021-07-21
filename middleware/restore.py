import sys
import os
import ecdsa
import ecdsa.util
from Crypto.Cipher import AES
from comm.english_mnemonic import EnglishMnemonic
from argparse import ArgumentParser
from comm.utils import is_hex_string_of_length

DEFAULT_SEED_BACKUP_FILE = "seedbackup.bin"
KEY_LENGTH = 32

# # Key Backup
#
# Backup is 65 bytes, and is composed of:
#
# * bytes 0-31 (32 bytes): 128-bit AES encrypted raw 256-bit seed.
#   The encryption key is the first 16 bytes of the SHA256 hash of the compressed
#   ECDH shared secret public key point computed from:
#     - RSK key (held by RSK)
#     - HSM key (generated randomly at onboarding)
# * bytes 32-64 (33 bytes): Compressed HSM's public key (used for ECDH shared secret computation).
BACKUP_LENGTH = 65
SEPARATOR_OFFSET = 32
AES_KEY_LENGTH = 16

if __name__ == '__main__':
    parser = ArgumentParser(description="HSM 2 Restore tool")
    parser.add_argument("-k", "--key", dest="key", \
                        help=f"Backup private key (in hex format).", required=True)
    parser.add_argument("-b", "--backup", dest="seed_backup_file", \
                        help=f"Seed backup file. (default '{DEFAULT_SEED_BACKUP_FILE}')", \
                        default=DEFAULT_SEED_BACKUP_FILE)
    options = parser.parse_args()

    if not os.path.isfile(options.seed_backup_file):
        print(f"File '{options.seed_backup_file}' does not exist")
        sys.exit(1)

    if not is_hex_string_of_length(options.key, KEY_LENGTH, allow_prefix=True):
        print(f"Invalid {KEY_LENGTH}-byte hex-encoded key '{options.key}'")
        sys.exit(1)

    with open(options.seed_backup_file, "rb") as backup:
        backup_bytes = backup.read()

    if len(backup_bytes) != BACKUP_LENGTH:
        print(f"Invalid backup: expected {BACKUP_LENGTH} bytes but got {len(backup_bytes)}")
        sys.exit(1)

    # Decrypt the backup
    encrypted_seed = backup_bytes[:SEPARATOR_OFFSET]
    hsm_key_bytes = backup_bytes[SEPARATOR_OFFSET:]
    rsk_key = ecdsa.SigningKey.from_string(bytes.fromhex(options.key), curve=ecdsa.SECP256k1)
    hsm_key = ecdsa.VerifyingKey.from_string(hsm_key_bytes, curve=ecdsa.SECP256k1)
    dh_point = hsm_key.pubkey.point * rsk_key.privkey.secret_multiplier
    dh_pub = ecdsa.VerifyingKey.from_public_point(dh_point, curve=ecdsa.SECP256k1)
    aes_key = ecdsa.util.sha256(dh_pub.to_string("compressed")).digest()[:AES_KEY_LENGTH]
    aes = AES.new(aes_key, AES.MODE_CBC, b'\x00'*16)
    seed = aes.decrypt(encrypted_seed)
    seed_mnemonic = EnglishMnemonic().to_mnemonic(seed)
    words = seed_mnemonic.split(" ")

    print("*" * 78)
    print("Backup restored. Mnemonic:")
    for n, word in enumerate(words, 1):
        print(f"Word #{n}: {word}")
    print("*" * 78)

    sys.exit(0)
