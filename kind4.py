import base64
import binascii
from os import urandom

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


class Kind4MessageEncoder:
    def __init__(self, hex_private_key, hex_public_key):
        self.hex_private_key = hex_private_key
        self.hex_public_key = hex_public_key
        # self.message = message
        self.private_key = self._generate_private_key()
        self.public_key = self._generate_public_key()

    def _generate_private_key(self):
        private_key_int = int(self.hex_private_key, 16)
        return ec.derive_private_key(private_key_int, ec.SECP256K1(), default_backend())

    def _generate_public_key(self):
        public_key_bytes = binascii.unhexlify("02" + self.hex_public_key)
        return ec.EllipticCurvePublicKey.from_encoded_point(
            ec.SECP256K1(), public_key_bytes
        )

    def encrypt_message(self, message):
        shared_key = self.private_key.exchange(ec.ECDH(), self.public_key)
        shared_x = shared_key[:32]
        iv = urandom(16)
        cipher = Cipher(
            algorithms.AES(shared_x), modes.CBC(iv), backend=default_backend()
        )
        encryptor = cipher.encryptor()
        padder = padding.PKCS7(algorithms.AES.block_size).padder()
        padded_data = padder.update(message.encode("utf-8")) + padder.finalize()
        encrypted_message = encryptor.update(padded_data) + encryptor.finalize()
        encrypted_message_base64 = base64.b64encode(encrypted_message).decode("utf-8")
        iv_base64 = base64.b64encode(iv).decode("utf-8")
        stringed = f"{encrypted_message_base64}?iv={iv_base64}"
        return stringed
