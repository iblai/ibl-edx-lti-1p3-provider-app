import logging

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

log = logging.getLogger(__name__)


def generate_private_key_pem(public_exponent=65537, key_size=2048) -> str:
    """Generate a private key PEM

    https://cryptography.io/en/latest/hazmat/primitives/asymmetric/rsa/#generation
    """
    private_key = rsa.generate_private_key(
        public_exponent=public_exponent, key_size=key_size
    )
    return private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode("utf-8")


def priv_to_public_key_pem(private_key: str):
    """Return public key from private key in PEM format

    https://cryptography.io/en/latest/hazmat/primitives/asymmetric/rsa/#key-serialization
    """
    private = serialization.load_pem_private_key(
        private_key.encode("utf-8"),
        password=None,
    )
    public_key = private.public_key()
    public_key_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return public_key_pem.decode("utf-8")


def is_valid_private_key(private_key: str) -> bool:
    """Return True if this is a valid private key in PEM format"""
    try:
        serialization.load_pem_private_key(
            private_key.encode("utf-8"),
            password=None,
        )
    except Exception as e:
        log.warning("Invalid Private Key: %s", e)
        return False

    return True
