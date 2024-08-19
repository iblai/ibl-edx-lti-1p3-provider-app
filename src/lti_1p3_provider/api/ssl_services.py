from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization


def priv_to_public_key_pem(private_key: str):
    """Return public key from private key in PEM format"""
    private = serialization.load_pem_private_key(
        private_key.encode("utf-8"),
        password=None,  # Replace with the password if the private key is encrypted
        backend=default_backend(),
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
            backend=default_backend(),
        )
    except Exception:
        return False
    return True
