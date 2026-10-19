"""Ed25519 signing, canonical encoding and domain separation. No web framework dependency."""
import hashlib
import json

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey


def canonical(obj) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()


def sha256_hex(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


# Domain separation: a signature made for one purpose can never be replayed for another.
def sheet_message(payload: dict) -> bytes:
    return b"EC8A-v1|" + canonical(payload)


def countersign_message(payload_hash: str) -> bytes:
    return b"EC8A-v1-COUNTERSIGN|" + payload_hash.encode()


def checkpoint_message(tree_size: int, root_hex: str) -> bytes:
    return f"CHECKPOINT-v1|{tree_size}|{root_hex}".encode()


def generate_keypair() -> tuple[bytes, str]:
    priv = Ed25519PrivateKey.generate()
    pem = priv.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                             serialization.NoEncryption())
    return pem, public_hex(priv)


def public_hex(priv: Ed25519PrivateKey) -> str:
    return priv.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw).hex()


def load_private(pem: bytes) -> Ed25519PrivateKey:
    key = serialization.load_pem_private_key(pem, password=None)
    if not isinstance(key, Ed25519PrivateKey):
        raise ValueError("private key is not Ed25519")
    return key


def sign(priv: Ed25519PrivateKey, msg: bytes) -> str:
    return priv.sign(msg).hex()


def verify(pub_hex: str, sig_hex: str, msg: bytes) -> bool:
    try:
        Ed25519PublicKey.from_public_bytes(bytes.fromhex(pub_hex)).verify(bytes.fromhex(sig_hex), msg)
        return True
    except (InvalidSignature, ValueError):
        return False
