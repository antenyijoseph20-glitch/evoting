"""RFC 6962-style Merkle tree: 0x00 prefix for leaves, 0x01 for nodes (blocks second-preimage tricks)."""
import hashlib


def _leaf(d: bytes) -> bytes:
    return hashlib.sha256(b"\x00" + d).digest()


def _node(l: bytes, r: bytes) -> bytes:
    return hashlib.sha256(b"\x01" + l + r).digest()


def _split(n: int) -> int:  # largest power of two strictly less than n
    k = 1
    while k * 2 < n:
        k *= 2
    return k


def root(leaves: list[bytes]) -> bytes:
    n = len(leaves)
    if n == 0:
        return hashlib.sha256(b"").digest()
    if n == 1:
        return _leaf(leaves[0])
    k = _split(n)
    return _node(root(leaves[:k]), root(leaves[k:]))


def proof(leaves: list[bytes], m: int) -> list[bytes]:
    n = len(leaves)
    if n == 1:
        return []
    k = _split(n)
    if m < k:
        return proof(leaves[:k], m) + [root(leaves[k:])]
    return proof(leaves[k:], m - k) + [root(leaves[:k])]


def _from_proof(leaf_hash: bytes, m: int, n: int, path: list[bytes]):
    if n == 1:
        return leaf_hash if not path else None
    if not path:
        return None
    k, sib, rest = _split(n), path[-1], path[:-1]
    if m < k:
        sub = _from_proof(leaf_hash, m, k, rest)
        return None if sub is None else _node(sub, sib)
    sub = _from_proof(leaf_hash, m - k, n - k, rest)
    return None if sub is None else _node(sib, sub)


def verify_proof(leaf: bytes, index: int, tree_size: int, path: list[bytes], expected_root: bytes) -> bool:
    if not 0 <= index < tree_size:
        return False
    return _from_proof(_leaf(leaf), index, tree_size, path) == expected_root
