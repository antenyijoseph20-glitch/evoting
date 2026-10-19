"""Cryptographic and helper-level invariants."""
from types import SimpleNamespace

import config
import ledger
import merkle
import security as sec
import signing as sg


def test_voter_hash_is_keyed_and_deterministic(monkeypatch):
    a = sec.voter_hash("12345678901", "NG12345678")
    assert a == sec.voter_hash("12345678901", "ng12345678")  # VIN is normalised
    assert a != sec.voter_hash("12345678902", "NG12345678")
    assert a != sec.voter_hash("12345678901", "NG12345679")
    assert len(a) == 64


def test_otp_is_bound_to_the_session():
    token_hash = sec.token_hash(sec.new_token())
    other_hash = sec.token_hash(sec.new_token())
    expected = sec.otp_hash(token_hash, "123456")
    assert expected == sec.otp_hash(token_hash, "123456")
    assert expected != sec.otp_hash(other_hash, "123456")
    assert expected != sec.otp_hash(token_hash, "654321")


def test_password_hashing_round_trip():
    salt, digest = sec.hash_password("correct-horse-battery-staple")
    assert sec.check_password("correct-horse-battery-staple", salt, digest) is True
    assert sec.check_password("wrong-password", salt, digest) is False
    salt2, digest2 = sec.hash_password("correct-horse-battery-staple")
    assert salt2 != salt and digest2 != digest  # fresh salt each time


def test_phone_masking_keeps_only_prefix_and_suffix():
    assert sec.mask_phone("+2348012345678") == "+234" + "*" * 7 + "678"
    assert "+2348012345678" not in sec.mask_phone("+2348012345678")


def test_client_ip_honours_forwarded_for_only_when_trusted(monkeypatch):
    request = SimpleNamespace(headers={"x-forwarded-for": "203.0.113.9, 10.0.0.1"},
                              client=SimpleNamespace(host="127.0.0.1"))
    monkeypatch.setattr(config, "TRUST_PROXY", False)
    assert sec.client_ip(request) == "127.0.0.1"
    monkeypatch.setattr(config, "TRUST_PROXY", True)
    assert sec.client_ip(request) == "203.0.113.9"


def test_merkle_proofs_across_tree_sizes():
    for n in range(1, 20):
        leaves = [bytes([i]) * 32 for i in range(n)]
        root = merkle.root(leaves)
        for m in range(n):
            path = merkle.proof(leaves, m)
            assert merkle.verify_proof(leaves[m], m, n, path, root)
            wrong = bytearray(leaves[m])
            wrong[0] ^= 0xFF
            assert not merkle.verify_proof(bytes(wrong), m, n, path, root)


def test_signature_domain_separation():
    pem, public = sg.generate_keypair()
    key = sg.load_private(pem)
    payload = {"v": 1}
    signature = sg.sign(key, sg.sheet_message(payload))
    assert sg.verify(public, signature, sg.sheet_message(payload))
    # a sheet signature cannot be replayed as a checkpoint signature
    assert not sg.verify(public, signature, sg.checkpoint_message(1, "0" * 64))
    assert not sg.verify(public, signature, sg.countersign_message("0" * 64))


def test_ledger_hash_and_checkpoint_message():
    first = ledger.compute_hash(ledger.GENESIS, "PRESIDENTIAL", "APC", "PU-001")
    assert first == ledger.compute_hash(ledger.GENESIS, "PRESIDENTIAL", "APC", "PU-001")
    assert first != ledger.compute_hash(ledger.GENESIS, "PRESIDENTIAL", "LP", "PU-001")
    assert b"LEDGER-CHECKPOINT-v1" in ledger.checkpoint_message(7, first)


def test_face_matcher_plugin(monkeypatch):
    import sys
    import types

    module = types.ModuleType("test_fake_matcher")
    module.matches = lambda data: data == b"enrolled-voter"
    sys.modules["test_fake_matcher"] = module
    monkeypatch.setenv("EVOTING_FACE_MATCHER", "test_fake_matcher:matches")
    monkeypatch.setattr(sec, "_matcher", None)
    monkeypatch.setattr(sec, "_matcher_spec", None)
    assert sec.face_check(b"enrolled-voter") is True
    assert sec.face_check(b"someone-else") is False

    monkeypatch.setenv("EVOTING_FACE_MATCHER", "not-a-valid-spec")
    monkeypatch.setattr(sec, "_matcher", None)
    monkeypatch.setattr(sec, "_matcher_spec", None)
    try:
        sec.face_check(b"x")
    except Exception as error:
        assert getattr(error, "status_code", None) == 503
    else:
        raise AssertionError("a malformed matcher spec must fail closed")
