import json
from verifier.pocket_verifier import verify, load_jwks, jcs, b64url_encode


def load(path):
    with open(path, 'r', encoding='utf-8') as f:
        return json.load(f)


def test_valid_receipt():
    jwks = load_jwks('tests/data/receipts/test_jwks.json')
    receipt = load('tests/data/receipts/valid_receipt.json')
    input_data = load('tests/data/receipts/input_nfd.json')
    output_data = load('tests/data/receipts/output.json')
    ok, reasons = verify(receipt, jwks, input_data, output_data)
    assert ok, reasons


def test_invalid_nonce():
    jwks = load_jwks('tests/data/receipts/test_jwks.json')
    receipt = load('tests/data/receipts/invalid_nonce.json')
    ok, reasons = verify(receipt, jwks)
    assert not ok


def test_invalid_issued_at():
    jwks = load_jwks('tests/data/receipts/test_jwks.json')
    receipt = load('tests/data/receipts/invalid_issued_at_offset.json')
    ok, reasons = verify(receipt, jwks)
    assert not ok


def test_unicode_commitment_vector():
    vec = load('tests/data/receipts/unicode_commitment.json')
    data = {'prompt': vec['nfd']}
    commit = 'sha256:' + b64url_encode(__import__('hashlib').sha256(jcs(data).encode()).digest())
    assert commit == vec['commitment']
