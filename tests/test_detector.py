import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from src.detector import scan_text, shannon_entropy
from src.masker import mask_content


def test_detects_aws_access_key():
    findings = scan_text('key = "AKIAIOSFODNN7EXAMPLE"', "test.py")
    types = {f.finding_type for f in findings}
    assert "aws_access_key_id" in types


def test_detects_private_key_block():
    text = "-----BEGIN RSA PRIVATE KEY-----\nFAKEDATA\n-----END RSA PRIVATE KEY-----"
    findings = scan_text(text, "id_rsa")
    types = {f.finding_type for f in findings}
    assert "private_key_block" in types


def test_detects_db_connection_string():
    findings = scan_text(
        'DB = "postgres://admin:hunter2@prod-db.example.com:5432/orders"', ".env"
    )
    types = {f.finding_type for f in findings}
    assert "db_connection_string" in types


def test_clean_code_has_no_findings():
    findings = scan_text('name = "Chethan"\nprint("hello world")', "app.py")
    assert findings == []


def test_entropy_low_for_words():
    assert shannon_entropy("password") < 4.3


def test_entropy_high_for_random_token():
    assert shannon_entropy("k3f8x92mQpL0zR7vT4wY1sN6bC5dH9jA2eU8gI3oP0m") > 4.3


def test_masking_removes_raw_secret_and_preserves_shape():
    original = 'key = "AKIAIOSFODNN7EXAMPLE"\nprint("still here")'
    findings = scan_text(original, "test.py")
    masked, vault_payload = mask_content(original, findings)

    assert "AKIAIOSFODNN7EXAMPLE" not in masked
    assert "GUARDRAIL_MASKED" in masked
    assert 'print("still here")' in masked
    assert len(vault_payload) == len(findings)


def test_fingerprint_is_stable_for_same_secret():
    findings_a = scan_text('key = "AKIAIOSFODNN7EXAMPLE"', "a.py")
    findings_b = scan_text('key = "AKIAIOSFODNN7EXAMPLE"', "a.py")
    assert findings_a[0].fingerprint == findings_b[0].fingerprint
