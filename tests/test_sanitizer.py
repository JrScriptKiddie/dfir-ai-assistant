"""Tests for sanitizer / masking pipeline."""

from src.pipeline.sanitizer import Sanitizer, SanitizerConfig, MaskStrategy


def test_mask_ntlm_hash():
    """NTLM hashes (32 hex) should be masked."""
    s = Sanitizer()
    text = "User hash: 8846F7EAEE8FB117AD06BDD830B7586C"
    result = s.sanitize(text)
    assert "8846F7EAEE8FB117AD06BDD830B7586C" not in result
    assert "[HASH:" in result or "[REDACTED:NTLM]" in result


def test_mask_sha256_hash():
    """SHA-256 hashes (64 hex) should be masked."""
    s = Sanitizer()
    text = "sha256: a1b2c3d4e5f6" + "0" * 52  # 64 hex chars total
    result = s.sanitize(text)
    assert "a1b2c3d4e5f6" + "0" * 52 not in result
    assert "[HASH:" in result or "[REDACTED:SHA256]" in result


def test_mask_password():
    """Password=secret patterns should be masked."""
    s = Sanitizer()
    text = "password=SecretPass123"
    result = s.sanitize(text)
    assert "SecretPass123" not in result
    assert "[REDACTED:PASSWORD]" in result or "[HASH:" in result


def test_mask_api_key():
    """API keys (sk-...) should be redacted."""
    s = Sanitizer()
    text = "key: sk-1234567890abcdefghijklmnop"
    result = s.sanitize(text)
    assert "sk-1234567890abcdefghijklmnop" not in result
    assert "[REDACTED:API_KEY]" in result


def test_mask_jwt():
    """JWT tokens should be redacted."""
    s = Sanitizer()
    text = "token: eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
    result = s.sanitize(text)
    assert "eyJhbGciOiJIUzI1NiJ9" not in result
    assert "[REDACTED:JWT]" in result


def test_mask_email_partial():
    """Emails should be partially masked (show first 2 chars)."""
    s = Sanitizer()
    text = "user: john.doe@company.com"
    result = s.sanitize(text)
    assert "john.doe" not in result
    assert "jo***@company.com" in result


def test_mask_ip_partial():
    """Internal IPs should be partially masked when enabled."""
    config = SanitizerConfig(mask_internal_ips=True)
    s = Sanitizer(config)
    text = "source: 172.16.2.20 connected"
    result = s.sanitize(text)
    assert "172.16.2.20" not in result
    # partial: show first 2 and last octet, mask third
    assert "172.16" in result
    assert "2.20" not in result  # third octet masked, last shown as ".20"
    assert "[***]" in result


def test_ip_not_masked_by_default():
    """IPs should NOT be masked by default (DFIR needs IPs)."""
    s = Sanitizer()
    text = "source: 172.16.2.20"
    result = s.sanitize(text)
    assert "172.16.2.20" in result


def test_tokenize_ip():
    """Tokenize strategy produces stable tokens."""
    config = SanitizerConfig(
        mask_internal_ips=True,
        ip_strategy=MaskStrategy.TOKENIZE,
    )
    s = Sanitizer(config)
    text1 = "from 172.16.2.20"
    text2 = "to 172.16.2.20 and 172.16.2.21"
    r1 = s.sanitize(text1)
    r2 = s.sanitize(text2)
    # same IP -> same token
    assert r1.count("[IP_001]") == 1
    assert "[IP_001]" in r2  # 172.16.2.20 -> IP_001
    assert "[IP_002]" in r2  # 172.16.2.21 -> IP_002


def test_sanitize_event():
    """sanitize_event should mask message but keep other fields."""
    s = Sanitizer()
    event = {
        "case_id": "test",
        "message": "password=hunter2 logon from 172.16.2.20",
        "source": "EVTX",
        "event_id": "4624",
        "user": "admin",
    }
    result = s.sanitize_event(event)
    assert "hunter2" not in result["message"]
    assert result["source"] == "EVTX"
    assert result["user"] == "admin"
    # IP preserved by default
    assert "172.16.2.20" in result["message"]


def test_credit_card_masked():
    """Credit card numbers should be redacted."""
    s = Sanitizer()
    text = "card: 4532-1234-5678-9012"
    result = s.sanitize(text)
    assert "4532-1234-5678-9012" not in result
    assert "[REDACTED:CREDIT_CARD]" in result


def test_token_map():
    """Token map should be retrievable for de-anonymization."""
    config = SanitizerConfig(
        mask_internal_ips=True,
        ip_strategy=MaskStrategy.TOKENIZE,
    )
    s = Sanitizer(config)
    s.sanitize("from 172.16.2.20")
    token_map = s.get_token_map()
    assert "172.16.2.20" in token_map
    assert token_map["172.16.2.20"] == "[IP_001]"


def test_no_false_positive_on_short_hex():
    """Short hex strings (not hashes) should not be masked."""
    s = Sanitizer()
    text = "event_id=4624 thread=abc123"
    result = s.sanitize(text)
    # "abc123" is only 6 chars, not 32 (NTLM) or 40 (SHA1) or 64 (SHA256)
    assert "abc123" in result


def test_sanitize_events_file(tmp_path):
    """sanitize_events_file should process JSONL and return stats."""
    import json

    events = [
        {"message": "password=secret123 from 172.16.2.20", "source": "EVTX"},
        {"message": "hash=8846F7EAEE8FB117AD06BDD830B7586C", "source": "EVTX"},
        {"message": "normal event no secrets", "source": "EVTX"},
    ]
    in_p = tmp_path / "events.jsonl"
    in_p.write_text("\n".join(json.dumps(e) for e in events), encoding="utf-8")
    out_p = tmp_path / "sanitized.jsonl"
    s = Sanitizer()
    stats = s.sanitize_events_file(str(in_p), str(out_p))
    assert stats["total"] == 3
    assert stats["masked"] == 2  # first two have secrets
    # verify output
    lines = out_p.read_text(encoding="utf-8").strip().split("\n")
    e0 = json.loads(lines[0])
    assert "secret123" not in e0["message"]
    e2 = json.loads(lines[2])
    assert "normal" in e2["message"]