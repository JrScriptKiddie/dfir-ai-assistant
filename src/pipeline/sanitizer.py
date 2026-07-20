"""Sanitizer / Masking Pipeline.

Preprocesses log events before sending to LLM context to prevent
leakage of sensitive data: password hashes, tokens, internal IPs,
email addresses, API keys, credit card numbers, SSN, etc.

Usage in pipeline:
  1. After normalizer produces events.jsonl
  2. Before chunker creates RAG chunks
  3. Sanitizer masks sensitive patterns in event.message
  4. Masked events -> chunker -> RAG (LLM never sees raw secrets)
  5. Original events kept separately for forensic reference

Masking strategies:
  - REDACT: replace with [REDACTED:TYPE]
  - HASH: replace with sha256 prefix (preserves correlation, hides value)
  - PARTIAL: show first/last chars, mask middle (e.g. 172.16.[MASKED].20)
  - TOKENIZE: replace with stable token (CORRELATION_ID_001)

Configurable per pattern type. Default: REDACT for secrets, PARTIAL for IPs.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from enum import Enum


class MaskStrategy(Enum):
    REDACT = "redact"      # [REDACTED:TYPE]
    HASH = "hash"          # [HASH:abc123]
    PARTIAL = "partial"    # 172.16.[***].20
    TOKENIZE = "tokenize"  # [IP_001] (stable per unique value)


@dataclass
class MaskRule:
    """A single masking rule."""

    name: str
    pattern: re.Pattern
    strategy: MaskStrategy
    replacement_template: str = "[REDACTED:{name}]"
    # for TOKENIZE: stable mapping of original -> token
    # for PARTIAL: how many chars to show on each side


@dataclass
class SanitizerConfig:
    """Configuration for the sanitizer."""

    # What to mask
    mask_passwords: bool = True
    mask_ntlm_hashes: bool = True
    mask_api_keys: bool = True
    mask_emails: bool = True
    mask_internal_ips: bool = False  # DFIR usually needs IPs visible
    mask_credit_cards: bool = True
    mask_tokens: bool = True
    mask_jwt: bool = True
    mask_private_keys: bool = True

    # Strategy per type
    password_strategy: MaskStrategy = MaskStrategy.REDACT
    hash_strategy: MaskStrategy = MaskStrategy.HASH
    ip_strategy: MaskStrategy = MaskStrategy.PARTIAL
    email_strategy: MaskStrategy = MaskStrategy.PARTIAL
    api_key_strategy: MaskStrategy = MaskStrategy.REDACT

    # Partial masking config
    ip_show_octets: int = 2  # show first 2 and last 2 octets
    email_show_chars: int = 2  # show first 2 chars of local part


# ---- regex patterns ----

# NTLM hashes (32 hex chars)
NTLM_HASH_RE = re.compile(r"\b[0-9a-fA-F]{32}\b")
# SHA-1 hashes (40 hex chars)
SHA1_HASH_RE = re.compile(r"\b[0-9a-fA-F]{40}\b")
# SHA-256 hashes (64 hex chars)
SHA256_HASH_RE = re.compile(r"\b[0-9a-fA-F]{64}\b")

# Password/token patterns in log messages
# Only match key=value or key: value with explicit separators
# Exclude "token:" followed by JWT (handled by JWT_RE separately)
PASSWORD_RE = re.compile(
    r"(?i)(password|passwd|pwd|secret|access_token|refresh_token|"
    r"auth_token|bearer|authorization)"
    r"[\s:=]+(['\"]?)(\S+?)(?:\2[\s,;]|$)"
)
# Capture group 3 = the actual secret value

# API keys (common patterns)
API_KEY_RE = re.compile(
    r"\b(?:sk-[a-zA-Z0-9]{20,}|"
    r"gh[pousr]_[A-Za-z0-9]{36}|"
    r"AKIA[A-Z0-9]{16}|"
    r"eyJ[a-zA-Z0-9_-]{10,}\.eyJ[a-zA-Z0-9_-]{10,})"
)

# JWT tokens
JWT_RE = re.compile(
    r"\beyJ[a-zA-Z0-9_-]+\.eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+\b"
)

# Email addresses
EMAIL_RE = re.compile(r"\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b")

# Internal/private IP ranges
INTERNAL_IP_RE = re.compile(
    r"\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|"
    r"172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|"
    r"192\.168\.\d{1,3}\.\d{1,3})\b"
)

# Credit card numbers (basic pattern)
CREDIT_CARD_RE = re.compile(
    r"\b(?:\d[ -]*?){13,16}\b"
)

# Private key markers
PRIVATE_KEY_RE = re.compile(
    r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |)PRIVATE KEY-----"
    r"[\s\S]*?-----END (?:RSA |EC |DSA |OPENSSH |)PRIVATE KEY-----"
)


class Sanitizer:
    """Log sanitizer that masks sensitive data before LLM context."""

    def __init__(self, config: SanitizerConfig | None = None) -> None:
        self.config = config or SanitizerConfig()
        self._token_map: dict[str, str] = {}
        self._token_counter: dict[str, int] = {}

    def sanitize(self, text: str) -> str:
        """Apply all masking rules to a text string.

        Order matters: JWT/API keys first (specific patterns), then
        password=key patterns (generic), then hashes, emails, IPs.
        """
        if self.config.mask_private_keys:
            text = self._mask_pattern(
                text, PRIVATE_KEY_RE, "PRIVATE_KEY", MaskStrategy.REDACT
            )
        if self.config.mask_jwt:
            text = self._mask_pattern(text, JWT_RE, "JWT", MaskStrategy.REDACT)
        if self.config.mask_api_keys:
            text = self._mask_pattern(
                text, API_KEY_RE, "API_KEY", self.config.api_key_strategy
            )
        if self.config.mask_passwords:
            text = self._mask_passwords(text)
        if self.config.mask_ntlm_hashes:
            text = self._mask_hashes(text)
        if self.config.mask_emails:
            text = self._mask_emails(text)
        if self.config.mask_internal_ips:
            text = self._mask_ips(text)
        if self.config.mask_credit_cards:
            text = self._mask_pattern(
                text, CREDIT_CARD_RE, "CREDIT_CARD", MaskStrategy.REDACT
            )
        return text

    def sanitize_event(self, event: dict) -> dict:
        """Sanitize a normalized event dict (modifies message field)."""
        event = dict(event)  # shallow copy
        if "message" in event:
            event["message"] = self.sanitize(event["message"])
        if "user" in event and event["user"]:
            # don't mask usernames (needed for DFIR), but mask if they look like emails
            if "@" in event["user"]:
                event["user"] = self.sanitize(event["user"])
        return event

    def sanitize_events_file(
        self, in_path: str, out_path: str
    ) -> dict:
        """Sanitize all events in a JSONL file.

        Returns stats: {total, masked, patterns_found}
        """
        import json
        from pathlib import Path

        stats = {"total": 0, "masked": 0, "patterns_found": 0}
        in_p = Path(in_path)
        out_p = Path(out_path)
        out_p.parent.mkdir(parents=True, exist_ok=True)

        with open(in_p, encoding="utf-8") as fin, open(out_p, "w", encoding="utf-8") as fout:
            for line in fin:
                line = line.strip()
                if not line:
                    continue
                stats["total"] += 1
                event = json.loads(line)
                original_msg = event.get("message", "")
                sanitized = self.sanitize_event(event)
                if sanitized.get("message", "") != original_msg:
                    stats["masked"] += 1
                fout.write(json.dumps(sanitized, ensure_ascii=False) + "\n")
        return stats

    def _mask_pattern(
        self, text: str, pattern: re.Pattern, name: str, strategy: MaskStrategy
    ) -> str:
        """Apply a regex pattern with given strategy."""
        if strategy == MaskStrategy.REDACT:
            return pattern.sub(f"[REDACTED:{name}]", text)
        elif strategy == MaskStrategy.HASH:
            def hash_repl(m: re.Match) -> str:
                import hashlib
                h = hashlib.sha256(m.group().encode()).hexdigest()[:8]
                return f"[HASH:{name}:{h}]"
            return pattern.sub(hash_repl, text)
        elif strategy == MaskStrategy.TOKENIZE:
            def token_repl(m: re.Match) -> str:
                val = m.group()
                if val not in self._token_map:
                    self._token_counter[name] = self._token_counter.get(name, 0) + 1
                    self._token_map[val] = f"[{name}_{self._token_counter[name]:03d}]"
                return self._token_map[val]
            return pattern.sub(token_repl, text)
        return pattern.sub(f"[REDACTED:{name}]", text)

    def _mask_passwords(self, text: str) -> str:
        """Mask password/token values in key=value patterns."""
        def password_repl(m: re.Match) -> str:
            key = m.group(1)
            val = m.group(3)
            if self.config.password_strategy == MaskStrategy.HASH:
                import hashlib
                h = hashlib.sha256(val.encode()).hexdigest()[:8]
                return f"{key}=[HASH:{h}]"
            elif self.config.password_strategy == MaskStrategy.TOKENIZE:
                if val not in self._token_map:
                    self._token_counter["PASSWORD"] = self._token_counter.get("PASSWORD", 0) + 1
                    self._token_map[val] = f"[PASSWORD_{self._token_counter['PASSWORD']:03d}]"
                return f"{key}={self._token_map[val]}"
            return f"{key}=[REDACTED:PASSWORD]"

        return PASSWORD_RE.sub(password_repl, text)

    def _mask_hashes(self, text: str) -> str:
        """Mask NTLM (32), SHA-1 (40), SHA-256 (64) hashes."""
        if self.config.hash_strategy == MaskStrategy.HASH:
            # hash the hash (preserves correlation)
            def hash_repl(m: re.Match) -> str:
                import hashlib
                h = hashlib.sha256(m.group().encode()).hexdigest()[:8]
                return f"[HASH:{h}]"
            text = SHA256_HASH_RE.sub(hash_repl, text)
            text = SHA1_HASH_RE.sub(hash_repl, text)
            text = NTLM_HASH_RE.sub(hash_repl, text)
        elif self.config.hash_strategy == MaskStrategy.REDACT:
            text = SHA256_HASH_RE.sub("[REDACTED:SHA256]", text)
            text = SHA1_HASH_RE.sub("[REDACTED:SHA1]", text)
            text = NTLM_HASH_RE.sub("[REDACTED:NTLM]", text)
        return text

    def _mask_emails(self, text: str) -> str:
        """Mask email addresses."""
        if self.config.email_strategy == MaskStrategy.PARTIAL:
            def email_repl(m: re.Match) -> str:
                email = m.group()
                local, domain = email.split("@", 1)
                show = self.config.email_show_chars
                masked_local = local[:show] + "***" if len(local) > show else "***"
                return f"{masked_local}@{domain}"
            return EMAIL_RE.sub(email_repl, text)
        elif self.config.email_strategy == MaskStrategy.REDACT:
            return EMAIL_RE.sub("[REDACTED:EMAIL]", text)
        return text

    def _mask_ips(self, text: str) -> str:
        """Mask internal IP addresses."""
        if self.config.ip_strategy == MaskStrategy.PARTIAL:
            def ip_repl(m: re.Match) -> str:
                ip = m.group()
                octets = ip.split(".")
                if len(octets) == 4:
                    # show first 2 and last 1 octet, mask middle
                    masked = [octets[0], octets[1], "[***]", octets[3]]
                    return ".".join(masked)
                return "[REDACTED:IP]"
            return INTERNAL_IP_RE.sub(ip_repl, text)
        elif self.config.ip_strategy == MaskStrategy.TOKENIZE:
            def ip_token_repl(m: re.Match) -> str:
                val = m.group()
                if val not in self._token_map:
                    self._token_counter["IP"] = self._token_counter.get("IP", 0) + 1
                    self._token_map[val] = f"[IP_{self._token_counter['IP']:03d}]"
                return self._token_map[val]
            return INTERNAL_IP_RE.sub(ip_token_repl, text)
        return INTERNAL_IP_RE.sub("[REDACTED:IP]", text)

    def get_token_map(self) -> dict[str, str]:
        """Return the token mapping (for de-anonymization by authorized analyst)."""
        return dict(self._token_map)

    def reset(self) -> None:
        """Reset token mapping."""
        self._token_map.clear()
        self._token_counter.clear()