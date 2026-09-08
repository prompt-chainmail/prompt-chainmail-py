from __future__ import annotations

import base64
import binascii
import re
from functools import lru_cache
from urllib.parse import unquote

from prompt_chainmail.rivets.base import FnRivet, NextFn, Rivet
from prompt_chainmail.rivets.pattern_detection import injection_patterns
from prompt_chainmail.rivets.types import SecurityFlags, ThreatLevel
from prompt_chainmail.rivets.utils import apply_threat_penalty
from prompt_chainmail.shared.regex_patterns import COMMON_PATTERNS, ENCODING_PATTERNS, HTML_ENTITIES
from prompt_chainmail.types import ChainmailContext, ChainmailResult


@lru_cache(maxsize=1)
def _rot13_extras() -> list[re.Pattern[str]]:
    return [
        re.compile(r"(?i)\bignore\b[\s\S]{0,24}\b(system|instructions?|rules?|prompts?)\b"),
        re.compile(
            r"(?i)\b(forget|disregard|override|bypass)\b[\s\S]{0,24}\b(all|previous|safety)\b"
        ),
    ]


def _rot13(text: str) -> str:
    out: list[str] = []
    for ch in text:
        if "A" <= ch <= "Z":
            out.append(chr((ord(ch) - 65 + 13) % 26 + 65))
        elif "a" <= ch <= "z":
            out.append(chr((ord(ch) - 97 + 13) % 26 + 97))
        else:
            out.append(ch)
    return "".join(out)


def _decode_base64(value: str) -> str | None:
    try:
        padding = (-len(value)) % 4
        decoded = base64.b64decode(value + ("=" * padding), validate=False)
        return decoded.decode("utf-8")
    except (binascii.Error, UnicodeDecodeError, ValueError):
        return None


def encoding_detection() -> Rivet:
    def handler(context: ChainmailContext, nxt: NextFn) -> ChainmailResult:
        match = ENCODING_PATTERNS.base64.search(context.sanitized)
        if match:
            decoded = _decode_base64(match.group(0))
            if decoded is not None:
                context.flags.add(SecurityFlags.BASE64_ENCODING)
                apply_threat_penalty(context, ThreatLevel.MEDIUM)
                context.metadata["decoded_content"] = decoded[:100]

        if ENCODING_PATTERNS.hex_escape.search(context.sanitized):
            context.flags.add(SecurityFlags.HEX_ENCODING)
            apply_threat_penalty(context, ThreatLevel.MEDIUM)

        url_match = ENCODING_PATTERNS.url_escape.search(context.sanitized)
        if url_match:
            try:
                decoded_url = unquote(url_match.group(0))
                context.flags.add(SecurityFlags.URL_ENCODING)
                apply_threat_penalty(context, ThreatLevel.MEDIUM)
                context.metadata["url_decoded_content"] = decoded_url[:100]
            except Exception:
                pass

        if ENCODING_PATTERNS.unicode_escape_regex.search(context.sanitized):
            decoded = context.sanitized
            while True:
                caps = ENCODING_PATTERNS.unicode_escape.search(decoded)
                if caps is None:
                    break
                code = int(caps.group(1), 16)
                decoded = decoded.replace(caps.group(0), chr(code), 1)
            context.flags.add(SecurityFlags.UNICODE_ENCODING)
            apply_threat_penalty(context, ThreatLevel.MEDIUM)
            context.metadata["unicode_decoded_content"] = decoded[:100]

        has_html_entities = HTML_ENTITIES.numeric_detection.search(
            context.sanitized
        ) or HTML_ENTITIES.named_detection.search(context.sanitized)
        if has_html_entities:
            decoded = context.sanitized
            while True:
                caps = HTML_ENTITIES.numeric.search(decoded)
                if caps is None:
                    break
                decoded = decoded.replace(caps.group(0), chr(int(caps.group(1))), 1)
            decoded = HTML_ENTITIES.lt.sub("<", decoded)
            decoded = HTML_ENTITIES.gt.sub(">", decoded)
            decoded = HTML_ENTITIES.amp.sub("&", decoded)
            decoded = HTML_ENTITIES.quot.sub('"', decoded)
            decoded = HTML_ENTITIES.apos.sub("'", decoded)
            context.flags.add(SecurityFlags.HTML_ENTITY_ENCODING)
            apply_threat_penalty(context, ThreatLevel.MEDIUM)
            context.metadata["html_decoded_content"] = decoded[:100]

        if ENCODING_PATTERNS.binary.fullmatch(context.sanitized.strip()):
            binary_string = COMMON_PATTERNS.whitespace.sub("", context.sanitized)
            decoded_chars: list[str] = []
            for i in range(0, len(binary_string), 8):
                chunk = binary_string[i : i + 8]
                if len(chunk) == 8:
                    decoded_chars.append(chr(int(chunk, 2)))
            context.flags.add(SecurityFlags.BINARY_ENCODING)
            apply_threat_penalty(context, ThreatLevel.HIGH)
            context.metadata["binary_decoded_content"] = "".join(decoded_chars)[:100]

        if ENCODING_PATTERNS.octal.search(context.sanitized):
            decoded = context.sanitized
            while True:
                caps = ENCODING_PATTERNS.octal_escape.search(decoded)
                if caps is None:
                    break
                decoded = decoded.replace(caps.group(0), chr(int(caps.group(1), 8)), 1)
            context.flags.add(SecurityFlags.OCTAL_ENCODING)
            apply_threat_penalty(context, ThreatLevel.MEDIUM)
            context.metadata["octal_decoded_content"] = decoded[:100]

        rot13_decoded = _rot13(context.sanitized)
        suspicious = [pattern for pattern, _label in injection_patterns()] + _rot13_extras()
        decoded_matches = any(pattern.search(rot13_decoded) for pattern in suspicious)
        original_matches = any(pattern.search(context.sanitized) for pattern in suspicious)
        if decoded_matches and not original_matches:
            context.flags.add(SecurityFlags.ROT13_ENCODING)
            apply_threat_penalty(context, ThreatLevel.MEDIUM)
            context.metadata["rot13_decoded_content"] = rot13_decoded[:100]

        words = COMMON_PATTERNS.whitespace_multiple.split(context.sanitized)
        mixed = [
            word
            for word in words
            if len(word) >= 4
            and (upper := len(COMMON_PATTERNS.uppercase.findall(word))) > 0
            and len(COMMON_PATTERNS.lowercase.findall(word)) > 0
            and upper / len(word) > 0.3
        ]
        if len(mixed) > 2:
            context.flags.add(SecurityFlags.MIXED_CASE_OBFUSCATION)
            apply_threat_penalty(context, ThreatLevel.MEDIUM)
            context.metadata["mixed_case_words"] = ",".join(mixed[:5])

        return nxt(context)

    return FnRivet("encoding_detection", handler)
