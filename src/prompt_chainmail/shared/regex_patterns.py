from __future__ import annotations

import re
from dataclasses import dataclass
from functools import lru_cache


@dataclass(frozen=True, slots=True)
class CommonPatterns:
    whitespace: re.Pattern[str]
    whitespace_multiple: re.Pattern[str]
    uppercase: re.Pattern[str]
    lowercase: re.Pattern[str]
    alphabetic: re.Pattern[str]
    alphanumeric: re.Pattern[str]
    word_char: re.Pattern[str]
    word_chars: re.Pattern[str]
    digit: re.Pattern[str]
    digits: re.Pattern[str]
    non_word_chars: re.Pattern[str]
    consecutive_consonants: re.Pattern[str]
    slot_pattern: re.Pattern[str]
    bracket_open: re.Pattern[str]
    bracket_close: re.Pattern[str]


@dataclass(frozen=True, slots=True)
class HtmlEntities:
    lt: re.Pattern[str]
    gt: re.Pattern[str]
    amp: re.Pattern[str]
    quot: re.Pattern[str]
    apos: re.Pattern[str]
    numeric: re.Pattern[str]
    numeric_detection: re.Pattern[str]
    named_detection: re.Pattern[str]


@dataclass(frozen=True, slots=True)
class EncodingPatterns:
    unicode_escape: re.Pattern[str]
    octal_escape: re.Pattern[str]
    hex_digits: re.Pattern[str]
    binary_digits: re.Pattern[str]
    base64: re.Pattern[str]
    hex_escape: re.Pattern[str]
    url_escape: re.Pattern[str]
    binary: re.Pattern[str]
    octal: re.Pattern[str]
    unicode_escape_regex: re.Pattern[str]


@lru_cache(maxsize=1)
def _common_patterns() -> CommonPatterns:
    return CommonPatterns(
        whitespace=re.compile(r"\s"),
        whitespace_multiple=re.compile(r"\s+"),
        uppercase=re.compile(r"[A-Z]"),
        lowercase=re.compile(r"[a-z]"),
        alphabetic=re.compile(r"[a-zA-Z]"),
        alphanumeric=re.compile(r"[a-zA-Z0-9]"),
        word_char=re.compile(r"\w"),
        word_chars=re.compile(r"\w+"),
        digit=re.compile(r"\d"),
        digits=re.compile(r"\d+"),
        non_word_chars=re.compile(r"[^\w\s]", re.UNICODE),
        consecutive_consonants=re.compile(r"[bcdfghjklmnpqrstvwxyzBCDFGHJKLMNPQRSTVWXYZ]{4,}"),
        slot_pattern=re.compile(r"\[(\w+)\]"),
        bracket_open=re.compile(r"\["),
        bracket_close=re.compile(r"\]"),
    )


@lru_cache(maxsize=1)
def _html_entities() -> HtmlEntities:
    return HtmlEntities(
        lt=re.compile(r"&lt;"),
        gt=re.compile(r"&gt;"),
        amp=re.compile(r"&amp;"),
        quot=re.compile(r"&quot;"),
        apos=re.compile(r"&#x27;"),
        numeric=re.compile(r"&#(\d+);"),
        numeric_detection=re.compile(r"&#\d{2,3};"),
        named_detection=re.compile(r"&[a-zA-Z]+;"),
    )


@lru_cache(maxsize=1)
def _encoding_patterns() -> EncodingPatterns:
    return EncodingPatterns(
        unicode_escape=re.compile(r"\\u([0-9a-fA-F]{4})"),
        octal_escape=re.compile(r"\\([0-7]{3})"),
        hex_digits=re.compile(r"[0-9a-fA-F]"),
        binary_digits=re.compile(r"[01]"),
        base64=re.compile(r"[A-Za-z0-9+/=]{20,}"),
        hex_escape=re.compile(r"(?:0x)?[0-9a-fA-F\s]{20,}"),
        url_escape=re.compile(r"(%[0-9a-fA-F]{2}){4,}"),
        binary=re.compile(r"^[01\s]{32,}$"),
        octal=re.compile(r"\\[0-7]{3}"),
        unicode_escape_regex=re.compile(r"\\u[0-9a-fA-F]{4}"),
    )


COMMON_PATTERNS = _common_patterns()
HTML_ENTITIES = _html_entities()
ENCODING_PATTERNS = _encoding_patterns()
