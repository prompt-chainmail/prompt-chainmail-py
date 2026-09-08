from __future__ import annotations

import unicodedata

from prompt_chainmail.shared.language_detection.consts import (
    LANGUAGE_DETECTION_COMBINING_DIACRITICS,
    LANGUAGE_DETECTION_COMMON_PUNCTUATION,
    LANGUAGE_DETECTION_LOOKALIKE_CHARS,
    LANGUAGE_DETECTION_OBFUSCATION_PATTERN,
    LANGUAGE_DETECTION_OPERATORS_AND_PIPES,
    LANGUAGE_DETECTION_SEPARATORS,
)
from prompt_chainmail.shared.regex_patterns import COMMON_PATTERNS


def normalize_text(text: str) -> str:
    space_char = " "
    empty_char = ""
    normalized = unicodedata.normalize("NFD", text.lower())
    normalized = LANGUAGE_DETECTION_COMBINING_DIACRITICS.sub(empty_char, normalized)
    normalized = LANGUAGE_DETECTION_COMMON_PUNCTUATION.sub(space_char, normalized)
    normalized = LANGUAGE_DETECTION_OPERATORS_AND_PIPES.sub(space_char, normalized)
    normalized = COMMON_PATTERNS.whitespace_multiple.sub(space_char, normalized)

    collapsed: list[str] = []
    last_end = 0
    for match in LANGUAGE_DETECTION_OBFUSCATION_PATTERN.finditer(normalized):
        collapsed.append(normalized[last_end : match.start()])
        collapsed.append(LANGUAGE_DETECTION_SEPARATORS.sub(empty_char, match.group(0)))
        last_end = match.end()
    collapsed.append(normalized[last_end:])
    normalized = "".join(collapsed).strip()

    has_cyrillic = any(0x0400 <= ord(ch) <= 0x04FF for ch in normalized)
    if not has_cyrillic:
        for lookalike, replacement in LANGUAGE_DETECTION_LOOKALIKE_CHARS:
            if lookalike in normalized:
                normalized = normalized.replace(lookalike, replacement)
    return normalized


def has_language_script_mixing(text: str) -> bool:
    scripts: set[str] = set()
    for ch in text:
        code = ord(ch)
        if 0x0000 <= code <= 0x007F:
            scripts.add("Latin")
        elif 0x0400 <= code <= 0x04FF:
            scripts.add("Cyrillic")
        elif 0x0370 <= code <= 0x03FF:
            scripts.add("Greek")
        elif 0x0590 <= code <= 0x05FF:
            scripts.add("Hebrew")
        elif 0x0600 <= code <= 0x06FF:
            scripts.add("Arabic")
        elif 0x4E00 <= code <= 0x9FFF:
            scripts.add("CJK")
        elif 0x3040 <= code <= 0x309F:
            scripts.add("Hiragana")
        elif 0x30A0 <= code <= 0x30FF:
            scripts.add("Katakana")
        elif 0x0900 <= code <= 0x097F:
            scripts.add("Devanagari")
    return len(scripts) > 1


def detect_lookalike_chars(text: str) -> bool:
    return any(lookalike in text for lookalike, _ in LANGUAGE_DETECTION_LOOKALIKE_CHARS)
