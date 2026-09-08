from __future__ import annotations

from dataclasses import dataclass
from unicodedata import normalize

DEFAULT_WINDOW_SIZE = 1024
DEFAULT_WINDOW_STRIDE = 768

_UNICODE_WHITESPACE = frozenset(
    {
        "\u0009",
        "\u000a",
        "\u000b",
        "\u000c",
        "\u000d",
        "\u0020",
        "\u0085",
        "\u00a0",
        "\u1680",
        "\u2000",
        "\u2001",
        "\u2002",
        "\u2003",
        "\u2004",
        "\u2005",
        "\u2006",
        "\u2007",
        "\u2008",
        "\u2009",
        "\u200a",
        "\u2028",
        "\u2029",
        "\u202f",
        "\u205f",
        "\u3000",
    }
)


@dataclass(slots=True)
class ClassifierWindow:
    bytes: bytes
    start: int
    end: int


def _replace_lone_surrogates(text: str) -> str:
    return "".join("\ufffd" if 0xD800 <= ord(ch) <= 0xDFFF else ch for ch in text)


def normalize_classifier_text(text: str) -> str:
    """Lone surrogates → U+FFFD, NFKC, unicode whitespace → space, lowercase.

    Trims at most one leading and one trailing ASCII space after collapse.
    """
    nfkc = normalize("NFKC", _replace_lone_surrogates(text))

    collapsed: list[str] = []
    in_ws = False
    for ch in nfkc:
        if ch in _UNICODE_WHITESPACE:
            if not in_ws:
                collapsed.append(" ")
                in_ws = True
        else:
            collapsed.append(ch)
            in_ws = False

    lower = "".join(collapsed).lower()
    if lower.startswith(" "):
        lower = lower[1:]
    if lower.endswith(" "):
        lower = lower[:-1]
    return lower


def _is_continuation_byte(value: int) -> bool:
    return (value & 0b1100_0000) == 0b1000_0000


def window_classifier_ranges(
    text: str,
    size: int = DEFAULT_WINDOW_SIZE,
    stride: int = DEFAULT_WINDOW_STRIDE,
) -> list[ClassifierWindow]:
    if size <= 0 or stride <= 0:
        raise ValueError("size and stride must be positive integers")

    encoded = normalize_classifier_text(text).encode("utf-8")
    windows: list[ClassifierWindow] = []
    previous_start = -1
    nominal_start = 0

    while nominal_start < len(encoded):
        start = nominal_start
        while start > 0 and _is_continuation_byte(encoded[start]):
            start -= 1

        if start == previous_start:
            nominal_start += stride
            continue

        end = min(start + size, len(encoded))
        while end < len(encoded) and end > start and _is_continuation_byte(encoded[end]):
            end -= 1

        if end == start:
            raise ValueError("size is too small for a UTF-8 code point")

        windows.append(ClassifierWindow(bytes=encoded[start:end], start=start, end=end))
        previous_start = start

        if end == len(encoded):
            break

        nominal_start += stride

    return windows


def window_classifier_bytes(
    text: str,
    size: int = DEFAULT_WINDOW_SIZE,
    stride: int = DEFAULT_WINDOW_STRIDE,
) -> list[bytes]:
    return [window.bytes for window in window_classifier_ranges(text, size, stride)]


def default_window_params() -> tuple[int, int]:
    return (DEFAULT_WINDOW_SIZE, DEFAULT_WINDOW_STRIDE)
