import re

LANGUAGE_DETECTION_LOOKALIKE_CHARS: tuple[tuple[str, str], ...] = (
    ("а", "a"),
    ("е", "e"),
    ("о", "o"),
    ("р", "p"),
    ("с", "c"),
    ("х", "x"),
    ("А", "A"),
    ("В", "B"),
    ("Е", "E"),
    ("К", "K"),
    ("М", "M"),
    ("О", "O"),
    ("α", "a"),
    ("ο", "o"),
    ("ρ", "p"),
    ("Α", "A"),
    ("Β", "B"),
    ("Ο", "O"),
)

LANGUAGE_DETECTION_COMBINING_DIACRITICS = re.compile(r"[\u0300-\u036f]")
LANGUAGE_DETECTION_COMMON_PUNCTUATION = re.compile(r"[:;,!?]")
LANGUAGE_DETECTION_OPERATORS_AND_PIPES = re.compile(r"[|&<>]")
LANGUAGE_DETECTION_OBFUSCATION_PATTERN = re.compile(r"(\w)(?:[-._]+\w)+", re.UNICODE)
LANGUAGE_DETECTION_SEPARATORS = re.compile(r"[-._|]+")
