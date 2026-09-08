from prompt_chainmail import (
    PromptChainmail,
    Rivets,
    detect_lookalike_chars,
    has_language_script_mixing,
    normalize_text,
)


def test_normalize_strips_diacritics_and_lowercases() -> None:
    assert normalize_text("café résumé naïve") == normalize_text("cafe resume naive")
    assert normalize_text("HELLO WORLD") == "hello world"


def test_normalize_collapses_obfuscation() -> None:
    assert normalize_text("o-v-e-r-r-i-d-e") == "override"


def test_normalize_greek_lookalikes_without_cyrillic() -> None:
    assert normalize_text("hεllo wοrld") == "hεllo world"


def test_script_mixing_and_lookalikes() -> None:
    assert has_language_script_mixing("hello мир")
    assert not has_language_script_mixing("hello world")
    assert detect_lookalike_chars("а")
    assert not detect_lookalike_chars("a")


def test_language_detection_rivet_sets_metadata() -> None:
    result = PromptChainmail().forge(Rivets.language_detection()).protect("Hello world")
    detected = result.context.metadata["detected_languages"]
    assert isinstance(detected, list)
    assert detected
    assert detected[0][0]
