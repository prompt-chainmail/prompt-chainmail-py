from prompt_chainmail import Chainmails


def test_basic_preset_allows_benign() -> None:
    result = Chainmails.basic().protect("What is the weather like today?")
    assert result.success
    assert result.context.confidence > 0.3


def test_strict_preset_has_expected_length() -> None:
    mail = Chainmails.strict()
    assert mail.length == 14


def test_advanced_preset_has_expected_length() -> None:
    assert Chainmails.advanced().length == 14


def test_development_adds_logger() -> None:
    assert Chainmails.development().length == 15
