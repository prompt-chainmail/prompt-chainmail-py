from __future__ import annotations

from dataclasses import dataclass

from lingua import IsoCode639_3, Language, LanguageDetectorBuilder

from prompt_chainmail.shared.language_detection.normalize import normalize_text


@dataclass(slots=True)
class DetectOptions:
    only: list[str] | None = None
    ignore: list[str] | None = None


def _iso3(language: Language) -> str:
    return language.iso_code_639_3.name.lower()


class LanguageDetector:
    def detect(self, text: str, options: DetectOptions | None = None) -> list[tuple[str, float]]:
        normalized = normalize_text(text)
        if not normalized:
            return [("und", 1.0)]

        builder = LanguageDetectorBuilder.from_all_languages()
        if options and options.only:
            langs = [lang for lang in Language.all() if _iso3(lang) in options.only]
            if langs:
                builder = LanguageDetectorBuilder.from_languages(*langs)
        elif options and options.ignore:
            deny = {code.lower() for code in options.ignore}
            langs = [lang for lang in Language.all() if _iso3(lang) not in deny]
            if langs:
                builder = LanguageDetectorBuilder.from_languages(*langs)

        detector = builder.build()
        confidence_values = detector.compute_language_confidence_values(normalized)
        if not confidence_values:
            return [("und", 1.0)]
        ranked = [(_iso3(item.language), float(item.value)) for item in confidence_values]
        ranked.sort(key=lambda pair: pair[1], reverse=True)
        return ranked or [("und", 1.0)]


# Keep IsoCode639_3 imported so type checkers see lingua usage if needed.
_ = IsoCode639_3
