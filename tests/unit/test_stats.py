"""Feature mathematics. Exact expected values, no fixtures, no randomness."""

from __future__ import annotations

import math

import pytest

from sih_ntd.features import stats


def test_entropy_of_uniform_distribution_is_log2_k():
    assert stats.shannon_entropy({"a": 1, "b": 1, "c": 1, "d": 1}) == pytest.approx(2.0)
    assert stats.shannon_entropy({"a": 1}) == 0.0
    assert stats.shannon_entropy({}) == 0.0


def test_normalised_entropy_is_scale_free():
    """The point of normalising: 4 uniform sources and 1000 uniform sources both == 1."""
    assert stats.normalised_entropy({str(i): 1 for i in range(4)}) == pytest.approx(1.0)
    assert stats.normalised_entropy({str(i): 1 for i in range(1000)}) == pytest.approx(1.0)
    assert stats.normalised_entropy({"only": 5}) == 0.0


def test_char_entropy_rises_with_randomness():
    assert stats.char_entropy("aaaaaaaa") == 0.0
    assert stats.char_entropy("kq3x9zvb") > 2.5


def test_coefficient_of_variation():
    assert stats.coefficient_of_variation([10, 10, 10]) == 0.0
    assert stats.coefficient_of_variation([]) == 0.0
    assert stats.coefficient_of_variation([1, 2, 3, 4]) == pytest.approx(
        stats.stdev([1, 2, 3, 4]) / 2.5
    )


def test_periodicity_perfect_beacon_scores_one():
    assert stats.periodicity_score([30.0] * 12) == pytest.approx(1.0)


def test_periodicity_scales_down_with_thin_evidence():
    """Three regular gaps are not proof; support must discount them."""
    assert stats.periodicity_score([30.0, 30.0], min_intervals=6) == pytest.approx(1 / 3)
    assert stats.periodicity_score([30.0] * 6, min_intervals=6) == pytest.approx(1.0)


def test_periodicity_falls_with_jitter():
    regular = stats.periodicity_score([30.0, 30.2, 29.8, 30.1, 29.9, 30.0, 30.0])
    jittery = stats.periodicity_score([5.0, 60.0, 12.0, 90.0, 3.0, 45.0, 30.0])
    assert regular > 0.95 > jittery


def test_burstiness_bounds():
    assert stats.burstiness([30.0] * 10) == pytest.approx(-1.0)
    assert stats.burstiness([1.0]) == 0.0
    assert -1.0 <= stats.burstiness([0.001, 0.001, 10.0, 0.001]) <= 1.0


def test_zscore_handles_flat_and_empty_baselines():
    """A flat baseline must not produce an infinite anomaly score."""
    assert stats.zscore(5.0, 0.0, 0.0) == 0.0
    assert math.isfinite(stats.zscore(100.0, 10.0, 0.0))
    assert stats.zscore(12.0, 10.0, 2.0) == pytest.approx(1.0)


def test_ratio_is_bounded_and_defined_at_zero():
    assert stats.ratio(10, 0) == 1e6
    assert stats.ratio(0, 0) == 0.0
    assert stats.ratio(10, 5) == 2.0


def test_normalise_exceedance_anchors_at_threshold():
    assert stats.normalise_exceedance(500, 500) == pytest.approx(0.5)
    assert stats.normalise_exceedance(2000, 500) == pytest.approx(1.0)
    assert stats.normalise_exceedance(250, 500) == pytest.approx(0.25)
    assert stats.normalise_exceedance(0, 500) == 0.0


def test_dns_lexical_features_separate_random_from_dictionary_names():
    dga = stats.dns_lexical_features("kq3x9zvbmwlp.example.com")
    benign = stats.dns_lexical_features("cloudstore.example.com")
    assert dga["dns_char_entropy"] > benign["dns_char_entropy"]
    assert dga["dns_vowel_ratio"] < benign["dns_vowel_ratio"]
    assert set(dga) == set(stats.DNS_LEXICAL_FEATURES)


def test_dns_lexical_payload_excludes_the_registrable_suffix():
    """Otherwise the model learns the TLD instead of the randomness."""
    features = stats.dns_lexical_features("abcdefgh.example.com")
    assert features["dns_payload_length"] == len("abcdefgh")
    assert features["dns_suffix_length"] == len("examplecom")


def test_hex_and_digit_ratios():
    assert stats.hex_ratio("deadbeef") == 1.0
    assert stats.digit_ratio("ab12") == 0.5
    assert stats.longest_consonant_run("strength") == 4  # n,g,t,h
