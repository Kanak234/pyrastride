"""Tests for the original STRIDE-mapping logic."""
from pyrastride.stride_map import STRIDE, category_weight, map_finding


def test_secret_maps_to_disclosure_and_elevation():
    m = map_finding("SEC001", "Hardcoded AWS secret key found")
    assert "INFORMATION_DISCLOSURE" in m.categories
    assert "ELEVATION_OF_PRIVILEGE" in m.categories
    assert m.matched_on  # transparency: something triggered it


def test_privileged_container_is_elevation():
    m = map_finding("SEC050", "Privileged container allows host escape")
    assert m.categories[0] == "ELEVATION_OF_PRIVILEGE"


def test_logging_disabled_is_repudiation():
    m = map_finding("SEC090", "Audit logging disabled on the bucket")
    assert m.categories == ("REPUDIATION",)


def test_unmatched_is_unknown_not_forced():
    m = map_finding("SEC999", "something with xyzzy plugh foobar")
    assert m.categories == ("UNKNOWN",)
    assert m.matched_on == ""


def test_elevation_outranks_repudiation():
    assert category_weight("ELEVATION_OF_PRIVILEGE") > category_weight("REPUDIATION")


def test_all_six_stride_categories_present():
    assert set(STRIDE) == {
        "SPOOFING", "TAMPERING", "REPUDIATION",
        "INFORMATION_DISCLOSURE", "DENIAL_OF_SERVICE", "ELEVATION_OF_PRIVILEGE",
    }


def test_unknown_weight_is_low_but_nonzero():
    w = category_weight("UNKNOWN")
    assert 0 < w < category_weight("REPUDIATION")
