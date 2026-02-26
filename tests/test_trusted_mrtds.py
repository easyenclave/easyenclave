import pytest


def test_trusted_mrtd_upsert_validates_hex():
    from app.storage import trusted_mrtd_store

    with pytest.raises(ValueError, match="96-character hex"):
        trusted_mrtd_store.upsert("not-hex", mrtd_type="agent")

    with pytest.raises(ValueError, match="96-character hex"):
        trusted_mrtd_store.upsert("a" * 95, mrtd_type="agent")

    with pytest.raises(ValueError, match="96-character hex"):
        trusted_mrtd_store.upsert("g" * 96, mrtd_type="agent")


def test_trusted_mrtd_upsert_and_delete_round_trip():
    from app.storage import get_trusted_mrtd, load_trusted_mrtds, trusted_mrtd_store

    mrtd = "a" * 96
    assert get_trusted_mrtd(mrtd) is None

    obj = trusted_mrtd_store.upsert(mrtd, mrtd_type="agent", note="gcp baseline")
    assert obj.mrtd == mrtd
    assert obj.mrtd_type == "agent"

    # In-memory cache should reflect it.
    load_trusted_mrtds()
    assert get_trusted_mrtd(mrtd) == "agent"

    assert trusted_mrtd_store.delete(mrtd) is True
    load_trusted_mrtds()
    assert get_trusted_mrtd(mrtd) is None
