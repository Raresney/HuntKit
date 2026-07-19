import pytest

from huntkit.utils import filesystem as fs


def test_write_and_read_roundtrip(tmp_path):
    p = tmp_path / "a" / "b.txt"
    fs.write_text(p, "héllo — wörld\n")  # non-ascii must survive
    assert fs.read_text(p) == "héllo — wörld\n"


def test_read_missing_returns_default(tmp_path):
    assert fs.read_text(tmp_path / "nope.txt") == ""
    assert fs.read_text(tmp_path / "nope.txt", default="x") == "x"


def test_append_unique_dedupes_and_counts(tmp_path):
    p = tmp_path / "subs.txt"
    assert fs.append_unique(p, ["b.com", "a.com", "a.com"]) == 2
    assert fs.read_lines(p) == ["a.com", "b.com"]  # sorted + unique
    assert fs.append_unique(p, ["a.com", "c.com"]) == 1  # only c.com is new
    assert fs.read_lines(p) == ["a.com", "b.com", "c.com"]


def test_append_unique_empty_input(tmp_path):
    p = tmp_path / "e.txt"
    assert fs.append_unique(p, []) == 0
    assert not p.exists()


def test_safe_join_allows_inside(tmp_path):
    got = fs.safe_join(tmp_path, "recon", "subs.txt")
    assert str(got).startswith(str(tmp_path.resolve()))


def test_safe_join_blocks_traversal(tmp_path):
    with pytest.raises(ValueError):
        fs.safe_join(tmp_path, "..", "..", "etc", "passwd")


def test_atomic_write_leaves_no_tmp(tmp_path):
    p = tmp_path / "x.txt"
    fs.write_text(p, "data")
    leftovers = list(tmp_path.glob("*.tmp"))
    assert leftovers == []


def test_human_size():
    assert fs.human_size(500) == "500B"
    assert fs.human_size(1536) == "1.5KB"
    assert fs.human_size(5 * 1024 * 1024) == "5.0MB"
