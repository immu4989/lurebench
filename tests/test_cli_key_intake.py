"""CLI key intake uses the bounded file boundary without unsigned fallback."""

import os
from argparse import Namespace

import pytest

from lurebench.cli import _cmd_aggregate_receipts, _cmd_verify_receipt, _read_bounded_key


def test_key_size_and_nonregular_intake(tmp_path):
    target = tmp_path / "key.pem"
    target.write_bytes(b"x" * (64 * 1024))
    assert len(_read_bounded_key(str(target))) == 64 * 1024
    target.write_bytes(b"x" * (64 * 1024 + 1))
    with pytest.raises(ValueError, match="bounded size"):
        _read_bounded_key(str(target))
    alias = tmp_path / "alias.pem"
    alias.symlink_to(target)
    with pytest.raises(ValueError, match="non-symlink"):
        _read_bounded_key(str(alias))
    target.write_bytes(b"")
    with pytest.raises(ValueError):
        _read_bounded_key(str(target))


@pytest.mark.skipif(os.name != "posix", reason="POSIX private permissions")
def test_private_key_requires_owner_only_permissions_but_public_key_does_not(tmp_path):
    target = tmp_path / "key.pem"
    target.write_bytes(b"synthetic key")
    target.chmod(0o644)
    assert _read_bounded_key(str(target)) == b"synthetic key"
    with pytest.raises(ValueError, match="group or world"):
        _read_bounded_key(str(target), private=True)
    target.chmod(0o600)
    assert _read_bounded_key(str(target), private=True) == b"synthetic key"


def test_empty_explicit_key_paths_do_not_fall_back_to_unsigned(tmp_path, monkeypatch, capsys):
    import lurebench.receipts as receipts

    monkeypatch.setattr(receipts, "load_verified_artifact",
                        lambda *a, **kw: pytest.fail("artifact read before key preflight"))
    assert _cmd_verify_receipt(Namespace(public_key="", artifact="unused",
                                        require_signature=False)) == 1
    assert "nonempty" in capsys.readouterr().err
    output = tmp_path / "absent.json"
    assert _cmd_aggregate_receipts(Namespace(signing_key="", source_key=[], receipt=[],
                                            out=str(output))) == 1
    assert "nonempty" in capsys.readouterr().err
    assert not output.exists()
