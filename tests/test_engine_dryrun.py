"""Safety is the thing under test: plan() is read-only, execute() + methods are guarded."""
import pytest

from secure_delete import engine, methods
from secure_delete.detect import TargetInfo


def test_plan_is_readonly_and_dryrun(tmp_path):
    f = tmp_path / "secret.txt"
    f.write_text("sensitive")
    res = engine.plan(str(f))
    assert res.performed is False
    assert f.read_text() == "sensitive"  # plan() never touched the file
    assert res.claim                      # produced an honest claim


def test_execute_is_gated(tmp_path):
    f = tmp_path / "x.txt"
    f.write_text("x")
    res = engine.plan(str(f))
    with pytest.raises(methods.DestructionNotEnabled):
        engine.execute(res, confirm_token="yes")
    assert f.read_text() == "x"  # nothing destroyed


def test_all_erase_methods_are_guarded():
    info = TargetInfo(path="/tmp/x")
    for fn in (methods.overwrite_file, methods.crypto_erase, methods.freespace_wipe, methods.whole_drive_sanitize):
        with pytest.raises(methods.DestructionNotEnabled):
            fn(info)
