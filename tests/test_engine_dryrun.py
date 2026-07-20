"""plan() is read-only; execute() refuses without an exact-match confirmation."""
import pytest

from secure_delete import engine, guards


def test_plan_is_readonly_and_dryrun(tmp_path):
    f = tmp_path / "secret.txt"
    f.write_text("sensitive")
    res = engine.plan(str(f))
    assert res.performed is False
    assert f.read_text() == "sensitive"  # plan() never touched the file
    assert res.claim


def test_execute_without_confirmation_refuses_and_keeps_the_file(tmp_path):
    f = tmp_path / "x.txt"
    f.write_text("x")
    plan = engine.plan(str(f), method="overwrite")  # force overwrite so we reach the confirmation gate
    with pytest.raises(guards.ConfirmationRequired):
        engine.execute(plan, confirm=None)
    with pytest.raises(guards.ConfirmationRequired):
        engine.execute(plan, confirm="yes")  # a generic 'yes' is not enough — must equal the exact path
    assert f.read_text() == "x"  # nothing destroyed


def test_advisory_methods_run_nothing(tmp_path):
    f = tmp_path / "d.txt"
    f.write_text("d")
    san = engine.advise_sanitize(str(f))
    cry = engine.advise_crypto(str(f))
    assert san.performed is False and cry.performed is False
    assert "ADVISORY" in san.claim and "ADVISORY" in cry.claim
    assert f.read_text() == "d"  # advisories touch nothing
