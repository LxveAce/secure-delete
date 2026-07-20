"""Real erasure on THROWAWAY files only, the best-effort refusal, the internal gate, and free-space."""
import pytest

from secure_delete import engine, guards, methods
from secure_delete.detect import TargetInfo
from secure_delete.result import Media, Method, ScopedResult


def test_execute_overwrite_erases_the_file(tmp_path):
    f = tmp_path / "burn.txt"
    f.write_text("top secret payload " * 100)
    plan = engine.plan(str(f), method="overwrite")  # force overwrite (this box may be SSD)
    rp = guards.check_file_target(str(f))
    res = engine.execute(plan, confirm=guards.confirmation_token(rp))  # confirm == the resolved path
    assert res.performed is True
    assert not f.exists()  # the file is gone
    assert "burn.txt" not in [p.name for p in tmp_path.iterdir()]  # name obscured (best-effort)


def test_besteffort_plan_is_refused_then_overwrite_forces_it(tmp_path):
    f = tmp_path / "s.txt"
    f.write_text("x")
    rp = guards.check_file_target(str(f))
    auto = engine.plan(str(f))  # auto routing (crypto_erase on SSD/CoW/unknown)
    if auto.method is Method.OVERWRITE:
        pytest.skip("target routed to overwrite (HDD) — best-effort refusal not applicable")
    with pytest.raises(guards.BestEffortRefused):
        engine.execute(auto, confirm=guards.confirmation_token(rp))
    assert f.exists()  # a crypto_erase-labeled plan does NOT silently delete
    forced = engine.plan(str(f), method="overwrite")
    res = engine.execute(forced, confirm=guards.confirmation_token(rp))
    assert res.performed and not f.exists()


def test_execute_without_exact_confirm_keeps_the_file(tmp_path):
    f = tmp_path / "keep.txt"
    f.write_text("x")
    plan = engine.plan(str(f), method="overwrite")
    with pytest.raises(guards.ConfirmationRequired):
        engine.execute(plan, confirm="yes")  # a generic 'yes' is not the exact path
    assert f.read_text() == "x"


def test_execute_refuses_a_directory(tmp_path):
    d = tmp_path / "adir"
    d.mkdir()
    plan = ScopedResult(target=str(d), media=Media.HDD, filesystem="x", method=Method.OVERWRITE)
    with pytest.raises(guards.UnsafeTarget):
        engine.execute(plan, confirm=str(d.resolve()))
    assert d.exists()


def test_execute_refuses_missing_file(tmp_path):
    missing = tmp_path / "nope.txt"
    plan = ScopedResult(target=str(missing), media=Media.HDD, filesystem="x", method=Method.OVERWRITE)
    with pytest.raises(guards.UnsafeTarget):
        engine.execute(plan, confirm=str(missing))


def test_methods_require_internal_flag(tmp_path):
    f = tmp_path / "a.txt"
    f.write_text("x")
    rp = guards.check_file_target(str(f))
    info = TargetInfo(path=str(rp), media=Media.HDD, filesystem="x")
    with pytest.raises(RuntimeError):
        methods.overwrite_file(rp, info)  # no _internal -> refuse
    assert f.exists()  # untouched
    with pytest.raises(RuntimeError):
        methods.freespace_wipe(info, tmp_path)  # no _internal -> refuse


def test_freespace_method_writes_and_cleans_up(tmp_path):
    info = TargetInfo(path=str(tmp_path), media=Media.UNKNOWN, filesystem="ntfs")
    res = methods.freespace_wipe(info, tmp_path, margin_bytes=1 << 20, max_bytes=2 << 20, _internal=True)
    assert res.performed is True
    assert not (tmp_path / ".secure-delete-freespace-tmp").exists()  # fill cleaned up


def test_execute_freespace_refuses_system_volume(tmp_path):
    if not guards.is_system_volume(str(tmp_path)):
        pytest.skip("tmp is not on the system volume in this environment")
    rp = guards.check_dir_target(str(tmp_path))
    with pytest.raises(guards.UnsafeTarget):
        engine.execute_freespace(str(tmp_path), confirm=guards.confirmation_token(rp))  # no --allow-system-volume
