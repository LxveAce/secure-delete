"""The safety guards that keep destruction from hitting the wrong thing."""
import os
import sys

import pytest

from secure_delete import guards


def test_accepts_a_normal_file(tmp_path):
    # also the M5 regression: a normal user file must be ACCEPTED (previously '/' as an ancestor refused everything on Linux)
    f = tmp_path / "ok.txt"
    f.write_text("x")
    assert guards.check_file_target(str(f)).is_file()


def test_is_volume_root_detects_drive_root(tmp_path):
    from pathlib import Path
    anchor = Path(str(tmp_path)).anchor  # 'C:\\' or '/'
    assert guards._is_volume_root(Path(anchor))
    assert not guards._is_volume_root(tmp_path)


def test_refuses_a_file_directly_in_a_volume_root():
    cands = ([r"C:\bootmgr", r"C:\pagefile.sys", r"C:\BOOTNXT"] if sys.platform.startswith("win")
             else ["/vmlinuz", "/initrd.img"])
    target = next((c for c in cands if os.path.exists(c)), None)
    if target is None:
        pytest.skip("no volume-root file present to test")
    with pytest.raises(guards.UnsafeTarget):
        guards.check_file_target(target)


def test_refuses_missing(tmp_path):
    with pytest.raises(guards.UnsafeTarget):
        guards.check_file_target(str(tmp_path / "nope"))


def test_refuses_directory(tmp_path):
    with pytest.raises(guards.UnsafeTarget):
        guards.check_file_target(str(tmp_path))


def test_refuses_protected_system_root():
    if sys.platform.startswith("win"):
        target = os.path.join(os.environ.get("SystemRoot", r"C:\Windows"), "notepad.exe")
    else:
        target = "/etc/hostname"
    if not os.path.exists(target):
        pytest.skip("no protected-root sample file present")
    with pytest.raises(guards.UnsafeTarget):
        guards.check_file_target(target)


def test_require_confirmation_needs_exact_match(tmp_path):
    f = tmp_path / "c.txt"
    f.write_text("x")
    rp = guards.check_file_target(str(f))
    with pytest.raises(guards.ConfirmationRequired):
        guards.require_confirmation(rp, None)
    with pytest.raises(guards.ConfirmationRequired):
        guards.require_confirmation(rp, "wrong")
    guards.require_confirmation(rp, guards.confirmation_token(rp))  # exact -> no raise
