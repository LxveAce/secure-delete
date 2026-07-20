"""The honesty contract is the thing under test: no bare 'unrecoverable', SSD stays honest."""
from secure_delete.result import Media, Method, build_claim, residuals_for


def test_ssd_overwrite_is_honest_best_effort():
    claim = build_claim(Media.SSD_FLASH, Method.OVERWRITE).lower()
    assert "best-effort" in claim
    assert "not a guarantee" in claim
    assert "crypto-erase" in claim  # points to the robust alternative


def test_hdd_overwrite_scoped_to_current_blocks():
    claim = build_claim(Media.HDD, Method.OVERWRITE).lower()
    assert "current" in claim and "blocks" in claim
    # HDD overwrite may say recovery is infeasible, but only for THIS file's current blocks — never a blanket promise.


def test_crypto_erase_claim_is_conditional():
    claim = build_claim(Media.SSD_FLASH, Method.CRYPTO_ERASE).lower()
    assert "if the data was encrypted" in claim or "only as strong as" in claim


def test_cow_residual_mentions_snapshots():
    r = " ".join(residuals_for(Media.HDD, "btrfs", cow=True)).lower()
    assert "snapshot" in r


def test_ssd_residual_mentions_spare_nand():
    r = " ".join(residuals_for(Media.SSD_FLASH, "ext4", cow=False)).lower()
    assert "over-provision" in r or "spare" in r


def test_ntfs_residual_mentions_shadow_copies():
    r = " ".join(residuals_for(Media.HDD, "ntfs", cow=False)).lower()
    assert "vss" in r or "shadow" in r
