"""The honest routing matrix: overwrite only on HDD + in-place FS; everything else -> crypto-erase."""
from secure_delete.detect import TargetInfo
from secure_delete.engine import choose_method
from secure_delete.result import Media, Method


def _info(media, cow=False, fs="ext4"):
    return TargetInfo(path="/x", media=media, filesystem=fs, cow=cow)


def test_hdd_inplace_routes_to_overwrite():
    assert choose_method(_info(Media.HDD, cow=False)) is Method.OVERWRITE


def test_ssd_routes_to_crypto_erase():
    assert choose_method(_info(Media.SSD_FLASH)) is Method.CRYPTO_ERASE


def test_cow_hdd_routes_to_crypto_erase():
    # even on an HDD, a copy-on-write FS makes overwrite unreliable -> crypto-erase
    assert choose_method(_info(Media.HDD, cow=True, fs="btrfs")) is Method.CRYPTO_ERASE


def test_unknown_media_routes_to_crypto_erase():
    assert choose_method(_info(Media.UNKNOWN)) is Method.CRYPTO_ERASE


def test_explicit_method_is_honored():
    assert choose_method(_info(Media.HDD), requested="freespace_wipe") is Method.FREESPACE_WIPE
