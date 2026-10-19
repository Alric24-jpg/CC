from tempdrop.security import create_pin_digest, sanitize_filename, verify_pin


def test_pin_digest_is_not_plaintext_and_verifies():
    digest = create_pin_digest("23456789ABCD", "0427")
    assert digest != "0427"
    assert len(digest) == 64
    assert verify_pin("23456789ABCD", "0427", digest)
    assert not verify_pin("23456789ABCD", "0428", digest)
    assert not verify_pin("23456789ABCD", "bad!", digest)


def test_filename_sanitization_blocks_paths_and_reserved_names():
    assert sanitize_filename(r"..\..\secret.txt") == "secret.txt"
    assert sanitize_filename("../../NUL.txt").startswith("_NUL")
    assert "/" not in sanitize_filename("folder/name.txt")
    assert "\\" not in sanitize_filename(r"folder\name.txt")
    assert sanitize_filename("\x00\x01") == "file"
    assert len(sanitize_filename("x" * 300)) <= 180
