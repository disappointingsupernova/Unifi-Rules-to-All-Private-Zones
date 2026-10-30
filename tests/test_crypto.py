"""Unit tests for the AES-256-GCM backup encryption module."""

import pytest
from src.unifi_manager.crypto import encrypt_backup, decrypt_backup


def test_roundtrip():
    data = b"unifi backup data"
    password = "correct-horse-battery-staple"
    encrypted = encrypt_backup(data, password)
    assert encrypted != data
    assert decrypt_backup(encrypted, password) == data


def test_wrong_password_raises():
    data = b"sensitive config"
    encrypted = encrypt_backup(data, "right-password")
    with pytest.raises(ValueError, match="Decryption failed"):
        decrypt_backup(encrypted, "wrong-password")


def test_invalid_magic_raises():
    with pytest.raises(ValueError, match="Not a valid encrypted backup file"):
        decrypt_backup(b"not-a-valid-file", "any-password")


def test_encrypted_output_is_longer_than_input():
    data = b"x" * 100
    encrypted = encrypt_backup(data, "password")
    assert len(encrypted) > len(data)


def test_each_encryption_produces_unique_ciphertext():
    data = b"same data"
    password = "same-password"
    assert encrypt_backup(data, password) != encrypt_backup(data, password)
