"""Small, auditable cryptographic building blocks for training.

This module deliberately relies on the maintained ``cryptography`` package
instead of implementing production primitives by hand.
"""

from __future__ import annotations

import base64
import json
import os
from typing import Any

from cryptography.exceptions import InvalidSignature, InvalidTag
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt


FORMAT_VERSION = 1
AAD = b"cipherguard-mini-lab:v1"
SCRYPT_N = 2**14
SCRYPT_R = 8
SCRYPT_P = 1


class DecryptionError(ValueError):
    """Raised when an envelope cannot be authenticated or decoded."""


def _b64(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode("ascii")


def _unb64(value: str) -> bytes:
    return base64.urlsafe_b64decode(value.encode("ascii"))


def _derive_key(password: str, salt: bytes, *, n: int = SCRYPT_N) -> bytes:
    if len(password) < 10:
        raise ValueError("密码至少需要10个字符")
    kdf = Scrypt(salt=salt, length=32, n=n, r=SCRYPT_R, p=SCRYPT_P)
    return kdf.derive(password.encode("utf-8"))


def encrypt_bytes(plaintext: bytes, password: str) -> bytes:
    """Encrypt bytes with Scrypt-derived AES-256-GCM and fresh randomness."""
    salt = os.urandom(16)
    nonce = os.urandom(12)
    key = _derive_key(password, salt)
    ciphertext = AESGCM(key).encrypt(nonce, plaintext, AAD)
    envelope: dict[str, Any] = {
        "version": FORMAT_VERSION,
        "cipher": "AES-256-GCM",
        "kdf": "scrypt",
        "kdf_params": {"n": SCRYPT_N, "r": SCRYPT_R, "p": SCRYPT_P},
        "salt": _b64(salt),
        "nonce": _b64(nonce),
        "aad": AAD.decode("ascii"),
        "ciphertext": _b64(ciphertext),
    }
    return json.dumps(envelope, ensure_ascii=False, sort_keys=True).encode("utf-8")


def decrypt_bytes(payload: bytes, password: str) -> bytes:
    """Authenticate and decrypt an envelope; reject tampering uniformly."""
    try:
        envelope = json.loads(payload.decode("utf-8"))
        if envelope["version"] != FORMAT_VERSION:
            raise DecryptionError("不支持的密文格式版本")
        if envelope["cipher"] != "AES-256-GCM" or envelope["kdf"] != "scrypt":
            raise DecryptionError("不支持的密码算法组合")
        params = envelope["kdf_params"]
        key = _derive_key(password, _unb64(envelope["salt"]), n=int(params["n"]))
        return AESGCM(key).decrypt(
            _unb64(envelope["nonce"]),
            _unb64(envelope["ciphertext"]),
            envelope["aad"].encode("ascii"),
        )
    except DecryptionError:
        raise
    except (InvalidTag, KeyError, TypeError, ValueError, json.JSONDecodeError) as error:
        raise DecryptionError("密文认证失败：密码错误、文件损坏或数据被篡改") from error


def generate_signing_key() -> tuple[bytes, bytes]:
    """Generate an RSA-3072 signing key pair in PEM format."""
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=3072)
    private_pem = private_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    public_pem = private_key.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return private_pem, public_pem


def sign_bytes(data: bytes, private_pem: bytes) -> bytes:
    private_key = serialization.load_pem_private_key(private_pem, password=None)
    if not isinstance(private_key, rsa.RSAPrivateKey):
        raise TypeError("需要RSA私钥")
    return private_key.sign(
        data,
        padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
        hashes.SHA256(),
    )


def verify_bytes(data: bytes, signature: bytes, public_pem: bytes) -> bool:
    public_key = serialization.load_pem_public_key(public_pem)
    if not isinstance(public_key, rsa.RSAPublicKey):
        raise TypeError("需要RSA公钥")
    try:
        public_key.verify(
            signature,
            data,
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
            hashes.SHA256(),
        )
        return True
    except InvalidSignature:
        return False

