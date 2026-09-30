"""Command-line interface for the lab."""

from __future__ import annotations

import argparse
import getpass
import json
from pathlib import Path

from .audit import audit_config
from .core import decrypt_bytes, encrypt_bytes, generate_signing_key, sign_bytes, verify_bytes


def _password() -> str:
    return getpass.getpass("输入口令（至少10个字符）：")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="cipherguard", description="密码应用安全小型实验平台")
    sub = parser.add_subparsers(dest="command", required=True)

    encrypt = sub.add_parser("encrypt", help="AES-256-GCM认证加密文件")
    encrypt.add_argument("input", type=Path)
    encrypt.add_argument("output", type=Path)

    decrypt = sub.add_parser("decrypt", help="认证并解密文件")
    decrypt.add_argument("input", type=Path)
    decrypt.add_argument("output", type=Path)

    keygen = sub.add_parser("keygen", help="生成RSA-3072签名密钥")
    keygen.add_argument("private", type=Path)
    keygen.add_argument("public", type=Path)

    sign = sub.add_parser("sign", help="使用RSA-PSS/SHA-256签名")
    sign.add_argument("input", type=Path)
    sign.add_argument("private", type=Path)
    sign.add_argument("signature", type=Path)

    verify = sub.add_parser("verify", help="验证RSA-PSS签名")
    verify.add_argument("input", type=Path)
    verify.add_argument("public", type=Path)
    verify.add_argument("signature", type=Path)

    audit = sub.add_parser("audit", help="审计简化的密码应用配置")
    audit.add_argument("config", type=Path)
    return parser


def main() -> int:
    args = build_parser().parse_args()
    if args.command == "encrypt":
        args.output.write_bytes(encrypt_bytes(args.input.read_bytes(), _password()))
        print(f"已生成认证密文：{args.output}")
    elif args.command == "decrypt":
        args.output.write_bytes(decrypt_bytes(args.input.read_bytes(), _password()))
        print(f"认证通过并完成解密：{args.output}")
    elif args.command == "keygen":
        private, public = generate_signing_key()
        args.private.write_bytes(private)
        args.public.write_bytes(public)
        print("RSA-3072密钥对已生成。请妥善保护私钥。")
    elif args.command == "sign":
        args.signature.write_bytes(sign_bytes(args.input.read_bytes(), args.private.read_bytes()))
        print(f"签名已生成：{args.signature}")
    elif args.command == "verify":
        valid = verify_bytes(args.input.read_bytes(), args.signature.read_bytes(), args.public.read_bytes())
        print("签名有效" if valid else "签名无效")
        return 0 if valid else 1
    elif args.command == "audit":
        findings = audit_config(json.loads(args.config.read_text(encoding="utf-8")))
        print(json.dumps([item.to_dict() for item in findings], ensure_ascii=False, indent=2))
        return 1 if findings else 0
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

