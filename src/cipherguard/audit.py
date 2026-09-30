"""Educational password-application configuration audit rules."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any


@dataclass(frozen=True)
class Finding:
    severity: str
    code: str
    message: str
    remediation: str

    def to_dict(self) -> dict[str, str]:
        return asdict(self)


def audit_config(config: dict[str, Any]) -> list[Finding]:
    """Inspect a simplified deployment configuration for common risks."""
    findings: list[Finding] = []
    algorithm = str(config.get("encryption_algorithm", "")).upper()
    mode = str(config.get("block_mode", "")).upper()
    tls = str(config.get("minimum_tls", ""))

    if algorithm in {"DES", "3DES", "RC4", "MD5", "SHA1"}:
        findings.append(Finding("high", "CG-A01", f"检测到弱算法：{algorithm}", "改用经过批准的现代算法并迁移历史数据。"))
    if mode == "ECB":
        findings.append(Finding("high", "CG-A02", "ECB模式会泄露明文结构", "改用带唯一Nonce的认证加密模式，如AES-GCM。"))
    if tls and tls not in {"1.2", "1.3"}:
        findings.append(Finding("high", "CG-P01", f"最低TLS版本过低：{tls}", "至少启用TLS 1.2，并优先评估TLS 1.3。"))
    if config.get("hardcoded_key") is True:
        findings.append(Finding("critical", "CG-K01", "密钥被硬编码在应用配置中", "迁移到受控密钥管理系统，执行密钥轮换并限制访问。"))
    if not config.get("key_rotation_days"):
        findings.append(Finding("medium", "CG-K02", "未定义密钥轮换周期", "根据业务和风险制定密钥生命周期及轮换策略。"))
    if config.get("audit_logging") is not True:
        findings.append(Finding("medium", "CG-O01", "关键密码操作未启用审计日志", "记录密钥管理、解密、签名和配置变更事件并保护日志完整性。"))
    if config.get("certificate_validation") is not True:
        findings.append(Finding("high", "CG-P02", "未强制验证通信对端证书", "验证证书链、主机名、有效期和吊销状态。"))
    return findings

