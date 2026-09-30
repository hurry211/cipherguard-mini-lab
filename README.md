# CipherGuard Mini Lab

面向2026年第23届ISCC“密码安全赛”备赛的可运行小型项目。它把密码算法原理、协议安全、部署运维和合规检查放进一个便于审计的Python命令行工具中。

> 本项目用于教学和竞赛训练，不是经认证的商用密码产品，也不替代正式密评。

## 能力映射

- **算法原理**：AES-256-GCM认证加密、Scrypt口令派生、RSA-3072 PSS签名；
- **协议设计**：通过AAD绑定协议上下文，验证篡改必然被拒绝；
- **部署运维**：密钥生成、文件加解密、签名及验签的完整命令行流程；
- **合规检测**：发现弱算法、ECB、旧TLS、硬编码密钥、无轮换、无审计、未验证证书等风险；
- **攻防意识**：测试错误口令、密文篡改、签名对象变化和Nonce唯一性。

## 安全设计

1. 每次加密生成独立的16字节盐和12字节Nonce；
2. 使用Scrypt从口令派生256位密钥；
3. 使用AES-GCM同时提供机密性、完整性和来源认证；
4. 使用AAD绑定密文格式和应用上下文；
5. 使用RSA-PSS与SHA-256签名，避免陈旧的确定性填充；
6. 解密时统一处理认证失败，避免输出未经验证的明文。

## 快速开始

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -e .
python -m unittest discover -s tests -v
```

配置风险审计：

```powershell
cipherguard audit examples\insecure_config.json
```

文件认证加密与解密：

```powershell
cipherguard encrypt README.md demo.enc
cipherguard decrypt demo.enc recovered.md
```

签名与验签：

```powershell
cipherguard keygen private.pem public.pem
cipherguard sign README.md private.pem README.sig
cipherguard verify README.md public.pem README.sig
```

## 项目结构

```text
src/cipherguard/core.py   认证加密、密钥派生、签名与验签
src/cipherguard/audit.py  密码应用配置审计规则
src/cipherguard/cli.py    命令行入口
tests/                    安全性质与回归测试
examples/                 安全/不安全配置样例
docs/                     团队说明和演示记录
```

## 训练延伸

- 增加国密算法接口和数字证书链检查；
- 增加TLS服务端配置扫描；
- 根据GB/T 39786设计分层检查项；
- 构造Nonce复用、错误验签和弱随机数的对抗样例；
- 为每个缺陷形成“发现—验证—修复—复测”的WriteUp。

## 团队分工建议

- 成员A：算法与认证加密实现；
- 成员B：CLI、测试、异常场景与攻防验证；
- 成员C：配置审计规则、文档和合规映射。

## 许可证

MIT License。项目不包含任何真实密钥、账号或业务数据。

