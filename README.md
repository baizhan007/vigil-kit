# VigilKit

零依赖的 .NET Framework 工具集。C# 5 / net48，不引入任何第三方包。

[![tests](https://github.com/baizhan007/vigil-kit/actions/workflows/tests.yml/badge.svg)](https://github.com/baizhan007/vigil-kit/actions/workflows/tests.yml)
[![license](https://img.shields.io/badge/license-MIT-blue)](LICENSE)
[![.NET Framework](https://img.shields.io/badge/.NET%20Framework-4.8-512BD4)](https://dotnet.microsoft.com/download/dotnet-framework)

> 状态：可用。96 项断言全部通过，零编译警告。

---

## 为什么造这个

在 .NET Framework 4.x（一直到 4.8）上写工具时，有几个常用能力**没有托管实现**，而引入第三方库又会带来依赖、体积和分发上的麻烦：

| 需求 | .NET Framework 的处境 |
|---|---|
| AES-GCM | **完全缺失**。`System.Security.Cryptography.AesGcm` 直到 .NET Core 3.0 才出现 |
| 读 SQLite 文件 | 需要 `System.Data.SQLite`（带原生 DLL），或自己解析文件格式 |
| HKDF | `Rfc2898DeriveBytes` 是 PBKDF2，没有 HKDF |
| 不依赖系统的 Zip | `System.IO.Compression.ZipArchive` 在 4.5+ 才有，且需要额外的程序集引用 |
| 轻量 JSON | `System.Text.Json` 是 .NET Core 的；`DataContractJsonSerializer` 笨重 |

VigilKit 把这几个能力用纯托管代码（加少量 P/Invoke）补齐，**每个文件都能单独拷进你的项目用**。

---

## 包含什么

| 模块 | 命名空间 | 行数 | 说明 |
|---|---|---|---|
| SQLite 解析器 | `VigilKit.Sqlite` | 340 | B-tree 全表扫描、全部 serial type、溢出页、变长整数、共享读取 |
| AES-GCM | `VigilKit.Crypto` | 230 | 走 Windows CNG，支持 AAD |
| 密封信封 | `VigilKit.Crypto` | 209 | AES-256-CBC + HMAC-SHA256（Encrypt-then-MAC） |
| HKDF | `VigilKit.Crypto` | 99 | RFC 5869，含 `byte[]` 重载 |
| 通道密钥 | `VigilKit.Crypto` | 54 | 方向隔离的配套密钥派生 |
| 长度分档 | `VigilKit.Crypto` | 204 | 按档位填充，遮蔽密文长度；含 Hex/Base64/摘要工具 |
| JSON | `VigilKit` | 287 | 解析 + 序列化 |
| Zip / CRC32 | `VigilKit.Archive` | 174 | Deflate 压缩与解压 |

合计 8 个源文件、1,422 行。

---

## 快速开始

### SQLite：不装任何东西读取数据库

```csharp
using VigilKit.Sqlite;

using (var reader = new SqliteReader(@"C:\path\to\data.db"))
{
    foreach (string table in reader.TableNames())
        Console.WriteLine(table);

    string schema = reader.CreateSql("users");
    Console.WriteLine(schema);

    foreach (object[] row in reader.ReadTable("users"))
        Console.WriteLine(row[0] + " / " + row[1]);
}
```

也可以直接从内存中的字节读取（例如已经解密或从别处取到的数据）：

```csharp
byte[] data = GetDatabaseBytes();
using (var reader = new SqliteReader(data)) { ... }
```

### AES-GCM：.NET Framework 上缺失的能力

```csharp
using VigilKit.Crypto;

byte[] key   = Digest.RandomBytes(32);
byte[] nonce = Digest.RandomBytes(12);

byte[] sealed = AesGcm.Encrypt(key, nonce, plaintext, associatedData);
byte[] opened = AesGcm.Decrypt(key, nonce, sealed, associatedData);

// 认证失败（数据被篡改、密钥错误）返回 null，不抛异常
if (opened == null) { /* 认证失败 */ }
```

> **注意**：同一个密钥下**绝不能重复使用同一个 nonce**。GCM 的保密性完全依赖这一点。

### 密封信封：完整的加密+认证格式

如果不需要兼容既有格式，用这个更省事——它自带 IV、认证标签和长度填充：

```csharp
using VigilKit.Crypto;

var outbound = ChannelKeys.FromMaster(masterKey, "client->server");
var inbound  = ChannelKeys.FromMaster(masterKey, "server->client");

byte[] envelope = SealedBox.Seal(outbound.EncryptionKey, outbound.AuthenticationKey, payload);
byte[] plain    = SealedBox.Open(inbound.EncryptionKey, inbound.AuthenticationKey, envelope);
```

`ChannelKeys` 保证两个方向的密钥互相独立，因此**上行密文无法被反射当作下行密文使用**。

### HKDF：从一个主密钥派生多个用途隔离的子密钥

```csharp
using VigilKit.Crypto;

byte[] sessionKey = Hkdf.Derive(masterKey, "session/2024-01", 32);
byte[] macKey     = Hkdf.Derive(masterKey, "mac/2024-01", 32);
```

与 RFC 5869 测试向量逐字节一致：

```csharp
byte[] ikm  = /* 0x0b × 22 */;
byte[] salt = /* 0x00..0x0c */;
byte[] info = /* 0xf0..0xf9 */;
byte[] okm  = Hkdf.Derive(ikm, salt, info, 42);
// = 3cb25f25...c5bf34007208d5b887185865
```

### JSON

```csharp
using VigilKit;

var obj = MiniJson.AsObj(MiniJson.Parse(jsonText));
string name = MiniJson.Str(obj, "name", "默认值");
int count   = MiniJson.Int(obj, "count", 0);
bool flag   = MiniJson.Bool(obj, "flag", false);
```

---

## 构建与测试

### 方式一：系统自带的编译器（推荐）

只要有 .NET Framework 4.x 就能跑，不需要 SDK：

```powershell
pwsh -File build.ps1
```

输出：

```
[*] 编译 VigilKit 库
[+] VigilKit.dll 已生成: 25,600 字节
[*] 编译测试程序
[+] VigilKit.Tests.exe 已生成: 23,552 字节
[*] 运行自测
...
全部通过：96 项
[+] 自测通过
```

### 方式二：dotnet SDK

```powershell
dotnet build src/VigilKit/VigilKit.csproj
```

### 测试覆盖

96 项断言，覆盖范围：

| 类别 | 验证内容 |
|---|---|
| HKDF | RFC 5869 官方向量（用例 1 与 3）、确定性、参数校验 |
| 密封信封 | 往返、篡改 IV/密文/MAC 全部被拒、随机 IV、1B–64KB 各长度、误用防护 |
| 通道密钥 | 方向隔离、防反射、密钥独立性 |
| 长度分档 | 档位边界、随机填充、负值拒绝 |
| 编码 | 十六进制、Base64、URL 安全变体往返 |
| 摘要 | SHA-256 / MD5 / SHA-1 标准向量、常数时间比较 |
| JSON | 解析、序列化往返、中文、转义字符 |
| SQLite | 手工构造的库文件、表枚举、建表语句、数据读取、非法输入拒绝 |
| AES-GCM | 往返、篡改拒绝、AAD、空明文 |
| Zip | CRC32 标准向量、Deflate 往返 |

SQLite 的测试夹具是**在代码里手工构造字节**的，不是往仓库里塞二进制文件。布局已用官方 `sqlite3` 模块交叉验证（见 `tests/verify-sqlite-layout.py`）：生成的文件能被官方实现打开并通过 `PRAGMA integrity_check`。

---

## 设计说明

### 为什么不复用同一把密钥做 AES 和 HMAC

`SealedBox.Seal` 要求两个独立的密钥，而不是一个。这是刻意的：

用同一把密钥同时做加密和消息认证在密码学上是**危险的反模式**。AES 和 HMAC 对密钥的要求不同，共用会引入相关性，历史上出现过由此导致的攻击。安全 API（如 TLS 1.3、Noise 协议、libsodium）全都强制分离。

`ChannelKeys.FromMaster` 会一次性派生出配套的两把。

### 为什么填充要走多字节校验

`SealedBox` 在填充区写入三个字节，全部由填充长度推导：

```
padded[L-1] = padLength
padded[L-2] = padLength ^ 0xFF
padded[L-3] = padLength ^ 0xA5
```

正常使用下 MAC 已经保证了完整性，这个校验用不上。它防的是**误用**：有人手工拼错密钥、或者加密密钥和认证密钥不配套时，单靠填充长度校验有约 1/16 的概率会偶然通过，把随机垃圾当成合法明文返回。

三字节把误接受率压到约 **1/50 万**。这一点很重要——两字节校验留下的约 1/2000 概率会让测试套件随机失败，而**会随机失败的测试比没有测试更糟**。加密库的行为必须是统计上稳定可依赖的。

为此填充长度取 3..18 而不是 1..16，保证末尾三个字节总是存在。

### 为什么 P/Invoke 必须声明 `CharSet.Unicode`

BCrypt 系列 API 全部是 Unicode 版本。`DllImport` 的默认 `CharSet` 是 `Ansi`，所以：

```csharp
// 错误：字符串被 marshal 成 ANSI，"AES" 变成单字节
[DllImport("bcrypt.dll")]
static extern int BCryptOpenAlgorithmProvider(out IntPtr h, string algId, string impl, uint flags);

// 正确
[DllImport("bcrypt.dll", CharSet = CharSet.Unicode)]
static extern int BCryptOpenAlgorithmProvider(out IntPtr h, string algId, string impl, uint flags);
```

漏掉这一行，`BCryptOpenAlgorithmProvider` 会返回 `0xC0000225`（`STATUS_NOT_FOUND`）——BCrypt 把单字节的 `"AES"` 按 UTF-16 解析，找的是一个不存在的算法名。

---

## 已知限制

**SQLite 解析器**

- 只读，不支持写入
- 不支持索引（只做全表扫描）
- 不支持 SQLCipher 等加密库
- 不支持 WAL 中未合并的数据
- 读取时使用 `FileShare.ReadWrite`，因此**目标进程正在使用该文件时依然能读**（浏览器运行中读取其 History / Login Data 已验证）；但若写入正在进行，读到的可能是某一瞬间的快照

**AES-GCM**

- 依赖 Windows CNG，只能在 Windows 上跑
- 加解密失败统一返回 `null`，不区分原因（避免给攻击者差异化反馈）；调试时可用 `tests/probe/BCryptProbe.cs` 逐步打印 NTSTATUS

**其他**

- 目标框架 net48，语言级别 C# 5（不用 `?.`、字符串插值、`nameof`）
- `MiniJson` 不是通用 JSON 解析器：不支持深度嵌套的极端情况，也不做严格的 RFC 8259 校验，够用优先

---

## 许可

MIT，详见 [LICENSE](LICENSE)。