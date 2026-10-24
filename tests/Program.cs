using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using VigilKit;
using VigilKit.Archive;
using VigilKit.Crypto;
using VigilKit.Sqlite;

namespace VigilKit.Tests
{
    /// <summary>
    /// VigilKit 自测程序。不依赖任何测试框架，直接编译运行即可。
    ///
    /// 测试覆盖：
    ///   · HKDF  — RFC 5869 官方测试向量
    ///   · 加密  — 往返、篡改检测、IV 随机性、边界长度
    ///   · 编码  — 十六进制 / Base64 / URL 安全变体
    ///   · 摘要  — 已知向量
    ///   · JSON  — 解析与序列化往返
    ///   · SQLite — 手工构造的数据库文件
    ///   · Zip   — CRC32 向量与压缩往返
    /// </summary>
    public static class Program
    {
        private static int _passed;
        private static int _failed;
        private static readonly List<string> _failures = new List<string>();

        public static int Main(string[] args)
        {
            // 控制台编码在 stdout 被重定向时（CI、管道、文件）可能设置失败，
            // 例如 GitHub Actions 里就没有真实控制台。这不是致命错误，
            // 输出退化成默认编码即可，不能因此中断测试。
            try { Console.OutputEncoding = Encoding.UTF8; }
            catch { }

            Console.WriteLine("================ VigilKit 自测 ================");
            Console.WriteLine();

            Section("HKDF（RFC 5869 官方向量）", TestHkdf);
            Section("加密信封 SealedBox", TestSealedBox);
            Section("通道密钥 ChannelKeys", TestChannelKeys);
            Section("长度分档 LengthPadding", TestLengthPadding);
            Section("编码 Hex / Base64", TestEncoding);
            Section("摘要 Digest", TestDigest);
            Section("JSON MiniJson", TestMiniJson);
            Section("SQLite 解析器", TestSqlite);
            Section("AES-GCM（CNG）", TestAesGcm);
            Section("Zip / CRC32", TestZip);

            OptionalRealSqlite();

            Console.WriteLine();
            Console.WriteLine("==============================================");
            if (_failed == 0)
            {
                Console.WriteLine(string.Format("全部通过：{0} 项", _passed));
                Console.WriteLine("==============================================");
                return 0;
            }

            Console.WriteLine(string.Format("通过 {0} 项，失败 {1} 项", _passed, _failed));
            Console.WriteLine();
            Console.WriteLine("失败明细：");
            foreach (string f in _failures) Console.WriteLine("  · " + f);
            Console.WriteLine("==============================================");
            return 1;
        }

        // ================= 测试框架 =================

        private static void Section(string title, Action test)
        {
            Console.WriteLine("--- " + title + " ---");
            try
            {
                test();
            }
            catch (Exception ex)
            {
                Check(title + " 整体执行", false, "抛出异常: " + ex.GetType().Name + ": " + ex.Message);
            }
            Console.WriteLine();
        }

        private static void Check(string name, bool condition, string detail)
        {
            if (condition)
            {
                _passed++;
                Console.WriteLine("  PASS  " + name);
            }
            else
            {
                _failed++;
                string line = name + (string.IsNullOrEmpty(detail) ? "" : " — " + detail);
                _failures.Add(line);
                Console.WriteLine("  FAIL  " + line);
            }
        }

        private static void Check(string name, bool condition)
        {
            Check(name, condition, null);
        }

        private static void CheckEqual(string name, string expected, string actual)
        {
            bool ok = expected == actual;
            Check(name, ok, ok ? null : "期望 " + Short(expected) + "，实际 " + Short(actual));
        }

        private static void CheckThrows<T>(string name, Action action) where T : Exception
        {
            try
            {
                action();
                Check(name, false, "未抛出 " + typeof(T).Name);
            }
            catch (T)
            {
                Check(name, true);
            }
            catch (Exception ex)
            {
                Check(name, false, "抛出的是 " + ex.GetType().Name + " 而非 " + typeof(T).Name);
            }
        }

        private static string Short(string s)
        {
            if (s == null) return "(null)";
            return s.Length <= 32 ? s : s.Substring(0, 32) + "...";
        }

        // ================= HKDF =================

        private static void TestHkdf()
        {
            // RFC 5869 Test Case 1
            byte[] ikm = Repeat(0x0b, 22);
            byte[] salt = Range(0x00, 13);
            byte[] info = Range(0xf0, 10);

            byte[] okm = Hkdf.Derive(ikm, salt, info, 42);

            CheckEqual("RFC 5869 用例 1 输出",
                "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865",
                Hex.Encode(okm));

            // RFC 5869 Test Case 3：无盐、无 info
            byte[] okm3 = Hkdf.Derive(Repeat(0x0b, 22), null, "", 42);

            CheckEqual("RFC 5869 用例 3 输出（零盐）",
                "8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d9d201395faa4b61a96c8",
                Hex.Encode(okm3));

            // 不同 info 必须派生出不同结果
            byte[] a = Hkdf.Derive(ikm, "channel-a", 32);
            byte[] b = Hkdf.Derive(ikm, "channel-b", 32);
            Check("不同 info 派生不同密钥", !Digest.FixedTimeEquals(a, b));

            // 相同输入必须可重复
            byte[] a2 = Hkdf.Derive(ikm, "channel-a", 32);
            Check("相同输入派生结果确定", Digest.FixedTimeEquals(a, a2));

            // 长度参数
            Check("输出长度符合要求", Hkdf.Derive(ikm, "x", 100).Length == 100);
            CheckThrows<ArgumentOutOfRangeException>("长度 0 被拒绝",
                delegate { Hkdf.Derive(ikm, "x", 0); });
            CheckThrows<ArgumentOutOfRangeException>("长度超上限被拒绝",
                delegate { Hkdf.Derive(ikm, "x", Hkdf.MaxLength + 1); });
            CheckThrows<ArgumentNullException>("空主密钥被拒绝",
                delegate { Hkdf.Derive(null, "x", 32); });
        }

        // ================= SealedBox =================

        private static void TestSealedBox()
        {
            byte[] encKey = Digest.RandomBytes(32);
            byte[] macKey = Digest.RandomBytes(32);

            // 基本往返
            byte[] plain = Encoding.UTF8.GetBytes("烛幽 Vigil — sealed box round trip");
            byte[] envelope = SealedBox.Seal(encKey, macKey, plain);
            byte[] recovered = SealedBox.Open(encKey, macKey, envelope);

            Check("往返还原明文", Encoding.UTF8.GetString(recovered) == Encoding.UTF8.GetString(plain));
            Check("信封长度符合布局", envelope.Length >= SealedBox.MinEnvelopeSize
                && (envelope.Length - SealedBox.IvSize - SealedBox.MacSize) % SealedBox.BlockSize == 0);

            // IV 随机性：同一明文两次加密结果必须不同
            byte[] envelope2 = SealedBox.Seal(encKey, macKey, plain);
            Check("相同明文两次加密不同（随机 IV）", !Digest.FixedTimeEquals(envelope, envelope2));

            // 空明文
            byte[] emptyEnvelope = SealedBox.Seal(encKey, macKey, new byte[0]);
            byte[] emptyBack = SealedBox.Open(encKey, macKey, emptyEnvelope);
            Check("空明文往返", emptyBack.Length == 0);

            // 各种长度
            int[] sizes = new int[] { 1, 15, 16, 17, 255, 256, 4096, 65536 };
            bool allOk = true;
            foreach (int size in sizes)
            {
                byte[] data = Digest.RandomBytes(size);
                byte[] back = SealedBox.Open(encKey, macKey, SealedBox.Seal(encKey, macKey, data));
                if (!Digest.FixedTimeEquals(data, back)) { allOk = false; break; }
            }
            Check("1B..64KB 各长度往返", allOk);

            // 篡改检测：翻转任意一个字节都必须失败
            byte[] tampered = (byte[])envelope.Clone();
            tampered[SealedBox.IvSize + 3] ^= 0x01;
            CheckThrows<System.Security.Cryptography.CryptographicException>("篡改密文被拒绝",
                delegate { SealedBox.Open(encKey, macKey, tampered); });

            byte[] tamperedMac = (byte[])envelope.Clone();
            tamperedMac[tamperedMac.Length - 1] ^= 0x01;
            CheckThrows<System.Security.Cryptography.CryptographicException>("篡改 MAC 被拒绝",
                delegate { SealedBox.Open(encKey, macKey, tamperedMac); });

            byte[] tamperedIv = (byte[])envelope.Clone();
            tamperedIv[0] ^= 0x01;
            CheckThrows<System.Security.Cryptography.CryptographicException>("篡改 IV 被拒绝（IV 参与认证）",
                delegate { SealedBox.Open(encKey, macKey, tamperedIv); });

            // 错误密钥：两者都错，MAC 必然失败
            CheckThrows<System.Security.Cryptography.CryptographicException>("错误密钥对均不正确被拒绝",
                delegate { SealedBox.Open(Digest.RandomBytes(32), Digest.RandomBytes(32), envelope); });

            // 只错加密密钥、MAC 密钥正确：靠填充里的双字节校验拦截
            // （这不是攻击场景——encKey 与 macKey 由同一主密钥派生，总是配套出现——
            //   而是防误用：有人手工拼错密钥时应当快速失败而不是返回垃圾数据）
            bool misuseRejected = false;
            int misuseAccepted = 0;
            for (int i = 0; i < 256; i++)
            {
                try
                {
                    SealedBox.Open(Digest.RandomBytes(32), macKey, envelope);
                    misuseAccepted++;
                }
                catch (System.Security.Cryptography.CryptographicException)
                {
                    misuseRejected = true;
                }
            }
            Check("只错加密密钥时被拒绝（256 次抽样应全拒）",
                misuseRejected && misuseAccepted == 0,
                string.Format("256 次中有 {0} 次被误接受", misuseAccepted));

            // 过短信封
            CheckThrows<System.Security.Cryptography.CryptographicException>("过短信封被拒绝",
                delegate { SealedBox.Open(encKey, macKey, new byte[10]); });

            // 密钥长度校验
            CheckThrows<ArgumentException>("非 32 字节密钥被拒绝",
                delegate { SealedBox.Seal(new byte[16], macKey, plain); });
        }

        // ================= ChannelKeys =================

        private static void TestChannelKeys()
        {
            byte[] master = Digest.RandomBytes(32);

            ChannelKeys a2b = ChannelKeys.FromMaster(master, "a2b");
            ChannelKeys b2a = ChannelKeys.FromMaster(master, "b2a");

            Check("加密密钥长度 32", a2b.EncryptionKey.Length == 32);
            Check("认证密钥长度 32", a2b.AuthenticationKey.Length == 32);
            Check("加密与认证密钥不同",
                !Digest.FixedTimeEquals(a2b.EncryptionKey, a2b.AuthenticationKey));

            // 方向隔离：两个方向的密钥必须完全不同
            Check("方向隔离 — 加密密钥",
                !Digest.FixedTimeEquals(a2b.EncryptionKey, b2a.EncryptionKey));
            Check("方向隔离 — 认证密钥",
                !Digest.FixedTimeEquals(a2b.AuthenticationKey, b2a.AuthenticationKey));

            // 方向隔离的实际意义：A 发出的密文不能被当作 B 的密文解开
            byte[] message = Encoding.UTF8.GetBytes("hello from a");
            byte[] sealedByA = SealedBox.Seal(a2b.EncryptionKey, a2b.AuthenticationKey, message);

            bool crossFailed = false;
            try
            {
                SealedBox.Open(b2a.EncryptionKey, b2a.AuthenticationKey, sealedByA);
            }
            catch (System.Security.Cryptography.CryptographicException)
            {
                crossFailed = true;
            }
            Check("交叉方向解密失败（防反射）", crossFailed);

            // 同方向往返
            byte[] back = SealedBox.Open(a2b.EncryptionKey, a2b.AuthenticationKey, sealedByA);
            Check("同方向往返正确", Encoding.UTF8.GetString(back) == "hello from a");

            // CreatePair 便捷方法
            ChannelKeys outbound, inbound;
            ChannelKeys.CreatePair(master, "req", "resp", out outbound, out inbound);
            Check("CreatePair 产出两个不同方向",
                !Digest.FixedTimeEquals(outbound.EncryptionKey, inbound.EncryptionKey));
        }

        // ================= LengthPadding =================

        private static void TestLengthPadding()
        {
            Check("0 字节归入首档", LengthPadding.ToBucket(0) == 1024);
            Check("整档边界不越级", LengthPadding.ToBucket(1024) == 1024);
            Check("超出 1 字节进下一档", LengthPadding.ToBucket(1025) == 4096);
            Check("中段归入 16K", LengthPadding.ToBucket(10000) == 16384);
            Check("超最大档按倍数取整", LengthPadding.ToBucket(300000) == 262144 * 2);

            // 自定义档位
            int[] buckets = new int[] { 100, 200, 400 };
            Check("自定义档位 — 命中", LengthPadding.ToBucket(150, buckets) == 200);
            Check("自定义档位 — 越界向上取整", LengthPadding.ToBucket(500, buckets) == 800);

            // 填充生成
            byte[] pad = LengthPadding.CreatePadding(1000, null);
            Check("填充长度正确", pad.Length == 24);
            byte[] pad2 = LengthPadding.CreatePadding(1000, null);
            Check("填充内容随机", !Digest.FixedTimeEquals(pad, pad2));

            CheckThrows<ArgumentOutOfRangeException>("负长度被拒绝",
                delegate { LengthPadding.ToBucket(-1); });
        }

        // ================= 编码 =================

        private static void TestEncoding()
        {
            byte[] data = new byte[] { 0x00, 0x0F, 0x10, 0xFF, 0xAB, 0xCD };

            CheckEqual("十六进制编码", "000f10ffabcd", Hex.Encode(data));
            Check("十六进制往返", Digest.FixedTimeEquals(data, Hex.Decode("000f10ffabcd")));
            Check("十六进制解析大写", Digest.FixedTimeEquals(data, Hex.Decode("000F10FFABCD")));
            Check("十六进制忽略分隔符",
                Digest.FixedTimeEquals(data, Hex.Decode("00:0f:10:ff:ab:cd")));
            Check("空输入返回空数组", Hex.Decode("").Length == 0);
            CheckThrows<FormatException>("奇数长度十六进制被拒绝",
                delegate { Hex.Decode("abc"); });

            // Base64
            string b64 = Base64.Encode(data);
            Check("Base64 往返", Digest.FixedTimeEquals(data, Base64.Decode(b64)));

            // URL 安全变体
            byte[] tricky = new byte[] { 0xFB, 0xFF, 0xBF, 0x00 };
            string urlSafe = Base64.EncodeUrlSafe(tricky);
            Check("URL 安全变体不含 + / =",
                urlSafe.IndexOf('+') < 0 && urlSafe.IndexOf('/') < 0 && urlSafe.IndexOf('=') < 0);
            Check("URL 安全变体往返", Digest.FixedTimeEquals(tricky, Base64.DecodeUrlSafe(urlSafe)));
            Check("URL 安全变体可放 DNS 标签", urlSafe.Length <= 63);
        }

        // ================= 摘要 =================

        private static void TestDigest()
        {
            CheckEqual("SHA-256 空串",
                "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                Digest.Sha256Hex(new byte[0]));

            CheckEqual("SHA-256 \"abc\"",
                "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
                Digest.Sha256Hex(Encoding.ASCII.GetBytes("abc")));

            CheckEqual("MD5 空串", "d41d8cd98f00b204e9800998ecf8427e",
                Digest.Md5Hex(new byte[0]));

            CheckEqual("MD5 \"abc\"", "900150983cd24fb0d6963f7d28e17f72",
                Digest.Md5Hex(Encoding.ASCII.GetBytes("abc")));

            CheckEqual("SHA-1 \"abc\"", "a9993e364706816aba3e25717850c26c9cd0d89d",
                Digest.Sha1Hex(Encoding.ASCII.GetBytes("abc")));

            // 常数时间比较
            byte[] x = new byte[] { 1, 2, 3 };
            Check("相同数组比较为真", Digest.FixedTimeEquals(x, new byte[] { 1, 2, 3 }));
            Check("不同数组比较为假", !Digest.FixedTimeEquals(x, new byte[] { 1, 2, 4 }));
            Check("长度不同比较为假", !Digest.FixedTimeEquals(x, new byte[] { 1, 2 }));

            // 随机数
            byte[] r1 = Digest.RandomBytes(32);
            byte[] r2 = Digest.RandomBytes(32);
            Check("随机数不重复", !Digest.FixedTimeEquals(r1, r2));
            Check("随机数长度正确", r1.Length == 32);
        }

        // ================= MiniJson =================

        private static void TestMiniJson()
        {
            string json = "{\"name\":\"vigil\",\"version\":2,\"enabled\":true,"
                + "\"items\":[\"a\",\"b\"],\"nested\":{\"key\":\"value\"},\"ratio\":1.5}";

            object parsed = MiniJson.Parse(json);
            Dictionary<string, object> obj = MiniJson.AsObj(parsed);

            Check("解析出对象", obj != null);
            CheckEqual("读取字符串", "vigil", MiniJson.Str(obj, "name", ""));
            CheckEqual("读取整数", "2", MiniJson.Int(obj, "version", 0).ToString());
            Check("读取布尔", MiniJson.Bool(obj, "enabled", false));

            CheckEqual("缺失键返回默认值", "fallback", MiniJson.Str(obj, "missing", "fallback"));
            CheckEqual("缺失整数返回默认值", "99", MiniJson.Int(obj, "missing", 99).ToString());

            // 序列化往返
            var source = new Dictionary<string, object>();
            source["text"] = "中文测试";
            source["number"] = 12345;
            source["flag"] = true;
            source["list"] = new List<object> { "x", "y" };

            string serialized = MiniJson.Serialize(source);
            Dictionary<string, object> back = MiniJson.AsObj(MiniJson.Parse(serialized));

            Check("序列化后能解析", back != null);
            CheckEqual("中文往返", "中文测试", MiniJson.Str(back, "text", ""));
            CheckEqual("数字往返", "12345", MiniJson.Int(back, "number", 0).ToString());
            Check("布尔往返", MiniJson.Bool(back, "flag", false));

            // 转义处理
            var tricky = new Dictionary<string, object>();
            tricky["quote"] = "he said \"hi\"";
            tricky["newline"] = "line1\nline2";
            string trickyJson = MiniJson.Serialize(tricky);
            Dictionary<string, object> trickyBack = MiniJson.AsObj(MiniJson.Parse(trickyJson));
            CheckEqual("引号转义往返", "he said \"hi\"", MiniJson.Str(trickyBack, "quote", ""));
            CheckEqual("换行转义往返", "line1\nline2", MiniJson.Str(trickyBack, "newline", ""));
        }

        // ================= SQLite =================

        private static void TestSqlite()
        {
            byte[] db = SqliteFixture.BuildMinimal();
            Check("夹具文件大小 8192", db.Length == 8192);
            Check("夹具魔数正确",
                Encoding.ASCII.GetString(db, 0, 15) == "SQLite format 3");

            using (var reader = new SqliteReader(db))
            {
                List<string> tables = reader.TableNames();
                Check("枚举到 test 表", tables.Contains("test"));

                string schema = reader.CreateSql("test");
                CheckEqual("读取建表语句",
                    "CREATE TABLE test (id INTEGER, name TEXT)", schema);

                List<object[]> rows = reader.ReadTable("test");
                Check("读取到 2 行", rows.Count == 2);

                if (rows.Count == 2)
                {
                    CheckEqual("第 1 行 id", "1", Convert.ToString(rows[0][0]));
                    CheckEqual("第 1 行 name", "hello", Convert.ToString(rows[0][1]));
                    CheckEqual("第 2 行 id", "2", Convert.ToString(rows[1][0]));
                    CheckEqual("第 2 行 name", "world", Convert.ToString(rows[1][1]));
                }

                // 列名解析
                List<string> columns = SqliteReader.ParseColumns(schema);
                Check("解析出列 id", columns.Contains("id"));
                Check("解析出列 name", columns.Contains("name"));
            }

            // 非 SQLite 数据必须被拒绝
            CheckThrows<InvalidDataException>("非 SQLite 数据被拒绝",
                delegate { new SqliteReader(new byte[200]); });
            CheckThrows<InvalidDataException>("过短数据被拒绝",
                delegate { new SqliteReader(new byte[50]); });

            // 变长整数解析
            byte[] varint = new byte[] { 0x81, 0x00 };
            int pos = 0;
            long value = SqliteReader.ReadVarint(varint, ref pos);
            Check("变长整数 0x81 0x00 = 128", value == 128);
        }

        // ================= AES-GCM =================

        private static void TestAesGcm()
        {
            byte[] key = Digest.RandomBytes(32);
            byte[] nonce = Digest.RandomBytes(12);
            byte[] plain = Encoding.UTF8.GetBytes("AES-GCM via Windows CNG");

            byte[] sealed1 = AesGcm.Encrypt(key, nonce, plain, null);
            if (sealed1 == null)
            {
                Check("AES-GCM 加密", false, "BCrypt 调用失败（系统可能不支持）");
                return;
            }

            Check("密文长度 = 明文 + 16 字节 tag", sealed1.Length == plain.Length + AesGcm.TagSize);

            byte[] back = AesGcm.Decrypt(key, nonce, sealed1, null);
            Check("往返还原明文", back != null
                && Encoding.UTF8.GetString(back) == Encoding.UTF8.GetString(plain));

            // 篡改检测
            byte[] tampered = (byte[])sealed1.Clone();
            tampered[0] ^= 0x01;
            Check("篡改密文返回 null", AesGcm.Decrypt(key, nonce, tampered, null) == null);

            byte[] tamperedTag = (byte[])sealed1.Clone();
            tamperedTag[tamperedTag.Length - 1] ^= 0x01;
            Check("篡改 tag 返回 null", AesGcm.Decrypt(key, nonce, tamperedTag, null) == null);

            // 错误 nonce
            Check("错误 nonce 返回 null",
                AesGcm.Decrypt(key, Digest.RandomBytes(12), sealed1, null) == null);

            // 附加认证数据
            byte[] aad = Encoding.UTF8.GetBytes("header-v1");
            byte[] sealed2 = AesGcm.Encrypt(key, nonce, plain, aad);
            Check("带 AAD 往返",
                Encoding.UTF8.GetString(AesGcm.Decrypt(key, nonce, sealed2, aad))
                == Encoding.UTF8.GetString(plain));
            Check("AAD 不匹配返回 null",
                AesGcm.Decrypt(key, nonce, sealed2, Encoding.UTF8.GetBytes("header-v2")) == null);

            // 空明文
            byte[] emptySealed = AesGcm.Encrypt(key, nonce, new byte[0], null);
            Check("空明文加密得到 16 字节 tag", emptySealed != null && emptySealed.Length == 16);
        }

        // ================= Zip =================

        private static void TestZip()
        {
            // CRC32 标准校验值
            byte[] check = Encoding.ASCII.GetBytes("123456789");
            CheckEqual("CRC32(\"123456789\") = CBF43926",
                "CBF43926", Zip.Crc32(check).ToString("X8"));

            CheckEqual("CRC32 空数据", "00000000", Zip.Crc32(new byte[0]).ToString("X8"));

            // Deflate 往返
            string text = "烛幽 Vigil — deflate round trip test data. " +
                          "重复内容用于确保压缩率大于 1。重复内容用于确保压缩率大于 1。";
            byte[] raw = Encoding.UTF8.GetBytes(text);

            byte[] compressed;
            using (var output = new MemoryStream())
            {
                using (var deflate = new System.IO.Compression.DeflateStream(
                    output, System.IO.Compression.CompressionMode.Compress, true))
                {
                    deflate.Write(raw, 0, raw.Length);
                }
                compressed = output.ToArray();
            }

            byte[] inflated = Zip.Inflate(compressed);
            Check("Deflate 往返还原",
                inflated != null && Encoding.UTF8.GetString(inflated) == text);
            Check("压缩确实变小", compressed.Length < raw.Length);
        }

        // ================= 可选：真实 SQLite 文件 =================

        /// <summary>
        /// 如果系统上存在真实浏览器数据库，顺带验证一次。
        /// 这一步不影响测试结果，只作为额外信心来源。
        /// </summary>
        private static void OptionalRealSqlite()
        {
            string[] candidates = new string[]
            {
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                    "Microsoft", "Edge", "User Data", "Default", "History"),
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                    "Google", "Chrome", "User Data", "Default", "History")
            };

            string found = null;
            foreach (string c in candidates)
                if (File.Exists(c)) { found = c; break; }

            if (found == null)
            {
                Console.WriteLine("--- 真实 SQLite 文件（跳过：系统上未找到浏览器数据库） ---");
                Console.WriteLine();
                return;
            }

            Console.WriteLine("--- 真实 SQLite 文件（额外验证） ---");
            try
            {
                using (var reader = new SqliteReader(found))
                {
                    List<string> tables = reader.TableNames();
                    Console.WriteLine(string.Format("  文件: {0}", Path.GetFileName(found)));
                    Console.WriteLine(string.Format("  表数: {0}  例如: {1}",
                        tables.Count, tables.Count > 0 ? string.Join(", ", tables.GetRange(0,
                            Math.Min(5, tables.Count)).ToArray()) : "(无)"));

                    if (tables.Contains("urls"))
                    {
                        List<object[]> rows = reader.ReadTable("urls");
                        Console.WriteLine(string.Format("  urls 表行数: {0}", rows.Count));
                        Check("真实库 urls 表可读", rows.Count > 0);
                    }
                    else
                    {
                        Console.WriteLine("  （该库无 urls 表，仅验证表枚举）");
                    }
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine("  跳过（只读占用或被锁定）: " + ex.Message);
            }
            Console.WriteLine();
        }

        // ================= 辅助 =================

        private static byte[] Repeat(byte value, int count)
        {
            var result = new byte[count];
            for (int i = 0; i < count; i++) result[i] = value;
            return result;
        }

        private static byte[] Range(int start, int count)
        {
            var result = new byte[count];
            for (int i = 0; i < count; i++) result[i] = (byte)(start + i);
            return result;
        }
    }
}