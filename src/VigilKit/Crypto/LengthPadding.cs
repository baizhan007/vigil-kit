using System;
using System.Security.Cryptography;
using System.Text;

namespace VigilKit.Crypto
{
    /// <summary>
    /// 长度分档填充。
    ///
    /// 动机：即使内容已加密，**密文长度仍会泄漏明文长度**。
    /// 如果每次都把载荷填充到固定档位（4K / 8K / 16K …），
    /// 观察者只能区分出载荷落在哪一档，无法还原精确长度。
    ///
    /// 适用于请求体、心跳包这类大小差异较大、但可以容忍固定开销的场景。
    /// 代价是增加了带宽占用，档位越粗遮蔽效果越好、开销越大。
    /// </summary>
    public static class LengthPadding
    {
        /// <summary>默认档位（字节）。</summary>
        public static readonly int[] DefaultBuckets = new int[]
        {
            1024, 4096, 8192, 16384, 32768, 65536, 131072, 262144
        };

        /// <summary>
        /// 返回能容纳 <paramref name="length"/> 的最小档位。
        /// 超过最大档位时按最大档位向上取整。
        /// </summary>
        public static int ToBucket(int length)
        {
            return ToBucket(length, DefaultBuckets);
        }

        /// <summary>
        /// 返回能容纳 <paramref name="length"/> 的最小档位（自定义档位表）。
        /// </summary>
        /// <param name="length">原始长度，必须为非负。</param>
        /// <param name="buckets">升序排列的档位表，至少一个元素。</param>
        public static int ToBucket(int length, int[] buckets)
        {
            if (length < 0) throw new ArgumentOutOfRangeException("length");
            if (buckets == null || buckets.Length == 0)
                throw new ArgumentException("buckets required", "buckets");

            for (int i = 0; i < buckets.Length; i++)
                if (length <= buckets[i]) return buckets[i];

            int top = buckets[buckets.Length - 1];
            if (top <= 0) throw new ArgumentException("buckets must be positive", "buckets");
            return ((length + top - 1) / top) * top;
        }

        /// <summary>
        /// 生成填充到指定档位的随机尾巴。调用方负责拼接。
        /// </summary>
        /// <param name="currentLength">当前已用长度。</param>
        /// <param name="buckets">档位表，为 null 时使用默认档位。</param>
        /// <returns>随机填充字节；已超最大档位时返回空数组。</returns>
        public static byte[] CreatePadding(int currentLength, int[] buckets)
        {
            if (buckets == null) buckets = DefaultBuckets;

            int target = ToBucket(currentLength, buckets);
            int padLength = target - currentLength;
            if (padLength <= 0) return new byte[0];

            var padding = new byte[padLength];
            using (var rng = RandomNumberGenerator.Create())
                rng.GetBytes(padding);
            return padding;
        }
    }

    /// <summary>十六进制编码。</summary>
    public static class Hex
    {
        /// <summary>字节数组转小写十六进制字符串。</summary>
        public static string Encode(byte[] data)
        {
            if (data == null) return string.Empty;
            var sb = new StringBuilder(data.Length * 2);
            for (int i = 0; i < data.Length; i++)
                sb.Append(data[i].ToString("x2"));
            return sb.ToString();
        }

        /// <summary>解析十六进制字符串，忽略大小写与空白字符。</summary>
        public static byte[] Decode(string hex)
        {
            if (string.IsNullOrEmpty(hex)) return new byte[0];

            var clean = new StringBuilder(hex.Length);
            for (int i = 0; i < hex.Length; i++)
            {
                char c = hex[i];
                if (c == ' ' || c == '\t' || c == '\r' || c == '\n' || c == ':' || c == '-') continue;
                clean.Append(c);
            }

            string s = clean.ToString();
            if (s.Length % 2 != 0) throw new FormatException("hex length must be even");

            var result = new byte[s.Length / 2];
            for (int i = 0; i < result.Length; i++)
                result[i] = Convert.ToByte(s.Substring(i * 2, 2), 16);
            return result;
        }
    }

    /// <summary>Base64 编码。</summary>
    public static class Base64
    {
        /// <summary>编码为 Base64 字符串。</summary>
        public static string Encode(byte[] data)
        {
            return Convert.ToBase64String(data ?? new byte[0]);
        }

        /// <summary>解码 Base64 字符串；空或 null 返回空数组。</summary>
        public static byte[] Decode(string text)
        {
            if (string.IsNullOrEmpty(text)) return new byte[0];
            return Convert.FromBase64String(text);
        }

        /// <summary>
        /// URL 安全变体：<c>+</c> → <c>-</c>，<c>/</c> → <c>_</c>，去除 <c>=</c> 填充。
        /// 适合放进 URL 路径或 DNS 标签。
        /// </summary>
        public static string EncodeUrlSafe(byte[] data)
        {
            return Convert.ToBase64String(data ?? new byte[0])
                .Replace('+', '-').Replace('/', '_').TrimEnd('=');
        }

        /// <summary>解析 URL 安全变体。</summary>
        public static byte[] DecodeUrlSafe(string text)
        {
            if (string.IsNullOrEmpty(text)) return new byte[0];

            string s = text.Replace('-', '+').Replace('_', '/');
            switch (s.Length % 4)
            {
                case 2: s += "=="; break;
                case 3: s += "="; break;
                case 1: throw new FormatException("invalid base64url length");
            }
            return Convert.FromBase64String(s);
        }
    }

    /// <summary>摘要计算。</summary>
    public static class Digest
    {
        /// <summary>SHA-256，返回小写十六进制。</summary>
        public static string Sha256Hex(byte[] data)
        {
            using (var sha = SHA256.Create())
                return Hex.Encode(sha.ComputeHash(data ?? new byte[0]));
        }

        /// <summary>SHA-256 原始字节。</summary>
        public static byte[] Sha256(byte[] data)
        {
            using (var sha = SHA256.Create())
                return sha.ComputeHash(data ?? new byte[0]);
        }

        /// <summary>MD5，返回小写十六进制。仅用于非安全场景（如文件去重）。</summary>
        public static string Md5Hex(byte[] data)
        {
            using (var md5 = MD5.Create())
                return Hex.Encode(md5.ComputeHash(data ?? new byte[0]));
        }

        /// <summary>SHA-1，返回小写十六进制。仅用于兼容既有格式。</summary>
        public static string Sha1Hex(byte[] data)
        {
            using (var sha1 = SHA1.Create())
                return Hex.Encode(sha1.ComputeHash(data ?? new byte[0]));
        }

        /// <summary>常数时间比较两个字节数组是否相等。</summary>
        public static bool FixedTimeEquals(byte[] a, byte[] b)
        {
            if (a == null || b == null) return a == b;
            if (a.Length != b.Length) return false;

            int diff = 0;
            for (int i = 0; i < a.Length; i++) diff |= a[i] ^ b[i];
            return diff == 0;
        }

        /// <summary>生成密码学安全随机字节。</summary>
        public static byte[] RandomBytes(int count)
        {
            if (count < 0) throw new ArgumentOutOfRangeException("count");
            var buffer = new byte[count];
            using (var rng = RandomNumberGenerator.Create())
                rng.GetBytes(buffer);
            return buffer;
        }
    }
}