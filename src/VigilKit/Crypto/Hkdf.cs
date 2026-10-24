using System;
using System.Security.Cryptography;
using System.Text;

namespace VigilKit.Crypto
{
    /// <summary>
    /// HKDF-SHA256 密钥派生（RFC 5869）。
    ///
    /// 用于从一个主密钥派生出多个用途隔离的子密钥。同一条主密钥可以派生出
    /// 任意数量的、互相不可推导的子密钥（例如双向通道的两个方向各一组）。
    /// </summary>
    public static class Hkdf
    {
        /// <summary>SHA-256 输出长度。</summary>
        public const int HashLength = 32;

        /// <summary>HKDF 单次派生的最大输出长度（255 × HashLength）。</summary>
        public const int MaxLength = 255 * HashLength;

        /// <summary>
        /// 使用零盐派生。适合双方共享同一主密钥、且不需要额外上下文的场景。
        /// </summary>
        /// <param name="ikm">输入密钥材料（主密钥）。</param>
        /// <param name="info">用途标签，按 UTF-8 编码。不同标签派生出互不相关的子密钥。</param>
        /// <param name="length">需要的输出字节数。</param>
        public static byte[] Derive(byte[] ikm, string info, int length)
        {
            return Derive(ikm, null, EncodeInfo(info), length);
        }

        /// <summary>
        /// 完整 HKDF：Extract 用盐，Expand 用用途标签。
        /// </summary>
        /// <param name="ikm">输入密钥材料。</param>
        /// <param name="salt">盐。传 null 或空数组时使用全零盐。</param>
        /// <param name="info">用途标签，按 UTF-8 编码。</param>
        /// <param name="length">输出字节数，1..8160。</param>
        public static byte[] Derive(byte[] ikm, byte[] salt, string info, int length)
        {
            return Derive(ikm, salt, EncodeInfo(info), length);
        }

        /// <summary>
        /// 完整 HKDF，用途标签为任意字节序列。
        /// 需要与既有实现（如 RFC 测试向量）逐字节对齐时使用此重载。
        /// </summary>
        /// <param name="ikm">输入密钥材料。</param>
        /// <param name="salt">盐。传 null 或空数组时使用全零盐。</param>
        /// <param name="info">用途标签的原始字节。传 null 视作空。</param>
        /// <param name="length">输出字节数，1..8160。</param>
        public static byte[] Derive(byte[] ikm, byte[] salt, byte[] info, int length)
        {
            if (ikm == null) throw new ArgumentNullException("ikm");
            if (length <= 0 || length > MaxLength)
                throw new ArgumentOutOfRangeException("length", "length must be 1.." + MaxLength);

            if (salt == null || salt.Length == 0) salt = new byte[HashLength];

            // Extract: PRK = HMAC-SHA256(salt, ikm)
            byte[] prk;
            using (var h = new HMACSHA256(salt))
                prk = h.ComputeHash(ikm);

            // Expand: T(i) = HMAC-SHA256(PRK, T(i-1) || info || i)
            byte[] infoBytes = info ?? new byte[0];
            var okm = new byte[length];
            var t = new byte[0];
            int pos = 0;
            byte counter = 1;

            using (var h = new HMACSHA256(prk))
            {
                while (pos < length)
                {
                    var buf = new byte[t.Length + infoBytes.Length + 1];
                    Buffer.BlockCopy(t, 0, buf, 0, t.Length);
                    Buffer.BlockCopy(infoBytes, 0, buf, t.Length, infoBytes.Length);
                    buf[buf.Length - 1] = counter;

                    t = h.ComputeHash(buf);

                    int n = Math.Min(t.Length, length - pos);
                    Buffer.BlockCopy(t, 0, okm, pos, n);
                    pos += n;
                    counter++;
                }
            }

            Array.Clear(prk, 0, prk.Length);
            return okm;
        }

        private static byte[] EncodeInfo(string info)
        {
            return string.IsNullOrEmpty(info) ? new byte[0] : Encoding.UTF8.GetBytes(info);
        }
    }
}
