using System;
using System.Security.Cryptography;

namespace VigilKit.Crypto
{
    /// <summary>
    /// 密封信封：AES-256-CBC 加密 + HMAC-SHA256 认证（Encrypt-then-MAC）。
    ///
    /// 信封布局（无分隔符，按固定偏移解析）：
    /// <code>
    /// [ IV 16 字节 ][ 密文 n 字节（16 的倍数）][ HMAC 32 字节 ]
    /// </code>
    ///
    /// 安全性质：
    /// <list type="bullet">
    /// <item>认证覆盖 IV 与密文整体，篡改任意一字节都会被拒绝。</item>
    /// <item>MAC 比较使用常数时间实现，不泄漏首个不匹配的位置。</item>
    /// <item>每帧独立随机 IV，相同明文两次加密产生完全不同的密文。</item>
    /// <item>填充字节为随机值（末字节记录填充长度），使密文长度不暴露明文长度的低位信息。</item>
    /// </list>
    ///
    /// 注意：本类只提供机密性与完整性，不提供重放保护。
    /// 需要防重放时，应在明文载荷内加入单调递增序号或时间戳，并由调用方校验。
    /// </summary>
    public static class SealedBox
    {
        /// <summary>AES 块大小。</summary>
        public const int BlockSize = 16;

        /// <summary>IV 长度。</summary>
        public const int IvSize = 16;

        /// <summary>HMAC-SHA256 输出长度。</summary>
        public const int MacSize = 32;

        /// <summary>空信封（IV + 一个密文块 + MAC）的最小长度。</summary>
        public const int MinEnvelopeSize = IvSize + BlockSize + MacSize;

        /// <summary>
        /// 加密并认证。
        /// </summary>
        /// <param name="encryptionKey">AES-256 密钥，32 字节。</param>
        /// <param name="authenticationKey">HMAC-SHA256 密钥，32 字节。</param>
        /// <param name="plaintext">明文，可为空数组。</param>
        /// <returns>完整信封。</returns>
        public static byte[] Seal(byte[] encryptionKey, byte[] authenticationKey, byte[] plaintext)
        {
            ValidateKeys(encryptionKey, authenticationKey);
            if (plaintext == null) plaintext = new byte[0];

            // ---------- 随机填充 ----------
            // 末尾三个字节构成填充校验：
            //   padded[L-1] = padLength
            //   padded[L-2] = padLength ^ 0xFF
            //   padded[L-3] = padLength ^ 0xA5
            //
            // 作用：在"MAC 密钥正确但加密密钥错误"这类误用下快速失败，避免把随机
            // 垃圾当成合法明文返回。单字节校验的偶然通过率约 1/16；三个字节把
            // 它降到约 1/50 万，使行为在统计上稳定可依赖。
            //
            // 填充长度取 3..18 而非 1..16：保证末尾三个字节总是存在，校验在任何
            // 长度下都生效。总长度仍是 16 的倍数。
            // 其余填充字节为随机值，避免暴露明文末尾的可预测模式。
            int remainder = plaintext.Length % BlockSize;
            int padLength = BlockSize - remainder;
            if (padLength < 3) padLength += BlockSize;

            var padded = new byte[plaintext.Length + padLength];
            Buffer.BlockCopy(plaintext, 0, padded, 0, plaintext.Length);

            var random = new byte[padLength];
            FillRandom(random);
            random[padLength - 1] = (byte)padLength;
            random[padLength - 2] = (byte)(padLength ^ 0xFF);
            random[padLength - 3] = (byte)(padLength ^ 0xA5);
            Buffer.BlockCopy(random, 0, padded, plaintext.Length, padLength);

            // ---------- 加密 ----------
            var iv = new byte[IvSize];
            FillRandom(iv);

            byte[] ciphertext;
            using (var aes = Aes.Create())
            {
                aes.KeySize = 256;
                aes.Mode = CipherMode.CBC;
                aes.Padding = PaddingMode.None;
                aes.Key = encryptionKey;
                aes.IV = iv;
                using (var encryptor = aes.CreateEncryptor())
                    ciphertext = encryptor.TransformFinalBlock(padded, 0, padded.Length);
            }

            // ---------- 认证（覆盖 IV + 密文） ----------
            byte[] mac = ComputeMac(authenticationKey, iv, ciphertext);

            var envelope = new byte[IvSize + ciphertext.Length + MacSize];
            Buffer.BlockCopy(iv, 0, envelope, 0, IvSize);
            Buffer.BlockCopy(ciphertext, 0, envelope, IvSize, ciphertext.Length);
            Buffer.BlockCopy(mac, 0, envelope, IvSize + ciphertext.Length, MacSize);

            Array.Clear(padded, 0, padded.Length);
            return envelope;
        }

        /// <summary>
        /// 验签并解密。
        /// </summary>
        /// <param name="encryptionKey">AES-256 密钥，32 字节。</param>
        /// <param name="authenticationKey">HMAC-SHA256 密钥，32 字节。</param>
        /// <param name="envelope">完整信封。</param>
        /// <returns>明文。</returns>
        /// <exception cref="CryptographicException">
        /// 信封过短、认证失败或填充非法。异常信息统一为固定字符串，
        /// 不区分具体原因，避免给攻击者提供差异化反馈。
        /// </exception>
        public static byte[] Open(byte[] encryptionKey, byte[] authenticationKey, byte[] envelope)
        {
            ValidateKeys(encryptionKey, authenticationKey);
            if (envelope == null || envelope.Length < MinEnvelopeSize)
                throw new CryptographicException("invalid envelope");

            // ---------- 先验签，再解密（Encrypt-then-MAC 的关键顺序） ----------
            int cipherOffset = IvSize;
            int cipherLength = envelope.Length - IvSize - MacSize;
            if (cipherLength <= 0 || cipherLength % BlockSize != 0)
                throw new CryptographicException("invalid envelope");

            var iv = new byte[IvSize];
            Buffer.BlockCopy(envelope, 0, iv, 0, IvSize);

            byte[] expected = ComputeMac(authenticationKey, iv, envelope, cipherOffset, cipherLength);

            int diff = 0;
            for (int i = 0; i < MacSize; i++)
                diff |= expected[i] ^ envelope[cipherOffset + cipherLength + i];
            if (diff != 0) throw new CryptographicException("invalid envelope");

            // ---------- 解密 ----------
            byte[] padded;
            using (var aes = Aes.Create())
            {
                aes.KeySize = 256;
                aes.Mode = CipherMode.CBC;
                aes.Padding = PaddingMode.None;
                aes.Key = encryptionKey;
                aes.IV = iv;
                using (var decryptor = aes.CreateDecryptor())
                    padded = decryptor.TransformFinalBlock(envelope, cipherOffset, cipherLength);
            }

            if (padded.Length == 0) return padded;

            int padLength = padded[padded.Length - 1];
            if (padLength < 3 || padLength > 2 * BlockSize || padLength > padded.Length)
                throw new CryptographicException("invalid envelope");

            // 三字节填充校验（详见 Seal 中的说明）。
            // 使用常数时间比较，避免通过响应时间泄露校验进度。
            var expectedPad = new byte[3];
            expectedPad[0] = (byte)(padLength ^ 0xA5);
            expectedPad[1] = (byte)(padLength ^ 0xFF);
            expectedPad[2] = (byte)padLength;

            var actualPad = new byte[3];
            Buffer.BlockCopy(padded, padded.Length - 3, actualPad, 0, 3);

            if (!Digest.FixedTimeEquals(expectedPad, actualPad))
                throw new CryptographicException("invalid envelope");

            var plaintext = new byte[padded.Length - padLength];
            Buffer.BlockCopy(padded, 0, plaintext, 0, plaintext.Length);

            Array.Clear(padded, 0, padded.Length);
            return plaintext;
        }

        // ---------- 内部实现 ----------

        private static void ValidateKeys(byte[] encryptionKey, byte[] authenticationKey)
        {
            if (encryptionKey == null || encryptionKey.Length != 32)
                throw new ArgumentException("encryption key must be 32 bytes (AES-256)", "encryptionKey");
            if (authenticationKey == null || authenticationKey.Length != 32)
                throw new ArgumentException("authentication key must be 32 bytes (HMAC-SHA256)", "authenticationKey");
        }

        private static byte[] ComputeMac(byte[] key, byte[] iv, byte[] ciphertext)
        {
            return ComputeMac(key, iv, ciphertext, 0, ciphertext.Length);
        }

        private static byte[] ComputeMac(byte[] key, byte[] iv, byte[] buffer, int offset, int count)
        {
            using (var hmac = new HMACSHA256(key))
            {
                hmac.TransformBlock(iv, 0, iv.Length, null, 0);
                hmac.TransformFinalBlock(buffer, offset, count);
                return hmac.Hash;
            }
        }

        private static void FillRandom(byte[] buffer)
        {
            using (var rng = RandomNumberGenerator.Create())
                rng.GetBytes(buffer);
        }
    }
}