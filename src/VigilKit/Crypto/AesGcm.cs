using System;
using System.Runtime.InteropServices;

namespace VigilKit.Crypto
{
    /// <summary>
    /// AES-GCM 认证加密，走 Windows CNG（bcrypt.dll）。
    ///
    /// 存在的理由：.NET Framework 直到 4.8 都没有托管的 <c>AesGcm</c> 实现
    /// （该类型从 .NET Core 3.0 才引入），而 AES-GCM 已经是现代协议的主流选择
    /// （TLS 1.3、JWE、以及各类本地加密存储格式都用它）。
    /// 本类通过直接调用系统 CNG 提供该能力，不引入任何第三方依赖。
    ///
    /// 与 <see cref="SealedBox"/> 的分工：
    /// <list type="bullet">
    /// <item><see cref="SealedBox"/> 是自描述信封格式，适合自定义协议。</item>
    /// <item>本类是裸 AES-GCM 原语，适合与既有数据格式互通。</item>
    /// </list>
    /// </summary>
    public static class AesGcm
    {
        /// <summary>GCM 推荐 nonce 长度。</summary>
        public const int RecommendedNonceSize = 12;

        /// <summary>GCM 认证标签长度。</summary>
        public const int TagSize = 16;

        /// <summary>
        /// 加密。返回 <c>[密文 n][tag 16]</c>。
        /// </summary>
        /// <param name="key">密钥，16 / 24 或 32 字节。</param>
        /// <param name="nonce">随机数，建议 12 字节。同一密钥下绝不可重复使用同一个 nonce。</param>
        /// <param name="plaintext">明文。</param>
        /// <param name="associatedData">附加认证数据（不加密但参与认证），可为 null。</param>
        /// <returns><c>[密文][tag]</c>；失败返回 null。</returns>
        public static byte[] Encrypt(byte[] key, byte[] nonce, byte[] plaintext, byte[] associatedData)
        {
            return Transform(true, key, nonce, plaintext, associatedData);
        }

        /// <summary>
        /// 解密。输入为 <c>[密文 n][tag 16]</c>。
        /// 认证失败（数据被篡改、密钥错误或 nonce 不匹配）返回 null。
        /// </summary>
        public static byte[] Decrypt(byte[] key, byte[] nonce, byte[] ciphertextWithTag, byte[] associatedData)
        {
            return Transform(false, key, nonce, ciphertextWithTag, associatedData);
        }

        /// <summary>解密不带附加认证数据的密文。</summary>
        public static byte[] Decrypt(byte[] key, byte[] nonce, byte[] ciphertextWithTag)
        {
            return Transform(false, key, nonce, ciphertextWithTag, null);
        }

        // ---------- 内部实现 ----------

        private static byte[] Transform(bool encrypt, byte[] key, byte[] nonce,
            byte[] input, byte[] associatedData)
        {
            if (key == null || key.Length == 0) return null;
            if (nonce == null || nonce.Length == 0) return null;
            if (input == null) input = new byte[0];

            IntPtr algorithm = IntPtr.Zero;
            IntPtr keyHandle = IntPtr.Zero;
            IntPtr infoPointer = IntPtr.Zero;
            IntPtr noncePointer = IntPtr.Zero;
            IntPtr authDataPointer = IntPtr.Zero;
            IntPtr tagPointer = IntPtr.Zero;

            try
            {
                if (BCryptOpenAlgorithmProvider(out algorithm, "AES", null, 0) != 0) return null;

                // 设置 GCM 链接模式（属性值为 UTF-16 字符串）
                byte[] mode = System.Text.Encoding.Unicode.GetBytes("ChainingModeGCM");
                if (BCryptSetProperty(algorithm, "ChainingMode", mode, mode.Length, 0) != 0) return null;

                if (BCryptGenerateSymmetricKey(algorithm, out keyHandle, IntPtr.Zero, 0,
                        key, key.Length, 0) != 0) return null;

                // ---------- 拆分正文与标签 ----------
                byte[] payload;
                var tag = new byte[TagSize];

                if (encrypt)
                {
                    payload = input;
                }
                else
                {
                    if (input.Length < TagSize) return null;
                    int bodyLength = input.Length - TagSize;
                    payload = new byte[bodyLength];
                    Buffer.BlockCopy(input, 0, payload, 0, bodyLength);
                    Buffer.BlockCopy(input, bodyLength, tag, 0, TagSize);
                }

                // ---------- 非托管缓冲区 ----------
                // 注意：不能把 byte[] 直接放进 P/Invoke 结构体——marshaler 会复制一份，
                // 导致 BCrypt 写入的 tag 无法回传到托管数组（加密场景会拿到全零）。
                // 因此所有指针字段都用 IntPtr，手动分配与回收。
                noncePointer = AllocCopy(nonce);
                if (associatedData != null && associatedData.Length > 0)
                    authDataPointer = AllocCopy(associatedData);
                tagPointer = AllocCopy(tag);

                var info = new AUTHENTICATED_CIPHER_MODE_INFO();
                info.cbSize = Marshal.SizeOf(typeof(AUTHENTICATED_CIPHER_MODE_INFO));
                info.dwInfoVersion = 1;
                info.pbNonce = noncePointer;
                info.cbNonce = nonce.Length;
                info.pbAuthData = authDataPointer;
                info.cbAuthData = associatedData == null ? 0 : associatedData.Length;
                info.pbTag = tagPointer;
                info.cbTag = TagSize;

                infoPointer = Marshal.AllocHGlobal(info.cbSize);
                Marshal.StructureToPtr(info, infoPointer, false);

                var output = new byte[payload.Length + 16];
                int produced;

                // GCM 模式下 nonce 与 tag 都通过 info 结构传递，pbIV 必须为空
                int status = encrypt
                    ? BCryptEncrypt(keyHandle, payload, payload.Length, infoPointer,
                        null, 0, output, output.Length, out produced, 0)
                    : BCryptDecrypt(keyHandle, payload, payload.Length, infoPointer,
                        null, 0, output, output.Length, out produced, 0);

                if (status != 0) return null;
                if (produced < 0 || produced > output.Length) return null;

                if (!encrypt)
                {
                    var plaintext = new byte[produced];
                    Buffer.BlockCopy(output, 0, plaintext, 0, produced);
                    return plaintext;
                }

                // 加密：BCrypt 把算出的 tag 写进了非托管缓冲区，需要读回
                Marshal.Copy(tagPointer, tag, 0, TagSize);

                var result = new byte[produced + TagSize];
                Buffer.BlockCopy(output, 0, result, 0, produced);
                Buffer.BlockCopy(tag, 0, result, produced, TagSize);
                return result;
            }
            catch
            {
                return null;
            }
            finally
            {
                FreeIfAllocated(infoPointer);
                FreeIfAllocated(noncePointer);
                FreeIfAllocated(authDataPointer);
                FreeIfAllocated(tagPointer);

                if (keyHandle != IntPtr.Zero) BCryptDestroyKey(keyHandle);
                if (algorithm != IntPtr.Zero) BCryptCloseAlgorithmProvider(algorithm, 0);
            }
        }

        private static IntPtr AllocCopy(byte[] data)
        {
            IntPtr pointer = Marshal.AllocHGlobal(data.Length);
            Marshal.Copy(data, 0, pointer, data.Length);
            return pointer;
        }

        private static void FreeIfAllocated(IntPtr pointer)
        {
            if (pointer != IntPtr.Zero) Marshal.FreeHGlobal(pointer);
        }

        // ---------- P/Invoke ----------

        [DllImport("bcrypt.dll", CharSet = CharSet.Unicode)]
        private static extern int BCryptOpenAlgorithmProvider(out IntPtr phAlgorithm,
            string pszAlgId, string pszImplementation, uint dwFlags);

        [DllImport("bcrypt.dll", CharSet = CharSet.Unicode)]
        private static extern int BCryptSetProperty(IntPtr hObject, string pszProperty,
            byte[] pbInput, int cbInput, uint dwFlags);

        [DllImport("bcrypt.dll", CharSet = CharSet.Unicode)]
        private static extern int BCryptGenerateSymmetricKey(IntPtr hAlgorithm, out IntPtr phKey,
            IntPtr pbKeyObject, int cbKeyObject, byte[] pbSecret, int cbSecret, uint dwFlags);

        [DllImport("bcrypt.dll", CharSet = CharSet.Unicode)]
        private static extern int BCryptEncrypt(IntPtr hKey, byte[] pbInput, int cbInput,
            IntPtr pPaddingInfo, byte[] pbIV, int cbIV, byte[] pbOutput, int cbOutput,
            out int pcbResult, uint dwFlags);

        [DllImport("bcrypt.dll", CharSet = CharSet.Unicode)]
        private static extern int BCryptDecrypt(IntPtr hKey, byte[] pbInput, int cbInput,
            IntPtr pPaddingInfo, byte[] pbIV, int cbIV, byte[] pbOutput, int cbOutput,
            out int pcbResult, uint dwFlags);

        [DllImport("bcrypt.dll", CharSet = CharSet.Unicode)]
        private static extern int BCryptDestroyKey(IntPtr hKey);

        [DllImport("bcrypt.dll", CharSet = CharSet.Unicode)]
        private static extern int BCryptCloseAlgorithmProvider(IntPtr hAlgorithm, uint dwFlags);

        /// <summary>
        /// BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO 的托管映射。
        /// 字段顺序与原生结构严格一致，指针字段一律用 IntPtr。
        /// </summary>
        [StructLayout(LayoutKind.Sequential)]
        private struct AUTHENTICATED_CIPHER_MODE_INFO
        {
            public int cbSize;
            public int dwInfoVersion;
            public IntPtr pbNonce;
            public int cbNonce;
            public IntPtr pbAuthData;
            public int cbAuthData;
            public IntPtr pbTag;
            public int cbTag;
            public IntPtr pbMacContext;
            public int cbMacContext;
            public int cbAAD;
            public long cbData;
            public int dwFlags;
        }
    }
}