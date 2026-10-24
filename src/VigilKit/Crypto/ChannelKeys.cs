using System;
using System.Security.Cryptography;

namespace VigilKit.Crypto
{
    /// <summary>
    /// 双向通道的密钥对。
    ///
    /// 设计要点：AES 加密密钥与 HMAC 认证密钥**分开派生**。
    /// 复用同一把密钥同时做加密和 MAC 在密码学上是危险的反模式
    /// （两类算法对密钥的要求不同，且会产生相关性），
    /// 因此这里强制要求两组独立密钥。
    /// </summary>
    public sealed class ChannelKeys
    {
        /// <summary>AES-256 密钥，32 字节。</summary>
        public byte[] EncryptionKey { get; private set; }

        /// <summary>HMAC-SHA256 密钥，32 字节。</summary>
        public byte[] AuthenticationKey { get; private set; }

        private ChannelKeys() { }

        /// <summary>
        /// 从主密钥派生出某个方向/用途的密钥对。
        /// </summary>
        /// <param name="master">主密钥，双方共享。</param>
        /// <param name="label">
        /// 方向或用途标签。双方必须对同一方向使用同一个标签。
        /// 例如 A→B 用 "a2b"，B→A 用 "b2a"，这样两个方向的密文无法互相反射。
        /// </param>
        public static ChannelKeys FromMaster(byte[] master, string label)
        {
            if (master == null) throw new ArgumentNullException("master");
            if (string.IsNullOrEmpty(label)) throw new ArgumentException("label required", "label");

            return new ChannelKeys
            {
                EncryptionKey = Hkdf.Derive(master, label + "/enc", 32),
                AuthenticationKey = Hkdf.Derive(master, label + "/mac", 32)
            };
        }

        /// <summary>
        /// 一次性派生一对互逆方向的密钥（请求方向 + 响应方向）。
        /// </summary>
        public static void CreatePair(byte[] master, string requestLabel, string responseLabel,
            out ChannelKeys outbound, out ChannelKeys inbound)
        {
            outbound = FromMaster(master, requestLabel);
            inbound = FromMaster(master, responseLabel);
        }
    }
}
