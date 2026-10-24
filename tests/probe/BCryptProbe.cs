using System;
using System.Runtime.InteropServices;
using System.Text;

/// <summary>
/// BCrypt AES-GCM 调用链调试程序。
/// 逐步骤打印每个 CNG 调用的 NTSTATUS，用于定位 AES-GCM 失败的具体环节。
/// </summary>
internal static class BCryptProbe
{
    [DllImport("bcrypt.dll", CharSet = CharSet.Unicode)]
    private static extern int BCryptOpenAlgorithmProvider(out IntPtr phAlg, string pszAlgId,
        string pszImplementation, uint dwFlags);

    [DllImport("bcrypt.dll", CharSet = CharSet.Unicode)]
    private static extern int BCryptSetProperty(IntPtr hObject, string pszProperty,
        byte[] pbInput, int cbInput, uint dwFlags);

    [DllImport("bcrypt.dll", CharSet = CharSet.Unicode)]
    private static extern int BCryptGetProperty(IntPtr hObject, string pszProperty,
        byte[] pbOutput, int cbOutput, out int pcbResult, uint dwFlags);

    [DllImport("bcrypt.dll", CharSet = CharSet.Unicode)]
    private static extern int BCryptGenerateSymmetricKey(IntPtr hAlg, out IntPtr phKey,
        IntPtr pbKeyObject, int cbKeyObject, byte[] pbSecret, int cbSecret, uint dwFlags);

    [DllImport("bcrypt.dll", CharSet = CharSet.Unicode)]
    private static extern int BCryptEncrypt(IntPtr hKey, byte[] pbInput, int cbInput,
        IntPtr pPaddingInfo, byte[] pbIV, int cbIV, byte[] pbOutput, int cbOutput,
        out int pcbResult, uint dwFlags);

    [DllImport("bcrypt.dll", CharSet = CharSet.Unicode)]
    private static extern int BCryptDestroyKey(IntPtr hKey);

    [DllImport("bcrypt.dll", CharSet = CharSet.Unicode)]
    private static extern int BCryptCloseAlgorithmProvider(IntPtr hAlg, uint dwFlags);

    [StructLayout(LayoutKind.Sequential)]
    private struct AuthCipherModeInfo
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

    private static string Status(int code)
    {
        // NTSTATUS 的常见值
        switch (unchecked((uint)code))
        {
            case 0x00000000: return "STATUS_SUCCESS";
            case 0xC000000D: return "STATUS_INVALID_PARAMETER";
            case 0xC0000008: return "STATUS_INVALID_HANDLE";
            case 0xC0000023: return "STATUS_BUFFER_TOO_SMALL";
            case 0xC0000206: return "STATUS_INVALID_BUFFER_SIZE";
            case 0xC00000BB: return "STATUS_NOT_SUPPORTED";
            default: return "0x" + unchecked((uint)code).ToString("X8");
        }
    }

    private static int Main()
    {
        Console.OutputEncoding = Encoding.UTF8;

        IntPtr alg = IntPtr.Zero;
        IntPtr key = IntPtr.Zero;
        IntPtr infoPtr = IntPtr.Zero;
        IntPtr noncePtr = IntPtr.Zero;
        IntPtr tagPtr = IntPtr.Zero;
        IntPtr aadPtr = IntPtr.Zero;

        int st;

        Console.WriteLine("=== BCrypt AES-GCM 调用链探测 ===");
        Console.WriteLine();

        st = BCryptOpenAlgorithmProvider(out alg, "AES", null, 0);
        Console.WriteLine("1. BCryptOpenAlgorithmProvider(AES)      -> " + Status(st));
        if (st != 0) return 1;

        byte[] mode = Encoding.Unicode.GetBytes("ChainingModeGCM");
        st = BCryptSetProperty(alg, "ChainingMode", mode, mode.Length, 0);
        Console.WriteLine("2. BCryptSetProperty(ChainingModeGCM)   -> " + Status(st));
        if (st != 0) return 1;

        // 查询块长度与对象长度
        byte[] buf = new byte[16];
        int got;
        st = BCryptGetProperty(alg, "BlockLength", buf, 4, out got, 0);
        Console.WriteLine("3. BlockLength                          -> " + Status(st)
            + "  = " + BitConverter.ToUInt32(buf, 0));

        st = BCryptGetProperty(alg, "ObjectLength", buf, 4, out got, 0);
        Console.WriteLine("4. ObjectLength                         -> " + Status(st)
            + "  = " + BitConverter.ToUInt32(buf, 0));

        byte[] secret = new byte[32];
        for (int i = 0; i < secret.Length; i++) secret[i] = (byte)i;

        st = BCryptGenerateSymmetricKey(alg, out key, IntPtr.Zero, 0, secret, secret.Length, 0);
        Console.WriteLine("5. BCryptGenerateSymmetricKey(256bit)   -> " + Status(st));
        if (st != 0) return 1;

        // ---------- 准备 GCM 参数 ----------
        byte[] nonce = new byte[12];
        for (int i = 0; i < nonce.Length; i++) nonce[i] = (byte)(0xA0 + i);

        byte[] aad = Encoding.ASCII.GetBytes("header");
        byte[] tag = new byte[16];
        byte[] plain = Encoding.ASCII.GetBytes("hello gcm");

        Console.WriteLine();
        Console.WriteLine("AuthCipherModeInfo 托管大小 = "
            + Marshal.SizeOf(typeof(AuthCipherModeInfo)) + " 字节（原生应为 8 字节对齐）");
        Console.WriteLine();

        noncePtr = Marshal.AllocHGlobal(nonce.Length);
        Marshal.Copy(nonce, 0, noncePtr, nonce.Length);

        aadPtr = Marshal.AllocHGlobal(aad.Length);
        Marshal.Copy(aad, 0, aadPtr, aad.Length);

        tagPtr = Marshal.AllocHGlobal(16);
        Marshal.Copy(tag, 0, tagPtr, 16);

        var info = new AuthCipherModeInfo();
        info.cbSize = Marshal.SizeOf(typeof(AuthCipherModeInfo));
        info.dwInfoVersion = 1;
        info.pbNonce = noncePtr;
        info.cbNonce = nonce.Length;
        info.pbAuthData = aadPtr;
        info.cbAuthData = aad.Length;
        info.pbTag = tagPtr;
        info.cbTag = 16;

        infoPtr = Marshal.AllocHGlobal(info.cbSize);
        Marshal.StructureToPtr(info, infoPtr, false);

        // ---------- 尝试 1：pbIV 为空（GCM 的正确用法） ----------
        byte[] output = new byte[plain.Length + 32];
        int produced;

        st = BCryptEncrypt(key, plain, plain.Length, infoPtr, null, 0,
            output, output.Length, out produced, 0);
        Console.WriteLine("6. BCryptEncrypt(pbIV=null, cbIV=0)     -> " + Status(st)
            + "  produced=" + produced);
        Console.WriteLine("   密文: " + BitConverter.ToString(output, 0, Math.Max(0, Math.Min(produced, 16))));
        Console.WriteLine("   tag : " + BitConverter.ToString(tag));

        // ---------- 尝试 2：pbIV 传 nonce ----------
        byte[] tag2 = new byte[16];
        IntPtr tagPtr2 = Marshal.AllocHGlobal(16);
        Marshal.Copy(tag2, 0, tagPtr2, 16);
        info.pbTag = tagPtr2;
        Marshal.StructureToPtr(info, infoPtr, false);

        byte[] output2 = new byte[plain.Length + 32];
        st = BCryptEncrypt(key, plain, plain.Length, infoPtr, nonce, nonce.Length,
            output2, output2.Length, out produced, 0);
        Console.WriteLine();
        Console.WriteLine("7. BCryptEncrypt(pbIV=nonce, cbIV=12)   -> " + Status(st)
            + "  produced=" + produced);
        Console.WriteLine("   tag : " + BitConverter.ToString(tag2));

        Marshal.FreeHGlobal(tagPtr2);

        // ---------- 清理 ----------
        if (infoPtr != IntPtr.Zero) Marshal.FreeHGlobal(infoPtr);
        if (noncePtr != IntPtr.Zero) Marshal.FreeHGlobal(noncePtr);
        if (aadPtr != IntPtr.Zero) Marshal.FreeHGlobal(aadPtr);
        if (tagPtr != IntPtr.Zero) Marshal.FreeHGlobal(tagPtr);
        if (key != IntPtr.Zero) BCryptDestroyKey(key);
        if (alg != IntPtr.Zero) BCryptCloseAlgorithmProvider(alg, 0);

        Console.WriteLine();
        Console.WriteLine("探测完成");
        return 0;
    }
}