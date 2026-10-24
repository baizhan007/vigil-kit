using System;
using System.Collections.Generic;
using System.IO;
using System.IO.Compression;
using System.Text;

namespace VigilKit.Archive
{
    /// <summary>
    /// 极简 ZIP 打包器（store/deflate）。用 DeflateStream 自实现，
    /// 不依赖 System.IO.Compression.FileSystem，保证在最小引用集下也能编译运行。
    /// 用途：把收集到的文件按批打包回传，减少连接数。
    /// </summary>
    public static class Zip
    {
        private static readonly uint[] CrcTable = BuildCrcTable();

        private static uint[] BuildCrcTable()
        {
            var t = new uint[256];
            for (uint i = 0; i < 256; i++)
            {
                uint c = i;
                for (int k = 0; k < 8; k++) c = ((c & 1) != 0) ? (0xEDB88320u ^ (c >> 1)) : (c >> 1);
                t[i] = c;
            }
            return t;
        }

        public static uint Crc32(byte[] data)
        {
            uint c = 0xFFFFFFFFu;
            for (int i = 0; i < data.Length; i++) c = CrcTable[(c ^ data[i]) & 0xFF] ^ (c >> 8);
            return c ^ 0xFFFFFFFFu;
        }

        public sealed class Entry
        {
            public string Name;
            public byte[] Data;
            public uint Crc;
            public uint CompressedSize;
            public uint UncompressedSize;
            public ushort Method;
            public long LocalHeaderOffset;
        }

        public static string Pack(List<string> files, string zipPath)
        {
            var entries = new List<Entry>();
            foreach (string f in files)
            {
                try
                {
                    if (!File.Exists(f)) continue;
                    var fi = new FileInfo(f);
                    if (fi.Length > 64L * 1024 * 1024) continue;
                    var e = new Entry();
                    e.Name = UniqueName(entries, fi.Name);
                    e.Data = File.ReadAllBytes(f);
                    e.Crc = Crc32(e.Data);
                    e.UncompressedSize = (uint)e.Data.Length;
                    entries.Add(e);
                }
                catch { }
            }
            if (entries.Count == 0) return "[error] no files";

            using (var fs = new FileStream(zipPath, FileMode.Create, FileAccess.Write))
            using (var bw = new BinaryWriter(fs))
            {
                foreach (Entry e in entries)
                {
                    byte[] comp = Deflate(e.Data);
                    if (comp.Length >= e.Data.Length)
                    {
                        comp = e.Data;
                        e.Method = 0;
                    }
                    else e.Method = 8;
                    e.CompressedSize = (uint)comp.Length;
                    e.LocalHeaderOffset = fs.Position;

                    bw.Write(0x04034b50u);
                    bw.Write((ushort)20);
                    bw.Write((ushort)0);
                    bw.Write(e.Method);
                    bw.Write((ushort)0);
                    bw.Write((ushort)0);
                    bw.Write(e.Crc);
                    bw.Write(e.CompressedSize);
                    bw.Write(e.UncompressedSize);
                    ushort nameLen = (ushort)Encoding.UTF8.GetByteCount(e.Name);
                    bw.Write(nameLen);
                    bw.Write((ushort)0);
                    bw.Write(Encoding.UTF8.GetBytes(e.Name));
                    bw.Write(comp);
                }

                long cdStart = fs.Position;
                foreach (Entry e in entries)
                {
                    bw.Write(0x02014b50u);
                    bw.Write((ushort)20);
                    bw.Write((ushort)20);
                    bw.Write((ushort)0);
                    bw.Write(e.Method);
                    bw.Write((ushort)0);
                    bw.Write((ushort)0);
                    bw.Write(e.Crc);
                    bw.Write(e.CompressedSize);
                    bw.Write(e.UncompressedSize);
                    ushort nameLen = (ushort)Encoding.UTF8.GetByteCount(e.Name);
                    bw.Write(nameLen);
                    bw.Write((ushort)0);
                    bw.Write((ushort)0);
                    bw.Write((ushort)0);
                    bw.Write((ushort)0);
                    bw.Write((uint)0);
                    bw.Write((uint)e.LocalHeaderOffset);
                    bw.Write(Encoding.UTF8.GetBytes(e.Name));
                }
                long cdSize = fs.Position - cdStart;

                bw.Write(0x06054b50u);
                bw.Write((ushort)0);
                bw.Write((ushort)0);
                bw.Write((ushort)entries.Count);
                bw.Write((ushort)entries.Count);
                bw.Write((uint)cdSize);
                bw.Write((uint)cdStart);
                bw.Write((ushort)0);
            }
            return zipPath;
        }

        private static string UniqueName(List<Entry> entries, string name)
        {
            string candidate = name;
            int i = 1;
            while (entries.Exists(delegate (Entry e) { return e.Name == candidate; }))
            {
                candidate = Path.GetFileNameWithoutExtension(name) + "_" + i + Path.GetExtension(name);
                i++;
            }
            return candidate;
        }

        private static byte[] Deflate(byte[] data)
        {
            using (var ms = new MemoryStream())
            {
                using (var ds = new DeflateStream(ms, CompressionMode.Compress, true))
                {
                    ds.Write(data, 0, data.Length);
                }
                return ms.ToArray();
            }
        }

        public static byte[] Inflate(byte[] data)
        {
            using (var input = new MemoryStream(data))
            using (var ds = new DeflateStream(input, CompressionMode.Decompress))
            using (var outp = new MemoryStream())
            {
                var buf = new byte[8192];
                int n;
                while ((n = ds.Read(buf, 0, buf.Length)) > 0) outp.Write(buf, 0, n);
                return outp.ToArray();
            }
        }
    }
}
