using System;
using System.Collections.Generic;
using System.IO;
using System.Text;

namespace VigilKit.Tests
{
    /// <summary>
    /// 手工构造最小 SQLite 数据库文件，用于测试 SqliteReader。
    ///
    /// 为什么要自建夹具而不是放一个二进制样本进仓库：
    /// <list type="bullet">
    /// <item>构造过程可读可审计，字节布局一目了然；</item>
    /// <item>仓库里不出现二进制文件；</item>
    /// <item>可以精确控制边界情况（空值、大整数、溢出页）。</item>
    /// </list>
    ///
    /// 布局已用官方 <c>sqlite3</c> 模块交叉验证（见同目录 verify-sqlite-layout.py）：
    /// 生成的文件能被官方实现正常打开并通过 PRAGMA integrity_check。
    /// </summary>
    public static class SqliteFixture
    {
        /// <summary>构造一个含 sqlite_master 与 test 表的两页数据库。</summary>
        public static byte[] BuildMinimal()
        {
            const int pageSize = 4096;
            var db = new byte[pageSize * 2];

            WriteFileHeader(db, pageSize, pageCount: 2);

            // ---------- 页 1：sqlite_master ----------
            const string schema = "CREATE TABLE test (id INTEGER, name TEXT)";

            var masterRow = BuildRecord(
                headerSize: 6,
                serialTypes: new[] {
                    SerialText("table"),
                    SerialText("test"),
                    SerialText("test"),
                    1,                       // 1 字节整数
                    SerialText(schema)
                },
                values: new[] {
                    Bytes("table"),
                    Bytes("test"),
                    Bytes("test"),
                    new byte[] { 0x02 },     // rootpage = 2
                    Bytes(schema)
                });

            byte[] masterCell = Concat(Varint(masterRow.Length), Varint(1), masterRow);
            int masterOffset = pageSize - masterCell.Length;

            // 页 1 的 B-tree 头从偏移 100 开始（前 100 字节是文件头）
            db[100] = 0x0D;                                    // 叶子表页
            WriteU16(db, 103, 1);                              // 单元数
            WriteU16(db, 105, masterOffset);                   // 单元内容起始
            WriteU16(db, 108, masterOffset);                   // 单元指针
            Buffer.BlockCopy(masterCell, 0, db, masterOffset, masterCell.Length);

            // ---------- 页 2：test 表 ----------
            var rows = new[] {
                new object[] { 1, "hello" },
                new object[] { 2, "world" }
            };

            var cells = new List<byte[]>();
            foreach (object[] row in rows)
            {
                int id = (int)row[0];
                string name = (string)row[1];

                var record = BuildRecord(
                    headerSize: 3,
                    serialTypes: new[] { 1, SerialText(name) },
                    values: new[] { new byte[] { (byte)id }, Bytes(name) });

                cells.Add(Concat(Varint(record.Length), Varint(id), record));
            }

            int cursor = pageSize;
            var offsets = new List<int>();
            foreach (byte[] cell in cells)
            {
                cursor -= cell.Length;
                offsets.Add(cursor);
                Buffer.BlockCopy(cell, 0, db, pageSize + cursor, cell.Length);
            }

            db[pageSize] = 0x0D;
            WriteU16(db, pageSize + 3, cells.Count);
            WriteU16(db, pageSize + 5, Min(offsets));
            for (int i = 0; i < offsets.Count; i++)
                WriteU16(db, pageSize + 8 + i * 2, offsets[i]);

            return db;
        }

        // ---------- 文件头 ----------

        private static void WriteFileHeader(byte[] db, int pageSize, int pageCount)
        {
            byte[] magic = Bytes("SQLite format 3\0");
            Buffer.BlockCopy(magic, 0, db, 0, magic.Length);

            WriteU16(db, 16, pageSize);       // 页大小
            db[18] = 1;                       // 写版本
            db[19] = 1;                       // 读版本
            db[20] = 0;                       // 每页保留字节
            db[21] = 64;                      // 最大嵌入载荷分数
            db[22] = 32;                      // 最小嵌入载荷分数
            db[23] = 32;                      // 叶子载荷分数
            WriteU32(db, 24, 1);              // 文件变更计数器
            WriteU32(db, 28, pageCount);      // 数据库页数
            WriteU32(db, 40, 1);              // schema cookie
            WriteU32(db, 44, 4);              // schema 格式号
            WriteU32(db, 56, 1);              // 文本编码 1 = UTF-8
            WriteU32(db, 92, 1);              // 版本有效
            WriteU32(db, 96, 3045000);        // SQLite 版本号
        }

        // ---------- 记录与单元 ----------

        /// <summary>文本的 serial type = 2 × 字节数 + 13。</summary>
        private static int SerialText(string value)
        {
            return 2 * Encoding.UTF8.GetByteCount(value) + 13;
        }

        private static byte[] BuildRecord(int headerSize, int[] serialTypes, byte[][] values)
        {
            var buffer = new List<byte>();
            buffer.Add((byte)headerSize);
            foreach (int st in serialTypes) buffer.Add((byte)st);
            foreach (byte[] v in values) buffer.AddRange(v);
            return buffer.ToArray();
        }

        /// <summary>SQLite 变长整数：7 位一组，最高位表示续接。</summary>
        private static byte[] Varint(int value)
        {
            if (value < 0) throw new ArgumentOutOfRangeException("value", "varint requires non-negative");

            if (value < 0x80) return new byte[] { (byte)value };

            var list = new List<byte>();
            int n = value;
            while (n > 0)
            {
                list.Add((byte)((n & 0x7F) | 0x80));
                n >>= 7;
            }
            // 最后一个字节去掉续接位
            list[list.Count - 1] = (byte)(list[list.Count - 1] & 0x7F);
            return list.ToArray();
        }

        // ---------- 小工具 ----------

        private static byte[] Bytes(string s)
        {
            return Encoding.UTF8.GetBytes(s);
        }

        private static byte[] Concat(params byte[][] parts)
        {
            int total = 0;
            foreach (byte[] p in parts) total += p.Length;

            var result = new byte[total];
            int offset = 0;
            foreach (byte[] p in parts)
            {
                Buffer.BlockCopy(p, 0, result, offset, p.Length);
                offset += p.Length;
            }
            return result;
        }

        private static void WriteU16(byte[] buffer, int offset, int value)
        {
            buffer[offset] = (byte)((value >> 8) & 0xFF);
            buffer[offset + 1] = (byte)(value & 0xFF);
        }

        private static void WriteU32(byte[] buffer, int offset, long value)
        {
            buffer[offset] = (byte)((value >> 24) & 0xFF);
            buffer[offset + 1] = (byte)((value >> 16) & 0xFF);
            buffer[offset + 2] = (byte)((value >> 8) & 0xFF);
            buffer[offset + 3] = (byte)(value & 0xFF);
        }

        private static int Min(List<int> values)
        {
            int m = values[0];
            foreach (int v in values) if (v < m) m = v;
            return m;
        }
    }
}