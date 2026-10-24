using System;
using System.Collections.Generic;
using System.IO;
using System.Text;

namespace VigilKit.Sqlite
{
    /// <summary>
    /// 极简 SQLite 只读解析器（零依赖）。
    /// 用途：直接读浏览器 Login Data / Cookies / History 等库，不需要 System.Data.SQLite，
    /// 也就不会因为加载本地 SQLite 原生 DLL 而在磁盘上留下痕迹。
    /// 支持：sqlite_master 枚举、表 B-Tree 全表扫描、变长整数、全部 serial type、溢出页。
    /// 不支持：索引、触发器、加密库（SQLCipher）。
    /// </summary>
    public sealed class SqliteReader : IDisposable
    {
        private readonly byte[] _db;
        private readonly int _pageSize;
        private readonly int _usable;
        private readonly int _reserved;

        public SqliteReader(string path)
        {
            _db = ReadAllBytesShared(path);
            if (_db.Length < 100) throw new InvalidDataException("not sqlite");
            if (Encoding.ASCII.GetString(_db, 0, 15) != "SQLite format 3") throw new InvalidDataException("bad magic");
            int ps = (_db[16] << 8) | _db[17];
            _pageSize = ps == 1 ? 65536 : ps;
            _reserved = _db[20];
            _usable = _pageSize - _reserved;
        }

        /// <summary>
        /// 以共享方式读取文件。
        ///
        /// 不能用 <c>File.ReadAllBytes</c>：它内部以 FileShare.Read 打开，
        /// 而浏览器在运行时会独占自己的 History / Login Data，导致读取直接失败。
        /// 指定 FileShare.ReadWrite 后，即使目标进程正在使用该文件也能读到内容。
        /// </summary>
        private static byte[] ReadAllBytesShared(string path)
        {
            using (var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite))
            {
                long length = stream.Length;
                if (length > int.MaxValue) throw new IOException("file too large");

                var buffer = new byte[length];
                int total = 0;
                while (total < buffer.Length)
                {
                    int read = stream.Read(buffer, total, buffer.Length - total);
                    if (read <= 0) break;
                    total += read;
                }

                // 文件可能在读取过程中被追加（如浏览器正在写入），按实际读到的长度截断
                if (total < buffer.Length) Array.Resize(ref buffer, total);
                return buffer;
            }
        }

        public SqliteReader(byte[] data)
        {
            _db = data;
            if (_db == null || _db.Length < 100) throw new InvalidDataException("not sqlite");
            if (Encoding.ASCII.GetString(_db, 0, 15) != "SQLite format 3") throw new InvalidDataException("bad magic");
            int ps = (_db[16] << 8) | _db[17];
            _pageSize = ps == 1 ? 65536 : ps;
            _reserved = _db[20];
            _usable = _pageSize - _reserved;
        }

        public void Dispose() { }

        // ---------- 表枚举 ----------

        public List<string> TableNames()
        {
            var names = new List<string>();
            foreach (object[] row in ReadTable("sqlite_master"))
            {
                if (row.Length < 5) continue;
                string type = Convert.ToString(row[0]);
                if (type == "table") names.Add(Convert.ToString(row[1]));
            }
            return names;
        }

        public string CreateSql(string table)
        {
            foreach (object[] row in ReadTable("sqlite_master"))
            {
                if (row.Length < 5) continue;
                if (Convert.ToString(row[1]) == table) return Convert.ToString(row[4]);
            }
            return "";
        }

        // ---------- 全表扫描 ----------

        /// <summary>读取整张表，返回行（列值按 serial type 解码）。</summary>
        public List<object[]> ReadTable(string table)
        {
            var rows = new List<object[]>();
            int rootPage = FindRootPage(table);
            if (rootPage <= 0) return rows;
            WalkTable(rootPage, rows, 0);
            return rows;
        }

        private int FindRootPage(string table)
        {
            // sqlite_master 的根页固定为第 1 页，且它内部不会登记自己，
            // 因此必须特判——否则查 sqlite_master 会扫出一张空表。
            if (table == "sqlite_master") return 1;

            var rows = new List<object[]>();
            WalkTable(1, rows, 0);
            foreach (object[] r in rows)
            {
                if (r.Length < 4) continue;
                if (Convert.ToString(r[1]) == table) return Convert.ToInt32(r[3]);
            }
            return 0;
        }

        private void WalkTable(int pageNo, List<object[]> rows, int depth)
        {
            if (depth > 24 || pageNo <= 0) return;
            int pageOff = (pageNo - 1) * _pageSize;
            if (pageOff + 8 > _db.Length) return;

            int hdr = pageOff;
            if (pageNo == 1) hdr = pageOff + 100;   // 第 1 页含 100 字节文件头

            byte type = _db[hdr];
            int nCells = (_db[hdr + 3] << 8) | _db[hdr + 4];
            int cellStart = hdr + (type == 0x05 || type == 0x02 ? 12 : 8);

            if (type == 0x05) // interior table
            {
                for (int i = 0; i < nCells; i++)
                {
                    int ptr = (_db[cellStart + i * 2] << 8) | _db[cellStart + i * 2 + 1];
                    int cell = pageOff + ptr;
                    int child = (_db[cell] << 24) | (_db[cell + 1] << 16) | (_db[cell + 2] << 8) | _db[cell + 3];
                    WalkTable(child, rows, depth + 1);
                }
                // 最右子页
                int right = (_db[hdr + 8] << 24) | (_db[hdr + 9] << 16) | (_db[hdr + 10] << 8) | _db[hdr + 11];
                WalkTable(right, rows, depth + 1);
            }
            else if (type == 0x0D) // leaf table
            {
                for (int i = 0; i < nCells; i++)
                {
                    int ptr = (_db[cellStart + i * 2] << 8) | _db[cellStart + i * 2 + 1];
                    int cell = pageOff + ptr;
                    object[] row = ReadLeafCell(cell);
                    if (row != null) rows.Add(row);
                }
            }
        }

        private object[] ReadLeafCell(int cell)
        {
            int pos = cell;
            long payloadLen = ReadVarint(_db, ref pos);
            long rowid = ReadVarint(_db, ref pos);
            int maxLocal = _usable - 35;
            int minLocal = ((_usable - 12) * 32 / 255) - 23;
            int local = (int)payloadLen;
            if (payloadLen > maxLocal)
            {
                local = minLocal + (int)((payloadLen - minLocal) % (_usable - 4));
                if (local > maxLocal) local = minLocal;
            }

            var payload = new byte[payloadLen];
            int copy = Math.Min(local, (int)payloadLen);
            Buffer.BlockCopy(_db, pos, payload, 0, copy);

            if (copy < payloadLen)
            {
                // 溢出页链：cell 尾部 4 字节是第一页号
                int ovfl = (_db[pos + local] << 24) | (_db[pos + local + 1] << 16) |
                           (_db[pos + local + 2] << 8) | _db[pos + local + 3];
                int written = copy;
                int guard = 0;
                while (ovfl > 0 && written < payloadLen && guard++ < 4096)
                {
                    int off = (ovfl - 1) * _pageSize;
                    int next = (_db[off] << 24) | (_db[off + 1] << 16) | (_db[off + 2] << 8) | _db[off + 3];
                    int n = Math.Min(_pageSize - 4, (int)payloadLen - written);
                    Buffer.BlockCopy(_db, off + 4, payload, written, n);
                    written += n;
                    ovfl = next;
                }
            }

            return DecodeRecord(payload);
        }

        // ---------- 记录解码 ----------

        private static object[] DecodeRecord(byte[] rec)
        {
            int pos = 0;
            long hdrLen = ReadVarint(rec, ref pos);
            var types = new List<long>();
            int hpos = pos;
            while (hpos < hdrLen)
            {
                long t = ReadVarint(rec, ref hpos);
                types.Add(t);
            }

            var values = new object[types.Count];
            int body = (int)hdrLen;
            for (int i = 0; i < types.Count; i++)
            {
                long t = types[i];
                if (t == 0) { values[i] = null; continue; }
                if (t >= 1 && t <= 6)
                {
                    int len = (int)t;
                    long v = 0;
                    for (int k = 0; k < len; k++) v = (v << 8) | rec[body + k];
                    // 有符号
                    int shift = 64 - len * 8;
                    v = (v << shift) >> shift;
                    values[i] = v;
                    body += len;
                }
                else if (t == 7)
                {
                    values[i] = BitConverter.ToDouble(rec, body);
                    body += 8;
                }
                else if (t == 8) { values[i] = 0L; }
                else if (t == 9) { values[i] = 1L; }
                else if (t >= 12)
                {
                    int len = (int)((t % 2 == 0) ? (t - 12) / 2 : (t - 13) / 2);
                    if (t % 2 == 0)
                    {
                        var b = new byte[len];
                        Buffer.BlockCopy(rec, body, b, 0, Math.Min(len, rec.Length - body));
                        values[i] = b;
                    }
                    else
                    {
                        values[i] = Encoding.UTF8.GetString(rec, body, Math.Min(len, rec.Length - body));
                    }
                    body += len;
                }
                else values[i] = null;
            }
            return values;
        }

        public static long ReadVarint(byte[] buf, ref int pos)
        {
            long v = 0;
            for (int i = 0; i < 9; i++)
            {
                byte b = buf[pos++];
                if (i == 8) { v = (v << 8) | b; break; }
                v = (v << 7) | ((long)b & 0x7F);
                if ((b & 0x80) == 0) break;
            }
            return v;
        }

        // ---------- 便捷查询 ----------

        /// <summary>按列名取值（列名来自建表语句，简单解析）。</summary>
        public static List<Dictionary<string, object>> Query(string dbPath, string table, string[] wanted)
        {
            var outList = new List<Dictionary<string, object>>();
            using (var r = new SqliteReader(dbPath))
            {
                string sql = r.CreateSql(table);
                var cols = ParseColumns(sql);
                if (cols.Count == 0) return outList;
                foreach (object[] row in r.ReadTable(table))
                {
                    var d = new Dictionary<string, object>(StringComparer.OrdinalIgnoreCase);
                    for (int i = 0; i < cols.Count && i < row.Length; i++) d[cols[i]] = row[i];
                    if (wanted != null && wanted.Length > 0)
                    {
                        bool has = false;
                        foreach (string w in wanted) if (d.ContainsKey(w)) { has = true; break; }
                        if (!has) continue;
                    }
                    outList.Add(d);
                }
            }
            return outList;
        }

        /// <summary>从 CREATE TABLE 语句里抠出列名（跳过约束行）。</summary>
        public static List<string> ParseColumns(string createSql)
        {
            var cols = new List<string>();
            if (string.IsNullOrEmpty(createSql)) return cols;
            int lp = createSql.IndexOf('(');
            int rp = createSql.LastIndexOf(')');
            if (lp < 0 || rp <= lp) return cols;
            string body = createSql.Substring(lp + 1, rp - lp - 1);

            var parts = new List<string>();
            int depth = 0, start = 0;
            for (int i = 0; i < body.Length; i++)
            {
                char c = body[i];
                if (c == '(') depth++;
                else if (c == ')') depth--;
                else if (c == ',' && depth == 0) { parts.Add(body.Substring(start, i - start)); start = i + 1; }
            }
            parts.Add(body.Substring(start));

            string[] keywords = new string[] { "PRIMARY", "UNIQUE", "CHECK", "FOREIGN", "CONSTRAINT" };
            foreach (string raw in parts)
            {
                string s = raw.Trim();
                if (s.Length == 0) continue;
                bool skip = false;
                string upper = s.ToUpperInvariant();
                foreach (string k in keywords) if (upper.StartsWith(k)) { skip = true; break; }
                if (skip) continue;
                int sp = s.IndexOfAny(new char[] { ' ', '\t', '\r', '\n' });
                string name = sp > 0 ? s.Substring(0, sp) : s;
                name = name.Trim('"', '[', ']', '`', '\'');
                cols.Add(name);
            }
            return cols;
        }
    }
}
