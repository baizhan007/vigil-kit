"""手工构造最小 SQLite 文件的布局验证脚本。

用途：在把构造逻辑移植到 C# 之前，先用 Python 的官方 sqlite3 模块
验证手工算出的字节布局确实是一个合法的 SQLite 数据库。

如果本脚本能通过 sqlite3 读出预期数据，说明布局正确，
可以放心地把同样的逻辑写进 C# 测试夹具。
"""
import sqlite3
import struct
import tempfile
import os


def varint(n):
    """SQLite 变长整数编码（小端 7 位分组，最高位表示续接）。"""
    if n < 0:
        raise ValueError("varint only handles non-negative values")
    if n < 0x80:
        return bytes([n])
    out = bytearray()
    while n > 0:
        out.append((n & 0x7F) | 0x80)
        n >>= 7
    # 最后一个字节不带续接位
    out[-1] &= 0x7F
    return bytes(out)


def serial_text(s):
    """文本的 serial type = 2 * 字节数 + 13。"""
    return 2 * len(s) + 13


def build_record(header_size, serial_types, values):
    """组装一条记录：header_size + serial types + 值区。"""
    return bytes([header_size]) + bytes(serial_types) + b"".join(values)


def build_min_sqlite():
    """构造一个含 sqlite_master 与 test 表的最小 SQLite 数据库。"""
    page_size = 4096
    db = bytearray(page_size * 2)

    # ---------- 文件头（100 字节） ----------
    db[0:16] = b"SQLite format 3\x00"
    db[16:18] = struct.pack(">H", page_size)   # 页大小
    db[18] = 1                                  # 文件格式写版本
    db[19] = 1                                  # 文件格式读版本
    db[20] = 0                                  # 每页保留字节
    db[21] = 64                                 # 最大嵌入载荷分数
    db[22] = 32                                 # 最小嵌入载荷分数
    db[23] = 32                                 # 叶子载荷分数
    db[24:28] = struct.pack(">I", 1)            # 文件变更计数器
    db[28:32] = struct.pack(">I", 2)            # 数据库页数
    db[32:36] = struct.pack(">I", 0)            # 空闲页链表头
    db[36:40] = struct.pack(">I", 0)            # 空闲页总数
    db[40:44] = struct.pack(">I", 1)            # schema cookie
    db[44:48] = struct.pack(">I", 4)            # schema 格式号
    db[48:52] = struct.pack(">I", 0)            # 默认页缓存
    db[52:56] = struct.pack(">I", 0)            # 最大根页
    db[56:60] = struct.pack(">I", 1)            # 文本编码 1=UTF-8
    db[60:64] = struct.pack(">I", 0)            # 用户版本
    db[64:68] = struct.pack(">I", 0)            # 增量 vacuum
    db[68:72] = struct.pack(">I", 0)            # application id
    db[92:96] = struct.pack(">I", 1)            # 版本有效标志
    db[96:100] = struct.pack(">I", 3045000)     # SQLite 版本号

    # ---------- 页 1：sqlite_master（叶子表页） ----------
    sql = "CREATE TABLE test (id INTEGER, name TEXT)"
    master_row = build_record(
        header_size=6,
        serial_types=[serial_text("table"), serial_text("test"),
                      serial_text("test"), 1, serial_text(sql)],
        values=[b"table", b"test", b"test", b"\x02", sql.encode()],
    )
    payload_size = len(master_row)
    cell = varint(payload_size) + varint(1) + master_row
    cell_offset = page_size - len(cell)

    # 页 1 的 B-tree 头从偏移 100 开始
    db[100] = 0x0D
    db[103:105] = struct.pack(">H", 1)               # 单元数
    db[105:107] = struct.pack(">H", cell_offset)     # 单元内容起始
    db[108:110] = struct.pack(">H", cell_offset)     # 单元指针
    db[cell_offset:cell_offset + len(cell)] = cell

    # ---------- 页 2：test 表（叶子表页） ----------
    rows = [(1, "hello"), (2, "world")]
    cells = []
    for rowid, name in rows:
        rec = build_record(
            header_size=3,
            serial_types=[1, serial_text(name)],
            values=[bytes([rowid]), name.encode()],
        )
        cells.append(varint(len(rec)) + varint(rowid) + rec)

    base = page_size
    cursor = page_size
    offsets = []
    for c in cells:
        cursor -= len(c)
        offsets.append(cursor)
        db[base + cursor:base + cursor + len(c)] = c

    db[base] = 0x0D
    db[base + 3:base + 5] = struct.pack(">H", len(cells))
    db[base + 5:base + 7] = struct.pack(">H", min(offsets))
    for i, off in enumerate(offsets):
        db[base + 8 + i * 2: base + 10 + i * 2] = struct.pack(">H", off)

    return bytes(db)


def main():
    data = build_min_sqlite()
    print("生成文件大小: %d 字节 (2 页 × 4096)" % len(data))

    path = os.path.join(tempfile.gettempdir(), "vigil_layout_test.db")
    with open(path, "wb") as f:
        f.write(data)
    print("写入临时文件: %s" % path)

    # 用官方 sqlite3 模块验证
    conn = sqlite3.connect(path)
    cur = conn.cursor()

    tables = [r[0] for r in cur.execute(
        "SELECT name FROM sqlite_master WHERE type='table'").fetchall()]
    print("sqlite3 读到的表: %s" % tables)
    assert "test" in tables, "test 表未被识别"

    schema = cur.execute(
        "SELECT sql FROM sqlite_master WHERE name='test'").fetchone()[0]
    print("sqlite3 读到的 schema: %s" % schema)

    rows = cur.execute("SELECT id, name FROM test ORDER BY id").fetchall()
    print("sqlite3 读到的数据: %s" % rows)
    assert rows == [(1, "hello"), (2, "world")], "数据不匹配"

    # 完整性检查
    ok = cur.execute("PRAGMA integrity_check").fetchone()[0]
    print("integrity_check: %s" % ok)
    assert ok == "ok", "完整性检查失败"

    conn.close()
    print("\n[PASS] 手工构造的字节布局被官方 sqlite3 完全接受")

    # 导出十六进制，供 C# 侧比对
    hexpath = os.path.join(tempfile.gettempdir(), "vigil_layout_test.hex")
    with open(hexpath, "w") as f:
        f.write(data.hex())
    print("十六进制已导出: %s" % hexpath)


if __name__ == "__main__":
    main()