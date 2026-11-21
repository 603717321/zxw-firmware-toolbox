# -*- coding: utf-8 -*-
"""
中兴微固件工具箱 —— 通用版
================================================

面向四件核心事，界面与流程重新整理过，去掉了原版里不必要的功能：

  ① 通用信息   读/改 WiFi名、WiFi密码、IMEI、SN、默认SIM、软件版本、硬件版本、MAC
               改完自动写回原分区（nvrofs / userdata），无需用户关心分区
  ② 解包分区   解包任意分区为目录，对文件做增删改查（含权限）
  ③ 打包回写   按权限清单选择 JFFS2 / XZ SquashFS；容量检查后回写目标分区
  ④ 出固件     回写指定分区 / 合并整个固件，得到新的编程器固件

内嵌纯 Python 文件系统与分区引擎；图形界面依赖 PyQt5，部分扩展压缩算法需要可选包。
Windows 上不需要 Linux / WSL / msys2 / mksquashfs / unsquashfs。

用法：双击「启动工具.bat」或 python 中兴微固件工具箱.py
"""

import os
import re
import sys
import json
import stat
import shutil
import struct
import hashlib
import traceback

# =====================================================================
#                        内嵌引擎加载
# =====================================================================
# 开发期：同目录 _engine/ 下的真实 .py
# 交付期：下面的 *_SRC 常量被构建脚本替换为内嵌源码字符串
BASE_DIR = os.path.dirname(os.path.abspath(__file__))

JFFS2_SRC = '#!/usr/bin/env python3\n# -*- coding: utf-8 -*-\n"""\n中兴微固件 JFFS2 引擎 —— 纯 Python，Windows 本地可运行，零第三方依赖\n================================================================================\n\n背景\n----\n5.userdata / 6.oem 两个分区使用厂商定制的 JFFS2：\n  * compr = 8  = 裸 LZMA1，参数固定 lc=0 / lp=0 / pb=0（无 xz 容器头）\n  * 擦除块 = 32KB (32768)\n  * little-endian，无 cleanmarker\n\n标准 mtd-utils 的 jffs2reader / mkfs.jffs2 遇到 compr=8 会直接\n"Unsupported compression method!"。本模块自己实现全部节点解析与生成，\n因此 **不需要 Linux、不需要 mtd-utils、不需要 WSL**。\n\nJFFS2 节点格式（全部 little-endian）\n------------------------------------\n通用头 (12 字节)：\n    u16 magic       = 0x1985\n    u16 nodetype    0xE001=dirent, 0xE002=inode\n    u32 totlen      含头总长\n条目结点后面还有 u32 hdr_crc（本模块解析时跳过，生成时补 0）\n\ndirent (0xE001) 从 +12 开始：\n    u32 pino, u32 version, u32 ino, u32 mctime, u8 nsize, u8 dtype,\n    u16 _unused, u32 _ino2, u32 _pino2, then name (nsize bytes) at +40\n\ninode (0xE002) 从 +12 开始：\n    u32 ino, u32 version, u32 mode, u16 uid, u16 gid,\n    u32 isize, u32 atime, u32 mtime, u32 ctime, u32 offset,\n    u32 csize, u32 dsize, u8 compr, u8 usercompr, u16 flags,\n    then data (csize bytes) at +68\n\n节点前进量 = (totlen + 3) & ~3\n\n权限保持\n--------\nWindows 的 NTFS 没有 Unix mode/uid/gid 概念，解包出来的文件权限一律丢失。\n本模块在解包时把每个条目的 (mode, uid, gid) 写进 .perm.json 旁挂清单，\n打包时读回清单按真实值重建 inode —— 做到权限零漂移。\n新增的文件只要在清单里给出权限，也会被同样处理。\n"""\n\nimport io\nimport json\nimport lzma\nimport os\nimport stat\nimport struct\nimport sys\nimport time\n\n# ------------------------------------------------------------------ 常量\nMAGIC = 0x1985\nNT_DIRENT = 0xE001\nNT_INODE = 0xE002\nNT_CLEANMARKER = 0x2003\nNT_PADDING = 0x2004\n\nJFFS2_EMPTY = 0x00\nJFFS2_NORMAL = 0x01\n\nCOMPR_NONE = 0\nCOMPR_ZERO = 1\nCOMPR_RTIME = 2\nCOMPR_RUBINMIPS = 3\nCOMPR_COPY = 4\nCOMPR_DYNRUBIN = 5\nCOMPR_ZLIB = 6\nCOMPR_LZMA_VENDOR = 8       # 厂商定制：裸 LZMA1, lc=0 lp=0 pb=0\n\nLZMA_FILTERS = [{"id": lzma.FILTER_LZMA1, "lc": 0, "lp": 0, "pb": 0}]\nLZMA_FILTERS_ENC = [{"id": lzma.FILTER_LZMA1, "preset": 6, "lc": 0, "lp": 0, "pb": 0}]\n\nPERM_FILE = ".perm.json"\nDEFAULT_UMASK_MODE = 0o644\n\n# 工具自生成文件——打包时必须排除。JFFS2 模块可独立执行，故自带一份判据\n# （与 squashfs 模块的 is_auxiliary 语义一致）。\nJFFS2_SKIP_NAMES = {".DS_Store", "Thumbs.db", "desktop.ini", "__pycache__",\n                    ".git", ".svn"}\n\n\ndef is_auxiliary(rel, perm_files=(PERM_FILE, ".squashfs.perm.json")):\n    """rel 是否是工具自生成/应忽略的文件（\'/\' 分隔的相对路径）"""\n    parts = [p for p in str(rel).replace("\\\\", "/").split("/") if p]\n    if not parts:\n        return False\n    if parts[-1] in perm_files or parts[-1] in JFFS2_SKIP_NAMES:\n        return True\n    for p in parts[:-1]:\n        if p in ("__pycache__", ".git", ".svn"):\n            return True\n    return False\n\n# dtype 编码（JFFS2 内部用 8bit 表示，非 Unix 的 S_IFMT）\nDT_UNKNOWN = 0\nDT_FIFO = 1\nDT_CHR = 2\nDT_DIR = 4\nDT_BLK = 6\nDT_REG = 8\nDT_LNK = 10\nDT_SOCK = 12\nDT_WHT = 14\n\n\n# ------------------------------------------------------------------ 工具\ndef _md5(b):\n    import hashlib\n    return hashlib.md5(b).hexdigest()\n\n\ndef mode_to_dtype(mode):\n    """Unix mode -> JFFS2 dtype"""\n    fmt = stat.S_IFMT(mode)\n    return {\n        stat.S_IFIFO: DT_FIFO,\n        stat.S_IFCHR: DT_CHR,\n        stat.S_IFDIR: DT_DIR,\n        stat.S_IFBLK: DT_BLK,\n        stat.S_IFREG: DT_REG,\n        stat.S_IFLNK: DT_LNK,\n        stat.S_IFSOCK: DT_SOCK,\n    }.get(fmt, DT_REG)\n\n\ndef dtype_to_mode_bits(dtype):\n    """JFFS2 dtype -> Unix type bits"""\n    return {\n        DT_FIFO: stat.S_IFIFO,\n        DT_CHR: stat.S_IFCHR,\n        DT_DIR: stat.S_IFDIR,\n        DT_BLK: stat.S_IFBLK,\n        DT_REG: stat.S_IFREG,\n        DT_LNK: stat.S_IFLNK,\n        DT_SOCK: stat.S_IFSOCK,\n    }.get(dtype, stat.S_IFREG)\n\n\ndef _crc32(data):\n    import zlib\n    return (zlib.crc32(data, 0xffffffff) ^ 0xffffffff) & 0xffffffff\n\n\n\n# ------------------------------------------------------------------ 解压\ndef lzma_raw_decompress(data, dsize):\n    """厂商 compr=8：裸 LZMA1 (lc=0,lp=0,pb=0)，无容器头"""\n    d = lzma.LZMADecompressor(format=lzma.FORMAT_RAW, filters=LZMA_FILTERS)\n    out = d.decompress(data, dsize)\n    if len(out) < dsize:\n        # 某些实现会多消耗一点，再补一次\n        out += d.decompress(b"", dsize - len(out))\n    return out\n\n\ndef lzma_raw_compress(data):\n    """压回厂商格式。lit_contextbits 必须与解压端一致，否则设备读不了"""\n    f = dict(LZMA_FILTERS_ENC[0])\n    f["preset"] = 6\n    return lzma.compress(data, format=lzma.FORMAT_RAW, filters=[f])\n\n\ndef lzma_raw_compress_safe(data, max_size):\n    """\n    压缩并保证结果 <= max_size。LZMA 对极短数据可能反而变大，\n    此时逐级降级 preset，最后兜底用 COMPR_NONE 原样存。\n    返回 (compr, payload)。\n    """\n    if not data:\n        return COMPR_ZERO, b""\n    for preset in (6, 1):\n        f = {"id": lzma.FILTER_LZMA1, "preset": preset, "dict_size": 65536, "lc": 0, "lp": 0, "pb": 0}\n        try:\n            out = lzma.compress(data, format=lzma.FORMAT_RAW, filters=[f])\n        except Exception:\n            continue\n        if len(out) <= max_size:\n            return COMPR_LZMA_VENDOR, out\n    if len(data) <= max_size:\n        return COMPR_NONE, data\n    return COMPR_LZMA_VENDOR, lzma_raw_compress(data)   # 尽力而为\n\n\ndef decompress(compr, csize, dsize, data):\n    if dsize == 0:\n        return b""\n    if compr == COMPR_ZERO:\n        return b"\\x00" * dsize\n    if csize == 0:\n        return b""\n    if compr == COMPR_NONE:\n        return bytes(data[:dsize])\n    if compr == COMPR_COPY:\n        return bytes(data[:dsize])\n    if compr == COMPR_ZLIB:\n        import zlib\n        return zlib.decompress(bytes(data[:csize]))\n    if compr == 7:\n        return lzo1x_decompress(bytes(data[:csize]), dsize)\n    if compr == COMPR_LZMA_VENDOR:\n        return lzma_raw_decompress(bytes(data[:csize]), dsize)\n    if compr == COMPR_RTIME:\n        return _rtime_decompress(bytes(data[:csize]), dsize)\n    raise ValueError("不支持的压缩方式 compr=%d" % compr)\n\n\ndef lzo1x_compress(data):\n    """LZO1X v0 encoder using literal runs and 16 KiB M3 matches."""\n    if not data:\n        return b\'\\x11\\0\\0\'\n    segments, seen, p, anchor = [], {}, 0, 0\n    while p+4<=len(data):\n        key = data[p:p+4]\n        old = seen.get(key)\n        seen[key] = p\n        if old is not None and 0<p-old<=16384:\n            length = 4\n            while p+length<len(data) and data[old+length]==data[p+length]:\n                length += 1\n            segments.append((data[anchor:p],p-old,length))\n            end = p+length\n            for q in range(p+1,end):\n                if q+4<=len(data):\n                    seen[data[q:q+4]] = q\n            p,anchor = end,end\n        else:\n            p += 1\n    tail = data[anchor:]\n    out = bytearray()\n    previous_word = None\n    def extension(value):\n        while value>255:\n            out.append(0)\n            value -= 255\n        out.append(value)\n    def literals(blob, initial=False):\n        nonlocal previous_word\n        n = len(blob)\n        if not n:\n            return\n        if not initial and n<=3:\n            if previous_word is None:\n                raise ValueError(\'LZO 编码状态错误\')\n            out[previous_word] |= n\n        elif initial and n<=238:\n            out.append(17+n)\n        elif n<=18:\n            out.append(n-3)\n        else:\n            out.append(0)\n            extension(n-18)\n        out.extend(blob)\n    for blob,distance,length in segments:\n        literals(blob,not out)\n        if length<=33:\n            out.append(32+length-2)\n        else:\n            out.append(32)\n            extension(length-33)\n        previous_word = len(out)\n        out.extend(struct.pack(\'<H\',(distance-1)<<2))\n    literals(tail,not out)\n    out.extend(b\'\\x11\\0\\0\')\n    return bytes(out)\n\n\ndef lzo1x_decompress(src, limit):\n    """Bounded LZO1X v0 block decoder (JFFS2 compression ID 7)."""\n    p, out, state = 0, bytearray(), 0\n    def get():\n        nonlocal p\n        if p >= len(src):\n            raise ValueError(\'LZO 输入截断\')\n        value = src[p]\n        p += 1\n        return value\n    def literals(n):\n        nonlocal p\n        if p+n > len(src) or len(out)+n > limit:\n            raise ValueError(\'LZO literal 越界\')\n        out.extend(src[p:p+n])\n        p += n\n    def extended(base):\n        value = get()\n        while value == 0:\n            base += 255\n            value = get()\n        return base + value\n    if len(src) < 3:\n        raise ValueError(\'LZO 数据过短\')\n    if src[0] > 17:\n        n = get()-17\n        literals(n)\n        state = n if n < 4 else 4\n    while True:\n        token = get()\n        if token < 16:\n            if state == 0:\n                n = (extended(15) if token == 0 else token)+3\n                literals(n)\n                state = 4\n                continue\n            trailing = token & 3\n            back = len(out) - (2049 if state == 4 else 1) - (token >> 2) - (get() << 2)\n            n = 3 if state == 4 else 2\n        elif token >= 64:\n            trailing = token & 3\n            back = len(out)-1-((token >> 2)&7)-(get()<<3)\n            n = (token >> 5)+1\n        elif token >= 32:\n            n = token & 31\n            n = (extended(31) if n == 0 else n)+2\n            word = get() | get()<<8\n            back, trailing = len(out)-1-(word>>2), word&3\n        else:\n            n = token & 7\n            n = (extended(7) if n == 0 else n)+2\n            word = get() | get()<<8\n            back = len(out)-((token&8)<<11)-(word>>2)\n            trailing = word&3\n            if back == len(out):\n                if n != 3 or p != len(src) or len(out) != limit:\n                    raise ValueError(\'LZO 结束标记或输出尺寸无效\')\n                return bytes(out)\n            back -= 16384\n        if back < 0 or len(out)+n > limit:\n            raise ValueError(\'LZO match 越界\')\n        for _ in range(n):\n            out.append(out[back])\n            back += 1\n        literals(trailing)\n        state = trailing\n\n\ndef _rtime_decompress(src, dsize):\n    positions = [0] * 256\n    out = bytearray()\n    p = 0\n    while len(out) < dsize:\n        if p + 2 > len(src):\n            raise ValueError("RTIME 数据截断")\n        value, repeat = src[p:p+2]\n        p += 2\n        out.append(value)\n        back = positions[value]\n        positions[value] = len(out)\n        if len(out) + repeat > dsize:\n            raise ValueError("RTIME 输出越界")\n        for _ in range(repeat):\n            if back >= len(out):\n                raise ValueError("RTIME 回溯越界")\n            out.append(out[back])\n            back += 1\n    return bytes(out)\n\n\n\n# ------------------------------------------------------------------ 解析\nclass Jffs2Entry(object):\n    __slots__ = ("ino", "path", "mode", "uid", "gid", "isize",\n                 "mtime", "atime", "ctime", "data", "link")\n\n    def __init__(self):\n        self.ino = 0\n        self.path = ""\n        self.mode = 0\n        self.uid = 0\n        self.gid = 0\n        self.isize = 0\n        self.mtime = 0\n        self.atime = 0\n        self.ctime = 0\n        self.data = b""\n        self.link = None\n\n    @property\n    def is_dir(self):\n        return stat.S_IFMT(self.mode) == stat.S_IFDIR\n\n    @property\n    def is_link(self):\n        return stat.S_IFMT(self.mode) == stat.S_IFLNK\n\n    @property\n    def perm(self):\n        return stat.S_IMODE(self.mode)\n\n\ndef parse(image_path, emit=None, want_data=True):\n    """CRC-checked journal replay; newer fragments overwrite older byte ranges."""\n    import re\n    if isinstance(image_path, (bytes,bytearray)):\n        raw = bytes(image_path)\n    else:\n        with open(image_path,\'rb\') as f:\n            raw = f.read()\n    total = len(raw)\n    candidates = list(re.finditer(b\'(?=\\x85\\x19|\\x19\\x85)\', raw))\n    endian = None\n    stats = dict(nodes=0, dirent=0, inode=0, cleanmarker=0, padding=0,\n                 empty=0, unknown=0, bad_crc=0, obsolete=0, compression={}, data_block_sizes={}, erase_size=32768)\n    dirents, inodes, chunks = {}, {}, {}\n    nextoff = 0\n    markers = []\n    for match in candidates:\n        off = match.start()\n        if off < nextoff or off % 4 or off + 12 > total:\n            continue\n        order = \'<\' if raw[off:off+2] == b\'\\x85\\x19\' else \'>\'\n        magic, nt, length, crc = struct.unpack_from(order+\'HHII\', raw, off)\n        if length < 12 or off + length > total:\n            continue\n        # Obsolete nodes have their accurate bit cleared after writing the CRC.\n        header = bytearray(raw[off:off+8])\n        struct.pack_into(order+\'H\', header, 2, nt | 0x2000)\n        if _crc32(header) != crc:\n            stats[\'bad_crc\'] += 1\n            continue\n        if endian is not None and order != endian:\n            raise ValueError(\'同一镜像包含不同字节序的有效节点\')\n        endian = order\n        nextoff = off + ((length+3) & ~3)\n        stats[\'nodes\'] += 1\n        if not nt & 0x2000:\n            stats[\'obsolete\'] += 1\n            continue\n        body = raw[off:off+length]\n        if nt == NT_DIRENT:\n            if length < 40 or 40 + body[28] > length:\n                raise ValueError(\'dirent 长度无效 @%d\' % off)\n            nc, namecrc = struct.unpack_from(order+\'II\', body, 32)\n            name = body[40:40+body[28]]\n            if nc != _crc32(body[:32]) or namecrc != _crc32(name):\n                stats[\'bad_crc\'] += 1\n                continue\n            pino, ver, ino = struct.unpack_from(order+\'III\', body, 12)\n            # Each dirent component is a single Linux filename.\n            nm = name.decode(\'utf-8\', \'strict\')\n            if not nm or nm in (\'.\', \'..\') or any(c in nm for c in \'/\\\\\\x00:\'):\n                raise ValueError(\'不可安全还原的文件名: %r\' % name)\n            key = pino, nm\n            if key not in dirents or (ver, off) > dirents[key][:2]:\n                dirents[key] = ver, off, ino\n            stats[\'dirent\'] += 1\n        elif nt == NT_INODE:\n            if length < 68:\n                raise ValueError(\'inode 长度无效 @%d\' % off)\n            ino, ver, mode, uid, gid, isize, atime, mtime, ctime, offset, csize, dsize = struct.unpack_from(order+\'IIIHHIIIIIII\', body, 12)\n            if 68+csize > length:\n                raise ValueError(\'inode 数据越界 @%d\' % off)\n            dc, nc = struct.unpack_from(order+\'II\', body, 60)\n            payload = body[68:68+csize]\n            if nc != _crc32(body[:60]) or dc != _crc32(payload):\n                stats[\'bad_crc\'] += 1\n                continue\n            if isize > max(total*128, 64*1024*1024) or dsize > max(total*128, 64*1024*1024):\n                raise ValueError(\'inode 声明尺寸异常，拒绝分配内存 @%d\' % off)\n            meta = dict(mode=mode, uid=uid, gid=gid, isize=isize, atime=atime,\n                        mtime=mtime, ctime=ctime, version=ver, position=off)\n            if ino not in inodes or (ver,off) > (inodes[ino][\'version\'],inodes[ino][\'position\']):\n                inodes[ino] = meta\n            chunks.setdefault(ino, []).append((ver, off, offset, body[56], csize, dsize, payload, isize))\n            stats[\'compression\'][body[56]] = stats[\'compression\'].get(body[56],0)+1\n            if dsize >= 256 and dsize & (dsize - 1) == 0:\n                stats[\'data_block_sizes\'][dsize] = stats[\'data_block_sizes\'].get(dsize, 0) + 1\n            stats[\'inode\'] += 1\n        elif nt == NT_CLEANMARKER:\n            stats[\'cleanmarker\'] += 1\n            markers.append(off)\n        elif nt == NT_PADDING:\n            stats[\'padding\'] += 1\n        elif nt in (0xe008, 0xe009):\n            raise ValueError(\'此 JFFS2 含扩展属性节点，当前打包器无法无损保留\')\n        else:\n            stats[\'unknown\'] += 1\n            if nt & 0xc000 == 0xc000:\n                raise ValueError(\'未知不兼容 JFFS2 节点 0x%04x\' % nt)\n    if not stats[\'nodes\']:\n        raise ValueError(\'未找到 CRC 有效的 JFFS2 节点；不是可解析的 JFFS2\')\n    if stats[\'bad_crc\']:\n        raise ValueError(\'JFFS2 存在 %d 个 CRC 错误节点，停止无损解包\' % stats[\'bad_crc\'])\n    stats[\'byte_order\'] = endian or \'<\'\n    if len(markers) > 1:\n        import math, functools\n        step = functools.reduce(math.gcd, (b-a for a,b in zip(markers,markers[1:])))\n        if step >= 4096 and step & (step-1) == 0:\n            stats[\'erase_size\'] = step\n    children = {}\n    for (parent,name), (_,_,ino) in dirents.items():\n        if ino:\n            children.setdefault(parent,[]).append((name,ino))\n    entries, cache = {}, {}\n    def visit(ino, path, ancestors):\n        if ino in ancestors:\n            raise ValueError(\'JFFS2 目录环: \'+path)\n        meta = inodes.get(ino)\n        if meta is None:\n            raise ValueError(\'目录项缺少 inode: \'+path)\n        e = Jffs2Entry()\n        e.ino, e.path = ino, path\n        for key in (\'mode\',\'uid\',\'gid\',\'isize\',\'mtime\',\'atime\',\'ctime\'):\n            setattr(e,key,meta[key])\n        if want_data and not e.is_dir:\n            if ino not in cache:\n                buf = bytearray()\n                for ver,pos,offset,compr,csize,dsize,payload,isize in sorted(chunks.get(ino,[])):\n                    if len(buf) > isize:\n                        del buf[isize:]\n                    elif len(buf) < isize:\n                        buf.extend(b\'\\0\'*(isize-len(buf)))\n                    if not dsize or offset >= isize:\n                        continue\n                    piece = decompress(compr,csize,dsize,payload)\n                    if len(piece) != dsize:\n                        raise ValueError(\'解压尺寸不符: %s @%d (%d != %d)\' % (path,pos,len(piece),dsize))\n                    end = min(isize,offset+dsize)\n                    buf[offset:end] = piece[:end-offset]\n                cache[ino] = bytes(buf)\n            e.data = cache[ino]\n            if e.is_link:\n                e.link = e.data.decode(\'utf-8\',\'strict\')\n        entries[path] = e\n        if e.is_dir:\n            for name, child in sorted(children.get(ino,[])):\n                visit(child, path+\'/\'+name if path else name, ancestors | {ino})\n    if 1 not in inodes and (children.get(1) or stats[\'nodes\']):\n        # JFFS2 permits an implicit root with no on-flash inode.\n        inodes[1] = dict(mode=stat.S_IFDIR|0o755, uid=0, gid=0, isize=0,\n                         mtime=0, atime=0, ctime=0, version=0, position=0)\n    if 1 in inodes:\n        visit(1,\'\',set())\n    elif dirents:\n        raise ValueError(\'JFFS2 根 inode 缺失\')\n    if emit:\n        emit(\'JFFS2: %d 节点，%d 路径，字节序 %s\' % (stats[\'nodes\'],len(entries),stats[\'byte_order\']))\n    return entries, stats\n\n\n\n# ------------------------------------------------------------------ 解包到目录\ndef extract(image_path, outdir, emit=None, perm_file=PERM_FILE,\n            keep_special=True, keep_meta=True):\n    """\n    把 JFFS2 镜像解到 outdir，并写出权限清单 perm_file。\n\n    Windows 无法创建 socket / fifo / 设备节点，这些条目：\n      * keep_special=True  —— 记录到清单并生成一个 0 字节占位文件，\n                              打包时按清单还原（类型位来自清单，不靠文件本身）\n      * keep_special=False —— 只在清单里保留标记，不落盘\n    """\n    def log(s):\n        if emit:\n            emit(s)\n\n    entries, stats = parse(image_path, emit)\n    if os.path.isdir(outdir) and os.listdir(outdir):\n        raise ValueError("解包目录非空，请选择新目录: " + str(outdir))\n    os.makedirs(outdir, exist_ok=True)\n\n    manifest = {}\n    n_file = n_dir = n_link = n_special = 0\n\n    # 先建目录，保证层级\n    for path in sorted(entries):\n        e = entries[path]\n        if e.is_dir:\n            os.makedirs(os.path.join(outdir, path), exist_ok=True)\n\n    for path in sorted(entries):\n        e = entries[path]\n        dst = os.path.join(outdir, path)\n        rec = {\n            "mode": e.mode,\n            "uid": e.uid,\n            "gid": e.gid,\n            "inode": e.ino,\n        }\n        if keep_meta:\n            rec["mtime"] = e.mtime\n            rec["atime"] = e.atime\n            rec["ctime"] = e.ctime\n\n        if e.is_dir:\n            os.makedirs(dst, exist_ok=True)\n            manifest[path] = rec\n            n_dir += 1\n            continue\n\n        fmt = stat.S_IFMT(e.mode)\n        parent = os.path.dirname(dst)\n        if parent:\n            os.makedirs(parent, exist_ok=True)\n\n        if fmt == stat.S_IFLNK:\n            rec["link"] = e.link if e.link is not None else ""\n            parent = os.path.dirname(dst)\n            if parent:\n                os.makedirs(parent, exist_ok=True)\n            # 优先建真链接；Windows 无权限时不再落普通文件占位——占位文件会被\n            # 当成普通文件重新打包进镜像。目标路径已完整记录在清单 rec["link"]，\n            # 打包时按清单还即可。\n            try:\n                if os.path.lexists(dst):\n                    os.remove(dst)\n                raise OSError("符号链接仅写入权限清单")\n            except OSError:\n                log("  [符号链接] %-46s -> %s（磁盘未能创建，已记入清单，"\n                    "打包时自动还原）" % (path, rec["link"]))\n            manifest[path] = rec\n            n_link += 1\n            continue\n\n        if fmt in (stat.S_IFREG, stat.S_IFIFO, stat.S_IFCHR,\n                   stat.S_IFBLK, stat.S_IFSOCK):\n            if fmt == stat.S_IFREG:\n                with open(dst, "wb") as f:\n                    f.write(e.data)\n                n_file += 1\n            else:\n                # 特殊文件：Windows 无法创建，写占位 + 清单标记\n                n_special += 1\n                rec["special"] = {\n                    "S_IFIFO": fmt == stat.S_IFIFO,\n                    "S_IFCHR": fmt == stat.S_IFCHR,\n                    "S_IFBLK": fmt == stat.S_IFBLK,\n                    "S_IFSOCK": fmt == stat.S_IFSOCK,\n                }\n                rec["data_b64"] = _b64(e.data) if e.data else ""\n                if keep_special:\n                    try:\n                        with open(dst, "wb") as f:\n                            f.write(b"")\n                    except OSError:\n                        pass\n                log("  [特殊文件] %-46s 类型=%s 权限=%04o（Windows 无法创建，"\n                    "已记入清单，打包时自动还原）"\n                    % (path, _fmt_name(fmt), stat.S_IMODE(e.mode)))\n            manifest[path] = rec\n            continue\n\n        log("  ! 未知文件类型 %s mode=%o，跳过" % (path, e.mode))\n\n    mf = os.path.join(outdir, perm_file)\n    with open(mf, "w", encoding="utf-8") as f:\n        json.dump({"_comment": "Linux 权限清单：mode/uid/gid 按此还原，"\n                               "新增文件也可手工加进来",\n                   "_source": os.path.basename(image_path),\n                   "_erase_size": stats["erase_size"],\n                   "_byte_order": stats["byte_order"],\n                   "_compression": list(stats["compression"]),\n                   "_data_block_size": max(stats["data_block_sizes"], key=stats["data_block_sizes"].get) if stats["data_block_sizes"] else 2048,\n                   "entries": manifest}, f, indent=1, ensure_ascii=False)\n\n    log("解包完成 -> %s" % outdir)\n    log("  普通文件 %d / 目录 %d / 符号链接 %d / 特殊文件 %d"\n        % (n_file, n_dir, n_link, n_special))\n    log("  权限清单: %s" % mf)\n    return manifest\n\n\ndef _b64(b):\n    import base64\n    return base64.b64encode(b).decode("ascii")\n\n\ndef _fmt_name(fmt):\n    return {stat.S_IFIFO: "fifo", stat.S_IFCHR: "char", stat.S_IFBLK: "block",\n            stat.S_IFSOCK: "socket", stat.S_IFREG: "file",\n            stat.S_IFLNK: "symlink", stat.S_IFDIR: "dir"}.get(fmt, "?")\n\n\n# ------------------------------------------------------------------ 打包\nclass _NodeWriter(object):\n    """按 JFFS2 节点格式往缓冲区追加，自动 4 字节对齐"""\n\n    def __init__(self, erase_size=32768):\n        self.buf = bytearray()\n        self.erase = erase_size\n\n    @property\n    def size(self):\n        return len(self.buf)\n\n    def _append(self, blob):\n        if len(blob) > self.erase:\n            raise ValueError("JFFS2 节点超过擦除块")\n        left = self.erase - len(self.buf) % self.erase\n        if len(blob) > left:\n            self.buf += b"\\xff" * left\n        self.buf += blob\n        pad = (-len(blob)) % 4\n        if pad:\n            self.buf += b"\\x00" * pad\n\n    def dirent(self, pino, version, ino, name, dtype, mctime=0):\n        nb = name if isinstance(name, bytes) else name.encode("utf-8")\n        nsize = len(nb)\n        if not 1 <= nsize <= 254:\n            raise ValueError(\'JFFS2 文件名长度必须为 1..254 字节\')\n        totlen = 40 + nsize\n        n = bytearray(totlen)\n        struct.pack_into("<HHI", n, 0, MAGIC, NT_DIRENT, totlen)\n        struct.pack_into("<I", n, 8, 0)              # hdr_crc（设备不校验）\n        struct.pack_into("<III", n, 12, pino, version, ino)\n        struct.pack_into("<I", n, 24, mctime)\n        n[28] = nsize\n        n[29] = dtype\n        # 30..32 unused, 32..36 ino2, 36..40 pino2\n        struct.pack_into("<I", n, 32, ino)\n        struct.pack_into("<I", n, 36, pino)\n        n[40:40 + nsize] = nb\n        struct.pack_into("<I", n, 8, _crc32(n[:8]))\n        struct.pack_into("<I", n, 32, _crc32(n[:32]))\n        struct.pack_into("<I", n, 36, _crc32(nb))\n        self._append(bytes(n))\n\n    def inode(self, ino, version, mode, uid, gid, isize,\n              atime, mtime, ctime, offset, compr, payload, dsize):\n        csize = len(payload)\n        totlen = 68 + csize\n        n = bytearray(totlen)\n        struct.pack_into("<HHI", n, 0, MAGIC, NT_INODE, totlen)\n        struct.pack_into("<I", n, 8, 0)\n        struct.pack_into("<III", n, 12, ino, version, mode)\n        struct.pack_into("<HH", n, 24, uid & 0xFFFF, gid & 0xFFFF)\n        struct.pack_into("<I", n, 28, isize)\n        struct.pack_into("<IIII", n, 32, atime, mtime, ctime, offset)\n        struct.pack_into("<II", n, 48, csize, dsize)\n        n[56] = compr\n        n[57] = 0                                    # usercompr\n        struct.pack_into("<H", n, 58, 0)             # flags\n        struct.pack_into("<I", n, 60, 0)             # data_crc\n        n[68:68 + csize] = payload\n        struct.pack_into("<I", n, 8, _crc32(n[:8]))\n        struct.pack_into("<I", n, 60, _crc32(payload))\n        struct.pack_into("<I", n, 64, _crc32(n[:60]))\n        self._append(bytes(n))\n\n\ndef load_manifest(outdir, perm_file=PERM_FILE):\n    mf = os.path.join(outdir, perm_file)\n    if not os.path.isfile(mf):\n        return None\n    with open(mf, "r", encoding="utf-8") as f:\n        data = json.load(f)\n    return data.get("entries", data)\n\n\ndef pack(srcdir, out, emit=None, size=None, erase=32768,\n         perm_file=PERM_FILE, default_uid=0, default_gid=0,\n         default_mode=DEFAULT_UMASK_MODE, prune=True):\n    """\n    把目录重新打包成 JFFS2 镜像。\n\n    权限来源优先级：\n      1) sidecar 清单（解包时生成，最准确）\n      2) 新增文件 —— 清单里没有，用 default_mode / default_uid / default_gid\n         （GUI 的「新增文件指定权限」就是往清单里写记录，会走第 1 条）\n\n    prune=True 时会剔除 Windows 上无法落盘的残留（.DS_Store、Thumbs.db 等）\n    以及清单文件本身。\n    """\n    def log(s):\n        if emit:\n            emit(s)\n\n    if not os.path.isdir(srcdir):\n        raise RuntimeError("目录不存在: %s" % srcdir)\n\n    if os.path.splitdrive(os.path.realpath(srcdir))[0].lower()==os.path.splitdrive(os.path.realpath(out))[0].lower() and os.path.commonpath([os.path.realpath(srcdir),os.path.realpath(out)])==os.path.realpath(srcdir):\n        raise ValueError(\'输出镜像必须放在源目录以外\')\n    profile_path = os.path.join(srcdir, perm_file)\n    profile = {}\n    if os.path.isfile(profile_path):\n        with open(profile_path,encoding=\'utf-8\') as f:\n            profile = json.load(f)\n    if profile.get(\'_byte_order\', \'<\') != \'<\':\n        raise ValueError(\'大端 JFFS2 已支持读取，暂未支持原格式打包\')\n    erase = profile.get(\'_erase_size\', erase)\n    if not isinstance(erase,int) or erase < 4096 or erase & (erase-1):\n        raise ValueError(\'擦除块尺寸必须是至少 4096 的二次幂\')\n    data_block_size = profile.get(\'_data_block_size\', 2048)\n    if not isinstance(data_block_size, int) or data_block_size < 256 or data_block_size > 1048576 or data_block_size & (data_block_size - 1):\n        raise ValueError(\'JFFS2 数据分块大小无效\')\n    data_block_size = min(data_block_size, erase - 68)\n    use_vendor_lzma = 8 in profile.get(\'_compression\', [])\n    use_lzo = 7 in profile.get(\'_compression\', [])\n    manifest = load_manifest(srcdir, perm_file) or {}\n    # A stable fallback keeps identical edited trees reproducible across hosts.\n    now = max((rec.get("mtime", 0) for rec in manifest.values() if isinstance(rec, dict)), default=0)\n\n    # ---- 收集条目\n    entries = []   # (relpath, abspath, mode, uid, gid, kind, payload_src)\n    perm_names = (perm_file, PERM_FILE, ".perm.json")\n\n    for root, dirs, files in os.walk(srcdir):\n        dirs[:] = [d for d in dirs\n                   if not is_auxiliary(\n                       (os.path.relpath(os.path.join(root, d), srcdir)\n                        .replace(os.sep, "/")), perm_names)]\n        for name in list(files):\n            p = os.path.join(root, name)\n            rel = os.path.relpath(p, srcdir).replace(os.sep, "/")\n            if is_auxiliary(rel, perm_names):\n                continue\n            entries.append((rel, p, True))\n        for name in list(dirs):\n            p = os.path.join(root, name)\n            rel = os.path.relpath(p, srcdir).replace(os.sep, "/")\n            if is_auxiliary(rel, perm_names):\n                continue\n            entries.append((rel, p, False))\n\n    # ---- 补齐「清单里有、磁盘上没有」的条目\n    # Windows 上符号链接/特殊文件可能压根没落盘，atime 之类也只是清单独有。\n    # 只要清单记了 link= 且磁盘缺失，就按清单建一个虚拟条目，否则会丢链接。\n    on_disk = {rel for rel, _p, _f in entries}\n    restored = 0\n    for rel, rec in manifest.items():\n        if not isinstance(rec, dict):\n            continue\n        if rel in on_disk or rel == "":\n            continue\n        if rec.get("link") is None and not rec.get("special"):\n            continue\n        ap = os.path.join(srcdir, rel.replace("/", os.sep))\n        entries.append((rel, ap, False))\n        on_disk.add(rel)\n        restored += 1\n    if restored:\n        log("[jffs2] 按权限清单补齐 %d 个磁盘上缺失的条目（符号链接/特殊文件）"\n            % restored)\n\n    # ---- 分配 inode 号：root=1，其余从 2 递增（按路径排序保证稳定）\n    entries.sort(key=lambda x: x[0])\n    ino_of = {"": 1}\n    next_ino = 2\n    for rel, p, isfile in entries:\n        ino_of[rel] = next_ino\n        next_ino += 1\n\n    # ---- 解析每个条目的权限/元数据\n    resolved = []\n    for rel, p, isfile in entries:\n        rec = manifest.get(rel) or manifest.get(rel.replace("/", "\\\\")) or {}\n        got_mode = rec.get("mode")\n        uid = rec.get("uid", default_uid)\n        gid = rec.get("gid", default_gid)\n        mtime = rec.get("mtime", now)\n        atime = rec.get("atime", mtime)\n        ctime = rec.get("ctime", mtime)\n        isdir = os.path.isdir(p) and not os.path.islink(p) and rec.get("link") is None\n        special = rec.get("special") or {}\n\n        if special:\n            kind = "special"\n            fmt = (stat.S_IFSOCK if special.get("S_IFSOCK") else\n                   stat.S_IFIFO if special.get("S_IFIFO") else\n                   stat.S_IFCHR if special.get("S_IFCHR") else\n                   stat.S_IFBLK if special.get("S_IFBLK") else stat.S_IFREG)\n            if got_mode is None:\n                got_mode = fmt | 0o644\n            else:\n                got_mode = fmt | stat.S_IMODE(got_mode)\n            data = _unb64(rec.get("data_b64", ""))\n            resolved.append(dict(rel=rel, mode=got_mode, uid=uid, gid=gid,\n                                 mtime=mtime, atime=atime, ctime=ctime,\n                                 kind="special", data=data, link=None))\n            continue\n\n        if isdir:\n            if got_mode is None:\n                got_mode = stat.S_IFDIR | 0o755\n            else:\n                got_mode = stat.S_IFDIR | stat.S_IMODE(got_mode)\n            resolved.append(dict(rel=rel, mode=got_mode, uid=uid, gid=gid,\n                                 mtime=mtime, atime=atime, ctime=ctime,\n                                 kind="dir", data=b"", link=None))\n            continue\n\n        if rec.get("link") is not None or os.path.islink(p):\n            target = rec.get("link") if rec.get("link") is not None else os.readlink(p)\n            got_mode = (stat.S_IFLNK | stat.S_IMODE(got_mode)) if got_mode \\\n                else (stat.S_IFLNK | 0o777)\n            resolved.append(dict(rel=rel, mode=got_mode, uid=uid, gid=gid,\n                                 mtime=mtime, atime=atime, ctime=ctime,\n                                 kind="link", data=target.encode("utf-8"),\n                                 link=target))\n            continue\n\n        try:\n            with open(p,\'rb\') as f:\n                data = f.read()\n        except OSError as e:\n            log("  ! 读取失败 %s: %s" % (rel, e))\n            raise RuntimeError("读取文件失败: " + rel) from e\n        if got_mode is None:\n            got_mode = stat.S_IFREG | _guess_mode(p, default_mode)\n        else:\n            got_mode = stat.S_IFREG | stat.S_IMODE(got_mode)\n        resolved.append(dict(rel=rel, mode=got_mode, uid=uid, gid=gid,\n                             mtime=mtime, atime=atime, ctime=ctime,\n                             kind="file", data=data, link=None))\n\n    # Keep hardlinks when all aliases still have identical content and metadata.\n    shared = {}\n    for e in resolved:\n        rec = manifest.get(e[\'rel\'],{})\n        if e[\'kind\'] == \'dir\' or not rec.get(\'inode\'):\n            continue\n        signature = (rec[\'inode\'],e[\'mode\'],e[\'uid\'],e[\'gid\'],\n                     e[\'mtime\'],e[\'atime\'],e[\'ctime\'],e[\'data\'])\n        if signature in shared:\n            ino_of[e[\'rel\']] = shared[signature]\n        else:\n            shared[signature] = ino_of[e[\'rel\']]\n\n    # ---- 写节点\n    w = _NodeWriter(erase)\n    ver = 1\n\n    # root inode\n    rroot = manifest.get("") or {}\n    rmode = rroot.get("mode", stat.S_IFDIR | 0o755)\n    if stat.S_IFMT(rmode) != stat.S_IFDIR:\n        rmode = stat.S_IFDIR | stat.S_IMODE(rmode)\n    w.inode(1, ver, rmode, rroot.get("uid", default_uid),\n            rroot.get("gid", default_gid), 0, rroot.get(\'atime\',now), rroot.get(\'mtime\',now), rroot.get(\'ctime\',now), 0,\n            COMPR_ZERO, b"", 0)\n    for rel, p, isfile in []:\n        if "/" in rel:\n            continue\n        e = next(x for x in resolved if x["rel"] == rel)\n        w.dirent(1, ver, ino_of[rel], rel, mode_to_dtype(e["mode"]), e["mtime"])\n    ver += 1\n\n    for e in resolved:\n        rel = e["rel"]\n        if rel == "":\n            continue\n        parent = rel.rsplit("/", 1)[0] if "/" in rel else ""\n        pino = ino_of.get(parent, 1)\n        ino = ino_of[rel]\n        w.dirent(pino, ver, ino, rel.rsplit("/", 1)[-1],\n                 mode_to_dtype(e["mode"]), e["mtime"])\n        ver += 1\n\n    # 数据 inode（目录也写一个空 inode，保证 isize=0）\n    for e in resolved:\n        rel = e["rel"]\n        if rel == "":\n            continue\n        ino = ino_of[rel]\n        data = e["data"] or b""\n        if e["kind"] == "dir":\n            w.inode(ino, ver, e["mode"], e["uid"], e["gid"], 0,\n                    e["atime"], e["mtime"], e["ctime"], 0, COMPR_ZERO, b"", 0)\n            ver += 1\n            continue\n        if not data:\n            w.inode(ino, ver, e["mode"], e["uid"], e["gid"], 0,\n                    e["atime"], e["mtime"], e["ctime"], 0, COMPR_ZERO, b"", 0)\n            ver += 1\n            continue\n        for offset in range(0, len(data), data_block_size):\n            piece = data[offset:offset+data_block_size]\n            if use_vendor_lzma:\n                compr, payload = lzma_raw_compress_safe(piece, len(piece))\n            elif use_lzo:\n                compr, payload = 7, lzo1x_compress(piece)\n            else:\n                import zlib\n                payload = zlib.compress(piece)\n                compr = COMPR_ZLIB\n            if len(payload) >= len(piece):\n                compr, payload = COMPR_NONE, piece\n            w.inode(ino, ver, e["mode"], e["uid"], e["gid"], len(data),\n                    e["atime"], e["mtime"], e["ctime"], offset, compr, payload, len(piece))\n            ver += 1\n\n    blob = bytes(w.buf)\n\n    # ---- 按擦除块填充 0xFF\n    if size is not None and len(blob) > size:\n        raise RuntimeError(\n            "打包后 %d 字节，超过分区容量 %d 字节（超出 %d）。"\n            "请删减文件或换更小的内容。" % (len(blob), size, len(blob) - size))\n\n    padded = _pad_to_erase(blob, erase)\n    if size is not None:\n        if len(padded) > size:\n            raise RuntimeError("填充后 %d > 分区 %d" % (len(padded), size))\n        padded = padded + b"\\xff" * (size - len(padded))\n\n    verified,_ = parse(padded)\n    expected = {e[\'rel\']:e for e in resolved}\n    if set(verified)!=(set(expected)|{\'\'}):\n        raise ValueError(\'打包自检失败: 路径集合不一致\')\n    for path,e in expected.items():\n        v = verified[path]\n        if (v.mode,v.uid,v.gid,v.data)!=(e[\'mode\'],e[\'uid\'],e[\'gid\'],e[\'data\']):\n            raise ValueError(\'打包自检失败: \'+path)\n    _atomic_output(out,padded)\n\n    log("打包完成 -> %s" % out)\n    log("  条目 %d（文件 %d / 目录 %d / 链接 %d / 特殊 %d）"\n        % (len(resolved),\n           sum(1 for x in resolved if x["kind"] == "file"),\n           sum(1 for x in resolved if x["kind"] == "dir"),\n           sum(1 for x in resolved if x["kind"] == "link"),\n           sum(1 for x in resolved if x["kind"] == "special")))\n    log("  数据 %d 字节 -> 镜像 %d 字节%s"\n        % (len(blob), len(padded),\n           ("（分区 %d，占用 %.1f%%）" % (size, 100.0 * len(blob) / size))\n           if size else ""))\n    return out\n\n\ndef _unb64(s):\n    if not s:\n        return b""\n    import base64\n    try:\n        return base64.b64decode(s)\n    except Exception:\n        return b""\n\n\ndef _guess_mode(path, default_mode):\n    """没有清单时，按扩展名猜一个合理权限"""\n    name = os.path.basename(path).lower()\n    if name.endswith((".sh", ".cgi")):\n        return 0o755\n    if name in ("init", "rc", "rc.local"):\n        return 0o755\n    return default_mode\n\n\ndef _pad_to_erase(blob, erase):\n    """JFFS2 镜像末尾对齐到擦除块，用 0xFF 填（无 cleanmarker）"""\n    n = len(blob)\n    if n == 0:\n        return b"\\xff" * erase\n    rem = n % erase\n    if rem == 0:\n        return blob + b"\\xff" * erase\n    return blob + b"\\xff" * (erase - rem)\n\n\n# ------------------------------------------------------------------ 权限校验\ndef perm_snapshot(srcdir_or_image):\n    """\n    打印一个目录（解包结果）或镜像的权限快照，用于往返比对。\n    返回 {rel: (mode, uid, gid)}\n    """\n    if os.path.isfile(srcdir_or_image):\n        entries, _ = parse(srcdir_or_image)\n        return dict((p, (e.mode, e.uid, e.gid)) for p, e in entries.items())\n    manifest = load_manifest(srcdir_or_image)\n    if manifest is None:\n        return {}\n    return dict((p, (r.get("mode", 0), r.get("uid", 0), r.get("gid", 0)))\n                for p, r in manifest.items())\n\n\ndef diff_perms(a, b, emit=None):\n    """比较两个快照，返回 (缺失, 多余, 权限不同) 三个列表"""\n    def log(s):\n        if emit:\n            emit(s)\n    only_a = sorted(set(a) - set(b))\n    only_b = sorted(set(b) - set(a))\n    changed = []\n    for k in sorted(set(a) & set(b)):\n        if a[k] != b[k]:\n            changed.append((k, a[k], b[k]))\n    return only_a, only_b, changed\n\n\n# ------------------------------------------------------------------ CLI\ndef main():\n    import argparse\n    ap = argparse.ArgumentParser(description="中兴微 JFFS2 纯 Python 解包/打包")\n    sub = ap.add_subparsers(dest="op")\n\n    p1 = sub.add_parser("ls", help="列出镜像内容")\n    p1.add_argument("image")\n\n    p2 = sub.add_parser("x", help="解包镜像到目录")\n    p2.add_argument("image")\n    p2.add_argument("outdir")\n    p2.add_argument("--no-meta", action="store_true", help="不写时间戳到清单")\n\n    p3 = sub.add_parser("c", help="打包目录为镜像")\n    p3.add_argument("srcdir")\n    p3.add_argument("out")\n    p3.add_argument("--size", type=int, default=None, help="目标分区大小")\n    p3.add_argument("--erase", type=int, default=32768)\n\n    p4 = sub.add_parser("perms", help="打印镜像/目录的权限快照")\n    p4.add_argument("target")\n\n    a = ap.parse_args()\n    if a.op == "ls":\n        entries, stats = parse(a.image)\n        for k in sorted(entries):\n            e = entries[k]\n            print("  %-56s %-9s %04o %d:%-3d %8d" % (\n                k, _fmt_name(stat.S_IFMT(e.mode)), stat.S_IMODE(e.mode),\n                e.uid, e.gid, e.isize))\n        print("共 %d 项  %s" % (len(entries), stats))\n    elif a.op == "x":\n        extract(a.image, a.outdir, keep_meta=not a.no_meta,\n                emit=lambda s: print(s))\n    elif a.op == "c":\n        pack(a.srcdir, a.out, size=a.size, erase=a.erase,\n             emit=lambda s: print(s))\n    elif a.op == "perms":\n        snap = perm_snapshot(a.target)\n        for k in sorted(snap):\n            m, u, g = snap[k]\n            print("%-60s %04o %d:%d" % (k, stat.S_IMODE(m), u, g))\n        print("共 %d 项" % len(snap))\n    else:\n        ap.print_help()\n    return 0\n\n\nif __name__ == "__main__":\n    sys.exit(main())\n\n\ndef _backup_with_timestamp(path):\n    import shutil\n    from datetime import datetime, timezone, timedelta\n    stamp = datetime.now(timezone(timedelta(hours=8))).strftime(\'%Y%m%d%H%M%S\')\n    base = path + \'.\' + stamp\n    backup, index = base, 0\n    while True:\n        try:\n            stream = open(backup, \'xb\')\n            break\n        except FileExistsError:\n            index += 1\n            backup = base + \'.\' + str(index)\n    try:\n        with stream, open(path, \'rb\') as original:\n            shutil.copyfileobj(original, stream)\n            stream.flush()\n            os.fsync(stream.fileno())\n        shutil.copystat(path, backup)\n    except BaseException:\n        os.unlink(backup)\n        raise\n    return backup\n\n\ndef _atomic_output(path, data):\n    import tempfile\n    path = os.path.abspath(path)\n    os.makedirs(os.path.dirname(path), exist_ok=True)\n    fd, tmp = tempfile.mkstemp(prefix=\'.zxw-\', dir=os.path.dirname(path))\n    try:\n        with os.fdopen(fd, \'wb\') as stream:\n            stream.write(data)\n            stream.flush()\n            os.fsync(stream.fileno())\n        if os.path.isfile(path):\n            _backup_with_timestamp(path)\n        os.replace(tmp, path)\n    finally:\n        if os.path.exists(tmp):\n            os.unlink(tmp)\n\n'
FWPARTS_SRC = '#!/usr/bin/env python3\n# -*- coding: utf-8 -*-\n"""\n中兴微编程器固件 —— 分区表解析 / 拆分 / 合并\n================================================================================\n\n分区表位置\n----------\n分区表就藏在 0.zloader 分区内，偏移 **8224 (0x2020)** 处，每条 40 字节，\nlittle-endian，直到遇到全 0 条目为止：\n\n    +0   char name[16]     分区名，NUL 填充\n    +16  char type[16]     类型，正常情况下是 "nand"\n    +32  u32  offset       该分区在 flash 中的起始偏移\n    +36  u32  size         分区大小（字节）\n\n注意：offset 字段与累加值一致，但**以累加为准更稳**（有些固件 offset\n字段不填）。本模块两者都读，不一致时告警并按累加值走。\n\n支持 8MB / 16MB 两种固件。8MB 固件的 rootfs 是 squashfs，\n16MB 固件的 rootfs 是 jffs2。\n"""\n\nimport os\nimport struct\nimport sys\nimport re\nimport json\nimport hashlib\nimport tempfile\nimport shutil\n\nMAGIC_ZXIC = bytes.fromhex("00005a045a583735323156316c1e0000")   # 0x2020 之前的头\nPART_TABLE_OFF = 8224          # 0x2020\nPART_ENTRY_SIZE = 40\nPART_NAME_LEN = 16\nPART_TYPE_LEN = 16\nMAX_PARTS = 128\n\n# ---- 0x2000 头部 + 32 位 XOR 校验码 --------------------------------\n# 中兴微 7520V3 引导头在 0x201C 处存一个 u32（小端）校验码，\n# 它等于「整个分区表区域（0x2020 起，entry_count x 40 字节）\n# 按小端 u32 切分后逐条异或」的结果。\n# 实测 MZ804 原机 == 0xFA3D10E0，去控版亦相同（说明只改分区内容不动该码）。\nHDR_ENTRY_COUNT_OFF = 0x2018   # u32 分区表条目数（实测 = 9）\nHDR_CHECKSUM_OFF = 0x201C      # u32 XOR 校验码\n\nSQUASHFS_MAGIC = b"hsqs"\nJFFS2_MAGIC = b"\\x85\\x19"\n\nFS_SQUASHFS = "squashfs"\n\nFS_SQUASHFS = "squashfs"\nFS_JFFS2 = "jffs2"\nFS_RAW = "raw"\n\n# 已知分区的兜底猜测（当分区表不可用、或需要判断文件系统类型时）\nKNOWN_FS_HINT = {\n    "rootfs": FS_SQUASHFS,\n    "userdata": FS_JFFS2,\n    "oem": FS_JFFS2,\n    "nvrofs": FS_RAW,\n}\n\n\ndef _log(s, emit=None):\n    if emit:\n        emit(s)\n    else:\n        print(s)\n\n\nclass Partition(object):\n    __slots__ = ("index", "name", "offset", "size", "ptype", "fstype", "key")\n\n    def __init__(self, index, name, offset, size, ptype="nand"):\n        self.index = index\n        self.name = name\n        self.offset = offset\n        self.size = size\n        self.ptype = ptype\n        self.fstype = FS_RAW\n        self.key = "%d.%s" % (index, name)\n\n    def __repr__(self):\n        return "<Partition %s off=%d size=%d fs=%s>" % (\n            self.key, self.offset, self.size, self.fstype)\n\n\ndef parse_partition_table(raw, emit=None):\n    """Use explicit flash offsets; DDR/raw descriptors are not flash partitions."""\n    offsets = [PART_TABLE_OFF]\n    offsets += [m.start() for m in re.finditer(b\'zloader\\x00\', raw[:2*1024*1024]) if m.start() != PART_TABLE_OFF]\n    errors = []\n    for start in offsets:\n        if start+40 > len(raw):\n            continue\n        parts = []\n        try:\n            for i in range(MAX_PARTS):\n                off = start+i*40\n                e = raw[off:off+40]\n                if len(e) < 40 or not e.strip(b\'\\x00\\xff\'):\n                    break\n                name = e[:16].split(b\'\\0\')[0].decode(\'ascii\')\n                typ = e[16:32].split(b\'\\0\')[0].decode(\'ascii\')\n                if typ in (\'ddr\',\'raw\'):\n                    break\n                if not re.fullmatch(r\'[A-Za-z0-9_.-]{1,16}\',name) or name in (\'.\',\'..\') or typ not in (\'nand\',\'nor\',\'spi\',\'emmc\'):\n                    if parts:\n                        raise ValueError(\'分区表含非法条目 @0x%x\' % off)\n                    break\n                pos, size = struct.unpack_from(\'<II\',e,32)\n                if not size or size == 0xffffffff:\n                    raise ValueError(\'无效分区大小: \'+name)\n                parts.append(Partition(i,name,pos,size,typ))\n            if not parts:\n                continue\n            # Only a fully zero offset column is an unambiguous legacy layout.\n            if len(parts)>1 and all(p.offset == 0 for p in parts):\n                pos = 0\n                for part in parts:\n                    part.offset, pos = pos, pos+part.size\n                _log(\'分区表 offset 全为零，采用连续布局\',emit)\n            previous = 0\n            for part in parts:\n                if part.offset < previous or part.offset+part.size > len(raw):\n                    raise ValueError(\'分区重叠或固件被截断: \'+part.key)\n                previous = part.offset+part.size\n                part.fstype = detect_fs(raw[part.offset:previous],part.name)\n            _log(\'分区表 @0x%x，%d 个有效分区\' % (start,len(parts)),emit)\n            return parts\n        except (ValueError,UnicodeError,struct.error) as exc:\n            errors.append(str(exc))\n    fs = detect_fs(raw)\n    if fs != FS_RAW:\n        part = Partition(0,\'image\',0,len(raw),\'image\')\n        part.fstype = fs\n        return [part]\n    raise ValueError(\'未识别有效分区表或独立文件系统镜像\' + (\': \'+\'; \'.join(errors) if errors else \'\'))\n\n\n\ndef calc_partition_xor(raw, entry_count=None, pt_off=PART_TABLE_OFF):\n    """计算 0x201C 处的「分区表 XOR 校验码」。\n\n    算法（实测破译，见 ZEditor_分析报告.md §1）：\n        把分区表区域（entry_count 条 x 40 字节）按小端 u32 切分，\n        逐条异或，取低 32 位。\n\n    entry_count 为 None 时，从头部 0x2018 读取（实测 = 9）。\n    注意：必须是「完整条目数」（含 ddr 项与空项），少算一条就失配。\n    """\n    if entry_count is None:\n        if len(raw) < HDR_ENTRY_COUNT_OFF + 4:\n            return None\n        entry_count = struct.unpack_from("<I", raw, HDR_ENTRY_COUNT_OFF)[0]\n    if not (1 <= entry_count <= MAX_PARTS):\n        return None\n    end = pt_off + entry_count * PART_ENTRY_SIZE\n    if len(raw) < end:\n        return None\n    x = 0\n    for i in range(pt_off, end, 4):\n        x ^= struct.unpack_from("<I", raw, i)[0]\n    return x & 0xFFFFFFFF\n\n\ndef check_header_checksum(raw, emit=None):\n    """校验 0x201C 校验码是否与分区表一致。\n\n    返回 (ok, stored, calc, n):\n        ok     True = 一致\n        stored 固件里存的校验码（None = 结构不识别，跳过）\n        calc   按分区表算出来的校验码\n        n      参与计算的条目数\n    """\n    if len(raw) < HDR_CHECKSUM_OFF + 4 or len(raw) < PART_TABLE_OFF + PART_ENTRY_SIZE:\n        return None, None, None, 0\n    if raw[0x2000:0x2009] != b\'vHY1WF752\':\n        return None, None, None, 0\n    n = struct.unpack_from("<I", raw, HDR_ENTRY_COUNT_OFF)[0]\n    if not (1 <= n <= MAX_PARTS):\n        return None, None, None, 0\n    stored = struct.unpack_from("<I", raw, HDR_CHECKSUM_OFF)[0]\n    calc = calc_partition_xor(raw, n)\n    if calc is None:\n        return None, None, None, 0\n    ok = (stored == calc)\n    if emit:\n        if ok:\n            _log("  [校验] 0x201C XOR 校验码一致 "\n                 "(0x%08X，%d 条分区项) ✓" % (stored, n), emit)\n        else:\n            _log("  [校验] 0x201C XOR 校验码**失配**！"\n                 " 固件内=0x%08X，按分区表应为=0x%08X" % (stored, calc), emit)\n            _log("         → 若该固件曾改过分区表，刷机可能死灯，"\n                 "请核对原始固件分区表与校验值", emit)\n    return ok, stored, calc, n\n\n\n\n\ndef detect_fs(blob, part_name=None):\n    if len(blob)>=96 and blob[:4] == b\'hsqs\':\n        block = struct.unpack_from(\'<I\',blob,12)[0]\n        major,minor = struct.unpack_from(\'<HH\',blob,28)\n        used = struct.unpack_from(\'<Q\',blob,40)[0]\n        if major == 4 and minor == 0 and block >= 4096 and block <= 1048576 and block & (block-1) == 0 and 96 <= used <= len(blob):\n            return FS_SQUASHFS\n    # An erased first block is normal in journaled flash filesystems.\n    for m in re.finditer(b\'(?=\\x85\\x19|\\x19\\x85)\',blob[:min(len(blob),2*1024*1024)]):\n        off = m.start()\n        if off % 4 or off+12>len(blob):\n            continue\n        endian = \'<\' if blob[off:off+2] == b\'\\x85\\x19\' else \'>\'\n        _,nt,sz,crc = struct.unpack_from(endian+\'HHII\',blob,off)\n        if nt|0x2000 not in (0xe001,0xe002,0x2003,0x2004,0x2006,0xe008,0xe009) or not 12<=sz<=len(blob)-off:\n            continue\n        import zlib\n        header = bytearray(blob[off:off+8])\n        struct.pack_into(endian+\'H\',header,2,nt|0x2000)\n        if (zlib.crc32(header,0xffffffff)^0xffffffff) == crc:\n            return FS_JFFS2\n    if blob[:4] == b\'UBI#\':\n        return \'ubi\'\n    if blob[:4] == b\'\\x31\\x18\\x10\\x06\':\n        return \'ubifs\'\n    if len(blob)>=1082 and blob[1080:1082] == b\'\\x53\\xef\':\n        return \'ext\'\n    return FS_RAW\n\n\n\ndef squashfs_real_size(blob):\n    """squashfs 超级块 +40 处是 u64 总长度"""\n    if len(blob) < 48 or blob[:4] != SQUASHFS_MAGIC:\n        return None\n    return struct.unpack_from("<Q", blob, 40)[0]\n\n\ndef load_firmware(path, emit=None):\n    with open(path,\'rb\') as f:\n        raw = f.read()\n    parts = parse_partition_table(raw,emit)\n    for p in parts:\n        p.fstype = detect_fs(raw[p.offset:p.offset+p.size],p.name)\n        _log(\'%s @0x%x, %d bytes, %s\' % (p.key,p.offset,p.size,p.fstype),emit)\n    return raw,parts,len(raw)\n\n\n\ndef split_firmware(path, outdir, emit=None, write_json=True):\n    raw,parts,total = load_firmware(path,emit)\n    if os.path.isdir(outdir) and os.listdir(outdir):\n        raise ValueError(\'拆分目录非空，请选择新的样本专属目录: \'+str(outdir))\n    os.makedirs(outdir,exist_ok=True)\n    made, gaps, layout, pos = [], [], bytearray(), 0\n    for p in parts:\n        if p.offset>pos:\n            gaps.append(dict(offset=pos,size=p.offset-pos,data_offset=len(layout)))\n            layout.extend(raw[pos:p.offset])\n        dst = os.path.join(outdir,p.key)\n        atomic_write(dst,raw[p.offset:p.offset+p.size])\n        made.append(dst)\n        pos = p.offset+p.size\n    if pos<total:\n        gaps.append(dict(offset=pos,size=total-pos,data_offset=len(layout)))\n        layout.extend(raw[pos:])\n    if write_json:\n        atomic_write(os.path.join(outdir,\'_layout.bin\'),layout)\n        meta = dict(version=2,source=os.path.abspath(path),total=total,\n                    source_sha256=hashlib.sha256(raw).hexdigest(),\n                    layout_sha256=hashlib.sha256(layout).hexdigest(),gaps=gaps,\n                    partitions=[dict(key=p.key,name=p.name,index=p.index,offset=p.offset,\n                                     size=p.size,fstype=p.fstype,ptype=p.ptype) for p in parts])\n        atomic_write(os.path.join(outdir,\'partitions.json\'),json.dumps(meta,ensure_ascii=False,indent=2).encode(\'utf-8\'))\n    _log(\'拆分完成: %d 个分区，空隙及尾部保留 %d 字节\' % (len(parts),len(layout)),emit)\n    return made,parts\n\n\n\ndef join_firmware(partdir, dst, emit=None, allow_missing=False, fill=0xff):\n    with open(os.path.join(partdir,\'partitions.json\'),encoding=\'utf-8\') as f:\n        meta = json.load(f)\n    total = meta.get(\'total\')\n    if not isinstance(total,int) or not 0<total<=2*1024*1024*1024:\n        raise ValueError(\'固件总长度无效或超过 2 GiB\')\n    source = meta.get(\'source\',\'\')\n    if source and os.path.normcase(os.path.realpath(dst)) == os.path.normcase(os.path.realpath(source)):\n        raise ValueError(\'输出不得覆盖原始固件\')\n    buf = bytearray([fill])*total\n    ranges = []\n    layout_path = os.path.join(partdir,\'_layout.bin\')\n    layout = b\'\'\n    if os.path.isfile(layout_path):\n        with open(layout_path,\'rb\') as f:\n            layout = f.read()\n    if meta.get(\'layout_sha256\') and hashlib.sha256(layout).hexdigest()!=meta[\'layout_sha256\']:\n        raise ValueError(\'布局保留数据哈希不符\')\n    for g in meta.get(\'gaps\',[]):\n        off,size,start = g[\'offset\'],g[\'size\'],g[\'data_offset\']\n        if min(off,size,start)<0 or off+size>total or start+size>len(layout):\n            raise ValueError(\'布局保留区越界\')\n        buf[off:off+size] = layout[start:start+size]\n        ranges.append((off,off+size))\n    for p in meta[\'partitions\']:\n        key,off,size = p[\'key\'],p[\'offset\'],p[\'size\']\n        if not re.fullmatch(r\'[A-Za-z0-9_.-]+\',key) or key in (\'.\',\'..\') or size<=0 or off<0 or off+size>total:\n            raise ValueError(\'非法分区记录: \'+str(key))\n        src = os.path.join(partdir,key)\n        if os.path.normcase(os.path.realpath(dst)) == os.path.normcase(os.path.realpath(src)):\n            raise ValueError(\'输出不得覆盖分区输入\')\n        if not os.path.isfile(src):\n            if not allow_missing:\n                raise ValueError(\'缺少分区文件: \'+key)\n            data = bytes([fill])*size\n        else:\n            with open(src,\'rb\') as f:\n                data = f.read()\n        if len(data)!=size:\n            raise ValueError(\'分区 %s 长度 %d != %d；不自动截断或补齐\' % (key,len(data),size))\n        ranges.append((off,off+size))\n        buf[off:off+size] = data\n    pos = 0\n    for start,end in sorted(ranges):\n        if start != pos:\n            raise ValueError(\'布局存在空洞或重叠，无法无损合并\')\n        pos = end\n    if pos != total:\n        raise ValueError(\'缺少固件尾部保留数据，请重新拆分\')\n    parse_partition_table(buf,emit=lambda _:None)\n    atomic_write(dst,buf)\n    _log(\'合并完成: %s (%d 字节)\' % (dst,total),emit)\n    return dst\n\n\n\ndef verify_firmware(orig, new, emit=None):\n    """比较两个整机固件逐分区的变化"""\n    import hashlib\n    ro, po, _ = load_firmware(orig, None)\n    rn, pn, _ = load_firmware(new, None)\n    _log("", emit)\n    _log("分区变化对比", emit)\n    _log("  %-14s %-12s %-12s %s" % ("分区", "原机 md5", "新固件 md5", "状态"), emit)\n    result = {}\n    for a, b in zip(po, pn):\n        ha = hashlib.md5(ro[a.offset:a.offset + a.size]).hexdigest()\n        hb = hashlib.md5(rn[b.offset:b.offset + b.size]).hexdigest()\n        st = "SAME" if ha == hb else "CHANGED"\n        result[a.key] = st\n        _log("  %-14s %-12s %-12s %s" % (a.key, ha[:12], hb[:12], st), emit)\n    return result\n\n\ndef main():\n    import argparse\n    ap = argparse.ArgumentParser(description="中兴微固件分区拆分/合并")\n    sub = ap.add_subparsers(dest="op")\n\n    a1 = sub.add_parser("info", help="查看固件分区表")\n    a1.add_argument("bin")\n\n    a2 = sub.add_parser("split", help="拆分为分区文件")\n    a2.add_argument("bin")\n    a2.add_argument("outdir")\n\n    a3 = sub.add_parser("join", help="合并分区文件为整机固件")\n    a3.add_argument("partdir")\n    a3.add_argument("out")\n\n    a4 = sub.add_parser("verify", help="比较两个固件")\n    a4.add_argument("orig")\n    a4.add_argument("new")\n\n    a = ap.parse_args()\n    if a.op == "info":\n        load_firmware(a.bin, lambda s: print(s))\n    elif a.op == "split":\n        split_firmware(a.bin, a.outdir, lambda s: print(s))\n    elif a.op == "join":\n        join_firmware(a.partdir, a.out, lambda s: print(s))\n    elif a.op == "verify":\n        verify_firmware(a.orig, a.new, lambda s: print(s))\n    else:\n        ap.print_help()\n    return 0\n\n\nif __name__ == "__main__":\n    sys.exit(main())\n\n\ndef _backup_with_timestamp(path):\n    import shutil\n    from datetime import datetime, timezone, timedelta\n    stamp = datetime.now(timezone(timedelta(hours=8))).strftime(\'%Y%m%d%H%M%S\')\n    base = path + \'.\' + stamp\n    backup, index = base, 0\n    while True:\n        try:\n            stream = open(backup, \'xb\')\n            break\n        except FileExistsError:\n            index += 1\n            backup = base + \'.\' + str(index)\n    try:\n        with stream, open(path, \'rb\') as original:\n            shutil.copyfileobj(original, stream)\n            stream.flush()\n            os.fsync(stream.fileno())\n        shutil.copystat(path, backup)\n    except BaseException:\n        os.unlink(backup)\n        raise\n    return backup\n\n\ndef atomic_write(path, data, timestamp_backup=True):\n    import tempfile\n    path = os.path.abspath(path)\n    os.makedirs(os.path.dirname(path), exist_ok=True)\n    fd, tmp = tempfile.mkstemp(prefix=\'.zxw-\', dir=os.path.dirname(path))\n    try:\n        with os.fdopen(fd, \'wb\') as stream:\n            stream.write(data)\n            stream.flush()\n            os.fsync(stream.fileno())\n        if os.path.isfile(path):\n            _backup_with_timestamp(path)\n        os.replace(tmp, path)\n    finally:\n        if os.path.exists(tmp):\n            os.unlink(tmp)\n\n\n\ndef resolve_partition(parts, key):\n    matches = [p for p in parts if key in (p.key,p.name)]\n    if len(matches)!=1:\n        raise ValueError(\'无法唯一定位分区: \'+str(key))\n    return matches[0]\n\n\ndef replace_partition(raw, part, image):\n    if part.offset<0 or part.offset+part.size>len(raw) or len(image)>part.size:\n        raise ValueError(\'镜像超过分区容量或分区越界\')\n    original = raw[part.offset:part.offset+part.size]\n    fs = detect_fs(image)\n    if fs == FS_SQUASHFS:\n        actual_size = squashfs_real_size(image)\n        if actual_size and len(image) > actual_size and not image[actual_size:].strip(b\'\\xff\\x00\'):\n            image = image[:actual_size]\n        old_size = squashfs_real_size(original)\n        if not old_size:\n            raise ValueError(\'原分区不是有效 SquashFS\')\n        # Preserve vendor data after the old SquashFS. Only erased padding may grow.\n        tail = original[old_size:]\n        erased = len(tail)-len(tail.lstrip(b\'\\xff\'))\n        aligned = len(tail[erased:])-len(tail[erased:].lstrip(b\'\\x00\'))\n        aligned = min(aligned, (-old_size) % 4096)\n        padding = erased + aligned\n        limit = old_size+padding\n        if len(image)>limit:\n            raise ValueError(\'新 SquashFS 将覆盖原分区尾部的非填充数据\')\n        blob = image+b\'\\xff\'*max(0,old_size-len(image))+original[max(old_size,len(image)):]\n    elif fs == FS_JFFS2:\n        blob = image.ljust(part.size,b\'\\xff\')\n    else:\n        if len(image)!=part.size:\n            raise ValueError(\'原始分区回写必须提供完整等长镜像\')\n        blob = image\n    result = bytearray(raw)\n    result[part.offset:part.offset+part.size] = blob\n    if len(result)!=len(raw):\n        raise ValueError(\'回写改变了固件长度\')\n    return bytes(result)\n'
SQUASHFS_SRC = '# -*- coding: utf-8 -*-\n"""\n纯 Python squashfs 4.0 读写引擎（中兴微固件）\n\n本模块不依赖任何外部工具（不需要 unsquashfs / mksquashfs），\n使用标准库 lzma 直接解析与生成 squashfs 镜像。\n\n--------------------------------------------------------------------------\n针对本固件观察到的实况（4.rootfs, 3244032 字节）：\n--------------------------------------------------------------------------\n* 超级块 96 字节，magic 0x73717368 (\'hsqs\')\n    +0  u32 magic\n    +4  u32 inodes\n    +8  u32 mkfs_time\n    +12 u32 block_size          (262144)\n    +16 u32 fragments           (24)\n    +20 u16 compression         (4 = xz)\n    +22 u16 block_log           (18)\n    +24 u16 flags               (1216 = 0x4C0)\n    +26 u16 no_ids              (1)\n    +28 u16 ver_major           (4)\n    +30 u16 ver_minor           (0)\n    +32 u64 root_inode\n    +40 u64 bytes_used\n    +48 u64 id_table_start\n    +56 u64 xattr_id_table_start (0xFFFFFFFFFFFFFFFF = 无)\n    +64 u64 inode_table_start\n    +72 u64 dir_table_start\n    +80 u64 fragment_table_start\n    +88 u64 export_table_start\n\n* 超级块之后 10 字节的变体头（本固件特有）：\n    96..106 : 08 80 00 00 04 00 10 00 00 00\n    按 u16 读: 0x8008(元数据头: 未压缩/8字节) + 8 字节负载\n    负载按 u32 读: block_size(262144), 16\n  → 说明本变体在超级块后追加了一段"变长头"。\n    *数据区从 106 开始*，而不是标准 squashfs 的 96。\n    兼容处理：自动在 96 之后搜索第一个 xz 流魔数 FD 37 7A 58 5A 00 作为数据起点。\n\n* **数据块没有独立的块表（block list）**：\n    每个 regular inode 的 `start_block` 字段直接存放**绝对文件偏移**\n    （标准 squashfs 是"块索引"）。实测 ino=23 start_block=216438 正好是\n    一个 xz 流的起始偏移，连续 3 块解出 262144+262144+72052 = 596340 = file_size。\n    因此读取时只需按 `block_sizes[]` 逐块解压即可，无需块表。\n\n* **元数据块（inode/dir/fragment/id 表）使用完整 xz 容器**：\n    格式: u16 header (bit15 = 未压缩, 低15位 = 压缩后字节数) + 压缩负载\n    负载是一个 **完整 xz 流**（FORMAT_XZ），不是裸 LZMA1/LZMA2。\n    解压后上限 8192 字节/块（标准 squashfs 元数据块大小）。\n    → Python 标准库 lzma 完全可解，此前"元数据 >512KB 无法用 Python 处理"的\n      判断是错误的。\n\n* **root_inode / dir entry 的 block 字段**是**元数据区内的字节偏移**\n    （含 2 字节块头），offset 为该元数据块解压后的字节偏移。\n    例: root_inode = (1894 << 16) | 7611 → 元数据区偏移 1894（正好是第 2 个\n    元数据块起点）内的第 7611 字节。\n\n--------------------------------------------------------------------------\n数据结构要点\n--------------------------------------------------------------------------\n* inode 公共头 16 字节: type u16, mode u16, uid u16, guid u16, mtime u32, inode_number u32\n    type: 1=dir 2=file 3=symlink 4=blkdev 5=chrdev 6=fifo 7=sock\n          8=ldir 9=lreg 10=lsymlink 11=lblkdev 12=lchrdev 13=lfifo 14=lsock\n* regular inode: start_block u32, fragment u32, offset u32, file_size u32,\n                 block_sizes[n] u32（n = file_size//block_size 或向上取整）\n                 u32 bit24 = 0x1000000 表示该块未压缩\n* dir inode: start_block u32, nlink u32, file_size u16, block_offset u16, parent_inode u32\n* symlink inode: nlink u32, target_size u32, target[target_size]\n* 目录表: dir_header{ count u32(=实际数-1), start_block u32, inode_number u32 }\n          dir_entry{ offset u16, inode_number u16(相对增量), type u16, name_size u16, name[name_size+1] }\n          同一 header 内后续 entry 省略 header，直到 count 用完\n* fragment 表: 每组 16 字节 { u64 start, u32 size(bit24=未压缩), u32 unused }\n              + 结尾 u64 索引表（指向各元数据块）\n* id 表: u32 id 数组，用元数据块存储\n--------------------------------------------------------------------------\n"""\n\nimport os\nimport io\nimport sys\nimport json\nimport stat as _stat\nimport struct\nimport lzma\nimport shutil\n\n# --------------------------------------------------------------------------\n# 常量\n# --------------------------------------------------------------------------\nSQUASHFS_MAGIC = b"hsqs"\nSQUASHFS_MAGIC_LE = 0x73717368\nSUPERBLOCK_SIZE = 96\nMETADATA_BLOCK_SIZE = 8192\nXZ_MAGIC = b"\\xfd7zXZ\\x00"\nDEFAULT_BLOCK_SIZE = 262144\nINVALID_U32 = 0xFFFFFFFF\nINVALID_U64 = 0xFFFFFFFFFFFFFFFF\n\nPERM_FILE = ".squashfs.perm.json"\n\n# ---------------------------------------------------------------------------\n# 工具自生成 / 系统垃圾文件——**永远不参与打包**\n#\n# 权限清单 .squashfs.perm.json 是工具解包时在目录里留下的元数据侧车文件，\n# 打包时必须排除，否则镜像里会凭空多出 /.squashfs.perm.json 这种条目。\n# 其余是编辑器/系统常见垃圾。\n# ---------------------------------------------------------------------------\nSKIP_NAMES = {".DS_Store", "Thumbs.db", "desktop.ini", "__pycache__",\n              ".git", ".svn"}\n\n\ndef is_auxiliary(rel, perm_files=(PERM_FILE, ".perm.json")):\n    """判断 rel（相对路径，\'/\' 分隔）是否是工具自生成/应忽略的文件。\n\n    打包、清单扫描、「新增条目」检测三处必须共用同一判据，否则会出现\n    「扫描时当成新文件登记、打包时又滤掉」这类前后不一致。\n    """\n    parts = [p for p in rel.replace("\\\\", "/").split("/") if p]\n    if not parts:\n        return False\n    if parts == [\'.squashfs.source.bin\']:\n        return True\n    name = parts[-1]\n    if name in perm_files or name in SKIP_NAMES:\n        return True\n    # 任意层级的 __pycache__ / .git / .svn 目录\n    for p in parts[:-1]:\n        if p in ("__pycache__", ".git", ".svn"):\n            return True\n    return False\n\n\n# inode 类型\nT_DIR = 1\nT_FILE = 2\nT_SYMLINK = 3\nT_BLKDEV = 4\nT_CHRDEV = 5\nT_FIFO = 6\nT_SOCK = 7\nT_LDIR = 8\nT_LREG = 9\nT_LSYMLINK = 10\nT_LBLKDEV = 11\nT_LCHRDEV = 12\nT_LFIFO = 13\nT_LSOCK = 14\n\nTYPE_TO_NAME = {\n    1: "dir", 2: "file", 3: "symlink", 4: "blkdev", 5: "chrdev",\n    6: "fifo", 7: "sock", 8: "ldir", 9: "lreg", 10: "lsymlink",\n    11: "lblkdev", 12: "lchrdev", 13: "lfifo", 14: "lsock",\n}\n# 扩展类型 -> 基本类型\nEXT_TO_BASE = {8: 1, 9: 2, 10: 3, 11: 4, 12: 5, 13: 6, 14: 7}\n\nCOMPRESS_NONE = 0\nCOMPRESS_GZIP = 1\nCOMPRESS_LZMA = 2\nCOMPRESS_LZO = 3\nCOMPRESS_XZ = 4\nCOMPRESS_LZ4 = 5\nCOMPRESS_ZSTD = 6\nCOMPRESS_NAME = {0: "none", 1: "gzip", 2: "lzma", 3: "lzo", 4: "xz", 5: "lz4", 6: "zstd"}\n\n\n# --------------------------------------------------------------------------\n# xz 工具\n# --------------------------------------------------------------------------\ndef xz_compress(data, preset=6):\n    """用完整 xz 容器压缩（与固件中元数据块一致）"""\n    filters = [{"id":lzma.FILTER_ARMTHUMB},{"id":lzma.FILTER_LZMA2,"preset":preset,"dict_size":262144}]\n    plain = lzma.compress(data,format=lzma.FORMAT_XZ,check=lzma.CHECK_CRC32,filters=[filters[-1]])\n    thumb = lzma.compress(data,format=lzma.FORMAT_XZ,check=lzma.CHECK_CRC32,filters=filters)\n    return min((plain,thumb),key=len)\n\n\ndef xz_decompress(blob):\n    """解压完整 xz 流"""\n    return lzma.decompress(blob, format=lzma.FORMAT_XZ)\n\n\ndef xz_stream_size(data, off):\n    """返回从 off 开始的 xz 流的精确字节长度（用于探测数据块边界）"""\n    dec = lzma.LZMADecompressor(format=lzma.FORMAT_XZ)\n    n = 0\n    total = len(data)\n    while not dec.eof:\n        step = min(64, total - off - n)\n        if step <= 0:\n            raise ValueError("xz 流截断 @%d" % off)\n        dec.decompress(data[off + n:off + n + step])\n        n += step\n    return n - len(dec.unused_data)\n\n\n# --------------------------------------------------------------------------\n# 元数据块（xz 容器）读写\n# --------------------------------------------------------------------------\ndef read_metadata(data, off, stop, decoder=None):\n    """\n    从 off 读到 stop，解压整条元数据块链。\n    返回 (decompressed: bytes, blocks: [(file_off, csize, uncompressed, dsize, base_off)])\n    其中 base_off 是该块解压后在总流中的起始偏移。\n    """\n    out = bytearray()\n    blocks = []\n    while off < stop:\n        if off + 2 > len(data):\n            break\n        hdr = struct.unpack_from("<H", data, off)[0]\n        uncompressed = hdr >> 15\n        csize = hdr & 0x7FFF\n        if csize == 0:\n            break\n        payload = data[off + 2:off + 2 + csize]\n        if len(payload) < csize:\n            raise ValueError("元数据块越界 @%d" % off)\n        if uncompressed:\n            dec = payload\n        else:\n            dec = (decoder or xz_decompress)(payload)\n        blocks.append((off, csize, uncompressed, len(dec), len(out)))\n        if len(dec)>METADATA_BLOCK_SIZE:\n            raise ValueError("元数据解压超过 8192 字节")\n        out += dec\n        off += 2 + csize\n    return bytes(out), blocks\n\n\ndef write_metadata_chain(blob, chunk=METADATA_BLOCK_SIZE, compress=True):\n    """\n    把 blob 切成 chunk 大小的元数据块，逐块压缩。\n    返回 (链字节, [(该块文件内相对偏移, csize)]).\n    记录每块的相对偏移（含 2 字节头），供 inode 的 block_start 使用。\n    """\n    out = bytearray()\n    index = []\n    pos = 0\n    while pos < len(blob):\n        piece = blob[pos:pos + chunk]\n        pos += len(piece)\n        index.append(len(out))\n        comp = xz_compress(piece)\n        if compress and len(comp) < len(piece):\n            if len(comp) > 0x7FFF:\n                # 压不下 15 位长度，改成不压缩\n                out += struct.pack("<H", 0x8000 | len(piece)) + piece\n            else:\n                out += struct.pack("<H", len(comp)) + comp\n        else:\n            out += struct.pack("<H", 0x8000 | len(piece)) + piece\n    return bytes(out), index\n\n\ndef _meta_locate(block_start, offset, blocks, region_base=None):\n    """\n    block_start 是元数据区内的**相对字节偏移**（含 2 字节块头），\n    offset 是该元数据块解压后的字节偏移。\n    blocks 里的 file_off 是文件绝对偏移；region_base = 元数据区起始文件偏移。\n    返回 (block_index, base_in_flat) —— 解压后扁平流里的绝对位置。\n    """\n    if not blocks:\n        return 0, offset\n    if region_base is None:\n        region_base = blocks[0][0]\n    # 把每个块的 file_off 转成区域相对偏移\n    best = 0\n    for i, (foff, csize, unc, dsize, base) in enumerate(blocks):\n        rel = foff - region_base\n        if rel <= block_start:\n            best = i\n        else:\n            break\n    foff, csize, unc, dsize, base = blocks[best]\n    within = block_start - (foff - region_base) - 2\n    if within < 0:\n        within = 0\n    return best, base + within + offset\n\n\n# --------------------------------------------------------------------------\n# inode 解析\n# --------------------------------------------------------------------------\nclass Inode(object):\n    __slots__ = ("path", "inode_type", "mode", "uid", "gid", "mtime", "inode_number",\n                 "nlink", "file_size", "start_block", "fragment", "frag_offset",\n                 "block_sizes", "target", "dir_start", "dir_offset", "dir_size",\n                 "parent_inode", "rdev", "children", "data")\n\n    def __init__(self):\n        self.path = ""\n        self.inode_type = 0\n        self.mode = 0\n        self.uid = 0\n        self.gid = 0\n        self.mtime = 0\n        self.inode_number = 0\n        self.nlink = 0\n        self.file_size = 0\n        self.start_block = 0\n        self.fragment = INVALID_U32\n        self.frag_offset = 0\n        self.block_sizes = []\n        self.target = b""\n        self.dir_start = 0\n        self.dir_offset = 0\n        self.dir_size = 0\n        self.parent_inode = 0\n        self.rdev = 0\n        self.children = []\n        self.data = None\n\n    @property\n    def base_type(self):\n        return EXT_TO_BASE.get(self.inode_type, self.inode_type)\n\n    @property\n    def is_dir(self):\n        return self.base_type == T_DIR\n\n    @property\n    def is_file(self):\n        return self.base_type == T_FILE\n\n    @property\n    def is_symlink(self):\n        return self.base_type == T_SYMLINK\n\n    @property\n    def type_name(self):\n        return TYPE_TO_NAME.get(self.inode_type, "?")\n\n    def perm_mode(self):\n        """返回 Linux 权限位（不含类型）"""\n        return self.mode & 0o7777\n\n    def __repr__(self):\n        return "<Inode %s %s %#o size=%d>" % (self.type_name, self.path, self.perm_mode(), self.file_size)\n\n\ndef _sq_decompress(self, blob):\n    comp = self._sb[\'compression\']\n    if comp == 4:\n        return lzma.decompress(blob,format=lzma.FORMAT_XZ)\n    if comp == 1:\n        import zlib\n        return zlib.decompress(blob)\n    if comp == 2:\n        return lzma.decompress(blob,format=lzma.FORMAT_ALONE)\n    if comp == 5:\n        try:\n            import lz4.block\n        except ImportError as exc:\n            raise ValueError(\'LZ4 SquashFS 需要安装 lz4 包\') from exc\n        return lz4.block.decompress(blob,uncompressed_size=self.block_size)\n    if comp == 6:\n        try:\n            import compression.zstd as zstd\n        except ImportError:\n            try:\n                import zstandard as zstd\n            except ImportError as exc:\n                raise ValueError(\'Zstd SquashFS 需要 Python 3.14 或 zstandard 包\') from exc\n            return zstd.ZstdDecompressor().decompress(blob,max_output_size=self.block_size)\n        return zstd.decompress(blob)\n    raise ValueError(\'未支持的 SquashFS 压缩算法 ID=%d\' % comp)\n\n\ndef _sq_indexed_table(self, key, length):\n    if length == 0:\n        return b\'\'\n    start = self._sb[key]\n    count = (length+8191)//8192\n    if start<96 or start+count*8>self._sb[\'bytes_used\']:\n        raise ValueError(\'表索引越界: \'+key)\n    out = bytearray()\n    for ptr in struct.unpack_from(\'<%dQ\'%count,self.data,start):\n        if not 96<=ptr<start:\n            raise ValueError(\'表指针无效: \'+key)\n        hdr = struct.unpack_from(\'<H\',self.data,ptr)[0]\n        size = hdr&0x7fff\n        if not size or ptr+2+size>start:\n            raise ValueError(\'表元数据越界: \'+key)\n        raw = self.data[ptr+2:ptr+2+size]\n        piece = raw if hdr&0x8000 else self._decompress(raw)\n        if len(piece)>8192:\n            raise ValueError(\'表元数据尺寸无效: \'+key)\n        out.extend(piece)\n    if len(out)!=length:\n        raise ValueError(\'表解压长度不符: \'+key)\n    return bytes(out)\n\n\nclass SquashFS(object):\n    """纯 Python squashfs 镜像读取器"""\n\n    def __init__(self, data=None, path=None):\n        if data is None:\n            with open(path, "rb") as f:\n                data = f.read()\n        self.data = data\n        self.path = path\n        self._sb = None\n        self.inodes = {}        # inode_number -> Inode\n        self.root = None\n        self.id_table = []\n        self.fragments = []     # [(start, size, uncompressed)]\n        self.data_start = SUPERBLOCK_SIZE\n        self.warnings = []\n        if len(data) < SUPERBLOCK_SIZE:\n            raise ValueError("文件太小，不是 squashfs")\n        if data[:4] != SQUASHFS_MAGIC:\n            raise ValueError("magic 不是 hsqs: %r" % data[:4])\n        self._parse_superblock()\n        sb = self._sb\n        bs = sb[\'block_size\']\n        if (sb[\'ver_major\'],sb[\'ver_minor\'])!=(4,0) or not 4096<=bs<=1048576 or bs&(bs-1) or bs!=1<<sb[\'block_log\']:\n            raise ValueError(\'不支持的 SquashFS 版本或无效块大小\')\n        if not 96<=sb[\'inode_table_start\']<=sb[\'dir_table_start\']<=sb[\'bytes_used\']<=len(data):\n            raise ValueError(\'SquashFS 超级块指针越界或镜像截断\')\n        self.data = data[:sb[\'bytes_used\']]\n        self._detect_data_start()\n\n    _decompress = _sq_decompress\n    _indexed_table = _sq_indexed_table\n\n    # ---------------- 超级块 ----------------\n    def _parse_superblock(self):\n        (magic, inodes, mkfs_time, block_size, frags,\n         comp, block_log, flags, no_ids, vmaj, vmin) = struct.unpack_from("<IIIIIHHHHHH", self.data, 0)\n        root_inode, bytes_used = struct.unpack_from("<QQ", self.data, 32)\n        (id_tbl, xattr_tbl, inode_tbl, dir_tbl, frag_tbl, export_tbl) = \\\n            struct.unpack_from("<QQQQQQ", self.data, 48)\n        self._sb = {\n            "magic": magic, "inodes": inodes, "mkfs_time": mkfs_time,\n            "block_size": block_size, "fragments": frags, "compression": comp,\n            "block_log": block_log, "flags": flags, "no_ids": no_ids,\n            "ver_major": vmaj, "ver_minor": vmin,\n            "root_inode": root_inode, "bytes_used": bytes_used,\n            "id_table_start": id_tbl, "xattr_id_table_start": xattr_tbl,\n            "inode_table_start": inode_tbl, "dir_table_start": dir_tbl,\n            "fragment_table_start": frag_tbl, "export_table_start": export_tbl,\n        }\n\n    def _detect_data_start(self):\n        """\n        标准 squashfs 数据区从 96 开始；本固件变体在 96 之后有一段额外头。\n        做法：从 96 起在 96..96+64 范围内找第一个 xz 魔数。\n        """\n        p = self.data.find(XZ_MAGIC, SUPERBLOCK_SIZE, SUPERBLOCK_SIZE + 128)\n        if p < 0:\n            # 没有 xz → 可能未压缩，退回 96\n            self.data_start = SUPERBLOCK_SIZE\n        else:\n            self.data_start = p\n\n    # ---------------- 基本属性 ----------------\n    @property\n    def block_size(self):\n        return self._sb["block_size"] or DEFAULT_BLOCK_SIZE\n\n    @property\n    def compression_name(self):\n        return COMPRESS_NAME.get(self._sb["compression"], "unknown")\n\n    def info(self):\n        s = self._sb\n        return {\n            "路径": self.path,\n            "文件大小": len(self.data),\n            "inode 数": s["inodes"],\n            "block_size": s["block_size"],\n            "fragments": s["fragments"],\n            "压缩算法": self.compression_name,\n            "版本": "%d.%d" % (s["ver_major"], s["ver_minor"]),\n            "flags": "%#x" % s["flags"],\n            "bytes_used": s["bytes_used"],\n            "数据区起点": self.data_start,\n            "inode_table_start": s["inode_table_start"],\n            "dir_table_start": s["dir_table_start"],\n            "fragment_table_start": s["fragment_table_start"],\n            "id_table_start": s["id_table_start"],\n            "root_inode": s["root_inode"],\n        }\n\n    # ---------------- 表解析 ----------------\n    def _load_id_table(self):\n        blob = self._indexed_table(\'id_table_start\',self._sb[\'no_ids\']*4)\n        return list(struct.unpack(\'<%dI\' % self._sb[\'no_ids\'],blob))\n\n\n    def _load_fragment_table(self):\n        """\n        本固件变体的 fragment 池布局（已实测证明）：\n          数据区 = 一串 xz 流。\n          其中一部分流被「跨块大文件」的 block_sizes 直接引用（start_block=绝对偏移）；\n          剩下的流按顺序构成 fragment 池，inode.fragment 即池内下标，\n          inode.frag_offset 是其在池内该流解压数据中的字节偏移。\n\n        因此：先扫描所有流，再扣除被 block_sizes 引用的流，剩余即 fragment 池。\n        """\n        s = self._sb\n        stop = s["inode_table_start"]\n        if stop in (0, INVALID_U64) or stop > len(self.data):\n            stop = len(self.data)\n\n        # 1) 枚举数据区全部 xz 流\n        all_streams = []\n        off = self.data_start\n        guard = 0\n        while off < stop and guard < 100000:\n            guard += 1\n            if self.data[off:off + 6] == XZ_MAGIC:\n                try:\n                    csize = xz_stream_size(self.data, off)\n                except Exception:\n                    break\n                all_streams.append((off, csize, 0))\n                off += csize\n            else:\n                nxt = self.data.find(XZ_MAGIC, off + 1, stop)\n                if nxt < 0:\n                    break\n                all_streams.append((off, nxt - off, 1))\n                off = nxt\n        self.all_streams = all_streams\n\n        # 2) 标记被 block_sizes 引用的流\n        used_offsets = set()\n        for ino in self.inodes.values():\n            if ino.is_file and ino.block_sizes and ino.start_block:\n                p = ino.start_block\n                used_offsets.add(p)\n                for (cs, unc) in ino.block_sizes:\n                    p += cs\n                    used_offsets.add(p)\n        # 只保留"确实是块起点"的偏移\n        real_used = set()\n        for ino in self.inodes.values():\n            if ino.is_file and ino.block_sizes and ino.start_block:\n                p = ino.start_block\n                real_used.add(p)\n                for (cs, unc) in ino.block_sizes[:-1]:\n                    p += cs\n                    real_used.add(p)\n\n        pool = [st for st in all_streams if st[0] not in real_used]\n        return pool\n\n    # 兼容：也尝试读取标准 fragment 表（部分镜像会用到）\n    def _load_fragment_table_standard(self):\n        count = self._sb[\'fragments\']\n        if not count:\n            return []\n        blob = self._indexed_table(\'fragment_table_start\',count*16)\n        entries = []\n        for off in range(0,len(blob),16):\n            start,size,_ = struct.unpack_from(\'<QII\',blob,off)\n            cs,unc = size&0xffffff, bool(size&0x1000000)\n            if not cs or start<96 or start+cs>self._sb[\'inode_table_start\']:\n                raise ValueError(\'fragment 表数据块越界\')\n            entries.append((start,cs,unc))\n        return entries\n\n\n    def _load_inode_table(self):\n        s = self._sb\n        start = s["inode_table_start"]\n        stop = s["dir_table_start"]\n        blob, blocks = read_metadata(self.data, start, stop,self._decompress)\n        return blob, blocks\n\n    def _load_dir_table(self):\n        sb = self._sb\n        stops = [sb[\'bytes_used\']]\n        for name,count in [(\'fragment_table_start\',sb[\'fragments\']),(\'id_table_start\',sb[\'no_ids\'])]:\n            start = sb[name]\n            if count and 96<=start<sb[\'bytes_used\']-7:\n                ptr = struct.unpack_from(\'<Q\',self.data,start)[0]\n                if sb[\'dir_table_start\']<=ptr<start:\n                    stops.append(ptr)\n                elif sb[\'dir_table_start\']<start:\n                    stops.append(start)\n        return read_metadata(self.data,sb[\'dir_table_start\'],min(stops),self._decompress)\n\n\n    # ---------------- inode 解析 ----------------\n    def _parse_inode_at(self, flat, pos, blocks):\n        itype,mode,uid,gid,mtime,inum = struct.unpack_from(\'<HHHHII\',flat,pos)\n        if not 1<=itype<=14 or uid>=len(self.id_table) or gid>=len(self.id_table):\n            raise ValueError(\'inode 类型或 UID/GID 索引无效\')\n        ino = Inode()\n        ino.inode_type,ino.mode,ino.uid,ino.gid,ino.mtime,ino.inode_number = itype,mode,self.id_table[uid],self.id_table[gid],mtime,inum\n        p = pos+16\n        base = ino.base_type\n        if itype == T_DIR:\n            ino.dir_start,ino.nlink,ino.dir_size,ino.dir_offset,ino.parent_inode = struct.unpack_from(\'<IIHHI\',flat,p)\n            used = 32\n        elif itype == T_LDIR:\n            ino.nlink,ino.dir_size,ino.dir_start,ino.parent_inode,count,ino.dir_offset,xattr = struct.unpack_from(\'<IIIIHHI\',flat,p)\n            used = 40\n        elif base == T_FILE:\n            if itype == T_FILE:\n                ino.start_block,ino.fragment,ino.frag_offset,ino.file_size = struct.unpack_from(\'<IIII\',flat,p)\n                start = p+16\n            else:\n                ino.start_block,ino.file_size,sparse,ino.nlink,ino.fragment,ino.frag_offset,xattr = struct.unpack_from(\'<QQQIIII\',flat,p)\n                start = p+40\n            if ino.file_size>2*1024*1024*1024:\n                raise ValueError(\'文件超过当前 2 GiB 读取上限\')\n            count = (ino.file_size+self.block_size-1)//self.block_size if ino.fragment==INVALID_U32 else ino.file_size//self.block_size\n            ino.block_sizes = [(v&0xffffff,bool(v&0x1000000)) for v in struct.unpack_from(\'<%dI\'%count,flat,start)]\n            used = start-pos+count*4\n        elif base == T_SYMLINK:\n            ino.nlink,size = struct.unpack_from(\'<II\',flat,p)\n            if size>65535 or p+8+size>len(flat):\n                raise ValueError(\'符号链接长度无效\')\n            ino.target = flat[p+8:p+8+size]\n            ino.file_size = size\n            used = 24+size+(4 if itype>=8 else 0)\n        elif base in (T_BLKDEV,T_CHRDEV):\n            ino.nlink,ino.rdev = struct.unpack_from(\'<II\',flat,p)\n            used = 24+(4 if itype>=8 else 0)\n        else:\n            ino.nlink = struct.unpack_from(\'<I\',flat,p)[0]\n            used = 20+(4 if itype>=8 else 0)\n        return ino,used\n\n\n    def _get_inode(self, block_start, offset, flat, blocks):\n        _, pos = _meta_locate(block_start, offset, blocks)\n        ino, used = self._parse_inode_at(flat, pos, blocks)\n        return ino\n\n    def _parse_directory(self, ino, flat, blocks):\n        """\n        解析目录项列表。\n        dir 数据可能跨元数据块：用 ino.dir_start（区域相对偏移）+\n        ino.dir_offset 定位起点，然后**在扁平 dir 流里连续读** dir_size 字节。\n        每个 header 的 start_block 决定该组目录项的 inode 元数据块偏移，\n        entry.offset 为该块内偏移。\n        返回 [(name, type, inode_number, (block_start, entry_offset))]\n        """\n        dirblob, dirblocks = self._flat_dir\n        _, pos = _meta_locate(ino.dir_start, ino.dir_offset, dirblocks)\n        end = pos + max(0,ino.dir_size-3)\n        entries = []\n        while pos + 12 <= end and pos + 12 <= len(dirblob):\n            cnt, hdr_block_start, inum = struct.unpack_from("<III", dirblob, pos)\n            pos += 12\n            count = cnt + 1\n            if count <= 0 or count > 256:\n                break\n            for _i in range(count):\n                if pos + 8 > len(dirblob):\n                    return entries\n                e_off, e_ino_delta, etype, esize = struct.unpack_from("<HhHH", dirblob, pos)\n                name = dirblob[pos + 8:pos + 8 + esize + 1]\n                pos += 8 + esize + 1\n                entry_inum = inum + e_ino_delta\n                etype_base = EXT_TO_BASE.get(etype, etype)\n                entries.append((name, etype_base, entry_inum, (hdr_block_start, e_off), etype))\n        return entries\n\n    # ---------------- 数据读取 ----------------\n    def _read_data_blocks(self, ino):\n        out,off = bytearray(),ino.start_block\n        for csize,unc in ino.block_sizes:\n            expected = min(self.block_size,ino.file_size-len(out))\n            if not csize:\n                out.extend(b\'\\0\'*expected)\n                continue\n            if off<96 or off+csize>self._sb[\'inode_table_start\']:\n                raise ValueError(\'文件数据块越界: \'+ino.path)\n            block = self.data[off:off+csize]\n            off += csize\n            piece = block if unc else self._decompress(block)\n            if len(piece)!=expected:\n                raise ValueError(\'文件数据块解压尺寸不符: \'+ino.path)\n            out.extend(piece)\n        return bytes(out)\n\n\n    def _read_fragment(self, ino):\n        """读取某个 inode 的 fragment tail"""\n        if ino.fragment == INVALID_U32 or ino.fragment >= len(self.fragments):\n            return b""\n        start, csize, unc = self.fragments[ino.fragment]\n        raw = self.data[start:start + csize]\n        if unc:\n            blob = raw\n        else:\n            blob = xz_decompress(raw)\n        tail_len = ino.file_size - len(self._read_data_blocks(ino))\n        if tail_len <= 0:\n            return b""\n        return blob[ino.frag_offset:ino.frag_offset + tail_len]\n\n    def read_file(self, ino):\n        data = self._read_data_blocks(ino)\n        need = ino.file_size-len(data)\n        if need and ino.fragment!=INVALID_U32:\n            if ino.fragment>=len(self.fragments):\n                raise ValueError(\'fragment 索引越界: \'+ino.path)\n            start,size,unc = self.fragments[ino.fragment]\n            raw = self.data[start:start+size]\n            cache = getattr(self,\'_fragment_cache\',{})\n            if ino.fragment not in cache:\n                cache[ino.fragment] = raw if unc else self._decompress(raw)\n                self._fragment_cache = cache\n            data += cache[ino.fragment][ino.frag_offset:ino.frag_offset+need]\n        if len(data)!=ino.file_size:\n            raise ValueError(\'文件读取不完整: %s (%d != %d)\' % (ino.path,len(data),ino.file_size))\n        return data\n\n\n    # ---------------- 构建目录树 ----------------\n    def load(self, with_data=False, emit=None):\n        """解析整棵目录树，返回根 Inode"""\n        if emit:\n            emit("[squashfs] 解析超级块: %s 压缩, block=%d"\n                 % (self.compression_name, self.block_size))\n        self.inodes = {}\n        self.id_table = self._load_id_table()\n        flat, blocks = self._load_inode_table()\n        self._dirblob, self._dirblocks = self._load_dir_table()\n        self._flat_dir = (self._dirblob, self._dirblocks)\n        self._flat_inode = flat\n        self._inode_blocks = blocks\n\n        s = self._sb\n        ri = s["root_inode"]\n        block_start = ri >> 16\n        offset = ri & 0xFFFF\n        root = self._get_inode(block_start, offset, flat, blocks)\n        root.path = "/"\n        self.root = root\n        # 第一遍：建树（此时 fragment 池尚未确定，先不读数据）\n        self.fragments = []\n        self._walk(root, "", flat, blocks, False, emit)\n        # 第二遍：根据 inode 的 block_sizes 反推 fragment 池\n        try:\n            self.fragments = self._load_fragment_table_standard()\n            self.fragment_layout = \'standard\'\n        except ValueError:\n            if not getattr(self,\'allow_legacy_fragments\',False):\n                raise\n            if self._sb[\'compression\']!=4:\n                raise\n            self.fragments = self._load_fragment_table()\n            self.fragment_layout = \'legacy-xz-stream-pool\'\n        if len(self.inodes)!=self._sb[\'inodes\']:\n            raise ValueError(\'SquashFS inode 数量与超级块不符，目录树不完整\')\n        if self.warnings:\n            raise ValueError(\'目录树不完整: \'+\'; \'.join(self.warnings[:3]))\n        if emit:\n            emit("[squashfs] fragment 池: %d 个片段（数据区共 %d 条流）"\n                 % (len(self.fragments), len(getattr(self, "all_streams", []))))\n        if with_data:\n            for ino in self.inodes.values():\n                if ino.is_file:\n                    ino.data = self.read_file(ino)\n        return root\n\n    def _walk(self, ino, prefix, flat, blocks, with_data, emit):\n        ino.path = prefix if prefix else "/"\n        self.inodes[ino.inode_number] = ino\n        if not ino.is_dir:\n            if with_data and ino.is_file:\n                ino.data = self.read_file(ino)\n            return\n        try:\n            entries = self._parse_directory(ino, flat, blocks)\n        except Exception as ex:\n            self.warnings.append("目录 %s 解析失败: %s" % (ino.path, ex))\n            return\n        for (name, etype, inum, (hdr_block, e_off), raw_type) in entries:\n            try:\n                child = self._get_inode(hdr_block, e_off, flat, blocks)\n            except Exception as ex:\n                self.warnings.append("inode %s 解析失败: %s"\n                                     % (name.decode("utf-8", "replace"), ex))\n                continue\n            try:\n                nm = name.decode("utf-8")\n            except UnicodeDecodeError:\n                nm = name.decode("utf-8", "replace")\n            if not nm or nm in (\'.\',\'..\') or any(c in nm for c in \'/\\\\\\x00:\'):\n                raise ValueError(\'不可安全还原的文件名: \'+repr(nm))\n            if child.is_dir and any(x is child or (x.is_dir and x.inode_number==child.inode_number) for x in self.inodes.values()):\n                raise ValueError(\'SquashFS 目录环\')\n            child.path = (prefix + "/" + nm) if prefix else "/" + nm\n            if child.inode_number != inum:\n                raise ValueError("目录项 inode 编号与 inode 表不一致")\n            if child.inode_type != raw_type and EXT_TO_BASE.get(raw_type) == child.base_type:\n                child.inode_type = raw_type\n            ino.children.append((nm, child))\n            self._walk(child, child.path, flat, blocks, with_data, emit)\n\n    # ---------------- 列举 ----------------\n    def list_all(self):\n        """返回所有 inode 列表（深度优先）"""\n        out = []\n\n        def rec(ino):\n            out.append(ino)\n            for _n, c in ino.children:\n                rec(c)\n        if self.root:\n            rec(self.root)\n        return out\n\n\n# --------------------------------------------------------------------------\n# 便捷接口：解包\n# --------------------------------------------------------------------------\ndef is_squashfs(blob):\n    return len(blob) >= 4 and blob[:4] == SQUASHFS_MAGIC\n\n\ndef probe(path):\n    """快速探测一个 squashfs 镜像的基本信息"""\n    with open(path, "rb") as f:\n        head = f.read(SUPERBLOCK_SIZE)\n    if head[:4] != SQUASHFS_MAGIC:\n        return None\n    (magic, inodes, mkfs_time, block_size, frags,\n     comp, block_log, flags, no_ids, vmaj, vmin) = struct.unpack_from("<IIIIIHHHHHH", head, 0)\n    bytes_used = struct.unpack_from("<Q", head, 40)[0]\n    return {\n        "inodes": inodes, "block_size": block_size, "fragments": frags,\n        "compression": COMPRESS_NAME.get(comp, "?"), "flags": flags,\n        "bytes_used": bytes_used, "ver": "%d.%d" % (vmaj, vmin),\n    }\n\n\ndef _probe_symlink_support(tmpdir):\n    """探测当前环境能否**真正**创建符号链接。\n\n    返回 True / False / None：\n      * True  —— os.symlink 后 os.path.islink 为真（正常 Linux / 开了开发者模式的 Windows）\n      * False —— os.symlink 不报错但不是真链接（本机沙箱/受限环境会这样：\n                 建出 0 字节普通文件），或直接抛 OSError（普通 Windows 无权限）\n      * None  —— 探测本身失败，无法判断（按 False 处理较安全）\n\n    为什么要探测：与其对每个链接都「先建后删」，不如先探一次。探测为\n    False 时**根本不落盘**，全部交给权限清单还原——既避免脏占位文件，\n    也避免大批量 os.remove 触发批量删除保护。\n    """\n    try:\n        probe = os.path.join(tmpdir, ".sq_symlink_probe")\n        if os.path.lexists(probe):\n            os.remove(probe)\n        try:\n            os.symlink("_probe_target_", probe)\n        except OSError:\n            return False\n        ok = os.path.islink(probe)\n        try:\n            os.remove(probe)\n        except OSError:\n            pass\n        return bool(ok)\n    except Exception:\n        return None\n\n\ndef unpack(image_path_or_bytes, outdir, emit=None, perm_file=PERM_FILE,\n           with_data=True):\n    """\n    解包 squashfs 到目录树。会写出权限清单 perm_file。\n    返回 (n_inodes, n_files, n_dirs, n_symlinks)\n    """\n    if emit is None:\n        emit = lambda m: None\n    if isinstance(image_path_or_bytes, (bytes, bytearray)):\n        fs = SquashFS(data=bytes(image_path_or_bytes), path="<memory>")\n    else:\n        fs = SquashFS(path=image_path_or_bytes)\n    emit("[squashfs] 超级块: %s, block_size=%d, inode=%d, fragment=%d"\n         % (fs.compression_name, fs.block_size, fs._sb["inodes"], fs._sb["fragments"]))\n    root = fs.load(with_data=with_data, emit=emit)\n\n    if os.path.isdir(outdir) and os.listdir(outdir):\n        raise ValueError("解包目录非空，请选择新目录: "+str(outdir))\n    if os.path.isdir(outdir):\n        pass\n    else:\n        os.makedirs(outdir, exist_ok=True)\n\n    manifest = {}\n    counters = {"inode": 0, "file": 0, "dir": 0, "symlink": 0, "special": 0}\n    _symlink_created = 0\n    _symlink_failed = 0\n    # 先探一次符号链接能力：不可用时**完全不落盘**，全交给权限清单还原。\n    _symlink_ok = False\n\n    def real_path(p):\n        rel = p.lstrip("/")\n        return os.path.join(outdir, rel.replace("/", os.sep)) if rel else outdir\n\n    all_inodes = fs.list_all()\n    for ino in all_inodes:\n        counters["inode"] += 1\n        rp = real_path(ino.path)\n        # type 用 Python stat 的类型位（S_IFREG/S_IFDIR/S_IFLNK/...）表示，\n        # 这样清单是自描述的：打包端只看 type 就能决定建文件/目录/链接，\n        # 不再依赖「磁盘上是不是 link」这种在 Windows 上不可靠的信息。\n        _kind = ("dir" if ino.is_dir else\n                 "symlink" if ino.is_symlink else\n                 "file" if ino.is_file else "special")\n        _typ = {"dir": _stat.S_IFDIR, "symlink": _stat.S_IFLNK,\n                "file": _stat.S_IFREG}.get(_kind)\n        if not _typ:\n            # 特殊文件（设备/fifo/sock）：按 inode 基础类型取类型位\n            _typ = {T_BLKDEV: _stat.S_IFBLK,\n                    T_CHRDEV: _stat.S_IFCHR,\n                    T_FIFO: _stat.S_IFIFO,\n                    T_SOCK: _stat.S_IFSOCK}.get(ino.base_type) \\\n                or _stat.S_IFMT(ino.mode) or _stat.S_IFREG\n        # mode 写「完整 Unix 模式」= 类型位 | 权限位：\n        # 镜像 inode 头里的 mode 只有权限位，这里补上类型位，与 JFFS2\n        # 清单、GUI「类型」列、外部校验脚本的约定保持一致（打包端\n        # _perm_of() 依旧只取 mode & 0o7777，产物不受影响）。\n        rec = {\n            "mode": _typ | (ino.mode & 0o7777),\n            "uid": ino.uid,\n            "gid": ino.gid,\n            "mtime": ino.mtime,\n            "type": _typ,\n            "kind": _kind,\n            "inode": ino.inode_number,\n        }\n        if ino.is_dir:\n            counters["dir"] += 1\n            os.makedirs(rp, exist_ok=True)\n        elif ino.is_symlink:\n            counters["symlink"] += 1\n            rec["target"] = ino.target.decode("utf-8", "replace")\n            if _symlink_ok:\n                # 只有确定能建真链接时才落盘\n                parent = os.path.dirname(rp)\n                if parent:\n                    os.makedirs(parent, exist_ok=True)\n                if os.path.lexists(rp):\n                    try:\n                        os.remove(rp)\n                    except OSError:\n                        pass\n                try:\n                    os.symlink(rec["target"], rp)\n                except OSError as ex:\n                    _symlink_failed += 1\n                    if _symlink_failed <= 3:\n                        emit("  [!] 符号链接 %s -> %s 创建失败"\n                             "（已记入权限清单，打包时自动还原）: %s"\n                             % (ino.path, rec["target"], ex))\n                else:\n                    _symlink_created += 1\n            else:\n                # 环境不支持真链接：磁盘上不留任何占位，只记进权限清单。\n                _symlink_failed += 1\n        elif ino.is_file:\n            counters["file"] += 1\n            data = ino.data if ino.data is not None else fs.read_file(ino)\n            parent = os.path.dirname(rp)\n            if parent:\n                os.makedirs(parent, exist_ok=True)\n            with open(rp, "wb") as f:\n                f.write(data)\n        else:\n            # 设备节点 / fifo / sock\n            counters["special"] += 1\n            rec["rdev"] = ino.rdev\n            parent = os.path.dirname(rp)\n            if parent:\n                os.makedirs(parent, exist_ok=True)\n            with open(rp, "wb"):\n                pass\n        manifest[ino.path] = rec\n\n    perm_path = os.path.join(outdir, perm_file)\n    import hashlib\n    _atomic_output(os.path.join(outdir,\'.squashfs.source.bin\'),fs.data)\n    # `_source` 必须是一个**可用的分区名参考**，绝不能写 `<memory>` 这类占位符：\n    # 打包阶段 _guess_part_from_manifest() 会拿它反推回写目标（4.rootfs），\n    # 一旦是 `<memory>` 就会拼出非法路径 -> PermissionError / 生成垃圾文件。\n    # 规则：镜像来自文件 -> 用文件名；来自内存（从整机固件里抠分区）-> 用\n    # 解包目录名（如 4_rootfs），它经 _dir_to_part_name 能还原成 4.rootfs。\n    if isinstance(image_path_or_bytes, (bytes, bytearray)):\n        _src_name = os.path.basename(os.path.normpath(outdir or ""))\n        if _src_name in ("", os.curdir, os.pardir):\n            _src_name = "4_rootfs"\n    else:\n        _src_name = os.path.basename(image_path_or_bytes) or "4_rootfs"\n    with open(perm_path, "w", encoding="utf-8") as f:\n        json.dump({\n            "_comment": "squashfs 权限清单（mode=十进制完整模式：类型位|权限位）",\n            "_source": _src_name,\n            "_compression": fs.compression_name,\n            "_block_size": fs.block_size,\n            "_mkfs_time": fs._sb["mkfs_time"],\n            "_xattr_table": fs._sb["xattr_id_table_start"],\n            "_source_sha256": hashlib.sha256(fs.data).hexdigest(),\n            "entries": manifest,\n        }, f, ensure_ascii=False, indent=1)\n    emit("[squashfs] 完成: %d 个条目 (文件 %d / 目录 %d / 链接 %d / 特殊 %d)"\n         % (counters["inode"], counters["file"], counters["dir"],\n            counters["symlink"], counters["special"]))\n    if counters["symlink"]:\n        if _symlink_created:\n            emit("[squashfs] 已在磁盘创建 %d 个符号链接" % _symlink_created)\n        if _symlink_failed:\n            if _symlink_ok is False:\n                emit("[squashfs] 当前环境不支持创建真符号链接，"\n                     "%d 个链接**只记在权限清单 %s**（磁盘不落占位文件），"\n                     "打包时按清单自动还原，不影响结果。"\n                     % (_symlink_failed, perm_file))\n            else:\n                emit("[!] %d 个符号链接创建失败，已由权限清单 %s 记录，"\n                     "打包时会自动还原。" % (_symlink_failed, perm_file))\n    return counters\n\n\n# --------------------------------------------------------------------------\n# 打包（目录树 -> squashfs 镜像）\n# --------------------------------------------------------------------------\nSKIP_NAMES = {".DS_Store", "Thumbs.db", "desktop.ini", "__pycache__",\n              ".git", ".svn"}\n\n\ndef _scan_tree(srcdir, perm_file=PERM_FILE, emit=None):\n    """\n    扫描目录树，返回 (items, manifest, dir_kids)。\n      items      : [(relpath, abspath, "/inode/path", is_dir)]，父目录在前\n      manifest   : .squashfs.perm.json 里的 entries\n      dir_kids   : {"/dir" -> [子项路径]}\n\n    扫描阶段就把工具自生成文件（权限清单、系统垃圾）剔除掉——**打包必须与\n    扫描同源**，否则清单里会凭空出现 /.squashfs.perm.json 这类脏数据。\n    """\n    manifest = {}\n    perm_path = os.path.join(srcdir, perm_file)\n    if os.path.isfile(perm_path):\n        try:\n            with open(perm_path, "r", encoding="utf-8") as f:\n                manifest = json.load(f).get("entries", {})\n        except Exception:\n            manifest = {}\n\n    skipped = []\n    items = []\n    dir_kids = {}\n\n    def walk(rel):\n        absd = os.path.join(srcdir, rel.replace("/", os.sep)) if rel else srcdir\n        try:\n            names = sorted(os.listdir(absd))\n        except OSError:\n            return\n        for name in names:\n            r = (rel + "/" + name) if rel else name\n            if is_auxiliary(r, (perm_file, ".perm.json")):\n                skipped.append("/" + r)\n                continue\n            rp = "/" + r\n            ap = os.path.join(absd, name)\n            isdir = os.path.isdir(ap) and not os.path.islink(ap)\n            items.append((r, ap, rp, isdir))\n            parent = os.path.dirname(rp) or "/"\n            dir_kids.setdefault(parent, []).append(rp)\n            if isdir:\n                dir_kids.setdefault(rp, [])\n                walk(r)\n\n    walk("")\n    dir_kids.setdefault("/", [])\n    if skipped and emit:\n        # 只汇报「本来存在但被主动排除」的数量，避免每次打包刷屏\n        head = ", ".join(os.path.basename(s) for s in skipped[:3])\n        more = "" if len(skipped) <= 3 else " 等"\n        emit("[squashfs] 已排除 %d 个工具辅助文件（%s%s），不参与打包"\n             % (len(skipped), head, more))\n    return items, manifest, dir_kids\n\n\ndef _perm_of(manifest, rp, st, default):\n    """取权限：优先清单，其次磁盘（Windows 上不可靠，故默认给 0755/0644）\n\n    清单键容错：squashfs 习惯用绝对路径（/bin/cli），也可能被写成相对路径\n    （bin/cli），两种都接受。\n    """\n    rec = manifest.get(rp)\n    if rec is None:\n        alt = rp[1:] if rp.startswith("/") else "/" + rp\n        rec = manifest.get(alt)\n    rec = rec or {}\n    mode = rec.get("mode")\n    if mode is not None:\n        return mode & 0o7777, rec.get("uid", 0), rec.get("gid", 0), \\\n               rec.get("mtime", int(st.st_mtime if st else 0))\n    return default, 0, 0, int(st.st_mtime) if st else 0\n\n\ndef _rec_get(manifest, rp):\n    """取清单记录，绝对/相对路径两种写法都认。"""\n    if not manifest:\n        return None\n    rec = manifest.get(rp)\n    if rec is None:\n        alt = rp[1:] if rp.startswith("/") else "/" + rp\n        rec = manifest.get(alt)\n    return rec\n\n\ndef _rec_is_symlink(rec):\n    """判断清单记录是不是符号链接（兼容两种历史写法）：\n\n      * 新式：`type` = stat.S_IFLNK(0xA000)，或 `kind` == "symlink"\n      * 旧式：`type` == 3（squashfs inode 基础类型编号）\n      * 兜底：只要有 `target` 字段且不是特殊文件，就当链接\n    """\n    if not isinstance(rec, dict):\n        return False\n    t = rec.get("type")\n    if t is not None:\n        if (isinstance(t, int) and _stat.S_IFMT(t) == _stat.S_IFLNK):\n            return True\n        if t == 3:                       # 旧式 squashfs 基础类型编号\n            return True\n    if rec.get("kind") == "symlink":\n        return True\n    if rec.get("target") is not None and not rec.get("special"):\n        return True\n    return False\n\n\ndef _rec_symlink_target(rec):\n    """取符号链接目标字符串；没有则返回 None。"""\n    if not isinstance(rec, dict):\n        return None\n    t = rec.get("target")\n    return t if isinstance(t, str) and t != "" else None\n\n\ndef pack(srcdir, out_path, emit=None, block_size=DEFAULT_BLOCK_SIZE,\n         perm_file=PERM_FILE, compress_metadata=True, root_uid=0, root_gid=0,\n         size_limit=None, level=9, filesystem_output=None):\n    """\n    把目录树打包成 squashfs 镜像（与本固件 4.rootfs 的格式一致）：\n      * 超级块后是标准压缩选项元数据块：u16 0x8008 + <II(块大小, 16/armthumb)\n      * 超级块各表指针指向 u64 索引数组（标准语义），报告以 unsquashfs 4.6.1 实测为准\n      * inode/dir/frag/id 元数据块用完整 xz 容器（flags 声明为压缩）\n      * 数据区 = 所有 xz 流顺序排列\n         - 跨块大文件：block_sizes 数组 + start_block 绝对偏移\n         - 小文件/尾块：进入 fragment 池（每池一个 xz 流，多文件串联）\n      * inode/dir/frag/id 元数据块用完整 xz 容器\n    """\n    if os.path.splitdrive(os.path.realpath(srcdir))[0].lower()==os.path.splitdrive(os.path.realpath(out_path))[0].lower() and os.path.commonpath([os.path.realpath(srcdir),os.path.realpath(out_path)])==os.path.realpath(srcdir):\n        raise ValueError(\'输出镜像必须放在源目录以外\')\n    if emit is None:\n        emit = lambda m: None\n\n    filesystem_path = os.path.abspath(filesystem_output) if filesystem_output else os.path.join(os.path.dirname(os.path.abspath(out_path)), \'new.squashfs\')\n    if os.path.normcase(os.path.realpath(filesystem_path)) == os.path.normcase(os.path.realpath(out_path)):\n        raise ValueError(\'文件系统镜像与分区镜像输出路径必须不同\')\n    source_root = os.path.realpath(srcdir)\n    try:\n        inside_source = os.path.commonpath([source_root, os.path.realpath(filesystem_path)]) == source_root\n    except ValueError:\n        inside_source = False\n    if inside_source:\n        raise ValueError(\'文件系统镜像输出不得位于源目录内部\')\n    mf = os.path.join(srcdir,perm_file)\n    profile = {}\n    if os.path.isfile(mf):\n        with open(mf,encoding=\'utf-8\') as f:\n            profile = json.load(f)\n    if profile.get(\'_compression\',\'xz\')!=\'xz\':\n        raise ValueError(\'当前原格式打包支持 XZ SquashFS；此镜像的压缩算法不同\')\n    if profile.get(\'_xattr_table\',INVALID_U64)!=INVALID_U64:\n        raise ValueError(\'当前打包器无法无损保留 SquashFS xattr 表\')\n    block_size = profile.get(\'_block_size\',block_size)\n    if block_size<4096 or block_size>1048576 or block_size&(block_size-1):\n        raise ValueError(\'无效 SquashFS 块大小\')\n    items, manifest, dir_kids = _scan_tree(srcdir, perm_file, emit)\n    source_fs, source_paths = None, {}\n    if profile.get(\'_source_sha256\'):\n        import hashlib\n        with open(os.path.join(srcdir,\'.squashfs.source.bin\'),\'rb\') as f:\n            cached = f.read()\n        if hashlib.sha256(cached).hexdigest()!=profile[\'_source_sha256\']:\n            raise ValueError(\'原始 SquashFS 缓存校验失败\')\n        source_fs = SquashFS(data=cached)\n        source_fs.load()\n        import zlib\n        incompatible_check = False\n        scan = 0\n        while True:\n            scan = cached.find(b\'\\xfd7zXZ\\x00\', scan)\n            if scan < 0:\n                break\n            if scan + 12 <= len(cached):\n                header = cached[scan+6:scan+8]\n                if zlib.crc32(header) == struct.unpack_from(\'<I\', cached, scan+8)[0] and header[1] != 1:\n                    incompatible_check = True\n            scan += 6\n        if incompatible_check:\n            emit(\'[squashfs] 原缓存含非 CRC32 XZ 流，重新压缩以兼容设备内核\')\n        if incompatible_check or source_fs.data_start!=106 or source_fs.fragment_layout!=\'standard\':\n            source_fs = None\n        else:\n            source_paths = {i.path:i for i in source_fs.list_all()}\n    emit("[squashfs] 待打包条目: %d（目录 %d）"\n         % (len(items) + 1, sum(1 for it in items if it[3]) + 1))\n\n    # ---------- 1) 构造 inode 对象 ----------\n    class N(object):\n        __slots__ = ("rp", "ap", "kind", "mode", "uid", "gid", "mtime",\n                     "size", "inum", "target", "rdev", "nlink",\n                     "start_block", "fragment", "frag_offset", "bsizes",\n                     "payload", "data", "dir_entries", "parent_inode")\n\n    nodes = []\n    root = N()\n    root.rp = "/"\n    root.ap = srcdir\n    root.kind = "dir"\n    root.mode, root.uid, root.gid, root.mtime = _perm_of(\n        manifest, "/", None, 0o755)\n    # Root IDs were already restored from the permission manifest.\n    root.size = 0\n    root.inum = 1\n    root.target = None\n    root.rdev = 0\n    root.nlink = 2\n    root.start_block = 0\n    root.fragment = INVALID_U32\n    root.frag_offset = 0\n    root.bsizes = []\n    root.payload = b""\n    root.data = None\n    root.dir_entries = []\n    root.parent_inode = 1\n    nodes.append(root)\n\n    inum = 1\n    handled = set()\n    for (rel, ap, rp, isdir) in items:\n        if rp in handled:\n            continue\n        handled.add(rp)\n        n = N()\n        n.rp = rp\n        n.ap = ap\n        inum += 1\n        n.inum = inum\n        n.target = None\n        n.rdev = 0\n        n.nlink = 1\n        n.start_block = 0\n        n.fragment = INVALID_U32\n        n.frag_offset = 0\n        n.bsizes = []\n        n.payload = b""\n        n.data = None\n        n.dir_entries = []\n        n.parent_inode = 0\n        try:\n            st = os.lstat(ap)\n        except OSError:\n            st = None\n        if os.path.islink(ap):\n            n.kind = "symlink"\n            n.target = os.readlink(ap).encode("utf-8")\n            n.mode, n.uid, n.gid, n.mtime = _perm_of(\n                manifest, rp, st, 0o777)\n            n.size = len(n.target)\n        elif _rec_is_symlink(_rec_get(manifest, rp)):\n            # 权限清单记录为符号链接但磁盘上没有（Windows 无建链接权限，\n            # os.symlink 失败后磁盘上不留任何东西）→ 按清单目标还原\n            n.kind = "symlink"\n            n.target = _rec_symlink_target(\n                _rec_get(manifest, rp)).encode("utf-8")\n            n.mode, n.uid, n.gid, n.mtime = _perm_of(\n                manifest, rp, st, 0o777)\n            n.size = len(n.target)\n        elif _stat.S_IFMT((_rec_get(manifest,rp) or {}).get(\'type\',(_rec_get(manifest,rp) or {}).get(\'mode\',0))) in (_stat.S_IFCHR,_stat.S_IFBLK,_stat.S_IFIFO,_stat.S_IFSOCK):\n            n.kind = \'special\'\n            n.mode,n.uid,n.gid,n.mtime = _perm_of(manifest,rp,st,0o644)\n            n.rdev = (_rec_get(manifest,rp) or {}).get(\'rdev\',0)\n            n.size = 0\n        elif isdir:\n            n.kind = "dir"\n            n.mode, n.uid, n.gid, n.mtime = _perm_of(\n                manifest, rp, st, 0o755)\n            n.size = 0\n        elif os.path.isfile(ap):\n            n.kind = "file"\n            n.mode, n.uid, n.gid, n.mtime = _perm_of(\n                manifest, rp, st, 0o644)\n            with open(ap, "rb") as f:\n                n.data = f.read()\n            n.size = len(n.data)\n        else:\n            n.kind = "special"\n            n.mode, n.uid, n.gid, n.mtime = _perm_of(\n                manifest, rp, st, 0o644)\n            n.size = 0\n            n.rdev = (manifest.get(rp) or {}).get("rdev", 0)\n        nodes.append(n)\n\n    # 权限清单里是符号链接、磁盘上却没有（os.symlink 失败）→ 按清单补齐，\n    # 保证「解包 → 打包」不丢链接\n    _restored_missing = 0\n    for p, rec in manifest.items():\n        if p in handled or not _rec_is_symlink(rec):\n            continue\n        tgt = _rec_symlink_target(rec)\n        if tgt is None:\n            continue\n        n = N()\n        n.rp = p\n        n.ap = os.path.join(srcdir, p.lstrip("/").replace("/", os.sep))\n        inum += 1\n        n.inum = inum\n        n.target = None\n        n.rdev = 0\n        n.nlink = 1\n        n.start_block = 0\n        n.fragment = INVALID_U32\n        n.frag_offset = 0\n        n.bsizes = []\n        n.payload = b""\n        n.data = None\n        n.dir_entries = []\n        n.parent_inode = 0\n        n.kind = "symlink"\n        n.target = tgt.encode("utf-8")\n        n.mode, n.uid, n.gid, n.mtime = _perm_of(manifest, p, None, 0o777)\n        n.size = len(n.target)\n        nodes.append(n)\n        handled.add(p)\n        dir_kids.setdefault(os.path.dirname(p) or "/", []).append(p)\n        _restored_missing += 1\n    if _restored_missing:\n        emit("[squashfs] 按权限清单补齐 %d 个磁盘上缺失的符号链接"\n             % _restored_missing)\n\n    # 统一编号：按路径排序重新分配 inode 号，保证每次打包产物字节级可复现\n    # （不排序的话 libcurl.so / libcurl.so.4.8.0 这类名字的先后会漂移）。\n    nodes[1:] = sorted(nodes[1:], key=lambda x: x.rp)\n    for _i, _n in enumerate(nodes):\n        _n.inum = _i + 1\n\n    by_path = {n.rp: n for n in nodes}\n\n    # 父 inode 号（squashfs dir inode 需要）\n    for n in nodes:\n        if n.rp == "/":\n            n.parent_inode = 1\n        else:\n            pn = by_path.get(os.path.dirname(n.rp) or "/", root)\n            n.parent_inode = pn.inum\n\n    # ---------- 2) 数据区：分离「整块」与「fragment」 ----------\n    # 大文件：完整 block_size 的块走 block_sizes；不足一块的尾巴进 fragment\n    data_blob = bytearray(source_fs.data[106:source_fs._sb[\'inode_table_start\']] if source_fs else b\'\')\n    original_fragments = list(source_fs.fragments) if source_fs else []\n    preserved_files = set()\n    frag_items = []          # [(bytes, [ (节点, 池内偏移) ])] —— 每个池一段串联数据\n    FRAG_CHUNK = block_size     # 单个 fragment 池上限 64KB\n\n    def add_fragment(blob, owner):\n        """把 blob 追加到某个 fragment 池，返回 (池下标, 池内偏移)"""\n        for idx, item in enumerate(frag_items):\n            if len(item[0]) + len(blob) <= FRAG_CHUNK:\n                off = len(item[0])\n                item[0] += blob\n                item[1].append((owner, off))\n                return idx+len(original_fragments), off\n        frag_items.append([bytearray(blob), [(owner, 0)]])\n        return len(original_fragments)+len(frag_items)-1, 0\n\n    for n in nodes:\n        if n.kind != "file":\n            continue\n        old = source_paths.get(n.rp)\n        if old is not None and old.is_file and old.file_size==n.size and source_fs.read_file(old)==n.data:\n            n.start_block,n.fragment,n.frag_offset = old.start_block,old.fragment,old.frag_offset\n            n.bsizes = list(old.block_sizes)\n            preserved_files.add(n.rp)\n            continue\n        if n.size == 0:\n            n.bsizes = []\n            n.start_block = 0\n            continue\n        body = n.data\n        full = (n.size // block_size) * block_size\n        # 数据块部分\n        if full > 0:\n            for off in range(0, full, block_size):\n                blk = body[off:off + block_size]\n                comp = xz_compress(blk, preset=level)\n                if len(comp) < len(blk):\n                    n.payload += comp\n                    n.bsizes.append((len(comp), 0))\n                else:\n                    n.payload += blk\n                    n.bsizes.append((len(blk), 1))\n        else:\n            n.bsizes = []\n        tail = body[full:]\n        if tail:\n            fidx, foff = add_fragment(tail, n)\n            n.fragment = fidx\n            n.frag_offset = foff\n        else:\n            n.fragment = INVALID_U32\n            n.frag_offset = 0\n\n    # 布局：先写所有文件的 payload（按 inode 顺序），再写 fragment 池\n    # 标准布局：96 起是一个元数据块 —— u16 头 0x8008(未压缩/8字节) + 8 字节 xz\n    # 压缩选项 <II>(dict_size=262144, flags=16=armthumb)，xz 数据从 106 开始。\n    # 之前误写成裸 10 字节 <IIH，unsquashfs 把头读到 0x0000 → 报压缩选项错误。\n    variant_head = struct.pack("<H", 0x8008) + struct.pack("<II", block_size, 16)\n    assert len(variant_head) == 10\n    data_start = SUPERBLOCK_SIZE + len(variant_head)\n\n    cursor = len(data_blob)\n    for n in nodes:\n        if n.kind == "file" and n.payload:\n            n.start_block = data_start + cursor\n            data_blob += n.payload\n            cursor += len(n.payload)\n        elif n.kind == "file" and n.rp not in preserved_files:\n            n.start_block = 0\n\n    frag_abs = original_fragments   # [(abs_start, csize, unc)]\n    for item in frag_items:\n        raw = bytes(item[0])\n        comp = xz_compress(raw, preset=level)\n        if len(comp) < len(raw):\n            blob, unc = comp, 0\n        else:\n            blob, unc = raw, 1\n        frag_abs.append((data_start + cursor, len(blob), unc))\n        data_blob += blob\n        cursor += len(blob)\n\n    # ---------- 3) 目录内容 ----------\n    # 目录项分组规则：同一组内所有子 inode 必须位于**同一个 inode 元数据块**，\n    # 且不超过 256 项。块边界 / 256 项上限都要重新开一个 dir header。\n    # （inode_off 在步骤 4 才建立，故 dir_groups 延后到步骤 4 之后构造。）\n\n    # ---------- 4) inode 表（先写非目录，再写目录；目录项按深→浅）----------\n    inode_blob = bytearray()\n    inode_off = {}\n\n    ids = sorted(set([n.uid for n in nodes]+[n.gid for n in nodes]+[0]))\n    id_index = {value:i for i,value in enumerate(ids)}\n\n    def write_inode(n, body):\n        off = len(inode_blob)\n        inode_blob.extend(struct.pack("<HHHHII", _TYPE_OF(n), n.mode, id_index[n.uid],\n                                      id_index[n.gid], n.mtime, n.inum))\n        inode_blob.extend(body)\n        # 4 字节对齐（inode 记录本身需对齐）\n        pad = (4 - (len(inode_blob) % 4)) % 4\n        if pad:\n            inode_blob.extend(b"\\x00" * pad)\n        inode_off[n.inum] = off\n        return off\n\n    def _TYPE_OF(n):\n        if n.kind == "dir":\n            return T_DIR\n        if n.kind == "file":\n            return T_FILE\n        if n.kind == "symlink":\n            return T_SYMLINK\n        if n.kind == \'special\':\n            rec = manifest.get(n.rp,{})\n            typ = _stat.S_IFMT(rec.get(\'type\',rec.get(\'mode\',0)))\n            return {_stat.S_IFCHR:T_CHRDEV,_stat.S_IFBLK:T_BLKDEV,\n                    _stat.S_IFIFO:T_FIFO,_stat.S_IFSOCK:T_SOCK}.get(typ,T_FILE)\n        return T_FILE\n\n    # 非目录\n    for n in nodes:\n        if n.kind == "file":\n            body = struct.pack("<IIII", n.start_block,\n                               n.fragment, n.frag_offset, n.size)\n            for (cs, unc) in n.bsizes:\n                body += struct.pack("<I", (cs & 0xFFFFFF) | (unc << 24))\n            write_inode(n, body)\n        elif n.kind == "symlink":\n            body = struct.pack("<II", 1, len(n.target)) + n.target\n            write_inode(n, body)\n        elif n.kind == "special":\n            write_inode(n, struct.pack("<I",1) if _TYPE_OF(n) in (T_FIFO,T_SOCK) else struct.pack("<II", 1, n.rdev))\n\n    # 目录：占位（dir inode 16 字节 body），稍后回填\n    dir_slot = {}\n    dirs_sorted = sorted([n for n in nodes if n.kind == "dir"],\n                         key=lambda x: x.rp.count("/"), reverse=True)\n    for n in dirs_sorted:\n        parent = os.path.dirname(n.rp) or "/"\n        if parent == "":\n            parent = "/"\n        pin = by_path[parent].inum if parent in by_path else 1\n        n.nlink = 2 + sum(1 for k in dir_kids.get(n.rp, [])\n                          if k in by_path and by_path[k].kind == "dir")\n        body = struct.pack("<IIHHI", 0, n.nlink, 0, 0, pin)\n        dir_slot[n.inum] = len(inode_blob) + 16\n        write_inode(n, body)\n\n    # inode 偏移已确定 -> 现在按「同一元数据块」切分目录项分组\n    def build_dir_entries(parent_path, kids):\n        entries = []\n        ks = sorted(kids, key=lambda p: by_path[p].inum)\n        cur = []\n        cur_blk = None\n        for kp in ks:\n            c = by_path[kp]\n            blk = inode_off[c.inum] // METADATA_BLOCK_SIZE\n            if cur and (blk != cur_blk or len(cur) >= 256):\n                entries.append(cur)\n                cur = []\n            cur.append(kp)\n            cur_blk = blk\n        if cur:\n            entries.append(cur)\n        return entries\n\n    dir_groups = {}\n    for p, n in by_path.items():\n        if n.kind != "dir":\n            continue\n        kids = [k for k in dir_kids.get(p, []) if k in by_path]\n        dir_groups[p] = build_dir_entries(p, kids)\n\n    # ---------- 5) 目录表 ----------\n    dir_blob = bytearray()\n    dir_flat_pos = {}   # inum -> 在 dir_blob 中的扁平位置\n    dir_group_block = {}  # inum -> [每组在 dir_blob 中的位置]\n\n    def locate(flat, idx):\n        """返回 (元数据块在链中的相对偏移, 块内偏移)"""\n        bi = flat // METADATA_BLOCK_SIZE\n        if bi >= len(idx):\n            bi = len(idx) - 1\n        return idx[bi], flat - bi * METADATA_BLOCK_SIZE\n\n    # ---------- 6) 元数据块化 ----------\n    # 顺序很关键：\n    #   a) 先用 inode 链（此时 inode 内容已定，仅目录 inode 的 dir_start 待填）\n    #      → 得到每个目录块的相对偏移，用于 dir header 的 start_block\n    #   b) 构造 dir_blob（写入真实 start_block 与块内 offset）\n    #   c) 用 dir 链算出各目录 dir_start/dir_offset，回填 inode\n    #   d) 重新链化 inode（长度变化会移动块边界，故必须重算）\n    #   e) 用最终 inode 链回填所有 dir header 的 start_block\n    #   f) dir_blob 变了 -> 重新链化 dir；由于「块的相对偏移」是在**压缩后**的\n    #      链里定位的，回填会改变压缩长度、进而移动块边界，故整体迭代到收敛。\n    def dir_size_of(p):\n        size = 0\n        for group in dir_groups[p]:\n            size += 12\n            for kp in group:\n                size += 8 + len(os.path.basename(kp).encode("utf-8"))\n        return size\n\n    def build_dir_blob(chain_idx):\n        """按给定的 inode 链索引生成 dir_blob（start_block 先置 0）"""\n        blob = bytearray()\n        flat_pos = {}\n        group_pos = {}\n        for p in sorted(dir_groups.keys()):\n            n = by_path[p]\n            flat_pos[n.inum] = len(blob)\n            blocks = []\n            for group in dir_groups[p]:\n                blocks.append(len(blob))\n                start_inum = by_path[group[0]].inum\n                blob += struct.pack("<III", len(group) - 1, 0, start_inum)\n                prev = start_inum\n                for kp in group:\n                    c = by_path[kp]\n                    name = os.path.basename(kp).encode("utf-8")\n                    delta = c.inum - start_inum\n                    prev = c.inum\n                    _cs, c_off = locate(inode_off[c.inum], chain_idx)\n                    blob += struct.pack("<HhHH", c_off, delta,\n                                        _TYPE_OF(c), len(name) - 1) + name\n            group_pos[n.inum] = blocks\n        return blob, flat_pos, group_pos\n\n    def patch_dir_headers(blob, group_pos, chain_idx):\n        for p in sorted(dir_groups.keys()):\n            n = by_path[p]\n            for gi, group in enumerate(dir_groups[p]):\n                first = by_path[group[0]]\n                fstart, _foff = locate(inode_off[first.inum], chain_idx)\n                struct.pack_into("<I", blob, group_pos[n.inum][gi] + 4, fstart)\n\n    # 迭代到收敛。注意两处循环依赖：\n    #   * dir header 的 start_block 依赖 **inode 链**（压缩后块偏移）\n    #   * 目录 inode 的 dir_start 依赖 **dir 链**（压缩后块偏移）\n    # 两者互相影响，因此按「先补 dir_start(用上一轮 dir_idx) -> 链 inode\n    # -> 补 start_block -> 链 dir」的顺序迭代，直到 inode_blob/dir_blob 都不变。\n    def patch_inode_dir_starts(chain_idx):\n        for p in sorted(dir_groups.keys()):\n            n = by_path[p]\n            dstart, doff = locate(dir_flat_pos[n.inum], chain_idx)\n            inode_blob[dir_slot[n.inum]:dir_slot[n.inum] + 16] = struct.pack(\n                "<IIHHI", dstart, n.nlink, dir_size_of(p)+3, doff,\n                n.parent_inode)\n        root.parent_inode = root.inum\n        root.nlink = 2 + sum(1 for k in dir_kids.get("/", [])\n                             if k in by_path and by_path[k].kind == "dir")\n        dstart, doff = locate(dir_flat_pos[root.inum], chain_idx)\n        inode_blob[dir_slot[root.inum]:dir_slot[root.inum] + 16] = struct.pack(\n            "<IIHHI", dstart, root.nlink, dir_size_of("/")+3, doff,\n            root.inum)\n\n    inode_blob = bytearray(inode_blob)\n    dir_idx = [0]\n    # 先建一次 dir_blob 以得到 dir_flat_pos（位置只取决于目录顺序，与内容无关）\n    _seed_idx = write_metadata_chain(bytes(inode_blob),\n                                     compress=compress_metadata)[1]\n    dir_blob, dir_flat_pos, dir_group_block = build_dir_blob(_seed_idx)\n    prev_fp = None\n    for _round in range(8):\n        # 1) 用上一轮的 dir 链索引回填目录 inode 的 dir_start / dir_offset\n        patch_inode_dir_starts(dir_idx)\n        inode_chain, inode_idx = write_metadata_chain(\n            bytes(inode_blob), compress=compress_metadata)\n        # 2) 用当前 inode 链构造 dir_blob（含块内 offset）\n        dir_blob, dir_flat_pos, dir_group_block = build_dir_blob(inode_idx)\n        # 3) 回填 dir header 的 start_block（指向子 inode 所在元数据块）\n        patch_dir_headers(dir_blob, dir_group_block, inode_idx)\n        # 4) 链化 dir，得到本轮的 dir_idx（供下一轮回填 inode 用）\n        dir_chain, dir_idx = write_metadata_chain(bytes(dir_blob),\n                                                  compress=compress_metadata)\n        fp = (bytes(inode_blob), bytes(dir_blob), tuple(dir_idx))\n        if prev_fp == fp:\n            break\n        prev_fp = fp\n\n    # ---------- 7) fragment 表（写标准格式：元数据块 + 索引）----------\n    frag_meta = bytearray()\n    for (s, csize, unc) in frag_abs:\n        frag_meta += struct.pack("<QII", s, (csize & 0xFFFFFF) | (unc << 24), 0)\n    frag_chain, frag_idx = write_metadata_chain(bytes(frag_meta),\n                                                compress=compress_metadata)\n\n    # ---------- 8) id 表 ----------\n    ids = sorted(set([n.uid for n in nodes] + [n.gid for n in nodes] + [0]))\n    id_meta = b"".join(struct.pack("<I", v) for v in ids)\n    id_chain, id_idx = write_metadata_chain(id_meta, compress=compress_metadata)\n\n    # ---------- 9) 拼装 ----------\n    out = bytearray()\n    out += SQUASHFS_MAGIC\n    out += struct.pack("<IIII", len(nodes), profile.get("_mkfs_time", source_fs._sb["mkfs_time"] if source_fs else max((n.mtime for n in nodes), default=0)), block_size,\n                       len(frag_abs))\n    # CRC32 XZ streams and no-xattr/export flags match the embedded Linux format.\n    out += struct.pack("<HHHHHH", COMPRESS_XZ, block_size.bit_length()-1, (0x6C0 if compress_metadata else 0xEC9), len(ids), 4, 0)\n    out += struct.pack("<Q", 0)    # root_inode\n    out += struct.pack("<Q", 0)    # bytes_used\n    out += struct.pack("<QQQQQQ", 0, INVALID_U64, 0, 0, 0, 0)\n    assert len(out) == SUPERBLOCK_SIZE\n    out += variant_head\n    out += data_blob\n\n    inode_table_start = len(out)\n    out += inode_chain\n    dir_table_start = len(out)\n    out += dir_chain\n    frag_table_start = len(out)\n    out += frag_chain\n    # fragment 索引表（指向各元数据块）\n    frag_lookup_off = len(out)\n    for foff in frag_idx:\n        out += struct.pack("<Q", frag_table_start + foff)\n\n    export_meta = bytearray()\n    for node in sorted(nodes, key=lambda node: node.inum):\n        start, offset = locate(inode_off[node.inum], inode_idx)\n        export_meta += struct.pack("<Q", (start << 16) | offset)\n    export_chain, export_idx = write_metadata_chain(bytes(export_meta), compress=compress_metadata)\n    export_start = len(out)\n    out += export_chain\n    export_lookup_off = len(out)\n    for relative in export_idx:\n        out += struct.pack("<Q", export_start + relative)\n    id_table_start = len(out)\n    out += id_chain\n    id_lookup_off = len(out)\n    for foff in id_idx:\n        out += struct.pack("<Q", id_table_start + foff)\n    bytes_used = len(out)\n\n    rstart, roff = locate(inode_off[root.inum], inode_idx)\n    struct.pack_into("<Q", out, 32, (rstart << 16) | (roff & 0xFFFF))\n    struct.pack_into("<Q", out, 40, bytes_used)\n    # 标准语义：这些字段指向各「索引表」（u64 数组），而不是元数据链起点\n    struct.pack_into("<Q", out, 48, id_lookup_off)\n    struct.pack_into("<Q", out, 56, INVALID_U64)   # 无 xattr/export 表\n    struct.pack_into("<Q", out, 64, inode_table_start)\n    struct.pack_into("<Q", out, 72, dir_table_start)\n    struct.pack_into("<Q", out, 80, frag_lookup_off)\n    struct.pack_into("<Q", out, 88, export_lookup_off)\n\n    if size_limit and len(out)>size_limit:\n        raise ValueError("SquashFS 镜像超过指定容量")\n    if size_limit and len(out) < size_limit:\n        out += b"\\x00" * (size_limit - len(out))\n\n    verified = SquashFS(data=bytes(out))\n    verified.load()\n    actual = {i.path:i for i in verified.list_all()}\n    if set(actual)!=set(by_path):\n        raise ValueError(\'SquashFS 打包自检失败: 路径集合不一致\')\n    for n in nodes:\n        v = actual[n.rp]\n        if (v.mode,v.uid,v.gid)!=(n.mode,n.uid,n.gid):\n            raise ValueError(\'SquashFS 打包自检失败: 权限 \'+n.rp)\n        if n.kind==\'file\' and verified.read_file(v)!=n.data:\n            raise ValueError(\'SquashFS 打包自检失败: 内容 \'+n.rp)\n        if n.kind==\'symlink\' and v.target!=n.target:\n            raise ValueError(\'SquashFS 打包自检失败: 链接 \'+n.rp)\n    _atomic_output(filesystem_path, out[:bytes_used])\n    emit(\'[squashfs] 文件系统镜像已保存: \' + filesystem_path)\n    _atomic_output(out_path,out)\n    emit("[squashfs] 打包完成: %s (%d 字节, %d inode, %d fragment)"\n         % (os.path.basename(out_path), len(out), len(nodes), len(frag_abs)))\n    return len(out)\n\n\n# --------------------------------------------------------------------------\n# GUI 兼容层（纯 Python，无外部依赖）\n# --------------------------------------------------------------------------\nclass Backend(object):\n    """纯 Python 后端：为兼容旧 GUI 的 SQ.detect() 接口而保留"""\n\n    def __init__(self):\n        self.kind = "python"\n        self.label = "内置纯 Python 引擎（无需外部工具）"\n        self.unsquashfs = None\n        self.mksquashfs = None\n        self.can_unpack = True\n        self.can_pack = True\n\n    def __repr__(self):\n        return "<squashfs Backend python>"\n\n\ndef detect(_base_dir=None, _ssh=None, emit=None):\n    """总是返回内置纯 Python 后端"""\n    if emit:\n        emit("[squashfs] 使用内置纯 Python 引擎（无需 unsquashfs / mksquashfs）")\n    return Backend()\n\n\ndef hint_text():\n    return ("本工具的内置纯 Python 引擎已完整支持 squashfs 4.0（含 xz 元数据、\\n"\n            "fragment 池、绝对块偏移等本固件的私有变体），无需任何外部工具。\\n\\n"\n            "如遇问题请确认分区确实是 squashfs（前 4 字节为 \'hsqs\'）。")\n\n\ndef describe(path):\n    """返回镜像摘要（兼容旧 GUI 的字段名）"""\n    try:\n        fs = SquashFS(path=path)\n        s = fs._sb\n        return {\n            "compression": fs.compression_name,\n            "block_size": fs.block_size,\n            "total_size": len(fs.data),\n            "inodes": s["inodes"],\n            "fragments": s["fragments"],\n            "version": "%d.%d" % (s["ver_major"], s["ver_minor"]),\n        }\n    except Exception:\n        return None\n\n\ndef _compat_unpack(image, outdir, emit=None, **kw):\n    """签名兼容：unpack(后端, 镜像, 输出, emit) 或 unpack(镜像, 输出, emit)"""\n    if hasattr(image, "can_unpack"):          # 传进来的第一个参数是后端对象\n        image, outdir, emit = outdir, emit, kw.pop("emit", None) or emit\n    return _unpack_impl(image, outdir, emit=emit, **kw)\n\n\ndef _compat_pack(*a, **kw):\n    """签名兼容：\n         pack(后端, 源目录, 输出, emit, size=N)\n         pack(源目录, 输出, emit=..., size=N)\n    """\n    args = list(a)\n    if args and hasattr(args[0], "can_pack"):\n        args = args[1:]\n    src = args[0] if len(args) > 0 else kw.pop("srcdir")\n    out = args[1] if len(args) > 1 else kw.pop("out_path")\n    if len(args) > 2 and "emit" not in kw:\n        kw["emit"] = args[2]\n    size = kw.pop("size", None)\n    if size is not None and "size_limit" not in kw:\n        kw["size_limit"] = size\n    return _pack_impl(src, out, **kw)\n\n\n# 保留实现名，对外暴露兼容包装（GUI 直接调 SQ.unpack / SQ.pack）\n_unpack_impl = unpack\n_pack_impl = pack\nunpack = _compat_unpack\npack = _compat_pack\n# --------------------------------------------------------------------------\n# CLI\n# --------------------------------------------------------------------------\ndef _cli():\n    import argparse\n    ap = argparse.ArgumentParser(description="纯 Python squashfs 解包/打包工具")\n    sub = ap.add_subparsers(dest="cmd")\n\n    p1 = sub.add_parser("info", help="查看镜像信息")\n    p1.add_argument("image")\n\n    p2 = sub.add_parser("x", help="解包")\n    p2.add_argument("image")\n    p2.add_argument("outdir")\n    p2.add_argument("--no-data", action="store_true", help="不写文件内容")\n\n    p3 = sub.add_parser("ls", help="列出内容")\n    p3.add_argument("image")\n\n    p4 = sub.add_parser("c", help="打包")\n    p4.add_argument("srcdir")\n    p4.add_argument("out")\n    p4.add_argument("-b", "--block-size", type=int, default=DEFAULT_BLOCK_SIZE)\n\n    args = ap.parse_args()\n    if args.cmd == "info":\n        fs = SquashFS(path=args.image)\n        for k, v in fs.info().items():\n            print("  %-22s = %s" % (k, v))\n    elif args.cmd == "x":\n        unpack(args.image, args.outdir, emit=print, with_data=not args.no_data)\n    elif args.cmd == "ls":\n        fs = SquashFS(path=args.image)\n        fs.load()\n        for ino in fs.list_all():\n            extra = ""\n            if ino.is_symlink:\n                extra = " -> " + ino.target.decode("utf-8", "replace")\n            print("  %-10s %-5o %-6d %s%s" % (ino.type_name, ino.perm_mode(),\n                                              ino.file_size, ino.path, extra))\n    elif args.cmd == "c":\n        pack(args.srcdir, args.out, emit=print, block_size=args.block_size)\n    else:\n        ap.print_help()\n\n\nif __name__ == "__main__":\n    _cli()\n\n\ndef _backup_with_timestamp(path):\n    import shutil\n    from datetime import datetime, timezone, timedelta\n    stamp = datetime.now(timezone(timedelta(hours=8))).strftime(\'%Y%m%d%H%M%S\')\n    base = path + \'.\' + stamp\n    backup, index = base, 0\n    while True:\n        try:\n            stream = open(backup, \'xb\')\n            break\n        except FileExistsError:\n            index += 1\n            backup = base + \'.\' + str(index)\n    try:\n        with stream, open(path, \'rb\') as original:\n            shutil.copyfileobj(original, stream)\n            stream.flush()\n            os.fsync(stream.fileno())\n        shutil.copystat(path, backup)\n    except BaseException:\n        os.unlink(backup)\n        raise\n    return backup\n\n\ndef _atomic_output(path, data):\n    import tempfile\n    path = os.path.abspath(path)\n    os.makedirs(os.path.dirname(path), exist_ok=True)\n    fd, tmp = tempfile.mkstemp(prefix=\'.zxw-\', dir=os.path.dirname(path))\n    try:\n        with os.fdopen(fd, \'wb\') as stream:\n            stream.write(data)\n            stream.flush()\n            os.fsync(stream.fileno())\n        if os.path.isfile(path):\n            _backup_with_timestamp(path)\n        os.replace(tmp, path)\n    finally:\n        if os.path.exists(tmp):\n            os.unlink(tmp)\n\n'
FWINFO_SRC = (
    '# -*- coding: utf-8 -*-\n'
    '"""中兴微固件工具 · 通用信息（NV）读写引擎\n'
    '\n'
    '负责从固件里读出、并写回「通用信息」：\n'
    '  * IMEI            —— nvrofs 分区 → nvroall.bin @0x0000（8B 低半字节在前，F 填充）\n'
    '  * SN/单板序列号    —— nvroall.bin @0x0028（ASCII，最多 15 字节）\n'
    '  * WiFi MAC（主）   —— nvroall.bin @0x007C（6B）\n'
    '  * WiFi MAC2（5G）  —— nvroall.bin @0x02C0（6B）\n'
    '  * WiFi 名          —— userdata → etc_rw/nv/main/cfg 的 SSID1\n'
    '  * WiFi 密码        —— WPAPSK1（明文）/ WPAPSK1_encode（base64）/ Key1Str1 三级兜底\n'
    '  * 默认 SIM 卡      —— 同上 sim_select / sim_select_num_type\n'
    '  * 软件版本         —— 同上 cr_version\n'
    '  * 硬件版本         —— 同上 hw_version\n'
    '\n'
    '【WiFi 密码字段说明（实测 8 个机型确认）】\n'
    '  真实生效的密码存于 **WPAPSK1_encode**（base64）与 **WPAPSK1**（明文，部分机型有），\n'
    '  而 `Key1Str1` 在所有机型里恒为 `12345`，是**无用的历史字段**，不能当密码读。\n'
    '  `m_WPAPSK1_encode` 是配套副本，写入时必须同步，否则设备重启会回滚。\n'
    '\n'
    '【默认 SIM 卡说明】\n'
    '  sim_select      : RSIM_only / ESIM1_only / ...\n'
    '  sim_select_num_type : ESIM1_only / ...\n'
    '  两个键要一起写，值由用户在界面上选择或输入。\n'
    '\n'
    '写回策略：**自动定位并写回原分区**。\n'
    '  * NVRO 字段：解开 nvrofs(JFFS2) → 改 nvroall.bin → 重打包 nvrofs\n'
    '  * NV cfg 键值：解开 userdata(JFFS2) → 改 nv/main/cfg 与 nv/backup/cfg → 重打包 userdata\n'
    '\n'
    '零外部依赖：JFFS2 读写全部由内嵌引擎完成。\n'
    '"""\n'
    '\n'
    'import os\n'
    'import base64\n'
    'import struct\n'
    '\n'
    '\n'
    '# ======================================================================\n'
    '#                            NVRO 字段定义\n'
    '# ======================================================================\n'
    "# (键, 偏移, 长度, 类型)  类型: 'imei' / 'str' / 'mac'\n"
    'NVRO_FIELDS = [\n'
    '    ("imei",   0x0000,  8, "imei"),\n'
    '    ("sn",     0x0028, 15, "str"),\n'
    '    ("mac",    0x007C,  6, "mac"),\n'
    '    ("mac2",   0x02C0,  6, "mac"),\n'
    ']\n'
    '\n'
    '# NV cfg（userdata/etc_rw/nv/main|backup/cfg）里的通用信息键\n'
    '#\n'
    '# 【密码】读取优先级：WPAPSK1（明文） → WPAPSK1_encode（base64） → Key1Str1（兜底）\n'
    '#         写入：WPAPSK1 + WPAPSK1_encode + m_WPAPSK1_encode 三处同步\n'
    'NVCFG_FIELDS = [\n'
    '    ("wifi_ssid",  "SSID1"),\n'
    '    ("wifi_key",   "WPAPSK1"),          # 仅用于「读取时优先查这个键」\n'
    '    ("sim_select", "sim_select"),\n'
    '    ("sw_version", "cr_version"),\n'
    '    ("hw_version", "hw_version"),\n'
    ']\n'
    '\n'
    '# WiFi 密码相关的所有键\n'
    'KEY_PLAIN = "WPAPSK1"                 # 明文密码\n'
    'KEY_B64 = "WPAPSK1_encode"            # base64 密码（真实生效）\n'
    'KEY_B64_M = "m_WPAPSK1_encode"        # 配套备份副本，必须同步\n'
    'KEY_LEGACY = "Key1Str1"               # 历史无用字段（恒为 12345）\n'
    '\n'
    '# SIM 卡相关键\n'
    'SIM_KEYS = ["sim_select", "sim_select_num_type"]\n'
    '\n'
    '# 内置 SIM 卡选项（用户可选择或自行输入）\n'
    'SIM_CHOICES = [\n'
    '    ("RSIM_only", "实体卡（RSIM）"),\n'
    '    ("ESIM1_only", "eSIM 1"),\n'
    '    ("ESIM2_only", "eSIM 2"),\n'
    '    ("ESIM3_only", "eSIM 3"),\n'
    '    ("ESIM4_only", "eSIM 4"),\n'
    ']\n'
    '\n'
    '\n'
    '# ======================================================================\n'
    '#                            IMEI 编解码\n'
    '# ======================================================================\n'
    'def luhn_ok(digits):\n'
    '    """验证 IMEI 的 Luhn 校验位。digits 为纯数字字符串（15 位）。"""\n'
    '    s = 0\n'
    '    for i, ch in enumerate(reversed(digits)):\n'
    '        try:\n'
    '            n = int(ch)\n'
    '        except ValueError:\n'
    '            return False\n'
    '        if i % 2 == 1:\n'
    '            n *= 2\n'
    '            if n > 9:\n'
    '                n -= 9\n'
    '        s += n\n'
    '    return s % 10 == 0\n'
    '\n'
    '\n'
    'def luhn_check_digit(first14):\n'
    '    """由前 14 位算出第 15 位校验位。"""\n'
    '    s = 0\n'
    '    for i, ch in enumerate(reversed(first14 + "0")):\n'
    '        n = int(ch)\n'
    '        if i % 2 == 1:\n'
    '            n *= 2\n'
    '            if n > 9:\n'
    '                n -= 9\n'
    '        s += n\n'
    '    return str((10 - s % 10) % 10)\n'
    '\n'
    '\n'
    'def decode_imei(raw8):\n'
    '    """8 字节 → 15 位 IMEI 字符串。低半字节在前，0xF 为填充。"""\n'
    '    d = ""\n'
    '    for c in raw8[:8]:\n'
    '        d += "%x%x" % (c & 0x0F, (c >> 4) & 0x0F)\n'
    '    return d.rstrip("fF")\n'
    '\n'
    '\n'
    'def encode_imei(imei15):\n'
    '    """15 位 IMEI 字符串 → 8 字节。"""\n'
    '    d = (imei15 or "").strip()\n'
    '    if not (d.isdigit() and len(d) == 15):\n'
    '        raise ValueError("IMEI 必须是 15 位数字，当前 %d 位" % len(d))\n'
    '    d += "F"\n'
    '    out = bytearray()\n'
    '    for i in range(0, 16, 2):\n'
    '        out.append((int(d[i + 1], 16) << 4) | int(d[i], 16))\n'
    '    return bytes(out)\n'
    '\n'
    '\n'
    '# ======================================================================\n'
    '#                            MAC 编解码\n'
    '# ======================================================================\n'
    'def decode_mac(raw6):\n'
    '    return ":".join("%02X" % c for c in raw6[:6])\n'
    '\n'
    '\n'
    'def encode_mac(text):\n'
    '    t = (text or "").strip().replace("-", ":").replace(".", ":")\n'
    '    parts = t.split(":")\n'
    '    if len(parts) == 1 and len(t) == 12:\n'
    '        parts = [t[i:i + 2] for i in range(0, 12, 2)]\n'
    '    if len(parts) != 6:\n'
    '        raise ValueError("MAC 应为 6 段，如 3C:68:04:26:B0:C3")\n'
    '    return bytes(int(p, 16) for p in parts)\n'
    '\n'
    '\n'
    '# ======================================================================\n'
    '#                          密码 base64 编解码\n'
    '# ======================================================================\n'
    'def encode_pwd_b64(text):\n'
    '    """明文字符串 → base64（与机型一致：标准 base64，无换行）。"""\n'
    '    return base64.b64encode((text or "").encode("utf-8")).decode("ascii")\n'
    '\n'
    '\n'
    'def decode_pwd_b64(text):\n'
    '    """base64 → 明文；解不出就原样返回。"""\n'
    '    t = (text or "").strip()\n'
    '    if not t:\n'
    '        return ""\n'
    '    try:\n'
    '        pad = "=" * (-len(t) % 4)\n'
    '        return base64.b64decode(t + pad).decode("utf-8")\n'
    '    except Exception:\n'
    '        return ""\n'
    '\n'
    '\n'
    '# ======================================================================\n'
    '#                            NV cfg 解析\n'
    '# ======================================================================\n'
    'def parse_nvcfg(blob):\n'
    '    # surrogateescape preserves non-UTF8 bytes and all empty NUL records.\n'
    "    return [list(part.decode('utf-8','surrogateescape').split('=',1)) if b'=' in part\n"
    "            else [part.decode('utf-8','surrogateescape'),None] for part in blob.split(b'\\0')]\n"
    '\n'
    '\n'
    '\n'
    'def build_nvcfg(items):\n'
    "    return b'\\0'.join((k if v is None else k+'='+v).encode('utf-8','surrogateescape') for k,v in items)\n"
    '\n'
    '\n'
    '\n'
    'def nvcfg_get(items, key):\n'
    '    for k, v in items:\n'
    '        if k.strip() == key and v is not None:\n'
    '            return v\n'
    '    return None\n'
    '\n'
    '\n'
    'def nvcfg_set(items, key, value, create=True):\n'
    '    """就地修改所有同名键；不存在则追加。返回命中次数。"""\n'
    '    hit = 0\n'
    '    for it in items:\n'
    '        if it[0].strip() == key and it[1] is not None:\n'
    '            it[1] = value\n'
    '            hit += 1\n'
    '    if hit == 0 and create:\n'
    '        items.append([key, value])\n'
    '        hit = 1\n'
    '    return hit\n'
    '\n'
    '\n'
    'def nvcfg_delete(items, key):\n'
    '    """删除指定键（用于清理错误的历史字段）。"""\n'
    '    out = [it for it in items\n'
    '           if not (it[0].strip() == key and it[1] is not None)]\n'
    '    removed = len(items) - len(out)\n'
    '    items[:] = out\n'
    '    return removed\n'
    '\n'
    '\n'
    '# ======================================================================\n'
    '#                       WiFi 密码 / SIM 读取辅助\n'
    '# ======================================================================\n'
    'def read_wifi_key(items):\n'
    '    """按优先级读 WiFi 密码，返回 (明文, 来源键)。\n'
    '\n'
    '    ① WPAPSK1（明文存在且非空）\n'
    '    ② WPAPSK1_encode（base64 解码）\n'
    '    ③ Key1Str1（兜底，多数机型是无效的 12345）\n'
    '    """\n'
    '    v = nvcfg_get(items, KEY_PLAIN)\n'
    '    if v:\n'
    '        return v, KEY_PLAIN\n'
    '    v = nvcfg_get(items, KEY_B64)\n'
    '    if v:\n'
    '        dec = decode_pwd_b64(v)\n'
    '        if dec:\n'
    '            return dec, KEY_B64\n'
    '    v = nvcfg_get(items, KEY_LEGACY)\n'
    '    if v:\n'
    '        return v, KEY_LEGACY\n'
    '    return "", ""\n'
    '\n'
    '\n'
    'def write_wifi_key(items, plain):\n'
    '    """写 WiFi 密码：三处同步（明文 + base64 + 备份副本）。"""\n'
    '    nvcfg_set(items, KEY_PLAIN, plain)\n'
    '    nvcfg_set(items, KEY_B64, encode_pwd_b64(plain))\n'
    '    nvcfg_set(items, KEY_B64_M, encode_pwd_b64(plain))\n'
    '\n'
    '\n'
    'def read_sim(items):\n'
    '    """返回 (sim_select, sim_select_num_type)。"""\n'
    '    return (nvcfg_get(items, SIM_KEYS[0]) or "",\n'
    '            nvcfg_get(items, SIM_KEYS[1]) or "")\n'
    '\n'
    '\n'
    'def write_sim(items, sim_select, sim_type=None):\n'
    '    """写默认 SIM：两个键一起写。sim_type 为空则用 sim_select 的值。"""\n'
    '    nvcfg_set(items, SIM_KEYS[0], sim_select)\n'
    '    nvcfg_set(items, SIM_KEYS[1], sim_type if sim_type else sim_select)\n'
    '\n'
    '\n'
    '# ======================================================================\n'
    '#                          固件信息读写\n'
    '# ======================================================================\n'
    'class FirmwareInfo(object):\n'
    '    """一个整机固件的「通用信息」读写封装。"""\n'
    '\n'
    '    def __init__(self, raw, parts, emit=None):\n'
    '        self.raw = raw\n'
    '        self.parts = parts\n'
    '        self.emit = emit or (lambda m: None)\n'
    '        self._nvcfg_items = None\n'
    '\n'
    '    # ---------- 分区定位 ----------\n'
    '    def _part(self, *names):\n'
    '        for p in self.parts:\n'
    '            if p.name in names:\n'
    '                return p\n'
    '        return None\n'
    '\n'
    '    def _blob(self, part):\n'
    '        return self.raw[part.offset:part.offset + part.size]\n'
    '\n'
    '    # ---------- 解出某个分区的目录 ----------\n'
    '    def _extract(self, part, J, tag):\n'
    '        import tempfile\n'
    '        tmp = _temp_dir(tag)\n'
    '        img = os.path.join(tmp, "p.img")\n'
    '        open(img, "wb").write(bytes(self._blob(part)))\n'
    '        out = os.path.join(tmp, "x")\n'
    '        try:\n'
    '            J.extract(img, out, emit=lambda m: None)\n'
    '            return tmp, out\n'
    '        except Exception:\n'
    '            import shutil\n'
    '            shutil.rmtree(tmp,ignore_errors=True)\n'
    '            raise\n'
    '\n'
    '    @staticmethod\n'
    '    def _find_file(root, names):\n'
    '        lows = {n.lower() for n in names}\n'
    '        for r, _d, fs in os.walk(root):\n'
    '            for f in fs:\n'
    '                if f.lower() in lows:\n'
    '                    return os.path.join(r, f)\n'
    '        return None\n'
    '\n'
    '    @staticmethod\n'
    '    def _find_cfgs(root):\n'
    '        """找所有 nv/*/cfg（main 优先）。"""\n'
    '        main, others = [], []\n'
    '        for r, _d, fs in os.walk(root):\n'
    '            if os.sep + "nv" + os.sep not in (r + os.sep):\n'
    '                continue\n'
    '            for f in fs:\n'
    '                if f == "cfg":\n'
    '                    p = os.path.join(r, f)\n'
    '                    (main if (os.sep + "main" + os.sep) in p else others).append(p)\n'
    '        return main + others\n'
    '\n'
    '    # ---------- 读 ----------\n'
    '    def read(self, J):\n'
    '        """返回通用信息 dict。"""\n'
    '        info = {}\n'
    '        # --- NVRO：IMEI / SN / MAC ---\n'
    '        nvro = self._part("nvrofs", "nvro", "nvram")\n'
    '        if nvro is not None:\n'
    '            import shutil\n'
    '            tmp = out = None\n'
    '            try:\n'
    '                tmp, out = self._extract(nvro, J, "_nvinfo_")\n'
    '                target = self._find_file(out, ["nvroall.bin"])\n'
    '                if target:\n'
    '                    b = open(target, "rb").read()\n'
    '                    for key, off, ln, kind in NVRO_FIELDS:\n'
    '                        chunk = b[off:off + ln]\n'
    '                        if kind == "imei":\n'
    '                            info[key] = decode_imei(chunk)\n'
    '                        elif kind == "mac":\n'
    '                            info[key] = decode_mac(chunk)\n'
    '                        else:\n'
    '                            info[key] = chunk.split(b"\\x00")[0].decode(\n'
    '                                "utf-8", "replace").strip()\n'
    '            except Exception as e:\n'
    '                self.emit("[!] 读取 NVRO 失败: %s" % e)\n'
    '            finally:\n'
    '                if tmp:\n'
    '                    shutil.rmtree(tmp, ignore_errors=True)\n'
    '\n'
    '        # --- NV cfg：WiFi / SIM / 版本 ---\n'
    '        ud = self._part("userdata", "user", "etc_rw")\n'
    '        if ud is not None:\n'
    '            import shutil\n'
    '            tmp = None\n'
    '            try:\n'
    '                tmp, out = self._extract(ud, J, "_nvcfg_")\n'
    '                cfgs = self._find_cfgs(out)\n'
    '                if cfgs:\n'
    '                    self._nvcfg_items = parse_nvcfg(open(cfgs[0], "rb").read())\n'
    '                    it = self._nvcfg_items\n'
    '                    info["wifi_ssid"] = nvcfg_get(it, "SSID1") or ""\n'
    '                    key, src = read_wifi_key(it)\n'
    '                    info["wifi_key"] = key\n'
    '                    info["_wifi_key_src"] = src\n'
    '                    s1, s2 = read_sim(it)\n'
    '                    info["sim_select"] = s1\n'
    '                    info["sim_select_num_type"] = s2\n'
    '                    info["sw_version"] = nvcfg_get(it, "cr_version") or ""\n'
    '                    info["hw_version"] = nvcfg_get(it, "hw_version") or ""\n'
    '            except Exception as e:\n'
    '                self.emit("[!] 读取 NV cfg 失败: %s" % e)\n'
    '            finally:\n'
    '                if tmp:\n'
    '                    shutil.rmtree(tmp, ignore_errors=True)\n'
    '        return info\n'
    '\n'
    '    # ---------- 写 ----------\n'
    '    def write(self, changes, J, P):\n'
    '        """changes = {"imei": "...", "wifi_key": "...", "sim_select": "...", ...}\n'
    '\n'
    '        返回 (new_raw, 已改分区名集合)。\n'
    '        """\n'
    '        for key,value in changes.items():\n'
    "            if any(c in str(value) for c in '\\0\\r\\n'):\n"
    "                raise ValueError('字段不能包含 NUL 或换行: '+key)\n"
    '        raw = bytearray(self.raw)\n'
    '        changed = set()\n'
    '        nvro_keys = {k for k, *_ in NVRO_FIELDS}\n'
    '        cfg_keys = {"wifi_ssid", "wifi_key", "sim_select", "sim_select_num_type",\n'
    '                    "sw_version", "hw_version"}\n'
    '\n'
    '        if any(k in changes for k in nvro_keys):\n'
    '            self._write_nvro(raw, changes, J, changed)\n'
    '        if any(k in changes for k in cfg_keys):\n'
    '            self._write_cfg(raw, changes, J, changed)\n'
    '        if not changed:\n'
    '            raise ValueError("没有任何分区应用了修改")\n'
    '        return bytes(raw), changed\n'
    '\n'
    '    def _write_nvro(self, raw, changes, J, changed):\n'
    '        import tempfile, shutil\n'
    '        nvro = self._part("nvrofs", "nvro", "nvram")\n'
    '        if nvro is None:\n'
    '            raise ValueError("固件里没有可写的 nvrofs 分区")\n'
    '        tmp = _temp_dir("_nvw_")\n'
    '        try:\n'
    '            img = os.path.join(tmp, "nvrofs.img")\n'
    '            open(img, "wb").write(bytes(raw[nvro.offset:nvro.offset + nvro.size]))\n'
    '            out = os.path.join(tmp, "x")\n'
    '            J.extract(img, out, emit=lambda m: None)\n'
    '            target = self._find_file(out, ["nvroall.bin"])\n'
    '            if not target:\n'
    '                raise ValueError("nvrofs 内未找到 nvroall.bin，未应用固定偏移写入")\n'
    '            b = bytearray(open(target, "rb").read())\n'
    '            for key, off, ln, kind in NVRO_FIELDS:\n'
    '                if key not in changes:\n'
    '                    continue\n'
    '                val = str(changes[key])\n'
    '                if off+ln>len(b):\n'
    "                    raise ValueError('nvroall.bin 长度不支持字段: '+key)\n"
    '                if kind == "imei":\n'
    '                    enc = encode_imei(val)\n'
    '                elif kind == "mac":\n'
    '                    enc = encode_mac(val)\n'
    '                else:\n'
    '                    if len(val.encode("utf-8"))>ln or "\\0" in val:\n'
    '                        raise ValueError("字段超过允许长度: "+key)\n'
    '                    enc = val.encode("utf-8").ljust(ln,b"\\0")\n'
    '                b[off:off + ln] = enc[:ln]\n'
    '            open(target, "wb").write(bytes(b))\n'
    '            newimg = os.path.join(tmp, "new_nvrofs.img")\n'
    '            J.pack(out, newimg, emit=lambda m: None, size=nvro.size)\n'
    '            blob = open(newimg, "rb").read()\n'
    '            raw[nvro.offset:nvro.offset + nvro.size] = \\\n'
    '                blob[:nvro.size].ljust(nvro.size, b"\\xff")\n'
    '            changed.add(nvro.name)\n'
    '            self.emit("[*] 已写回 %s（IMEI/SN/MAC）" % nvro.name)\n'
    '        finally:\n'
    '            shutil.rmtree(tmp, ignore_errors=True)\n'
    '\n'
    '    def _write_cfg(self, raw, changes, J, changed):\n'
    '        import tempfile, shutil\n'
    '        ud = self._part("userdata", "user", "etc_rw")\n'
    '        if ud is None:\n'
    '            raise ValueError("固件里没有可写的 userdata 分区")\n'
    '        tmp = _temp_dir("_cfgw_")\n'
    '        try:\n'
    '            img = os.path.join(tmp, "userdata.img")\n'
    '            open(img, "wb").write(bytes(raw[ud.offset:ud.offset + ud.size]))\n'
    '            out = os.path.join(tmp, "x")\n'
    '            J.extract(img, out, emit=lambda m: None)\n'
    '            cfgs = self._find_cfgs(out)\n'
    '            if not cfgs:\n'
    '                raise ValueError("userdata 内未找到 nv/*/cfg，未修改未知格式")\n'
    '            for cp in cfgs:\n'
    '                items = parse_nvcfg(open(cp, "rb").read())\n'
    '                if "wifi_ssid" in changes:\n'
    '                    nvcfg_set(items, "SSID1", str(changes["wifi_ssid"]))\n'
    '                if "wifi_key" in changes:\n'
    '                    write_wifi_key(items, str(changes["wifi_key"]))\n'
    '                if "sim_select" in changes:\n'
    '                    write_sim(items, str(changes["sim_select"]),\n'
    '                              changes.get("sim_select_num_type"))\n'
    '                if "sw_version" in changes:\n'
    '                    nvcfg_set(items, "cr_version", str(changes["sw_version"]))\n'
    '                if "hw_version" in changes:\n'
    '                    nvcfg_set(items, "hw_version", str(changes["hw_version"]))\n'
    '                open(cp, "wb").write(build_nvcfg(items))\n'
    '                self.emit("[*] 已更新 %s" % os.path.relpath(cp, out))\n'
    '            newimg = os.path.join(tmp, "new_userdata.img")\n'
    '            J.pack(out, newimg, emit=lambda m: None, size=ud.size)\n'
    '            blob = open(newimg, "rb").read()\n'
    '            raw[ud.offset:ud.offset + ud.size] = \\\n'
    '                blob[:ud.size].ljust(ud.size, b"\\xff")\n'
    '            changed.add(ud.name)\n'
    '            self.emit("[*] 已写回 %s（WiFi/SIM/版本）" % ud.name)\n'
    '        finally:\n'
    '            shutil.rmtree(tmp, ignore_errors=True)\n'
    '\n'
    '\n'
    'def _temp_dir(prefix):\n'
    '    import tempfile,sys\n'
    "    root = globals().get('TEMP_ROOT') or os.path.join(os.path.dirname(os.path.abspath(globals().get('__file__',sys.argv[0]))),'_fw_temp')\n"
    '    os.makedirs(root,exist_ok=True)\n'
    '    import uuid\n'
    '    path = os.path.join(root,prefix+uuid.uuid4().hex)\n'
    '    os.mkdir(path,0o777)\n'
    '    return path\n'
)


def load_module(name, embedded_src):
    """优先用内嵌源码；没有则从 _engine/<name>.py 读。"""
    import types
    mod = types.ModuleType(name)
    mod.__file__ = os.path.join(BASE_DIR, name+".py")
    if embedded_src:
        exec(compile(embedded_src, "<%s embedded>" % name, "exec"), mod.__dict__)
        return mod
    path = os.path.join(BASE_DIR, "_engine", name + ".py")
    if os.path.isfile(path):
        src = open(path, encoding="utf-8").read()
        exec(compile(src, path, "exec"), mod.__dict__)
        return mod
    raise ImportError("找不到引擎模块 %s" % name)


J = load_module("jffs2", JFFS2_SRC)
P = load_module("fwparts", FWPARTS_SRC)
SQ = load_module("squashfs", SQUASHFS_SRC)
INFO = load_module("fw_info", FWINFO_SRC)

def apply_extracted_metadata(outdir, perm_file, emit=None):
    """Restore POSIX metadata without following filesystem links outside the tree."""
    if os.name != 'posix':
        return dict(applied=0, links_created=0, missing=0)
    with open(os.path.join(outdir, perm_file), encoding='utf-8') as stream:
        entries = json.load(stream)['entries']
    root = os.path.abspath(outdir)
    if os.path.islink(root):
        raise ValueError('解包根目录不得为符号链接')
    plan = []
    for key, rec in entries.items():
        relative = key.lstrip('/')
        segments = relative.split('/') if relative else []
        if any(piece in ('', '.', '..') for piece in segments):
            raise ValueError('权限清单含不安全路径: '+key)
        path = os.path.join(root, *segments)
        parent = root
        for segment in segments[:-1]:
            parent = os.path.join(parent, segment)
            if os.path.islink(parent):
                raise ValueError('权限恢复路径穿过符号链接: '+key)
        mode = int(rec['mode'])
        link = rec.get('link', rec.get('target'))
        if os.path.lexists(path):
            actual = os.lstat(path)
            if stat.S_IFMT(actual.st_mode) != stat.S_IFMT(mode):
                if stat.S_ISREG(actual.st_mode) and not (stat.S_ISREG(mode) or stat.S_ISDIR(mode) or stat.S_ISLNK(mode)):
                    continue  # Special nodes remain represented by their manifest.
                raise ValueError('磁盘类型与权限清单不一致: '+key)
        plan.append((path, rec, mode, link))
    applied = created = missing = 0
    # Apply restrictive directory modes only after every descendant is processed.
    plan.sort(key=lambda item: (stat.S_ISDIR(item[2]), -item[0].count(os.sep)))
    for path, rec, mode, target in plan:
        if not os.path.lexists(path):
            if stat.S_ISLNK(mode) and target is not None and os.path.isdir(os.path.dirname(path)):
                os.symlink(target, path)
                created += 1
            else:
                missing += 1
                continue
        current = os.lstat(path)
        uid, gid = int(rec.get('uid', current.st_uid)), int(rec.get('gid', current.st_gid))
        try:
            if (current.st_uid, current.st_gid) != (uid, gid):
                os.chown(path, uid, gid, follow_symlinks=False)
            if not stat.S_ISLNK(mode):
                os.chmod(path, stat.S_IMODE(mode), follow_symlinks=False)
            if 'mtime' in rec:
                os.utime(path, (rec.get('atime', rec['mtime']), rec['mtime']), follow_symlinks=False)
        except OSError as error:
            raise OSError('恢复Linux权限失败 %s: %s' % (path, error)) from error
        applied += 1
    if emit:
        emit('[权限] Linux已恢复 %d 项，创建 %d 个符号链接，跳过 %d 个缺失条目' % (applied, created, missing))
    return dict(applied=applied, links_created=created, missing=missing)


def _posix_extractor(original, default_manifest):
    def extract(image, outdir, *args, **kwargs):
        result = original(image, outdir, *args, **kwargs)
        emit = kwargs.get('emit', args[0] if args else None)
        manifest = kwargs.get('perm_file', args[1] if len(args)>1 else default_manifest)
        apply_extracted_metadata(outdir, manifest, emit=emit)
        return result
    return extract


J.extract = _posix_extractor(J.extract, J.PERM_FILE)
SQ.unpack = _posix_extractor(SQ.unpack, SQ.PERM_FILE)


def firmware_output(firmware, requested):
    """Keep generated output within the selected firmware directory."""
    root = os.path.dirname(os.path.abspath(firmware))
    target = os.path.abspath(requested) if requested else root
    try:
        inside = os.path.commonpath([os.path.realpath(root), os.path.realpath(target)]) == os.path.realpath(root)
    except ValueError:
        inside = False
    if not inside:
        target = os.path.join(root, os.path.basename(target))
    if os.path.normcase(os.path.realpath(target)) == os.path.normcase(os.path.realpath(firmware)):
        raise ValueError("输出不得覆盖原始固件")
    return target


def fresh_unpack_directory(path):
    candidate, index = path, 1
    while os.path.exists(candidate) and (not os.path.isdir(candidate) or os.listdir(candidate)):
        candidate = path + "_%d" % index
        index += 1
    return candidate


def unpack_filesystem(image, output, emit=print):
    with open(image, 'rb') as stream:
        kind = P.detect_fs(stream.read())
    if kind == 'jffs2':
        return J.extract(image, output, emit=emit)
    if kind == 'squashfs':
        return SQ.unpack(image, output, emit=emit)
    raise ValueError('不支持文件级解包的格式: '+kind)


def pack_filesystem(source, output, size=None, emit=print, filesystem_output=None):
    sq = os.path.isfile(os.path.join(source, SQ.PERM_FILE))
    jf = os.path.isfile(os.path.join(source, J.PERM_FILE))
    if sq == jf:
        raise ValueError('源目录必须有一种明确的文件系统权限清单')
    if sq:
        return SQ.pack(source, output, emit=emit, size_limit=size, filesystem_output=filesystem_output)
    return J.pack(source, output, emit=emit, size=size)


def rootfs_partition(parts):
    candidates = [part for part in parts if part.name.lower() == 'rootfs']
    if not candidates and len(parts) == 1:
        candidates = list(parts)
    if len(candidates) != 1 or candidates[0].fstype not in ('jffs2', 'squashfs'):
        raise ValueError('未识别到唯一的 JFFS2/SquashFS rootfs 分区')
    return candidates[0]


def unpack_rootfs(firmware, output, emit=print):
    raw, parts, total = P.load_firmware(firmware, emit=emit)
    part = rootfs_partition(parts)
    image = os.path.abspath(output)+'.original.rootfs'
    P.atomic_write(image, raw[part.offset:part.offset+part.size])
    unpack_filesystem(image, output, emit=emit)
    context = dict(size=part.size, key=part.key, filesystem=part.fstype,
                   source=os.path.abspath(firmware), source_sha256=hashlib.sha256(raw).hexdigest())
    P.atomic_write(os.path.abspath(output)+'.zxw-context.json',
                   json.dumps(context, ensure_ascii=False, indent=2).encode('utf-8'))
    return output


def pack_rootfs(source, output, emit=print):
    context_path = os.path.abspath(source)+'.zxw-context.json'
    if not os.path.isfile(context_path):
        raise ValueError('缺少 rootfs 容量上下文，请先从原始固件解包')
    with open(context_path, encoding='utf-8') as stream:
        context = json.load(stream)
    return pack_filesystem(source, output, size=context['size'], emit=emit)


def write_rootfs(firmware, image, output, emit=print):
    if os.path.normcase(os.path.realpath(firmware)) == os.path.normcase(os.path.realpath(output)):
        raise ValueError('输出不得覆盖原始固件')
    raw, parts, total = P.load_firmware(firmware, emit=emit)
    part = rootfs_partition(parts)
    with open(image, 'rb') as stream:
        blob = stream.read()
    if P.detect_fs(blob) != part.fstype:
        raise ValueError('回写镜像文件系统与目标 rootfs 不一致')
    new = P.replace_partition(raw, part, blob)
    if new[:part.offset] != raw[:part.offset] or new[part.offset+part.size:] != raw[part.offset+part.size:]:
        raise ValueError('回写越出 rootfs 分区')
    P.atomic_write(output, new)
    return output


def cli_main(argv):
    """Headless commands; no Qt installation is required."""
    import argparse
    import tempfile
    ap = argparse.ArgumentParser(description='中兴微固件工具箱命令行')
    sub = ap.add_subparsers(dest='op',required=True)
    for op in ('inspect','split','join','unpack','pack','rootfs-unpack','rootfs-pack','rootfs-write'):
        cmd = sub.add_parser(op)
        cmd.add_argument('source')
        if op!='inspect':
            cmd.add_argument('output')
        if op=='rootfs-write':
            cmd.add_argument('--firmware',required=True)
        if op=='pack':
            cmd.add_argument('--size',type=lambda v:int(v,0))
    args = ap.parse_args(argv)
    try:
        if args.op=='rootfs-unpack':
            unpack_rootfs(args.source,args.output,emit=print)
        elif args.op=='rootfs-pack':
            pack_rootfs(args.source,args.output,emit=print)
        elif args.op=='rootfs-write':
            write_rootfs(args.firmware,args.source,args.output,emit=print)
        elif args.op=='inspect':
            raw,parts,total = P.load_firmware(args.source,emit=lambda _:None)
            print(json.dumps(dict(size=total,sha256=hashlib.sha256(raw).hexdigest(),
                    checksum=P.check_header_checksum(raw),partitions=[dict(key=p.key,
                    offset=p.offset,size=p.size,filesystem=p.fstype) for p in parts]),ensure_ascii=False,indent=2))
        elif args.op=='split':
            P.split_firmware(args.source,args.output,emit=print)
        elif args.op=='join':
            P.join_firmware(args.source,args.output,emit=print)
        elif args.op=='unpack':
            data = open(args.source,'rb').read()
            kind = P.detect_fs(data)
            if kind=='jffs2':
                J.extract(args.source,args.output,emit=print)
            elif kind=='squashfs':
                SQ.unpack(args.source,args.output,emit=print)
            else:
                raise ValueError('此格式仅支持原始拆分与合并: '+kind)
        elif args.op=='pack':
            sq = os.path.isfile(os.path.join(args.source,SQ.PERM_FILE))
            jf = os.path.isfile(os.path.join(args.source,J.PERM_FILE))
            if sq==jf:
                raise ValueError('源目录必须有一种明确的文件系统权限清单')
            if sq:
                SQ.pack(args.source,args.output,emit=print,size_limit=args.size)
            else:
                J.pack(args.source,args.output,emit=print,size=args.size)
        return 0
    except Exception as exc:
        print('错误: '+str(exc),file=sys.stderr)
        return 1


if __name__=='__main__' and len(sys.argv)>1 and sys.argv[1]=='--cli':
    sys.exit(cli_main(sys.argv[2:]))



# =====================================================================
#                            样式
# =====================================================================
# ★ 全界面统一字号：所有 font-size 最终都会被下面这行正则强制改写成 FONT_PX
FONT_PX = 12  # Fallback only; runtime reads the system caption font.
FONT_MONO_PX = FONT_PX  # Log text uses the same pixel size as every other control.

# 主色板
C_ACCENT = "#1a6fd4"      # 主色
C_ACCENT_D = "#155ab0"
C_ACCENT_L = "#eaf2fd"
C_BORDER = "#c9d0d9"
C_BORDER_L = "#dfe4ea"
C_PANEL = "#ffffff"
C_PAGE = "#f2f4f7"
C_TEXT = "#1f2329"
C_SUB = "#6b7280"

QSS = """
QWidget { background:%(page)s; color:%(text)s;
          font-family:'Microsoft YaHei UI','Microsoft YaHei','Segoe UI';
          font-size:15px; }
QLabel { font-size:15px; background:transparent; }
QGroupBox { border:1px solid %(bd)s; border-radius:10px; margin-top:20px;
            background:%(panel)s; font-weight:bold; }
QGroupBox::title { subcontrol-origin:margin; left:14px; padding:3px 12px;
                   color:%(accent)s; font-weight:bold; font-size:16px;
                   background:%(panel)s; border-radius:7px; }
QPushButton { background:%(panel)s; border:1px solid %(bd)s; border-radius:8px;
              padding:0 22px; font-size:15px; min-height:46px; }
QPushButton:hover { background:%(acl)s; border:1px solid #7aa9e8; }
QPushButton:pressed { background:#d8e6f8; }
QPushButton:disabled, QPushButton[accent="true"]:disabled, QPushButton[danger="true"]:disabled { background:#f0f0f0; color:#a8a8a8; border:1px solid #e0e0e0; }
QPushButton[accent="true"] { background:%(accent)s; color:#ffffff;
                             border:1px solid %(accentd)s; font-weight:bold; }
QPushButton[accent="true"]:hover { background:#2f7fdd; }
QPushButton[accent="true"]:pressed { background:%(accentd)s; }
QPushButton[danger="true"] { color:#c0392b; border:1px solid #e0b4ae; }
QPushButton[danger="true"]:hover { background:#fdf1ef; border:1px solid #d98878; }
QPushButton[big="true"] { padding:0 26px; font-size:17px; font-weight:bold;
                          min-height:58px; border-radius:10px; }
QPushButton:checked { background:%(accent)s; color:#ffffff;
                      border:1px solid %(accentd)s; font-weight:bold; }
QLineEdit, QComboBox, QTextEdit, QPlainTextEdit {
        background:%(panel)s; border:1px solid %(bd)s; border-radius:7px;
        padding:0 10px; font-size:15px;
        selection-background-color:#bcdcff; }
QLineEdit { min-height:40px; }
QComboBox { min-height:40px; }
QLineEdit:focus, QTextEdit:focus, QComboBox:focus, QPlainTextEdit:focus
        { border:1px solid #4a9bff; }
QComboBox::drop-down { border:none; width:26px; }
QComboBox QAbstractItemView { border:1px solid %(bd)s; background:#fff;
                              font-size:15px;
                              selection-background-color:%(acl)s; }
QTextEdit { font-family:'Cascadia Mono','Consolas','Microsoft YaHei UI'; }
QTableWidget { background:%(panel)s; alternate-background-color:#fafbfc;
               gridline-color:#e6e9ed; border:1px solid %(bd)s;
               border-radius:8px; font-size:15px; }
QHeaderView::section { background:#eef1f5; border:none;
                       border-right:1px solid #e2e6eb;
                       border-bottom:1px solid #e2e6eb;
                       padding:9px 10px; font-weight:bold; color:#374151;
                       font-size:15px; }
QSplitter::handle { background:%(bdl)s; }
QFrame#heightGrip { background:transparent; border:none; border-radius:6px; }
QFrame#heightGrip:hover { background:%(acl)s; }
QCheckBox { spacing:9px; font-size:15px; background:transparent; }
QCheckBox::indicator { width:19px; height:19px; border:1px solid #b0b6bd;
                       border-radius:4px; background:#fff; }
QCheckBox::indicator:checked { background:%(accent)s; border:1px solid %(accentd)s; }
QScrollArea { border:none; background:transparent; }
QScrollBar:vertical { background:transparent; width:14px; margin:2px; }
QScrollBar::handle:vertical { background:#c2c8d0; border-radius:7px; min-height:34px; }
QScrollBar::handle:vertical:hover { background:#a9b1bb; }
QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical { height:0; }
QScrollBar:horizontal { background:transparent; height:14px; margin:2px; }
QScrollBar::handle:horizontal { background:#c2c8d0; border-radius:7px; min-width:34px; }
QScrollBar::add-line:horizontal, QScrollBar::sub-line:horizontal { width:0; }
QToolTip { font-size:14px; }
QFrame[panelCard="true"] { background:%(panel)s; border:1px solid %(bd)s;
                           border-radius:10px; }
""" % {"page": C_PAGE, "panel": C_PANEL, "bd": C_BORDER, "bdl": C_BORDER_L,
       "accent": C_ACCENT, "accentd": C_ACCENT_D, "acl": C_ACCENT_L,
       "text": C_TEXT}
# ★ 统一字号：无论上面写了多少种 px，这里全部归一为 FONT_PX
QSS = re.sub(r"font-size:\s*\d+px", "font-size:%dpx" % FONT_PX, QSS)

COLOR = {"ok": "#0a7d2c", "err": "#c0392b", "warn": "#a15c00",
         "info": C_ACCENT, "step": "#6b3fa0", "cmd": "#006060",
         "dim": C_SUB, "text": C_TEXT}


def _esc(s):
    return (str(s).replace("&", "&amp;").replace("<", "&lt;")
            .replace(">", "&gt;"))


from PyQt5.QtCore import Qt, QThread, pyqtSignal, QSize, QUrl, QRect, QPoint, QTimer, QSettings
from PyQt5.QtGui import (QFont, QColor, QTextCursor, QIcon, QPixmap, QPainter, QPen, QPainterPath,
                         QDesktopServices, QTextOption, QFontDatabase, QKeySequence, QTextDocument)
from PyQt5.QtWidgets import (
    QApplication, QWidget, QMainWindow, QVBoxLayout, QHBoxLayout, QGridLayout,
    QFormLayout, QLabel, QLineEdit, QComboBox, QPushButton, QTextEdit,
    QTableWidget, QTableWidgetItem, QHeaderView, QAbstractItemView, QGroupBox,
    QCheckBox, QFileDialog, QMessageBox, QSplitter, QScrollArea, QFrame,
    QDialog, QDialogButtonBox, QPlainTextEdit, QSizePolicy, QToolButton,
    QInputDialog, QMenu, QAction, QLayout, QGridLayout as _QGridLayout)


# =====================================================================
#                            公共小件
# =====================================================================
def remember_file_dialog(kind, parent, title, initial='', filters=''):
    """各文件选择入口独立记忆目录，首次使用参考固件选择历史。"""
    settings = QSettings('ZXW', 'FirmwareToolbox')
    key = 'dialogs/%s/%s/directories' % (kind, title)
    history = settings.value(key, [], type=list)
    history = [path for path in history if isinstance(path, str) and os.path.isdir(path)]
    requested = os.path.abspath(initial) if initial else ''
    context = requested if os.path.isdir(requested) else os.path.dirname(requested) if requested else ''
    if not os.path.isdir(context) or os.path.normcase(context) == os.path.normcase(os.path.abspath(BASE_DIR)):
        context = ''
    firmware = settings.value('firmware/recent_directories', [], type=list)
    firmware = [path for path in firmware if isinstance(path, str) and os.path.isdir(path)]
    shared = settings.value('dialogs/last_directory', '', type=str)
    directory = (history[0] if history else context or
                 (firmware[0] if firmware else '') or
                 (shared if os.path.isdir(shared) else '') or BASE_DIR)
    location = directory
    if kind == 'save' and requested and not os.path.isdir(requested):
        location = os.path.join(directory, os.path.basename(requested))
    if kind == 'directory':
        result = QFileDialog.getExistingDirectory(parent, title, location)
        selected = result
    elif kind == 'open':
        result = QFileDialog.getOpenFileName(parent, title, location, filters)
        selected = result[0]
    elif kind == 'save':
        result = QFileDialog.getSaveFileName(parent, title, location, filters)
        selected = result[0]
    else:
        raise ValueError('未知文件选择类型')
    if selected:
        directory = os.path.abspath(selected if kind == 'directory' else os.path.dirname(selected))
        if os.path.isdir(directory):
            history = [directory] + [path for path in history
                                     if os.path.normcase(os.path.abspath(path)) != os.path.normcase(directory)]
            settings.setValue(key, history[:12])
            settings.setValue('dialogs/last_directory', directory)
            settings.sync()
    return result


class FlowLayout(QLayout):
    """Wrap action controls instead of forcing their parent wider than its viewport."""
    def __init__(self, parent=None):
        super().__init__(parent)
        self._items=[]
        self.setContentsMargins(0,0,0,0)
        self.setSpacing(10)

    def addItem(self,item):
        self._items.append(item)

    def count(self):
        return len(self._items)

    def itemAt(self,index):
        return self._items[index] if 0<=index<len(self._items) else None

    def takeAt(self,index):
        return self._items.pop(index) if 0<=index<len(self._items) else None

    def addStretch(self,*args):
        pass  # Wrapping rows use natural item widths; no empty expanding items.

    def expandingDirections(self):
        return Qt.Orientations(0)

    def hasHeightForWidth(self):
        return True

    def heightForWidth(self,width):
        return self._arrange(QRect(0,0,width,0),False)

    def minimumSize(self):
        size=QSize(0,0)
        for item in self._items:
            if not item.isEmpty():
                size=size.expandedTo(item.minimumSize())
        margins=self.contentsMargins()
        return size+QSize(margins.left()+margins.right(),margins.top()+margins.bottom())

    def sizeHint(self):
        return self.minimumSize()

    def setGeometry(self,rect):
        super().setGeometry(rect)
        self._arrange(rect,True)

    def _arrange(self,rect,apply):
        margins=self.contentsMargins()
        area=rect.adjusted(margins.left(),margins.top(),-margins.right(),-margins.bottom())
        x,y,line_height=area.x(),area.y(),0
        gap=max(0,self.spacing())
        for item in self._items:
            if item.isEmpty():
                continue
            size=item.sizeHint().expandedTo(item.minimumSize())
            if x>area.x() and x+size.width()>area.right()+1:
                x=area.x()
                y+=line_height+gap
                line_height=0
            if apply:
                item.setGeometry(QRect(QPoint(x,y),size))
            x+=size.width()+gap
            line_height=max(line_height,size.height())
        return y-area.y()+line_height+margins.top()+margins.bottom()


def _btn(text, cb, accent=False, danger=False, tip="", width=None, big=False):
    b = QPushButton(text)
    if width:
        b.setFixedWidth(width)
    if tip:
        b.setToolTip(tip)
    b.clicked.connect(cb)
    if accent:
        b.setProperty("accent", "true")
    if danger:
        b.setProperty("danger", "true")
    if big:
        b.setProperty("big", "true")
    return b


def _step(no,title,hint=""):
    w=QWidget()
    grid=QGridLayout(w)
    grid.setContentsMargins(0,2,0,2)
    grid.setHorizontalSpacing(10)
    grid.setVerticalSpacing(5)
    number=QLabel(str(no))
    diameter=max(28,number.fontMetrics().height()+4)
    number.setFixedSize(diameter,diameter)
    number.setAlignment(Qt.AlignCenter)
    number.setStyleSheet('background:%s;color:white;border-radius:%dpx;font-weight:bold;' % (C_ACCENT,diameter//2))
    heading=QLabel(title)
    heading.setWordWrap(True)
    heading.setProperty('role','sectionTitle')
    heading.setSizePolicy(QSizePolicy.Ignored,QSizePolicy.Preferred)
    grid.addWidget(number,0,0,Qt.AlignTop)
    grid.addWidget(heading,0,1)
    if hint:
        detail=_hint(hint)
        detail.setSizePolicy(QSizePolicy.Ignored,QSizePolicy.Preferred)
        grid.addWidget(detail,1,1)
    grid.setColumnStretch(1,1)
    return w



def _row(label,*widgets,**kw):
    w=QWidget()
    layout=QHBoxLayout(w)
    layout.setContentsMargins(0,0,0,0)
    layout.setSpacing(9)
    if label:
        caption=QLabel(label)
        caption.setMinimumWidth(max(kw.get('lw',100),caption.fontMetrics().horizontalAdvance(label)+8))
        caption.setAlignment(Qt.AlignRight|Qt.AlignVCenter)
        layout.addWidget(caption)
    for item in widgets:
        if isinstance(item,str):
            layout.addWidget(QLabel(item))
        elif isinstance(item,(QLineEdit,QComboBox)):
            item.setMinimumWidth(0)
            item.setSizePolicy(QSizePolicy.Expanding,QSizePolicy.Preferred)
            if isinstance(item,QLineEdit):
                helptext = item.toolTip()
                item.textChanged.connect(lambda value, edit=item, helptext=helptext:
                                         edit.setToolTip('\n'.join(part for part in (helptext, value) if part)))
                item.setToolTip('\n'.join(part for part in (helptext, item.text()) if part))
            layout.addWidget(item,1)
        else:
            layout.addWidget(item,0)
    return w



def _card(title, hint="", no=None):
    """单页集成用的卡片容器：返回 (外框, 内容布局)。"""
    box = QFrame()
    box.setProperty("panelCard", "true")
    v = QVBoxLayout(box)
    v.setContentsMargins(14, 12, 14, 14)
    v.setSpacing(10)
    if title:
        if no is not None:
            v.addWidget(_step(no, title, hint))
        else:
            lb = QLabel(title)
            lb.setProperty("role","sectionTitle")
            v.addWidget(lb)
    return box, v


def _hint(text):
    label=QLabel(text)
    label.setWordWrap(True)
    label.setProperty('role','hint')
    return label



def _fit_dialog(dialog):
    """Move real widgets into the scrolling body, keeping the footer outside."""
    if getattr(dialog, '_content_scroll', None) is not None:
        return
    explicit_size = dialog.testAttribute(Qt.WA_Resized)
    requested_size = dialog.size()
    layout = dialog.layout()
    body = QWidget()
    content = QVBoxLayout(body)
    content.setContentsMargins(4, 4, 8, 4)
    content.setSizeConstraint(QLayout.SetMinAndMaxSize)
    footer = []

    def reparent_layout(nested):
        for index in range(nested.count()):
            child = nested.itemAt(index)
            if child.widget() is not None:
                child.widget().setParent(body)
            elif child.layout() is not None:
                reparent_layout(child.layout())
        if isinstance(nested, QFormLayout):
            nested.setRowWrapPolicy(QFormLayout.WrapLongRows)
        nested.invalidate()

    while layout.count():
        stretch = layout.stretch(0) if isinstance(layout, (QVBoxLayout, QHBoxLayout)) else 0
        item = layout.takeAt(0)
        widget, nested = item.widget(), item.layout()
        if isinstance(widget, QDialogButtonBox):
            footer.append(widget)
        elif widget is not None:
            content.addWidget(widget, stretch)
        elif nested is not None:
            reparent_layout(nested)
            nested.setParent(None)
            content.addLayout(nested, stretch)
        else:
            content.addItem(item)
    scroll = QScrollArea(dialog)
    scroll.setWidgetResizable(True)
    scroll.setMinimumSize(0, 0)
    scroll.setFrameShape(QFrame.NoFrame)
    scroll.setWidget(body)
    layout.addWidget(scroll, 1)
    for widget in footer:
        layout.addWidget(widget)
        for role, text in ((QDialogButtonBox.Ok, '确定'), (QDialogButtonBox.Cancel, '取消')):
            button = widget.button(role)
            if button is not None:
                button.setText(text)
    dialog._content_scroll = scroll
    dialog._content_body = body
    screen = dialog.screen() or QApplication.primaryScreen()
    if screen is not None:
        area = screen.availableGeometry()
        max_width = max(280, area.width()-32)
        max_height = max(200, area.height()-64)
        content.activate()
        layout.activate()
        margins = layout.contentsMargins()
        spacing = max(0, layout.spacing())
        footer_height = sum(widget.sizeHint().height() for widget in footer)
        natural = content.sizeHint().expandedTo(content.minimumSize())
        scale = max(1.0, dialog.fontMetrics().height() / 20.0)
        title_width = dialog.fontMetrics().horizontalAdvance(dialog.windowTitle()) + 140
        width = max(round(520 * scale), natural.width() + margins.left() + margins.right() + 24,
                    title_width)
        height = natural.height() + footer_height + margins.top() + margins.bottom() + spacing + 24
        if explicit_size:
            width = max(width, requested_size.width())
            height = max(height, requested_size.height())
        dialog.setMinimumSize(min(round(340 * scale), max_width),
                              min(round(180 * scale), max_height))
        dialog.setMaximumSize(max_width, max_height)
        dialog.resize(min(width, max_width), min(height, max_height))


def _rows_height(t, n):
    """按「刚好显示 n 行」算一个表格高度（表头 + n 行 + 边框）。

    用在列表框默认高度上：以前是拍脑袋写的 230px，实际只露 4 行；
    这里按当前字体/行高实算，7 行就是 7 行，换主题/改字号也不会失真。
    """
    rh = max(24, int(t.verticalHeader().defaultSectionSize() or 30))
    try:
        hh = max(30, int(t.horizontalHeader().sizeHint().height()))
    except Exception:
        hh = 34
    return hh + rh * int(n) + 2 * t.frameWidth() + 4


class HeightGrip(QFrame):
    """表格底部的高度拖拽条（那条「⋯」）：上下拖动 = 把上方表格拉高/压矮。

    为什么不用 QSplitter：整页是「单页滚动」结构，页面高度由内容撑开，
    QSplitter 只能在固定框内重新分配、没法把页面撑高，拖动时会被布局打回。
    这里直接改表格的固定高度 —— 页面高度随之变化，滚动条自动适配，
    想拉多高就拉多高（上限 max_h）。
    """

    def __init__(self, target, default_h, min_h=110, max_h=2400,
                 auto_cb=None,
                 tip="上下拖动可调整上方表格高度；双击恢复默认高度"):
        QFrame.__init__(self)
        self.setObjectName("heightGrip")
        self.t = target
        self.default_h = int(default_h)
        self.min_h = int(min_h)
        self.max_h = int(max_h)
        self.auto_cb = auto_cb          # 双击时回调（分区表：回到「随分区数自适应」）
        self.auto = True                # 仍处于「默认/自适应」高度；拖过就变 False
        self.setFixedHeight(12)
        self.setCursor(Qt.SizeVerCursor)
        self.setToolTip(tip)
        lay = QHBoxLayout(self)
        lay.setContentsMargins(0, 0, 0, 0)
        lay.setSpacing(0)
        g = QLabel("⋯")
        g.setAlignment(Qt.AlignCenter)
        g.setToolTip(tip)
        lay.addWidget(g)
        self._y0 = None
        self._h0 = None

    # ---- 拖动 = 改高度 ----
    def begin_drag(self, y_global=None):
        """开始一次拖动（记下起点），测试可直接调用。"""
        self._y0 = 0 if y_global is None else int(y_global)
        self._h0 = self.t.height()

    def drag_to(self, dy):
        """把表格高度调整到「起始高度 + dy」（并夹在 min_h..max_h 之间）。"""
        if self._h0 is None:
            self.begin_drag()
        h = max(self.min_h, min(self.max_h, self._h0 + int(dy)))
        self.auto = False
        self.t.setFixedHeight(h)
        return h

    def reset(self):
        """恢复默认高度（分区表有 auto_cb 时回到「随分区数自适应」）。"""
        self.auto = True
        self._y0 = None
        if self.auto_cb is not None:
            self.auto_cb()
        else:
            self.t.setFixedHeight(self.default_h)

    def mousePressEvent(self, e):
        if e.button() == Qt.LeftButton:
            self.begin_drag(e.globalPos().y())
            e.accept()
            return
        QFrame.mousePressEvent(self, e)

    def mouseMoveEvent(self, e):
        if self._y0 is None:
            return
        self.drag_to(e.globalPos().y() - self._y0)
        e.accept()

    def mouseReleaseEvent(self, e):
        self._y0 = None
        e.accept()

    def mouseDoubleClickEvent(self, e):
        self.reset()
        e.accept()


class AutoFitTable(QTableWidget):
    """列宽「自动铺满 + 也能自由手拖」的表格。

    - 所有列都是 Interactive —— 拖列边界即可改宽窄；
    - 只要用户还没手动拖过，窗口尺寸一变就按 weights 重新铺满
      （不用拍脑袋写像素，不会出现一截空白或挤成一团）；
    - 用户一旦拖过某一列，之后就不再自动动他的列宽了。
    """

    def __init__(self, rows, cols, parent=None):
        QTableWidget.__init__(self, rows, cols, parent)
        self.weights = None
        self._user_resized = False
        self._fit_pending = False
        hh = self.horizontalHeader()
        hh.setSectionResizeMode(QHeaderView.Interactive)
        hh.setMinimumSectionSize(46)
        hh.sectionResized.connect(self._mark_user)
        self.setWordWrap(False)
        self.verticalHeader().setDefaultSectionSize(max(36,self.fontMetrics().height()+12))

    def fit_columns(self, weights):
        """登记各列宽度权重（比例即可），随后自动铺一次。"""
        self.weights = [float(x) for x in weights]
        self._do_fit()

    def _mark_user(self, *_a):
        self._user_resized = True

    def resizeEvent(self, e):
        QTableWidget.resizeEvent(self, e)
        if not self._user_resized:
            self._do_fit()

    def _do_fit(self):
        if not self.weights or self._user_resized:
            return
        header=self.horizontalHeader()
        minima=[]
        for column in range(self.columnCount()):
            item=self.horizontalHeaderItem(column)
            text=item.text() if item else ''
            minimum=max(46,header.fontMetrics().horizontalAdvance(text)+30)
            if text=='路径':
                minimum=max(minimum,150)
            else:
                for row in range(min(self.rowCount(),120)):
                    cell=self.item(row,column)
                    if cell is not None:
                        minimum=max(minimum,min(220,self.fontMetrics().horizontalAdvance(cell.text())+24))
            minima.append(minimum)
        available=max(0,self.viewport().width()-2)
        spare=max(0,available-sum(minima))
        total=sum(self.weights) or 1
        header.blockSignals(True)
        try:
            for column,weight in enumerate(self.weights[:self.columnCount()]):
                self.setColumnWidth(column,minima[column]+int(spare*weight/total))
        finally:
            header.blockSignals(False)

    def setItem(self,row,column,item):
        if item is not None and not item.toolTip():
            item.setToolTip(item.text())
        super().setItem(row,column,item)
        if not self._user_resized and not self._fit_pending:
            self._fit_pending=True
            QTimer.singleShot(0,self._fit_after_items)

    def _fit_after_items(self):
        self._fit_pending=False
        self._do_fit()

    def setHorizontalHeaderLabels(self,labels):
        super().setHorizontalHeaderLabels(labels)
        for column,text in enumerate(labels):
            item=self.horizontalHeaderItem(column)
            if item is not None:
                item.setToolTip(str(text))


class SafeCombo(QComboBox):
    """「滚轮安全」下拉框：鼠标滚轮扫过时不误改选中值。

    只有点开列表、或下拉框已获得焦点（正在键盘操作）时才响应滚轮；
    未聚焦时滚轮事件交还给父级（页面滚动），避免滑页面时把值滑跑。
    wheelSelectionEnabled=False 时，即使聚焦也禁止滚轮改变选中值。
    """

    def wheelEvent(self, e):
        if self.hasFocus() and self.property('wheelSelectionEnabled') is not False:
            QComboBox.wheelEvent(self, e)
        else:
            e.ignore()


def permstr_to_mode(s9):
    """'rwxrwxr-x' → 0o775。纯函数，不依赖引擎内部实现。"""
    s9 = (s9 or "").ljust(9, "-")[:9]
    v = 0
    for i, ch in enumerate(s9):
        if ch in "rwxst":
            v |= 1 << (8 - i)
        if ch in "sStT":
            v |= 0o4000 if i < 3 else (0o2000 if i < 6 else 0o1000)
    return v


def parse_perm(text):
    text = (text or "").strip()
    if not text:
        return None
    if re.fullmatch(r"[r-][w-][xsS-][r-][w-][xsS-][r-][w-][xtT-]", text):
        return permstr_to_mode(text)
    if re.fullmatch(r"[0-7]{3,4}", text):
        return int(text, 8) & 0o7777
    return None


def fmt_mode(mode):
    return "%04o" % stat.S_IMODE(mode)


def fmt_type(mode):
    return {stat.S_IFREG: "文件", stat.S_IFDIR: "目录", stat.S_IFLNK: "链接",
            stat.S_IFCHR: "字符设备", stat.S_IFBLK: "块设备",
            stat.S_IFIFO: "管道", stat.S_IFSOCK: "套接字"}.get(
                stat.S_IFMT(mode), "?")


def full_mode_of(e):
    """把权限清单记录归一化为完整 Unix 模式（类型位 | 权限位）。

    兼容三类历史写法：
      * mode 已含类型位（新格式）—— 原样返回；
      * mode 只有权限位 + type 描述（S_IF* 类型位，或旧式 1/2/3 基础编号）；
      * mode 只有权限位 + kind（"dir" / "file" / "symlink" / "special"）。
    """
    m = e.get("mode", 0) or 0
    t = stat.S_IFMT(m)
    if not t:
        ty = e.get("type")
        if isinstance(ty, int) and ty > 0:
            t = stat.S_IFMT(ty) or {1: stat.S_IFDIR, 2: stat.S_IFREG,
                                    3: stat.S_IFLNK, 4: stat.S_IFBLK,
                                    5: stat.S_IFCHR, 6: stat.S_IFIFO,
                                    7: stat.S_IFSOCK}.get(ty, 0)
        if not t:
            t = {"dir": stat.S_IFDIR, "file": stat.S_IFREG,
                 "symlink": stat.S_IFLNK}.get(e.get("kind") or "", 0)
        if not t:
            t = stat.S_IFREG
        m = t | (m & 0o7777)
    return m


# =====================================================================
#                          彩色日志面板
# =====================================================================
class LogPanel(QWidget):
    def __init__(self, title="日志", parent=None):
        QWidget.__init__(self, parent)
        self.lines = []
        v = QVBoxLayout(self)
        v.setContentsMargins(0, 0, 0, 0)
        gb = QGroupBox(title)
        gl = QVBoxLayout(gb)
        gl.setContentsMargins(8, 6, 8, 8)
        gl.setSpacing(6)
        self.txt = QTextEdit()
        self.txt.setReadOnly(True)
        self.txt.setLineWrapMode(QTextEdit.WidgetWidth)
        self.txt.setWordWrapMode(QTextOption.WrapAtWordBoundaryOrAnywhere)
        f = QFont("Cascadia Mono")
        f.setPixelSize(FONT_PX)
        if not f.exactMatch():
            f = QFont("Consolas")
            f.setPixelSize(FONT_PX)
        f.setStyleHint(QFont.Monospace)
        f.insertSubstitution("Cascadia Mono", "Microsoft YaHei UI")
        f.insertSubstitutions("Consolas", ["Microsoft YaHei UI"])
        self.txt.setFont(f)
        self.txt.setStyleSheet(
            "QTextEdit{background:#fbfcfd;border:1px solid #d4d8dd;"
            "border-radius:4px;font-size:%dpx;}" % FONT_PX)
        gl.addWidget(self.txt, 1)
        bar = FlowLayout()
        self.chk_auto = QCheckBox("自动滚动")
        self.chk_auto.setChecked(True)
        bar.addWidget(self.chk_auto)
        bar.addStretch(1)
        bar.addWidget(_btn("清空", self.clear))
        bar.addWidget(_btn("导出日志", self.export))
        gl.addLayout(bar)
        v.addWidget(gb)

    @staticmethod
    def _color_of(s):
        low = s.strip().lower()
        if low.startswith("=== "):
            return COLOR["step"]
        if low.startswith("[异常") or "失败" in s or low.startswith("[错误") \
                or low.startswith("[!]"):
            return COLOR["err"]
        if "成功" in s or "✔" in s or low.startswith("==>") \
                or low.startswith("[+]") or "一致" in s:
            return COLOR["ok"]
        if low.startswith(">") or low.startswith("$"):
            return COLOR["cmd"]
        if low.startswith("[*]") or "警告" in s:
            return COLOR["warn"]
        if low.startswith("[") or low.startswith("="):
            return COLOR["step"]
        return None

    def append(self,s=""):
        s=str(s)
        self.lines.append(s)
        log_path = getattr(self, "log_path", None)
        if log_path:
            try:
                with open(log_path, "a", encoding="utf-8") as stream:
                    stream.write(s+"\n")
            except OSError as error:
                self.txt.setToolTip("日志写入失败: "+str(error))
        color=self._color_of(s) or COLOR['text']
        scrollbar=self.txt.verticalScrollBar()
        previous=scrollbar.value()
        cursor=QTextCursor(self.txt.document())
        cursor.movePosition(QTextCursor.End)
        cursor.insertHtml('<span style="color:%s;white-space:pre-wrap">%s</span><br>' % (color,_esc(s)))
        if self.chk_auto.isChecked():
            self.txt.setTextCursor(cursor)
            self.txt.ensureCursorVisible()
        else:
            scrollbar.setValue(previous)


    __call__ = append

    def clear(self):
        self.txt.clear()
        self.lines = []

    def export(self):
        p, _f = remember_file_dialog('save', 
            self, "导出日志", os.path.join(getattr(self, "output_root", BASE_DIR), "固件工具日志.txt"),
            "文本文件 (*.txt);;所有文件 (*)")
        if not p:
            return
        try:
            root = getattr(self, "output_root", None)
            if not root:
                raise ValueError("请先选择固件")
            p = os.path.join(root, os.path.basename(p))
            with open(p, "w", encoding="utf-8") as f:
                f.write("\r\n".join(self.lines))
        except (OSError, ValueError) as e:
            QMessageBox.critical(self, "导出失败", str(e))


# =====================================================================
#                          后台工作线程
# =====================================================================
class Worker(QThread):
    sig_log = pyqtSignal(str)
    sig_done = pyqtSignal(int, str)

    def __init__(self, fn, title):
        QThread.__init__(self)
        self.fn = fn
        self.title = title

    def run(self):
        try:
            msg = self.fn(self.sig_log.emit) or "完成"
            self.sig_done.emit(0, str(msg))
        except Exception as e:
            tb = traceback.format_exc()
            try:
                self.sig_log.emit("[错误] %s" % e)
                self.sig_log.emit(tb)
            except Exception:
                pass
            print("[Worker %s 错误] %s\n%s" % (self.title, e, tb))
            try:
                self.sig_done.emit(1, str(e))
            except Exception:
                pass


# =====================================================================
#                     ① 通用信息 页
# =====================================================================
class InfoPage(QWidget):
    """读取/修改固件通用信息，改完另存为新固件。"""

    # (键, 标签, 提示, 控件类型)  控件: "text" / "sim"
    FIELDS = [
        ("imei",       "IMEI",           "15 位数字，末位为 Luhn 校验位", "text"),
        ("sn",         "SN 序列号",       "单板序列号，ASCII 最多 15 字节", "text"),
        ("mac",        "WiFi MAC (2.4G)", "6 段十六进制，如 3C:68:04:26:B0:C3", "text"),
        ("mac2",       "WiFi MAC (5G)",   "6 段十六进制", "text"),
        ("wifi_ssid",  "WiFi 名称",       "出厂默认 SSID（SSID1）", "text"),
        ("wifi_key",   "WiFi 密码",       "出厂默认密码，写入时同步 "
                                          "WPAPSK1 / WPAPSK1_encode / "
                                          "m_WPAPSK1_encode 三处", "text"),
        ("sim_select", "默认 SIM 卡",     "点开下拉选择；选「自定义…」可填任意值；"
                                          "写入时同步 sim_select + "
                                          "sim_select_num_type", "sim"),
        ("sw_version", "软件版本",         "cr_version", "text"),
        ("hw_version", "硬件版本",         "hw_version", "text"),
    ]

    def __init__(self, win):
        QWidget.__init__(self)
        self.win = win
        self.edits = {}
        self.original = {}
        self.raw = None
        self.parts = None
        self._sim_custom = ""        # 当前自定义 SIM 值（下拉里的「自定义」条目）
        self._sim_in_dialog = False  # 条目重排/弹框期间抑制信号
        v = QVBoxLayout(self)
        v.setContentsMargins(0, 0, 0, 0)
        v.setSpacing(6)
        v.addWidget(_step("·", "设备信息"))

        gb = QGroupBox("设备通用信息")
        f = QFormLayout(gb)
        f.setLabelAlignment(Qt.AlignRight)
        f.setFieldGrowthPolicy(QFormLayout.AllNonFixedFieldsGrow)
        f.setRowWrapPolicy(QFormLayout.WrapLongRows)
        f.setHorizontalSpacing(12)
        f.setVerticalSpacing(10)
        for key, label, tip, kind in self.FIELDS:
            if kind == "sim":
                e = self._make_sim_box(tip)
            else:
                e = QLineEdit()
                e.setPlaceholderText("（未读取）")
                e.setToolTip(tip)
                e.textChanged.connect(lambda value, edit=e, helptext=tip: edit.setToolTip(helptext+"\n"+value))
                e.setMinimumWidth(0)
                e.setSizePolicy(QSizePolicy.Expanding,QSizePolicy.Preferred)
            self.edits[key] = e
            row = QHBoxLayout()
            row.addWidget(e, 1)
            f.addRow(label, row)
        v.addWidget(gb)

        # IMEI / SIM 辅助
        imei_bar = FlowLayout()
        imei_bar.addWidget(_btn('生成带校验位的 IMEI', self.rand_imei))
        imei_bar.addWidget(_btn("用该 IMEI 生成 WiFi 名", self.gen_ssid))
        imei_bar.addWidget(_btn("恢复为读取值", self.restore))
        imei_bar.addStretch(1)
        v.addLayout(imei_bar)

        r = FlowLayout()
        r.addWidget(_btn("读取通用信息", self.read_info, accent=True, big=True))
        r.addWidget(_btn('另存修改后的固件', self.write_info, big=True))
        r.addStretch(1)
        v.addLayout(r)

        self.e_pdir = QLineEdit()
        self.e_pdir.setPlaceholderText('选择新的拆分目录，或载入含 partitions.json 的已有目录')

    # ---- SIM 下拉（点开即出选项；「自定义…」可填任意值）----
    def _make_sim_box(self, tip):
        cb = SafeCombo()
        cb.setProperty('wheelSelectionEnabled', False)
        cb.setEditable(False)                    # 点开即出下拉选项
        cb.setToolTip(tip)
        cb.setMinimumWidth(0)
        cb.setMinimumContentsLength(12)
        cb.setSizeAdjustPolicy(QComboBox.AdjustToMinimumContentsLengthWithIcon)
        cb.setSizePolicy(QSizePolicy.Expanding,QSizePolicy.Preferred)
        cb.setMaxVisibleItems(12)
        cb.addItem("（不修改）", "")             # 留空 = 不修改
        for val, name in INFO.SIM_CHOICES:
            cb.addItem("%s   （%s）" % (val, name), val)
        cb.addItem("自定义…", "__custom__")
        cb.currentIndexChanged.connect(self._on_sim_pick)
        cb.setCurrentIndex(0)
        return cb

    def _on_sim_pick(self, i):
        """选中「自定义…」时弹输入框；取消则退回上一个有效选项。"""
        cb = self.edits.get("sim_select")
        if cb is None or i < 0 or cb.itemData(i) != "__custom__":
            return
        if self._sim_in_dialog:                  # 条目重排触发的信号，忽略
            return
        self._sim_in_dialog = True
        try:
            txt, ok = QInputDialog.getText(
                self, "自定义 SIM 值",
                "输入 sim_select 值（写入时同步 sim_select_num_type）：",
                text=self._sim_custom or "")
            if ok and txt.strip():
                self._sim_set_custom(txt.strip())
            else:                                # 取消：回到之前的选项
                j = cb.findData(self._sim_custom) if self._sim_custom else 0
                cb.setCurrentIndex(j if j >= 0 else 0)
        finally:
            self._sim_in_dialog = False

    def _sim_set_custom(self, val):
        """插入/更新「自定义」条目并选中它（机型自带的自定义值也走这里）。"""
        cb = self.edits["sim_select"]
        was = self._sim_in_dialog
        self._sim_in_dialog = True               # 重排条目期间不弹对话框
        try:
            old = self._sim_custom
            if old and old != val:
                k = cb.findData(old)
                if k >= 0:
                    cb.removeItem(k)
            if val and cb.findData(val) < 0:
                pos = max(0, cb.count() - 1)     # 插在「自定义…」之前
                cb.insertItem(pos, "%s   （自定义）" % val, val)
            self._sim_custom = val or ""
            j = cb.findData(val) if val else 0
            cb.setCurrentIndex(j if j >= 0 else 0)
        finally:
            self._sim_in_dialog = was

    def _field_value(self, key):
        w = self.edits[key]
        if isinstance(w, QComboBox):
            d = w.currentData()
            return "" if d is None or d == "__custom__" else str(d)
        return w.text().strip()

    def _field_set(self, key, val):
        w = self.edits[key]
        val = "" if val is None else str(val)
        if isinstance(w, QComboBox):
            if not val:
                w.setCurrentIndex(0)             # （不修改）
            else:
                idx = w.findData(val)
                if idx >= 0:
                    w.setCurrentIndex(idx)
                else:
                    self._sim_set_custom(val)    # 机型自带的自定义值
        else:
            w.setText(val)
            w.setCursorPosition(0)
            w.setToolTip(val or next((tip for k,_,tip,_ in self.FIELDS if k==key),""))

    # ---- 数据装载 ----
    def set_firmware(self, raw, parts):
        self.raw = raw
        self.parts = parts
        self.original = {}
        for key, _l, _t, _k in self.FIELDS:
            self._field_set(key, "")
        if raw and parts:
            self.read_info()
        else:
            self._status("尚未载入固件。请先在顶部选择固件。")

    def _pick_pdir(self):
        d = remember_file_dialog('directory', self, "选择分区目录",
                                             self.e_pdir.text() or BASE_DIR)
        if d:
            self.e_pdir.setText(d)
            self.win.set_partition_dir(d)

    def do_split(self):
        if not self.win.fw_path:
            QMessageBox.warning(self, '提示', '请先选择整机固件；已有分区目录使用载入入口')
            return
        output = self.e_pdir.text().strip() or os.path.join(os.path.dirname(self.win.fw_path), '固件分区')
        try:
            output = self.win.output_path(output)
        except Exception as error:
            QMessageBox.warning(self,'拆分路径错误',str(error))
            return
        def job(emit):
            P.split_firmware(self.win.fw_path, output, emit=emit)
            return output
        self.win.run_job(job, '拆分整机固件', lambda rc,msg: self.win.load_partition_directory(output) if rc==0 else None)


    def do_join(self, directory=None):
        if not directory:
            if not self.win._workspace_loaded:
                QMessageBox.warning(self, '提示', '请先选择分区目录或载入已有分区工作区')
                return
            directory = self.win.partition_dir()
        directory = os.path.abspath(directory)
        try:
            with open(os.path.join(directory, 'partitions.json'), encoding='utf-8') as stream:
                meta = json.load(stream)
            protected = [os.path.join(directory, name) for name in ('partitions.json', '_layout.bin')]
            protected += [os.path.join(directory, record['key']) for record in meta['partitions']]
            if meta.get('source'):
                protected.append(meta['source'])
        except Exception as error:
            QMessageBox.warning(self, '分区目录错误', str(error))
            return
        output, _ = remember_file_dialog('save', self, '合并整机固件（另存）',
                                               os.path.join(directory, 'new_firmware.bin'),
                                               '固件 (*.bin);;所有文件 (*)')
        if not output:
            return
        try:
            output = self.win.output_path(output)
            if any(os.path.normcase(os.path.realpath(output)) == os.path.normcase(os.path.realpath(path))
                   for path in protected):
                raise ValueError('输出不得覆盖分区输入、原固件或工作区元数据')
        except Exception as error:
            QMessageBox.warning(self, '输出错误', str(error))
            return
        def job(emit):
            P.join_firmware(directory, output, emit=emit)
            with open(output, 'rb') as stream:
                P.check_header_checksum(stream.read(), emit=emit)
            return output
        self.win.run_job(job, '合并整机固件')


    def _status(self, s):
        self.win.log("[*] %s" % s)

    # ---- 读 ----
    def read_info(self):
        if not self.raw or not self.parts:
            QMessageBox.warning(self, "提示", '请先载入整机固件')
            return
        self.win.log("=== 读取通用信息 ===")
        try:
            info = INFO.FirmwareInfo(self.raw, self.parts,
                                     emit=self.win.log).read(J)
        except Exception as e:
            QMessageBox.critical(self, "读取失败", str(e))
            return
        for key, _l, _t, _k in self.FIELDS:
            val = info.get(key, "")
            if key == "sim_select" and not val:
                # 该机型没有 sim_select 键：不猜值，留空由用户选择/输入
                val = ""
            self._field_set(key, val)
            self.original[key] = str(val)
        src = info.get("_wifi_key_src") or "未读到"
        self.win.log("[+] 已读取 %d 个字段（WiFi 密码来源：%s）"
                     % (len(self.FIELDS), src))
        if not info.get("sim_select"):
            self.win.log("[*] 该固件未包含 sim_select 键，"
                         "可在「默认 SIM 卡」里自行选择或输入")

    def restore(self):
        for k, v in self.original.items():
            if k in self.edits:
                self._field_set(k, v)

    def rand_imei(self):
        import random
        # 中国 TAC 前缀 86 + 随机 12 位，再补校验位
        head = "86" + "".join(random.choice("0123456789") for _ in range(12))
        val = head + INFO.luhn_check_digit(head)
        self._field_set("imei", val)
        self.win.log("[*] 已生成随机 IMEI: %s" % val)

    def gen_ssid(self):
        """用当前 IMEI 生成一个不重复的 WiFi 名。"""
        imei = self._field_value("imei").strip()
        if len(imei) < 4 or not imei[-4:].isdigit():
            QMessageBox.information(self, "提示", "请先读取或填写一个 IMEI")
            return
        ssid = "BTWIFI-%s" % imei[-6:]
        self._field_set("wifi_ssid", ssid)
        self.win.log("[*] 已按 IMEI 生成 WiFi 名: %s" % ssid)

    # ---- 写 ----
    def write_info(self):
        if not self.raw or not self.parts:
            QMessageBox.warning(self, "提示", '请先载入整机固件')
            return
        changes = {}
        for key, label, _t, _k in self.FIELDS:
            new = self._field_value(key)
            old = self.original.get(key, "")
            if new != old:
                changes[key] = new
        if not changes:
            QMessageBox.information(self, "提示", "没有检测到任何改动")
            return
        # 校验
        if "imei" in changes:
            v = changes["imei"].strip()
            if not (v.isdigit() and len(v) == 15):
                QMessageBox.warning(self, "IMEI 格式错误", "IMEI 必须是 15 位数字")
                return
            if not INFO.luhn_ok(v):
                if QMessageBox.question(
                        self, "IMEI 校验位不正确",
                        "「%s」的 Luhn 校验位不通过，设备可能拒绝注册。\n"
                        "是否自动修正末位？" % v) == QMessageBox.Yes:
                    v = v[:14] + INFO.luhn_check_digit(v[:14])
                    self._field_set("imei", v)
                    changes["imei"] = v
        for key in ("mac", "mac2"):
            if key in changes:
                try:
                    INFO.encode_mac(changes[key])
                except Exception as e:
                    QMessageBox.warning(self, "MAC 格式错误", "%s: %s" % (key, e))
                    return

        dst, _f = remember_file_dialog('save', 
            self, "另存为新固件",
            os.path.join(self.win.fw_dir(), "new_firmware.bin"),
            "固件 (*.bin);;所有文件 (*)")
        if not dst:
            return
        dst = self.win.output_path(dst)
        self.win.log("=== 写回通用信息 ===")
        for k, v in changes.items():
            self.win.log("  %s: %s → %s" % (k, self.original.get(k, ""), v))

        def job(emit):
            fw = INFO.FirmwareInfo(self.raw, self.parts, emit=emit)
            new_raw, changed = fw.write(changes, J, P)
            self.win.output_path(dst)
            P.atomic_write(dst,new_raw)
            emit("[*] 已改分区: %s" % "、".join(sorted(changed)))
            emit("[+] 新固件: %s (%d 字节)" % (dst, len(new_raw)))
            return "已写出新固件 %s" % os.path.basename(dst)

        self.win.run_job(job, "写回通用信息",
                         lambda rc, msg: self._after_write(rc, msg, dst))

    def _after_write(self, rc, msg, dst):
        if rc == 0:
            # 重新载入新固件，刷新 UI
            self.win.load_firmware(dst, silent=True)
            QMessageBox.information(self, "完成",
                                    "已写出新固件：\n%s\n\n"
                                    "并已重新载入，可继续修改其它内容。" % dst)


# =====================================================================
#                     ② 解包 / 文件编辑 页
# =====================================================================
def read_partition_workspace(directory):
    directory = os.path.abspath(directory)
    with open(os.path.join(directory, 'partitions.json'), encoding='utf-8') as stream:
        meta = json.load(stream)
    total = meta.get('total', 0)
    if not isinstance(total, int) or not 0 < total <= 2*1024**3:
        raise ValueError('分区目录总长度无效')
    image = bytearray(b'\xff')*total
    ranges = []
    layout_path = os.path.join(directory, '_layout.bin')
    layout = open(layout_path, 'rb').read() if os.path.isfile(layout_path) else b''
    if meta.get('layout_sha256') and hashlib.sha256(layout).hexdigest() != meta['layout_sha256']:
        raise ValueError('布局保留数据校验失败')
    for gap in meta.get('gaps', []):
        offset, size, start = gap['offset'], gap['size'], gap['data_offset']
        if min(offset, size, start)<0 or offset+size>total or start+size>len(layout):
            raise ValueError('布局保留区越界')
        image[offset:offset+size] = layout[start:start+size]
        ranges.append((offset, offset+size))
    for record in meta['partitions']:
        key, offset, size = record['key'], record['offset'], record['size']
        if not re.fullmatch(r'[A-Za-z0-9_.-]+', key) or key in ('.','..') or size<=0 or offset<0 or offset+size>total:
            raise ValueError('非法分区记录: '+str(key))
        path = os.path.join(directory, key)
        if not os.path.isfile(path) or os.path.getsize(path)!=size:
            raise ValueError('分区缺失或长度不匹配: '+key)
        with open(path, 'rb') as stream:
            image[offset:offset+size] = stream.read()
        ranges.append((offset, offset+size))
    cursor = 0
    for start, end in sorted(ranges):
        if start != cursor:
            raise ValueError('分区目录存在空洞或重叠')
        cursor = end
    if cursor != total:
        raise ValueError('分区目录未覆盖整机长度')
    image = bytes(image)
    parts = P.parse_partition_table(image)
    if [(p.key,p.offset,p.size) for p in parts] != [(r['key'],r['offset'],r['size']) for r in meta['partitions']]:
        raise ValueError('分区文件中的布局与 partitions.json 不一致')
    return image, parts, meta


class PartitionWorkspacePage(QWidget):
    def __init__(self, win):
        super().__init__()
        self.win = win
        v = QVBoxLayout(self)
        v.setContentsMargins(0, 0, 0, 0)
        v.setSpacing(6)
        v.addWidget(_step(2, '拆分 / 继续已有分区工作区'))
        self.e_dir = win.p_info.e_pdir
        v.addWidget(_row('分区工作目录', self.e_dir, _btn('选择目录', self.pick_directory)))
        actions = FlowLayout()
        self.btn_split = _btn('拆分整机固件到此目录', win.p_info.do_split, accent=True)
        self.btn_split.setEnabled(False)
        actions.addWidget(self.btn_split)
        actions.addWidget(_btn('载入已有分区目录', self.load_existing))
        v.addLayout(actions)
        self.status = _hint('')
        self.status.hide()
        v.addWidget(self.status)

    def pick_directory(self):
        path = remember_file_dialog('directory', self, '选择分区工作目录', self.e_dir.text() or self.win.artifact_dir())
        if path:
            self.e_dir.setText(path)

    def load_existing(self):
        path = self.e_dir.text().strip()
        if not os.path.isfile(os.path.join(path, 'partitions.json')):
            path = remember_file_dialog('directory', self, '载入已有分区目录（含 partitions.json）', path or self.win.artifact_dir())
        if path:
            self.win.load_partition_directory(path)


class UnpackPage(QWidget):

    def __init__(self, win):
        QWidget.__init__(self)
        self.win = win
        self.dir = None
        self.entries = {}
        self.orig = {}
        self.abs_keys = False
        self.perm_file = SQ.PERM_FILE
        self.part_name = ""
        self.parts = []
        self.source_raw = None
        self.deleted = {}         # 被删除的原文件 {路径: 原始记录}（供变更清单）
        self._auto_out = ""       # 上一次自动联动的输出目录（用于判断是否被手改）
        v = QVBoxLayout(self)
        v.setContentsMargins(0, 0, 0, 0)
        v.setSpacing(6)
        v.addWidget(_step(3, "选择分区 → 解包 → 编辑文件"))

        inputs = FlowLayout()
        inputs.addWidget(_btn('打开独立分区镜像', self.win.pick_partition_image))
        inputs.addWidget(_btn('打开已解包文件目录', self.pick_unpacked))
        v.addLayout(inputs)
        # Select an actual partition, or open an independent image.
        self.tbl_parts = AutoFitTable(0, 7)
        self.tbl_parts.setHorizontalHeaderLabels(
            ["序号", "分区", "偏移", "大小(byte)", "大小(KB)", "文件系统", "说明"])
        # 列宽：首次铺满按权重分配，之后每列都能手动拖（AutoFitTable 已设 Interactive）
        self.tbl_parts.fit_columns([0.8, 1.2, 1.3, 1.7, 1.1, 1.2, 2.2])
        self.tbl_parts.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.tbl_parts.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.tbl_parts.setSelectionMode(QAbstractItemView.SingleSelection)
        self.tbl_parts.setAlternatingRowColors(True)
        self.tbl_parts.verticalHeader().setVisible(False)
        self.tbl_parts.itemSelectionChanged.connect(self._on_part_row)
        self.tbl_parts.setFixedHeight(_rows_height(self.tbl_parts, 2))
        v.addWidget(self.tbl_parts)
        # 高度拖拽条：上下拖动可把分区表拉高（双击 = 回到「随分区数自适应」）
        self.grip_parts = HeightGrip(self.tbl_parts,
                                     default_h=_rows_height(self.tbl_parts, 2),
                                     min_h=110, max_h=1400,
                                     auto_cb=self._auto_h_parts)
        v.addWidget(self.grip_parts)

        self.e_out = QLineEdit()
        self.e_out.setPlaceholderText(
            '默认保存到当前工作目录/分区目录/序号_分区名，可另选目录')
        v.addWidget(_row("分区解包目录", self.e_out,
                         _btn('浏览', lambda: self._pick_dir(self.e_out))))

        r = FlowLayout()
        r.setSpacing(10)
        self.btn_unpack = _btn('解包所选分区到文件目录', self.do_unpack, accent=True, big=True)
        self.btn_unpack.setEnabled(False)
        r.addWidget(self.btn_unpack)
        r.addWidget(_btn("重新载入当前文件目录", lambda: self.load_dir(), big=True))
        r.addStretch(1)
        v.addLayout(r)

        # 文件搜索：实时过滤下方文件表，只影响显示，不改磁盘/权限清单
        self.e_search = QLineEdit()
        self.e_search.setPlaceholderText(
            '搜索路径子串，如 rc / sbin / busybox；多个词用空格分隔（同时满足）')
        self.e_search.setToolTip(
            '不区分大小写，按路径中的连续子串匹配；多个词用空格分隔，需同时满足。\n'
            '例如 rc 只列出路径里真的含 rc 的文件；清空即显示全部。')
        self.e_search.setClearButtonEnabled(True)
        self.lbl_search = QLabel("")
        self.lbl_search.setProperty("role", "hint")
        sr = QHBoxLayout()
        sr.setContentsMargins(0, 0, 0, 0)
        sr.setSpacing(9)
        sr.addWidget(self.e_search, 1)
        sr.addWidget(self.lbl_search, 0)
        v.addLayout(sr)
        self.e_search.textChanged.connect(self._on_search)

        # 文件表
        self.tbl = AutoFitTable(0, 7)
        self.tbl.setHorizontalHeaderLabels(
            ["路径", "类型", "权限", "uid", "gid", "大小", "状态"])
        # 列宽：首次铺满（路径占大头），之后每列都能手动拖
        self.tbl.fit_columns([3.0, 0.85, 1.05, 0.66, 0.66, 0.95, 1.15])
        self.tbl.setEditTriggers(QAbstractItemView.EditKeyPressed)
        self.tbl.doubleClicked.connect(self._double_click)
        self.tbl.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.tbl.setSelectionMode(QAbstractItemView.ExtendedSelection)
        self.tbl.setAlternatingRowColors(True)
        self.tbl.verticalHeader().setVisible(False)
        self.tbl.itemChanged.connect(self.on_edit)
        self.tbl.setContextMenuPolicy(Qt.CustomContextMenu)
        self.tbl.customContextMenuRequested.connect(self._file_menu)
        # 默认高度 7 行
        self.tbl.setFixedHeight(_rows_height(self.tbl, 2))
        v.addWidget(self.tbl)
        # 高度拖拽条：想一次看 20 行就把它往下拖
        self.grip_files = HeightGrip(self.tbl,
                                     default_h=_rows_height(self.tbl, 2),
                                     min_h=110, max_h=3000,
                                     auto_cb=self._auto_h_files)
        v.addWidget(self.grip_files)

        tb = FlowLayout()
        tb.setSpacing(8)
        tb.addWidget(_btn('＋ 新增文件/目录', self.add_file, accent=True))
        tb.addWidget(_btn("删除选中", self.del_sel))
        for perm in (0o777, 0o700, 0o666, 0o644, 0o000):
            tb.addWidget(_btn("设 %04o" % perm, lambda _checked=False, perm=perm: self.quick(perm)))
        tb.addWidget(_btn('恢复权限/属主', self.restore, tip='恢复本次载入目录时的权限和属主；未选中时应用全部条目。文件内容与已删除文件需单独处理。'))
        tb.addStretch(1)
        v.addLayout(tb)

        # 变更清单（新增 / 删除 / 修改，单独成表，避免与完整列表混在一起）
        self.lbl_chg = QLabel("变更清单（新增 / 修改 / 删除）")
        self.lbl_chg.hide()
        self.tbl_chg = AutoFitTable(0, 4)
        self.tbl_chg.setHorizontalHeaderLabels(["路径", "变更", "类型", "详情"])
        # 列宽：首次铺满，之后每列都能手动拖
        self.tbl_chg.fit_columns([3.2, 0.8, 0.8, 2.2])
        self.tbl_chg.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.tbl_chg.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.tbl_chg.setSelectionMode(QAbstractItemView.ExtendedSelection)
        self.tbl_chg.setAlternatingRowColors(True)
        self.tbl_chg.verticalHeader().setVisible(False)
        self.tbl_chg.setFixedHeight(_rows_height(self.tbl_chg, 2))
        self.tbl_chg.doubleClicked.connect(self._jump_to_main)
        v.addWidget(self.tbl_chg)
        # 高度拖拽条：条目多时可拉高（默认 4 行）
        self.grip_chg = HeightGrip(self.tbl_chg,
                                   default_h=_rows_height(self.tbl_chg, 2),
                                   min_h=90, max_h=1600)
        v.addWidget(self.grip_chg)

    # ---- 分区下拉 ----
    def set_parts(self, parts, raw=None):
        """填分区表：序号 / 分区 / 偏移 / 大小 / 文件系统 / 解包目录名。"""
        self.parts = list(parts or [])
        self.source_raw = raw if raw is not None else self.win.raw
        raw = raw if raw is not None else (self.win.raw or b"")
        t = self.tbl_parts
        t.blockSignals(True)
        t.setRowCount(len(self.parts))
        for i, p in enumerate(self.parts):
            blob = raw[p.offset:p.offset + p.size] if raw else b""
            fs = P.detect_fs(blob, p.name) if blob else "?"
            vals = [str(i), p.name, str(p.offset), str(p.size),
                    str(p.size // 1024), fs, self._dir_name(p)]
            for c, v in enumerate(vals):
                it = QTableWidgetItem(v)
                if c != 6:
                    it.setTextAlignment(Qt.AlignCenter)
                t.setItem(i, c, it)
        t.blockSignals(False)
        # 高度自适应：所有分区一次看全（超出则表内滚动）
        self._auto_h_parts()
        if self.parts:
            # 默认选中 rootfs（最常用的分区）；找不到就退回第一行。
            # 选中后立刻走一次联动，输出目录跟着填成「固件同级/4_rootfs」
            row = 0
            for i, p in enumerate(self.parts):
                if p.name == "rootfs":
                    row = i
                    break
            t.selectRow(row)
            t.setCurrentCell(row, 0)
            self._on_part_row()

    def _auto_h_parts(self):
        """分区表高度自适应：分区全看全（超出表内滚动）。

        用户手动拖过高度后就不再自动改了（`grip_parts.auto` 为 False），
        避免重新解析固件时把用户拉好的高度打回去；双击拖拽条可恢复自适应。
        """
        g = getattr(self, "grip_parts", None)
        if g is not None and not g.auto:
            return
        n = max(1, len(self.parts))
        self.tbl_parts.setFixedHeight(
            min(_rows_height(self.tbl_parts, n), 480))

    def _on_part_row(self):
        """分区表点选联动：选中哪一行，就解包哪个分区。

        输出目录为空、或仍是上一次自动填的值 → 跟随换成
        「工作目录/分区目录/序号_分区名」（如 4_rootfs）；用户手改过的路径保持不动。
        """
        row = self.tbl_parts.currentRow()
        if row < 0 or row >= len(self.parts):
            return
        p = self.parts[row]
        self.part_name = p.key
        self.btn_unpack.setEnabled(p.fstype in ('jffs2','squashfs'))
        fwdir = self.win.fw_dir()
        if not fwdir:
            return
        new_auto = os.path.join(self.win.artifact_dir(), "分区目录", self._dir_name(p))
        cur = self.e_out.text().strip()
        if not cur or cur == self._auto_out:
            if cur != new_auto:
                self.e_out.setText(new_auto)
        self._auto_out = new_auto

    def _dir_name(self, part):
        """解包目录名 = <序号>_<分区名>（如 4_rootfs / 5_userdata），
        与拆分文件「4.rootfs / 5.userdata」同一命名体系，打包/回写时自动对上。
        part 可传 Partition 对象或分区名。"""
        name = getattr(part, "name", None) or str(part) or "unpack"
        parts = getattr(self.win, "parts", None) or []
        names = [x.name for x in parts]
        if name in names:
            return getattr(part, "key", "%d.%s" % (names.index(name),name)).replace(".", "_", 1)
        return name.replace(".", "_")

    def _pick_dir(self, edit):
        d = remember_file_dialog('directory', 
            self, "选择目录", edit.text() or BASE_DIR)
        if d:
            edit.setText(d)

    # ---- 解包 ----
    def do_unpack(self):
        if not self.source_raw:
            QMessageBox.warning(self, "提示", "请选择整机固件、分区目录或独立分区镜像")
            return
        row = self.tbl_parts.currentRow()
        if row < 0 or row >= len(self.parts):
            QMessageBox.warning(self, "提示", "请先在分区表里点选一个分区")
            return
        p = self.parts[row]
        out = self.e_out.text().strip() or os.path.join(
            self.win.artifact_dir() or BASE_DIR, "分区目录", self._dir_name(p))
        try:
            out = fresh_unpack_directory(self.win.output_path(out))
        except Exception as error:
            QMessageBox.warning(self,'解包路径错误',str(error))
            return
        self.e_out.setText(out)
        raw = self.source_raw

        def job(emit):
            blob = raw[p.offset:p.offset + p.size]
            emit("=== 解包 %s (%d 字节) ===" % (p.name, len(blob)))
            import tempfile
            fd, tmp = tempfile.mkstemp(prefix=".zxw-unpack-", suffix=".img", dir=self.win.artifact_dir())
            os.close(fd)
            with open(tmp, "wb") as f:
                f.write(blob)
            try:
                fs = P.detect_fs(blob, p.name)
                if fs == P.FS_SQUASHFS or SQ.is_squashfs(blob):
                    n = SQ.unpack(tmp, out, emit=emit)
                    emit("[*] squashfs 解包: %s" % n)
                elif fs == P.FS_JFFS2:
                    J.extract(tmp, out, emit=emit)
                else:
                    raise ValueError("此分区为 %s；支持原始拆分与无损合并，暂不支持文件级解包" % fs)
                emit("[+] 解包完成: %s" % out)
            finally:
                try:
                    os.remove(tmp)
                except OSError:
                    pass
            return "解包完成"

        self.win.run_job(job, "解包",
                         lambda rc, msg: self._after_unpack(rc, out))

    def _after_unpack(self, rc, out):
        if rc == 0:
            self.win.save_directory_binding(out, self.part_name)
            self.load_dir(out)

    # ---- 载入目录 ----
    def pick_unpacked(self):
        path = remember_file_dialog('directory', self, '打开已解包文件目录（含权限清单）', self.e_out.text() or self.win.artifact_dir())
        if path:
            self.load_dir(path)

    def load_dir(self, d=None):
        d = (d or self.e_out.text().strip())
        if not d or not os.path.isdir(d):
            QMessageBox.warning(self, "提示", "解包目录不存在")
            return
        if sum(os.path.isfile(os.path.join(d, name)) for name in (SQ.PERM_FILE, J.PERM_FILE)) != 1:
            QMessageBox.warning(self, '缺少权限清单', '请选择含 .perm.json 或 .squashfs.perm.json 的文件目录；分区目录请在上一步载入。')
            return
        self.e_out.setText(d)
        self.dir = d
        self.perm_file = None
        for name in (SQ.PERM_FILE, J.PERM_FILE):
            if os.path.isfile(os.path.join(d, name)):
                self.perm_file = name
                break
        self.entries = {}
        if self.perm_file:
            try:
                doc = json.load(open(os.path.join(d, self.perm_file),
                                     encoding="utf-8"))
                self.entries = doc.get("entries", doc)
            except Exception as e:
                self.win.log("[!] 清单读取失败: %s" % e)
        # 归一化 mode：统一成「完整模式（类型位|权限位）」，兼容三类历史清单
        # （mode 只有权限位 + type=1/2/3；mode 只有权限位 + type=S_IF*/kind；
        #   已含类型位的完整模式）。这样「类型」列与权限编辑都直接可用。
        _fixed = 0
        for _e in self.entries.values():
            if isinstance(_e, dict):
                _m0 = _e.get("mode", 0) or 0
                _m1 = full_mode_of(_e)
                if _m1 != _m0:
                    _e["mode"] = _m1
                    _fixed += 1
        if _fixed:
            self.win.log("[i] 已归一化 %d 条旧格式权限记录（补全类型位）"
                         % _fixed)
        self.abs_keys = any(str(k).startswith("/") for k in self.entries)
        # 补磁盘上清单外的条目
        perm_names = (SQ.PERM_FILE, J.PERM_FILE)
        for root, dirs, files in os.walk(d):
            for name in list(dirs) + list(files):
                rel = os.path.relpath(os.path.join(root, name), d).replace(os.sep, "/")
                if SQ.is_auxiliary(rel, perm_names):
                    continue
                key = ("/" + rel) if self.abs_keys else rel
                if key in self.entries:
                    continue
                full = os.path.join(root, name)
                isdir = os.path.isdir(full) and not os.path.islink(full)
                m = (stat.S_IFDIR | 0o755) if isdir else (stat.S_IFREG | 0o644)
                self.entries[key] = {"mode": m, "uid": 0, "gid": 0, "_new": True}
        self.orig = json.loads(json.dumps(self.entries))
        self.deleted = {}
        self.fill()
        self.win.log("[+] 已载入 %s（%d 条目%s）"
                     % (d, len(self.entries),
                        "，含清单" if self.perm_file else "，无清单"))
        self.win.set_last_unpack(d, self.win.directory_binding(d).get('key', ''))

    # ---- 文件搜索（只过滤显示，不动磁盘与权限清单）----
    def _search_terms(self):
        """搜索词：不区分大小写，空白分隔，多词同时满足（AND）。"""
        return [t.lower() for t in re.split(r"\s+", self.e_search.text().strip()) if t]

    def _visible_rows(self):
        """按路径中的连续子串过滤：rc 只命中路径里真的含 rc 的条目。"""
        rows = sorted(self.entries)
        terms = self._search_terms()
        if not terms:
            return rows
        return [rel for rel in rows if all(t in rel.lower() for t in terms)]

    def _on_search(self, _text):
        self.fill()

    def _select_rel(self, rel):
        """定位到文件表中某路径；若被搜索条件过滤，先清空搜索再定位。"""
        def find():
            for r in range(self.tbl.rowCount()):
                it = self.tbl.item(r, 0)
                if it is not None and it.text() == rel:
                    return r
            return -1
        row = find()
        if row < 0 and self._search_terms() and rel in self.entries:
            self.e_search.clear()
            row = find()
        if row >= 0:
            self.tbl.selectRow(row)
            self.tbl.scrollToItem(self.tbl.item(row, 0),
                                  QAbstractItemView.PositionAtCenter)
        return row

    def _auto_h_files(self):
        grip = getattr(self, 'grip_files', None)
        if grip is None or grip.auto:
            self.tbl.setFixedHeight(
                _rows_height(self.tbl, min(7, max(2, self.tbl.rowCount()))))

    def fill(self):
        self.tbl.blockSignals(True)
        rows = self._visible_rows()
        self.tbl.setRowCount(len(rows))
        for i, rel in enumerate(rows):
            e = self.entries[rel]
            mode = e.get("mode", 0)
            vals = [rel, fmt_type(mode), fmt_mode(mode), str(e.get("uid", 0)),
                    str(e.get("gid", 0)), self._size(rel),
                    "新增" if e.get("_new") else ""]
            for c, t in enumerate(vals):
                it = QTableWidgetItem(t)
                if c:
                    it.setTextAlignment(Qt.AlignCenter)
                if c == 2:
                    it.setForeground(QColor("#1565c0"))
                if e.get("_new"):
                    it.setForeground(QColor("#e65100"))
                if c in (0, 1, 5, 6):        # 路径/类型/大小/状态不可改
                    it.setFlags(it.flags() & ~Qt.ItemIsEditable)
                self.tbl.setItem(i, c, it)
        self.tbl.blockSignals(False)
        terms = self._search_terms()
        self.lbl_search.setText(
            ("匹配 %d / %d 条" % (len(rows), len(self.entries))) if terms
            else ("共 %d 条" % len(self.entries)))
        self._auto_h_files()
        self.fill_changes()

    # ---- 变更清单（新增 / 删除 / 修改）----
    CHG_COLOR = {"新增": "#e65100", "删除": "#c62828", "修改": "#1565c0"}

    def changes(self):
        """相对「解包初始状态」的全部变更：[(路径, 变更, mode, 详情), ...]。"""
        out = []
        for rel, o in sorted((self.deleted or {}).items()):
            out.append((rel, "删除", o.get("mode", 0),
                        "原权限 %s，已从磁盘与清单移除"
                        % fmt_mode(o.get("mode", 0))))
        for rel in sorted(self.entries):
            e = self.entries[rel]
            o = self.orig.get(rel)
            if e.get("_new") or o is None:
                out.append((rel, "新增", e.get("mode", 0),
                            "权限 %s" % fmt_mode(e.get("mode", 0))))
                continue
            d = []
            if (e.get("mode") or 0) != (o.get("mode") or 0):
                d.append("权限 %s→%s" % (fmt_mode(o.get("mode", 0)),
                                        fmt_mode(e.get("mode", 0))))
            if (e.get("uid") or 0) != (o.get("uid") or 0):
                d.append("uid %s→%s" % (o.get("uid", 0), e.get("uid", 0)))
            if (e.get("gid") or 0) != (o.get("gid") or 0):
                d.append("gid %s→%s" % (o.get("gid", 0), e.get("gid", 0)))
            if e.get("_edited_content"):
                d.append("内容已编辑")
            if d:
                out.append((rel, "修改", e.get("mode", 0), "；".join(d)))
        return out

    def fill_changes(self):
        """刷新变更清单表 + 数量统计标题。"""
        ch = self.changes()
        self.tbl_chg.blockSignals(True)
        self.tbl_chg.setRowCount(len(ch))
        for i, (rel, kind, mode, detail) in enumerate(ch):
            vals = [rel, kind, fmt_type(mode), detail]
            for c, t in enumerate(vals):
                it = QTableWidgetItem(t)
                if c in (1, 2):
                    it.setTextAlignment(Qt.AlignCenter)
                it.setForeground(QColor(self.CHG_COLOR.get(kind, "#666666")))
                self.tbl_chg.setItem(i, c, it)
        self.tbl_chg.blockSignals(False)
        self._auto_h_chg(ch)

    def _auto_h_chg(self, ch):
        """变更清单：刷新高度 + 标题计数。

        高度至少 4 行，条目多了自动长高（上限 480）；用户手动拖过高度后
        不再自动改（`grip_chg.auto` 为 False），双击拖拽条可恢复自动。
        """
        g = getattr(self, "grip_chg", None)
        if g is None or g.auto:
            self.tbl_chg.setFixedHeight(
                min(_rows_height(self.tbl_chg, max(2, len(ch))), 480))
        n_new = sum(1 for x in ch if x[1] == "新增")
        n_mod = sum(1 for x in ch if x[1] == "修改")
        n_del = sum(1 for x in ch if x[1] == "删除")
        self.lbl_chg.setText(
            "变更清单（新增 %d / 修改 %d / 删除 %d）——只列变更项，"
            "与上方完整列表分开显示" % (n_new, n_mod, n_del))

    def _jump_to_main(self, idx):
        """双击变更行 → 跳转定位到上方完整列表中的同一路径。"""
        try:
            rel = self.tbl_chg.item(idx.row(), 0).text()
        except Exception:
            return
        if rel not in self.entries:
            self.win.log("[i]「%s」是删除项（已不在列表/磁盘中）" % rel)
            return
        if self._select_rel(rel) < 0:
            self.win.log("[i]「%s」不在文件列表中" % rel)

    def _size(self, rel):
        if not self.dir:
            return "-"
        p = os.path.join(self.dir, rel.lstrip("/").replace("/", os.sep))
        try:
            if os.path.isdir(p) and not os.path.islink(p):
                return "<dir>"
            return str(os.path.getsize(p))
        except OSError:
            return "-"

    # ---- 编辑 ----
    def on_edit(self, item):
        if not self.dir:
            return
        col, row = item.column(), item.row()
        rel = self.tbl.item(row, 0).text()
        e = self.entries.get(rel)
        if e is None:
            return
        if col == 2:
            val = parse_perm(item.text())
            if val is None:
                QMessageBox.warning(self, "格式错误", "权限填 0755 / 755 / rwxr-xr-x")
                self.tbl.blockSignals(True)
                item.setText(fmt_mode(e.get("mode", 0)))
                self.tbl.blockSignals(False)
                return
            e["mode"] = stat.S_IFMT(e.get("mode", 0)) | val
            self.tbl.blockSignals(True)
            item.setText(fmt_mode(e["mode"]))
            self.tbl.blockSignals(False)
        elif col in (3, 4):
            try:
                val = int(item.text().strip())
                assert 0 <= val <= 65535
            except Exception:
                QMessageBox.warning(self, "格式错误", "uid/gid 必须是 0-65535")
                self.tbl.blockSignals(True)
                item.setText(str(e.get("uid" if col == 3 else "gid", 0)))
                self.tbl.blockSignals(False)
                return
            e["uid" if col == 3 else "gid"] = val
        self.save()
        self.fill_changes()

    def selected(self):
        return sorted(set(i.row() for i in self.tbl.selectedIndexes()))

    def quick(self, perm):
        rows = self.selected()
        if not rows:
            QMessageBox.information(self, "提示", "请先选中要改的行")
            return
        n = 0
        for r in rows:
            rel = self.tbl.item(r, 0).text()
            e = self.entries.get(rel)
            if e is not None:
                e["mode"] = stat.S_IFMT(e.get("mode", 0)) | perm
                n += 1
        self.save()
        self.fill()
        self.win.log("[*] 已把 %d 个条目设为 %04o" % (n, perm))

    def restore(self):
        # 未选中 = 全部条目（不受搜索过滤影响）；选中时只处理可见的选中行
        sels = self.selected()
        rels = ([self.tbl.item(r, 0).text() for r in sels]
                if sels else list(self.entries))
        n = 0
        for rel in rels:
            if rel in self.orig:
                keep = self.entries.get(rel, {}).get("_edited_content")
                self.entries[rel] = json.loads(json.dumps(self.orig[rel]))
                if keep:
                    self.entries[rel]["_edited_content"] = True
                n += 1
        self.save()
        self.fill()
        self.win.log("[*] 已恢复 %d 个条目的权限/属主" % n)

    # ---- 右键菜单（选中后编辑）----
    def _abs_of_rel(self, rel):
        return os.path.join(self.dir, rel.lstrip("/").replace("/", os.sep))

    def _build_file_menu(self):
        """构造文件列表右键菜单（单独一个方法，便于测试取 actions）。"""
        menu = QMenu(self)
        rows = self.selected()
        if not rows:
            menu.addAction('＋ 新增文件/目录', self.add_file)
            return menu
        menu.addAction('编辑文件内容', self.edit_content)
        menu.addAction("用系统程序打开", self.open_external)
        menu.addSeparator()
        menu.addAction('编辑权限 / 属主', self.edit_perm)
        menu.addAction('恢复权限/属主', self.restore)
        menu.addSeparator()
        menu.addAction('＋ 新增文件/目录', self.add_file)
        menu.addAction("删除选中", self.del_sel)
        return menu

    def _file_menu(self, pos):
        """右键：先选中光标所在行，再弹编辑菜单。"""
        idx = self.tbl.indexAt(pos)
        if idx.isValid() and idx.row() not in self.selected():
            self.tbl.selectRow(idx.row())
        menu = self._build_file_menu()
        menu.exec_(self.tbl.viewport().mapToGlobal(pos))

    def _double_click(self, idx):
        """双击任意单元格 = 修改权限 / 属主（弹窗，多选批量应用）。

        原来双击「路径」可以改路径字符串，但改完并不生效（无用功能），
        已改为弹「编辑权限 / 属主」对话框。
        """
        if idx.isValid() and idx.row() not in self.selected():
            self.tbl.selectRow(idx.row())
        self.edit_perm()

    def edit_content(self):
        """编辑选中文件的内容（文本，≤1MB；二进制走「用系统程序打开」）。"""
        if not self.dir:
            QMessageBox.warning(self, "提示", "请先解包或载入一个目录")
            return
        rows = self.selected()
        if not rows:
            return
        rel = self.tbl.item(rows[0], 0).text()
        e = self.entries.get(rel)
        if e is None:
            return
        fmt = stat.S_IFMT(e.get("mode", 0))
        if fmt == stat.S_IFDIR:
            QMessageBox.information(self, "提示", "这是目录，不能编辑内容")
            return
        if fmt == stat.S_IFLNK:
            QMessageBox.information(
                self, "提示", "这是符号链接（→ %s），不能编辑内容"
                % (e.get("target") or "?"))
            return
        p = self._abs_of_rel(rel)
        if not os.path.isfile(p):
            QMessageBox.warning(self, "提示", "磁盘上找不到该文件：\n%s" % p)
            return
        try:
            data = open(p, "rb").read()
        except OSError as ex:
            QMessageBox.critical(self, "读取失败", str(ex))
            return
        if len(data) > 1024 * 1024:
            QMessageBox.information(
                self, "提示", "文件较大（%d 字节），暂只支持 1 MB 以内的"
                "文本编辑" % len(data))
            return
        if b"\x00" in data[:4096]:
            QMessageBox.information(
                self, "提示", "疑似二进制文件，不支持文本编辑\n"
                "（可用「用系统程序打开」）")
            return
        dlg = EditFileDialog(self, rel, data)
        if dlg.exec_() != QDialog.Accepted:
            return
        new = dlg.result_bytes()
        try:
            with open(p, "wb") as f:
                f.write(new)
        except OSError as ex:
            QMessageBox.critical(self, "写入失败", str(ex))
            return
        e["_edited_content"] = True
        self.win.log("[+] 已编辑内容: %s（%d → %d 字节）"
                     % (rel, len(data), len(new)))
        self.fill()
        if rel in self.entries:
            self._select_rel(rel)

    def open_external(self):
        """用系统默认程序打开选中文件（编辑脚本/查看二进制用）。"""
        if not self.dir:
            return
        rows = self.selected()
        if not rows:
            return
        rel = self.tbl.item(rows[0], 0).text()
        p = self._abs_of_rel(rel)
        if not os.path.exists(p):
            QMessageBox.warning(self, "提示", "磁盘上找不到该文件：\n%s" % p)
            return
        QDesktopServices.openUrl(QUrl.fromLocalFile(p))
        self.win.log("[i] 已交给系统程序打开: %s" % p)

    def edit_perm(self):
        """弹窗编辑选中条目的 权限/uid/gid（多选批量应用）。"""
        rows = self.selected()
        if not rows:
            return
        rel0 = self.tbl.item(rows[0], 0).text()
        dlg = EditPermDialog(self, rel0, self.entries.get(rel0, {}))
        if dlg.exec_() != QDialog.Accepted:
            return
        perm, uid, gid = dlg.result_info()
        n = 0
        for r in rows:
            rel = self.tbl.item(r, 0).text()
            e = self.entries.get(rel)
            if e is None:
                continue
            e["mode"] = stat.S_IFMT(e.get("mode", 0)) | perm
            e["uid"], e["gid"] = uid, gid
            n += 1
        self.save()
        self.fill()
        self.win.log("[*] 已编辑 %d 个条目的权限/属主（%04o uid=%d gid=%d）"
                     % (n, perm, uid, gid))

    # ---- 增 / 删 ----
    def add_file(self):
        if not self.dir:
            QMessageBox.warning(self, "提示", "请先解包或载入一个目录")
            return
        dlg = NewFileDialog(self, self.dir)
        if dlg.exec_() != QDialog.Accepted or not dlg.result_info:
            return
        info = dlg.result_info
        rel = info["rel"]
        key = ("/" + rel) if self.abs_keys else rel
        target = os.path.join(self.dir, rel.replace("/", os.sep))
        try:
            os.makedirs(os.path.dirname(target) or ".", exist_ok=True)
            if info.get("src"):
                data = open(info["src"], "rb").read()
            elif info.get("is_dir"):
                os.makedirs(target, exist_ok=True)
                data = None
            else:
                data = (info.get("content") or "").encode("utf-8")
            if data is not None:
                if info.get("lf") and b"\r\n" in data:
                    data = data.replace(b"\r\n", b"\n")
                open(target, "wb").write(data)
        except OSError as e:
            QMessageBox.critical(self, "写入失败", str(e))
            return
        previous = self.entries.get(key) or self.orig.get(key) or {}
        record = {field: previous[field] for field in ('mtime', 'atime', 'ctime', 'inode')
                  if field in previous}
        is_new = key not in self.orig or bool(self.orig.get(key, {}).get('_new'))
        record.update(mode=info['mode'], uid=info['uid'], gid=info['gid'], _new=is_new)
        if not is_new:
            record['_edited_content'] = True
        self.entries[key] = record
        self.deleted.pop(key, None)
        self.save()
        self.fill()
        self.win.log("[+] 新增 %s  权限 %s" % (key, fmt_mode(info["mode"])))

    def del_sel(self):
        rows = self.selected()
        if not rows:
            return
        names = [self.tbl.item(r, 0).text() for r in rows]
        if QMessageBox.question(
                self, "确认删除",
                "将从磁盘和清单里删除以下 %d 个条目：\n\n%s\n\n继续？"
                % (len(names), "\n".join(names[:20]) +
                   ("\n..." if len(names) > 20 else ""))) != QMessageBox.Yes:
            return
        removed = 0
        for rel in names:
            if rel not in self.entries:
                continue
            if not rel.strip('/'):
                self.win.log('[!] 请选中根目录下的文件或子目录进行删除')
                continue
            path = self._abs_of_rel(rel)
            prefix = rel.rstrip('/') + '/'
            descendants = [key for key in self.entries if key == rel or key.startswith(prefix)]
            try:
                if os.path.isdir(path) and not os.path.islink(path):
                    shutil.rmtree(path)
                elif os.path.lexists(path):
                    os.remove(path)
            except OSError as error:
                self.win.log('  [!] 删除失败 %s: %s' % (rel, error))
                continue
            for key in descendants:
                self.entries.pop(key, None)
                if key in self.orig:
                    self.deleted[key] = self.orig[key]
                removed += 1
        self.save()
        self.fill()
        self.win.log('[*] 已删除 %d 个条目' % removed)

    def save(self):
        if not self.dir or not self.perm_file:
            return
        data = {}
        for rel, e in self.entries.items():
            rec = {"mode": e.get("mode", 0), "uid": e.get("uid", 0),
                   "gid": e.get("gid", 0)}
            for k in ("mtime", "atime", "ctime", "link", "special", "rdev",
                      "target", "data_b64", "type", "kind", "inode"):
                if k in e:
                    rec[k] = e[k]
            data[rel] = rec
        manifest_path = os.path.join(self.dir,self.perm_file)
        doc = json.load(open(manifest_path,encoding='utf-8')) if os.path.isfile(manifest_path) else {}
        doc.update({'_source':os.path.basename(self.dir),'entries':data})
        try:
            with open(os.path.join(self.dir, self.perm_file), "w",
                      encoding="utf-8") as f:
                json.dump(doc, f, indent=1, ensure_ascii=False)
        except OSError as e:
            QMessageBox.critical(self, "保存失败", str(e))

    # ---- 供 ③ 调用 ----
    def current_dir(self):
        return self.dir

    def current_part_name(self):
        return self.part_name or ""


# =====================================================================
#                     ②b 新增文件对话框（目录映射表）
# =====================================================================
class NewFileDialog(QDialog):
    def __init__(self, parent, root_dir):
        QDialog.__init__(self, parent)
        self.setWindowTitle('新增文件 / 目录并指定权限')
        self.resize(720, 600)
        self.root_dir = root_dir
        self.result_info = None
        v = QVBoxLayout(self)
        f = QFormLayout()

        h = QHBoxLayout()
        self.e_src = QLineEdit()
        h.addWidget(self.e_src, 1)
        h.addWidget(_btn("选择本地文件", self.pick))
        f.addRow("本地文件", h)

        # 目录映射表
        self.tbl = QTableWidget(0, 3)
        self.tbl.setHorizontalHeaderLabels(["包内目录", "文件数", "大小"])
        hd = self.tbl.horizontalHeader()
        hd.setSectionResizeMode(0, QHeaderView.Stretch)
        hd.setSectionResizeMode(1, QHeaderView.Interactive)
        hd.setSectionResizeMode(2, QHeaderView.Interactive)
        self.tbl.setColumnWidth(1, 80)
        self.tbl.setColumnWidth(2, 96)
        self.tbl.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.tbl.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.tbl.setSelectionMode(QAbstractItemView.SingleSelection)
        self.tbl.setAlternatingRowColors(True)
        self.tbl.verticalHeader().setVisible(False)
        self.tbl.setMinimumHeight(200)
        f.addRow("包内目录", QLabel("点击选择目标目录（也可直接在下面改路径）"))
        f.addRow("", self.tbl)

        hp = QHBoxLayout()
        self.e_dir = QLineEdit("/")
        self.e_dir.setPlaceholderText("包内目录，如 /sbin/")
        self.e_name = QLineEdit()
        self.e_name.setPlaceholderText('文件或目录名，如 mytool.sh')
        hp.addWidget(self.e_dir, 2)
        hp.addWidget(self.e_name, 1)
        f.addRow("包内路径", hp)

        self.lbl = QLabel("")
        self.lbl.setProperty("role","hint")
        self.lbl.setWordWrap(True)
        f.addRow("", self.lbl)
        self.tbl.itemSelectionChanged.connect(self._pick_dir)
        self.e_dir.textChanged.connect(lambda _t: self._refresh())
        self.e_name.textChanged.connect(lambda _t: self._refresh())

        hm = QHBoxLayout()
        self.e_mode = QLineEdit("0755")
        self.e_mode.setMaximumWidth(90)
        pr = SafeCombo()
        self.perm_preset = pr
        for t in ("0755 可执行", "0644 普通文件", "0600 仅属主", "0755 新建目录"):
            pr.addItem(t, "directory" if t == "0755 新建目录" else "file")
        pr.currentTextChanged.connect(lambda t: self.e_mode.setText(t.split()[0]))
        hm.addWidget(self.e_mode)
        hm.addWidget(pr)
        hm.addStretch(1)
        f.addRow("权限", hm)

        ho = QHBoxLayout()
        self.e_uid = QLineEdit("0")
        self.e_uid.setMaximumWidth(90)
        self.e_gid = QLineEdit("0")
        self.e_gid.setMaximumWidth(90)
        ho.addWidget(QLabel("uid"))
        ho.addWidget(self.e_uid)
        ho.addWidget(QLabel("gid"))
        ho.addWidget(self.e_gid)
        ho.addStretch(1)
        f.addRow("属主", ho)
        v.addLayout(f)

        v.addWidget(QLabel('未选择本地文件时，使用以下文本（留空生成空文件）：'))
        self.e_txt = QPlainTextEdit()
        self.e_txt.setMaximumHeight(90)
        v.addWidget(self.e_txt)
        self.chk_lf = QCheckBox('写入时将 CRLF 转为 LF（导入本地文件也适用）')
        self.chk_lf.setChecked(True)
        v.addWidget(self.chk_lf)

        bb = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        bb.accepted.connect(self.ok)
        bb.rejected.connect(self.reject)
        v.addWidget(bb)
        self._fill_dirs()
        self._refresh()
        _fit_dialog(self)

    def _fill_dirs(self):
        rows = []
        try:
            for dp, dns, _f in os.walk(self.root_dir):
                dns.sort()
                rel = os.path.relpath(dp, self.root_dir).replace("\\", "/")
                segs = [s for s in rel.split("/") if s and s != "."]
                if any(s in (".git", ".svn", "__pycache__") for s in segs):
                    dns[:] = []
                    continue
                disp = "/" + "/".join(segs) + "/" if segs else "/"
                nfile = nsize = 0
                try:
                    for nm in os.listdir(dp):
                        fp = os.path.join(dp, nm)
                        if os.path.isfile(fp) and not os.path.islink(fp):
                            nfile += 1
                            try:
                                nsize += os.path.getsize(fp)
                            except OSError:
                                pass
                except OSError:
                    pass
                rows.append((disp, nfile, nsize))
        except Exception:
            pass
        rows.sort(key=lambda x: x[0])
        self.tbl.setRowCount(len(rows))
        for i, (disp, nf, ns) in enumerate(rows):
            for c, t in enumerate([disp, str(nf), self._hs(ns)]):
                it = QTableWidgetItem(t)
                if c:
                    it.setTextAlignment(Qt.AlignCenter)
                it.setData(Qt.UserRole, disp)
                self.tbl.setItem(i, c, it)
        if rows:
            self.tbl.selectRow(0)

    @staticmethod
    def _hs(n):
        for u in ("B", "K", "M", "G"):
            if n < 1024 or u == "G":
                return "%d%s" % (n, u) if u == "B" else "%.1f%s" % (n, u)
            n /= 1024.0
        return str(n)

    def _pick_dir(self):
        it = self.tbl.item(self.tbl.currentRow(), 0)
        if it is None:
            return
        self.e_dir.setText(it.data(Qt.UserRole) or it.text())

    def _rel(self):
        d = (self.e_dir.text() or "").strip().replace("\\", "/")
        nm = self.e_name.text().strip().replace("\\", "/").lstrip("/")
        if d in ("", "/"):
            return nm
        return d.strip("/") + "/" + nm if nm else d.strip("/")

    def _refresh(self):
        rel = self._rel()
        self.lbl.setText("完整包内路径: /%s" % rel if rel
                         else "完整包内路径: （请选择父目录并填写名称）")

    def pick(self):
        x, _f = remember_file_dialog('open', self, "选择本地文件", "", "所有 (*.*)")
        if x:
            self.e_src.setText(x)
            if not self.e_name.text().strip():
                self.e_name.setText(os.path.basename(x))

    def ok(self):
        rel = self._rel().replace("\\", "/").lstrip("/")
        if not rel:
            QMessageBox.warning(self, "提示", "请选择父目录并填写文件或目录名")
            return
        mode = parse_perm(self.e_mode.text())
        if mode is None:
            QMessageBox.warning(self, "格式错误", "权限填 0755 / 755 / rwxr-xr-x")
            return
        try:
            uid = int(self.e_uid.text().strip() or 0)
            gid = int(self.e_gid.text().strip() or 0)
            if not (0 <= uid <= 65535 and 0 <= gid <= 65535):
                raise ValueError('属主编号越界')
        except ValueError:
            QMessageBox.warning(self, "格式错误", "uid/gid 必须是 0-65535 的整数")
            return
        is_dir = self.perm_preset.currentData() == "directory"
        if is_dir and (self.e_src.text().strip() or self.e_txt.toPlainText()):
            QMessageBox.warning(self, "输入冲突", "新建目录时请清空本地文件和文本内容，或改选文件预设。")
            return
        full_mode = (stat.S_IFDIR if is_dir else stat.S_IFREG) | mode
        self.result_info = dict(
            rel=rel, mode=full_mode, uid=uid, gid=gid, is_dir=is_dir,
            src=self.e_src.text().strip() or None,
            content=self.e_txt.toPlainText() or None,
            lf=self.chk_lf.isChecked())
        self.accept()


# =====================================================================
#            ②c 右键编辑对话框（文件内容 / 权限属主）
# =====================================================================
class EditFileDialog(QDialog):
    """UTF-8 文本编辑，支持搜索替换与原生撤销历史。"""

    def __init__(self, parent, rel, data):
        QDialog.__init__(self, parent)
        self.setWindowTitle("编辑文件内容 - %s" % rel)
        self.resize(1000, 720)
        v = QVBoxLayout(self)
        tip = QLabel("路径: %s    |    %d 字节    |    保存后按 UTF-8 写回，换行归一为 LF"
                     % (rel, len(data)))
        tip.setWordWrap(True)
        v.addWidget(tip)
        self.e = QPlainTextEdit()
        editor_font = QFont("Consolas")
        editor_font.setPixelSize(FONT_PX)
        self.e.setFont(editor_font)
        self.e.setMinimumHeight(200)
        self.e.setLineWrapMode(QPlainTextEdit.NoWrap)
        self.e.setPlainText(data.decode("utf-8", "replace"))
        self.e.document().setModified(False)
        tools = FlowLayout()
        self.editor_actions = {}
        for name, shortcut, slot in (
                ('撤销', 'Ctrl+Z', self.e.undo),
                ('重做', 'Ctrl+Y', self.e.redo),
                ('剪切', 'Ctrl+X', self.e.cut),
                ('复制', 'Ctrl+C', self.e.copy),
                ('粘贴', 'Ctrl+V', self.e.paste),
                ('全选', 'Ctrl+A', self.e.selectAll),
                ('搜索', 'Ctrl+F', self.show_find),
                ('替换', 'Ctrl+H', lambda: self.show_find(True)),
                ('跳转行', 'Ctrl+G', self.goto_line)):
            action = QAction(name, self)
            action.setShortcut(QKeySequence(shortcut))
            editing = name in ('撤销', '重做', '剪切', '复制', '粘贴', '全选')
            action.setShortcutContext(Qt.WidgetShortcut if editing else Qt.WidgetWithChildrenShortcut)
            action.triggered.connect(lambda _checked=False, callback=slot: callback())
            (self.e if editing else self).addAction(action)
            button = QToolButton()
            button.setDefaultAction(action)
            button.setToolTip(name + ' (' + shortcut + ')')
            tools.addWidget(button)
            self.editor_actions[name] = action
        self.editor_actions['撤销'].setEnabled(False)
        self.editor_actions['重做'].setEnabled(False)
        self.editor_actions['剪切'].setEnabled(False)
        self.editor_actions['复制'].setEnabled(False)
        self.e.undoAvailable.connect(self.editor_actions['撤销'].setEnabled)
        self.e.redoAvailable.connect(self.editor_actions['重做'].setEnabled)
        self.e.copyAvailable.connect(self.editor_actions['剪切'].setEnabled)
        self.e.copyAvailable.connect(self.editor_actions['复制'].setEnabled)
        self.chk_wrap = QCheckBox('自动换行')
        self.chk_wrap.toggled.connect(lambda checked: self.e.setLineWrapMode(
            QPlainTextEdit.WidgetWidth if checked else QPlainTextEdit.NoWrap))
        tools.addWidget(self.chk_wrap)
        v.addLayout(tools)

        self.find_panel = QWidget()
        search_layout = QVBoxLayout(self.find_panel)
        search_layout.setContentsMargins(0, 0, 0, 0)
        row = FlowLayout()
        row.addWidget(QLabel('查找'))
        self.e_find = QLineEdit()
        self.e_find.setPlaceholderText('输入查找文本')
        self.e_find.setMinimumWidth(180)
        self.e_find.returnPressed.connect(lambda: self.find_text())
        row.addWidget(self.e_find)
        row.addWidget(_btn('上一个', lambda: self.find_text(True)))
        row.addWidget(_btn('下一个', self.find_text))
        self.chk_case = QCheckBox('区分大小写')
        self.chk_word = QCheckBox('全词匹配')
        row.addWidget(self.chk_case)
        row.addWidget(self.chk_word)
        row.addWidget(_btn('关闭搜索', self.hide_find))
        search_layout.addLayout(row)
        row = FlowLayout()
        row.addWidget(QLabel('替换为'))
        self.e_replace = QLineEdit()
        self.e_replace.setPlaceholderText('留空可删除匹配文本')
        self.e_replace.setMinimumWidth(180)
        row.addWidget(self.e_replace)
        row.addWidget(_btn('替换当前', self.replace_current))
        row.addWidget(_btn('全部替换', self.replace_all))
        search_layout.addLayout(row)
        self.find_status = QLabel('')
        self.find_status.setWordWrap(True)
        search_layout.addWidget(self.find_status)
        self.find_panel.hide()
        v.addWidget(self.find_panel)
        v.addWidget(self.e, 1)
        self.editor_status = QLabel()
        self.editor_status.setWordWrap(True)
        self.e.cursorPositionChanged.connect(self.update_status)
        self.e.document().modificationChanged.connect(self.update_status)
        self.e.textChanged.connect(self.update_status)
        v.addWidget(self.editor_status)
        self.update_status()
        for shortcut, callback in (('F3', self.find_text),
                                   ('Shift+F3', lambda: self.find_text(True)),
                                   ('Ctrl+S', self.accept)):
            action = QAction(self)
            action.setShortcut(QKeySequence(shortcut))
            action.setShortcutContext(Qt.WidgetWithChildrenShortcut)
            action.triggered.connect(lambda _checked=False, callback=callback: callback())
            self.addAction(action)
        bb = QDialogButtonBox(QDialogButtonBox.Save | QDialogButtonBox.Cancel)
        bb.button(QDialogButtonBox.Save).setText('保存')
        bb.button(QDialogButtonBox.Cancel).setText('取消')
        bb.accepted.connect(self.accept)
        bb.rejected.connect(self.reject)
        v.addWidget(bb)
        for button in self.findChildren(QPushButton):
            button.setAutoDefault(False)
            button.setDefault(False)
        _fit_dialog(self)
        self.e.setFocus()

    def update_status(self, *_args):
        cursor = self.e.textCursor()
        self.editor_status.setText('第 %d 行，第 %d 列 | 共 %d 行 | %s' % (
            cursor.blockNumber() + 1, cursor.positionInBlock() + 1,
            self.e.blockCount(), '已修改' if self.e.document().isModified() else '未修改'))

    def show_find(self, replace=False):
        selected = self.e.textCursor().selectedText()
        if selected and '\u2029' not in selected:
            self.e_find.setText(selected)
        self.find_panel.show()
        field = self.e_replace if replace else self.e_find
        field.setFocus()
        field.selectAll()
        self._content_scroll.ensureWidgetVisible(field)

    def hide_find(self):
        self.find_panel.hide()
        self.e.setFocus()

    def keyPressEvent(self, event):
        if event.key() in (Qt.Key_Return, Qt.Key_Enter):
            event.accept()
            return
        if event.key() == Qt.Key_Escape and not self.find_panel.isHidden():
            self.hide_find()
            event.accept()
            return
        super().keyPressEvent(event)

    def find_flags(self, backward=False):
        flags = QTextDocument.FindFlags()
        if self.chk_case.isChecked():
            flags |= QTextDocument.FindCaseSensitively
        if self.chk_word.isChecked():
            flags |= QTextDocument.FindWholeWords
        if backward:
            flags |= QTextDocument.FindBackward
        return flags

    def find_text(self, backward=False):
        query = self.e_find.text()
        if not query:
            self.show_find()
            self.find_status.setText('请输入查找文本')
            return False
        flags = self.find_flags(backward)
        document = self.e.document()
        found = document.find(query, self.e.textCursor(), flags)
        wrapped = found.isNull()
        if wrapped:
            start = QTextCursor(document)
            start.movePosition(QTextCursor.End if backward else QTextCursor.Start)
            found = document.find(query, start, flags)
        if found.isNull():
            self.find_status.setText('未找到匹配文本')
            return False
        self.e.setTextCursor(found)
        self.e.ensureCursorVisible()
        self.find_status.setText('已从边界循环查找' if wrapped else '已找到匹配文本')
        return True

    def replace_current(self):
        query = self.e_find.text()
        cursor = self.e.textCursor()
        if not query:
            self.find_text()
            return
        start = QTextCursor(self.e.document())
        start.setPosition(cursor.selectionStart())
        found = self.e.document().find(query, start, self.find_flags())
        if (not cursor.hasSelection() or found.isNull()
                or found.selectionStart() != cursor.selectionStart()
                or found.selectionEnd() != cursor.selectionEnd()):
            self.find_text()
            return
        cursor.insertText(self.e_replace.text())
        self.e.setTextCursor(cursor)
        self.find_text()

    def replace_all(self):
        query = self.e_find.text()
        if not query:
            self.find_text()
            return
        document = self.e.document()
        flags = self.find_flags()
        cursor = QTextCursor(document)
        cursor.beginEditBlock()
        count = 0
        found = document.find(query, 0, flags)
        while not found.isNull():
            found.insertText(self.e_replace.text())
            count += 1
            found = document.find(query, found.position(), flags)
        cursor.endEditBlock()
        self.find_status.setText('已替换 %d 处' % count)

    def goto_line(self):
        line, ok = QInputDialog.getInt(self, '跳转行', '行号',
                                       self.e.textCursor().blockNumber() + 1,
                                       1, self.e.blockCount())
        if ok:
            self.e.setTextCursor(QTextCursor(self.e.document().findBlockByNumber(line - 1)))
            self.e.ensureCursorVisible()
            self.e.setFocus()

    def result_bytes(self):
        text = self.e.toPlainText().replace('\r\n', '\n').replace('\r', '\n')
        return text.encode('utf-8')


class EditPermDialog(QDialog):
    """编辑权限 / 属主（权限支持 0755 / 755 / rwxr-xr-x）。"""

    def __init__(self, parent, rel, e):
        QDialog.__init__(self, parent)
        self.setWindowTitle("编辑权限 / 属主")
        v = QVBoxLayout(self)
        lb = QLabel("目标: %s" % rel)
        lb.setWordWrap(True)
        v.addWidget(lb)
        f = QFormLayout()
        self.e_perm = QLineEdit(fmt_mode(e.get("mode", 0)))
        self.e_perm.setMinimumWidth(220)
        f.addRow("权限", self.e_perm)
        self.e_uid = QLineEdit(str(e.get("uid", 0)))
        self.e_gid = QLineEdit(str(e.get("gid", 0)))
        self.e_uid.setMaximumWidth(110)
        self.e_gid.setMaximumWidth(110)
        ur = QHBoxLayout()
        ur.addWidget(self.e_uid)
        ur.addWidget(QLabel(": "))
        ur.addWidget(self.e_gid)
        ur.addStretch(1)
        f.addRow("属主 uid:gid", ur)
        v.addLayout(f)
        self.lbl_perm_preview = _hint('')
        v.addWidget(self.lbl_perm_preview)
        self.e_perm.textChanged.connect(self._update_perm_preview)
        self._update_perm_preview()
        v.addWidget(_hint("权限支持八进制数字或 rwx 字符；多选时统一按此应用。"))
        bb = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        bb.button(QDialogButtonBox.Ok).setText("确定")
        bb.button(QDialogButtonBox.Cancel).setText("取消")
        bb.accepted.connect(self._ok)
        bb.rejected.connect(self.reject)
        v.addWidget(bb)
        self._val = None
        _fit_dialog(self)

    def _update_perm_preview(self, _text=None):
        text = self.e_perm.text().strip()
        mode = parse_perm(text)
        if mode is None:
            self.lbl_perm_preview.setText('请输入有效权限' if not text else '权限格式无效')
        else:
            self.lbl_perm_preview.setText('当前权限：%04o  →  %s' % (
                mode, stat.filemode(mode)[1:]))

    def _ok(self):
        perm = parse_perm(self.e_perm.text())
        if perm is None:
            QMessageBox.warning(self, "格式错误",
                                "权限填 0755 / 755 / rwxr-xr-x")
            return
        try:
            uid = int(self.e_uid.text().strip() or 0)
            gid = int(self.e_gid.text().strip() or 0)
            assert 0 <= uid <= 65535 and 0 <= gid <= 65535
        except Exception:
            QMessageBox.warning(self, "格式错误", "uid/gid 必须是 0-65535")
            return
        self._val = (perm, uid, gid)
        self.accept()

    def result_info(self):
        return self._val or (0o755, 0, 0)


# =====================================================================
#                     ③ 打包 / 回写 页
# =====================================================================
class PackPage(QWidget):
    """目录压缩、镜像写回、工作区合并的独立操作。"""

    # 未载入固件时的兜底分区名（与拆分文件「0.zloader」体系一致）
    PART_ORDER = ("0.zloader", "1.nvrofs", "2.uboot", "3.imagefs",
                  "4.rootfs", "5.userdata", "6.oem")

    def __init__(self, win):
        super().__init__(win)
        self.win = win
        self._bound_context = {}
        self._auto_out = ''
        self._auto_filesystem_out = ''
        self._last_packed = None
        self._packed_key = None
        v = QVBoxLayout(self)
        v.setContentsMargins(0, 0, 0, 0)
        v.setSpacing(6)
        v.addWidget(_step(4, '生成镜像 → 写回分区 → 合并整机'))
        pack = QGroupBox('4.1 压缩文件目录，生成分区镜像')
        form = QVBoxLayout(pack)
        self.e_src = QLineEdit()
        form.addWidget(_row('已解包文件目录', self.e_src, _btn('使用当前编辑目录', self.use_unpacked), _btn('选择目录', lambda:self._pick(self.e_src))))
        self.e_filesystem_out = QLineEdit()
        self.e_filesystem_out.setPlaceholderText('选择 SquashFS 解包目录后自动生成')
        self.e_filesystem_out.setToolTip('SquashFS 有效文件系统内容，默认 new.squashfs，生成后用于写回。JFFS2 使用分区镜像输出。')
        self.btn_filesystem_save = _btn('另选保存位置', lambda:self._pick_save(self.e_filesystem_out))
        form.addWidget(_row('文件系统镜像输出', self.e_filesystem_out, self.btn_filesystem_save))
        self.e_out = QLineEdit()
        self.e_out.textChanged.connect(self._sync_filesystem_output)
        self.e_out.setPlaceholderText('选择有效解包目录后自动生成')
        self.e_out.setToolTip('按分区容量补齐的镜像，例如 new.4.rootfs。SquashFS 写回默认使用文件系统镜像。')
        self.btn_output_save = _btn('另选保存位置', lambda:self._pick_save(self.e_out))
        form.addWidget(_row('分区镜像输出', self.e_out, self.btn_output_save))
        self.btn_pack = _btn('压缩文件目录为镜像', self.do_pack, accent=True)
        form.addWidget(self.btn_pack)
        v.addWidget(pack)
        write = QGroupBox('4.2 将已有镜像写回所选分区')
        form = QVBoxLayout(write)
        self.e_image = QLineEdit()
        self.e_image.setPlaceholderText('SquashFS 默认使用 new.squashfs，也可选择已有分区镜像')
        form.addWidget(_row('待写回镜像', self.e_image, _btn('选择已有镜像', self.pick_image)))
        self.cb_part = SafeCombo(self)
        self.cb_part.hide()
        self.cb_part.currentIndexChanged.connect(self._on_part)
        self.e_target = QLineEdit()
        self.e_target.setPlaceholderText('根据解包来源匹配已有分区文件，默认 4.rootfs')
        self._auto_target = ''
        form.addWidget(_row('写回目标分区', self.e_target,
                            _btn('选择已有分区', self.pick_target_partition)))
        self.btn_write = _btn('将镜像写回所选分区', self.do_pack_write, accent=True)
        self.btn_write.setEnabled(False)
        self.e_target.textChanged.connect(self._update_write_ready)
        self.e_image.textChanged.connect(self._update_write_ready)
        form.addWidget(self.btn_write)
        v.addWidget(write)
        merge = QGroupBox('4.3 选择分区目录，另存整机固件')
        form = QVBoxLayout(merge)
        self.e_merge_dir = QLineEdit()
        self.e_merge_dir.setPlaceholderText('选择含 partitions.json 的固件分区目录')
        self._auto_merge_dir = ''
        form.addWidget(_row('固件分区目录', self.e_merge_dir,
                            _btn('选择目录', self.pick_merge_directory)))
        self.btn_merge = _btn('合并分区目录为整机固件', self.do_pack_join, accent=True)
        self.btn_merge.setEnabled(False)
        form.addWidget(self.btn_merge)
        self.e_merge_dir.textChanged.connect(lambda text: self.btn_merge.setEnabled(bool(text.strip())))
        v.addWidget(merge)
        self.lbl = _hint('')
        self.lbl.hide()
        v.addWidget(self.lbl)
        self.e_src.editingFinished.connect(lambda: self.set_source(self.e_src.text().strip()))
        self._fill_parts([])


    def pick_image(self):
        path, _ = remember_file_dialog('open', self, '选择已有分区镜像', self.win.artifact_dir(), '所有文件 (*)')
        if path:
            self.e_image.setText(path)
            self._last_packed = None
            self._packed_key = None

    def _pick(self, edit):
        directory = remember_file_dialog('directory', self, '选择已解包文件目录', edit.text() or self.win.artifact_dir())
        if directory:
            self.set_source(directory)


    def _pick_save(self, edit):
        x, _f = remember_file_dialog('save', self, '保存文件系统镜像' if edit is self.e_filesystem_out else '保存分区镜像',
                                            edit.text() or "", "所有 (*.*)")
        if x:
            edit.setText(x)

    def use_unpacked(self):
        directory = self.win.unpack_current_dir()
        if directory:
            self.set_source(directory,part=self.win.unpack_current_part())


    def _on_part(self, _i=None):
        self._sync_name()

    # ---- 输出分区下拉：按固件实际分区重建，默认选 rootfs ----
    def _fill_parts(self, items, prefer=None):
        """填「输出分区」下拉。

        items = [(序号, 分区名), ...]；prefer 指定想保持/默认选中的分区名。
        默认选 rootfs（找不到才退回第一项）——这个默认值同样会联动输出镜像名。
        """
        cur = prefer if prefer is not None else self.cb_part.currentData()
        self.cb_part.blockSignals(True)
        self.cb_part.clear()
        for _i, name in items:
            self.cb_part.addItem(str(name), str(name))
        idx = self.cb_part.findData(cur) if cur else -1
        if idx < 0:
            idx = 0
            for i in range(self.cb_part.count()):
                if str(self.cb_part.itemData(i)).endswith("rootfs"):
                    idx = i
                    break
        self.cb_part.setCurrentIndex(idx)
        self.cb_part.blockSignals(False)
        self._sync_name()          # 默认选择也要联动（输出镜像名跟着变）

    def set_parts(self, parts):
        self._fill_parts([(p.key,p.key) for p in parts or []])


    def _source_kind(self):
        source = self.e_src.text().strip()
        if not source or not os.path.isdir(source):
            return None
        sq = os.path.isfile(os.path.join(source, SQ.PERM_FILE))
        jf = os.path.isfile(os.path.join(source, J.PERM_FILE))
        if sq == jf:
            return None
        return 'squashfs' if sq else 'jffs2'

    def _out_name(self, directory, part):
        kind = self._source_kind()
        if kind is None:
            return ''
        target = next((p for p in self.win.parts or [] if p.key == part), None)
        key = target.key if target else self._bound_context.get('key') or 'partition'
        return 'new.' + key + ('' if kind == 'squashfs' else '.jffs2')

    def _sync_name(self):
        if not hasattr(self, 'e_out'):
            return
        kind = self._source_kind()
        ready = kind is not None
        self.e_out.setEnabled(ready)
        self.btn_output_save.setEnabled(ready)
        self.btn_pack.setEnabled(ready)
        self.e_filesystem_out.setEnabled(kind == 'squashfs')
        self.btn_filesystem_save.setEnabled(kind == 'squashfs')
        if not ready:
            self.e_out.clear()
            self._auto_out = ''
            self._sync_filesystem_output()
            return
        name = self._out_name(self.e_src.text().strip(), self.cb_part.currentData())
        base = self.win.artifact_dir() if self.win.input_path else os.path.dirname(os.path.abspath(self.e_src.text().strip()))
        path = os.path.join(base, name)
        current = self.e_out.text().strip()
        if not current or current == self._auto_out:
            self.e_out.setText(path)
        self._auto_out = path
        self._sync_filesystem_output()

    def _sync_filesystem_output(self, _text=None):
        output = self.e_out.text().strip()
        if self._source_kind() != 'squashfs' or not output:
            self.e_filesystem_out.clear()
            self._auto_filesystem_out = ''
            return
        path = os.path.join(os.path.dirname(output), 'new.squashfs')
        current = self.e_filesystem_out.text().strip()
        if not current or current == self._auto_filesystem_out:
            self.e_filesystem_out.setText(path)
        self._auto_filesystem_out = path

    # ---- 打包 ----
    def do_pack(self):
        self._pack()

    def _update_write_ready(self, _text=None):
        self.btn_write.setEnabled(os.path.isfile(self.e_image.text().strip())
                                  and os.path.isfile(self.e_target.text().strip()))

    def pick_target_partition(self):
        path, _ = remember_file_dialog('open', 
            self, '选择已有分区文件', self.e_target.text().strip() or self.win.artifact_dir(),
            '所有文件 (*)')
        if path:
            self.e_target.setText(path)

    def _sync_target_partition(self, key=None):
        directory = self.e_src.text().strip()
        context = self._bound_context
        key = key or context.get('key')
        if not key and directory:
            name = os.path.basename(os.path.normpath(directory))
            match = re.fullmatch(r'(\d+)[_.](.+)', name)
            if match:
                key = match.group(1) + '.' + match.group(2)
        if not key and directory:
            for manifest in (SQ.PERM_FILE, J.PERM_FILE):
                path = os.path.join(directory, manifest)
                if os.path.isfile(path):
                    try:
                        with open(path, encoding='utf-8') as stream:
                            source_name = json.load(stream).get('_source', '')
                        name = os.path.basename(source_name)
                        match = re.fullmatch(r'(\d+)[_.](.+)', name)
                        if match:
                            key = match.group(1) + '.' + match.group(2)
                    except (OSError, ValueError, TypeError, AttributeError):
                        pass
        key = key or self.cb_part.currentData() or '4.rootfs'
        bases = [context.get('workspace')]
        if directory:
            bases += [os.path.dirname(os.path.abspath(directory)),
                      os.path.dirname(os.path.dirname(os.path.abspath(directory)))]
        bases += [self.win.partition_dir(), self.win.artifact_dir()]
        bases = list(dict.fromkeys(os.path.abspath(base) for base in bases if base))
        candidates = [context.get('image')]
        candidates += [os.path.join(base, key) for base in bases]
        candidates += [os.path.join(base, '4.rootfs') for base in bases]
        path = next((os.path.abspath(path) for path in candidates if path and os.path.isfile(path)), '')
        if not path and (directory or self.win.input_path):
            path = os.path.join(bases[0], '4.rootfs')
        current = self.e_target.text().strip()
        if not current or current == self._auto_target:
            self.e_target.setText(path)
        self._auto_target = path
        self._update_write_ready()

    def do_pack_write(self):
        image = self.e_image.text().strip()
        target = self.e_target.text().strip()
        if not os.path.isfile(image) or not os.path.isfile(target):
            QMessageBox.warning(self, '提示', '请选择已有待写回镜像和目标分区文件')
            return
        if os.path.normcase(os.path.realpath(image)) == os.path.normcase(os.path.realpath(target)):
            QMessageBox.warning(self, '路径冲突', '待写回镜像与目标分区必须是不同文件')
            return
        key = os.path.basename(target)
        known = {p.key for p in self.win.parts or []}
        if image == self._last_packed and self._packed_key and key in known and key != self._packed_key:
            QMessageBox.warning(self, '来源不匹配', '该镜像由 ' + self._packed_key + ' 生成，请选择对应分区文件')
            return
        result = {}
        def job(emit):
            result.update(self._writeback_file(image, target, emit))
            return target
        self.win.run_job(job, '镜像写回分区文件',
                         lambda rc, msg: self._after_writeback(result) if rc == 0 else None)

    def pick_merge_directory(self):
        directory = remember_file_dialog('directory', 
            self, '选择固件分区目录（含 partitions.json）',
            self.e_merge_dir.text().strip() or self.win.artifact_dir())
        if directory:
            self.e_merge_dir.setText(directory)

    def sync_merge_directory(self, directory):
        current = self.e_merge_dir.text().strip()
        if not current or current == self._auto_merge_dir:
            self.e_merge_dir.setText(directory)
        self._auto_merge_dir = directory

    def do_pack_join(self):
        directory = self.e_merge_dir.text().strip()
        if not directory:
            self.pick_merge_directory()
            directory = self.e_merge_dir.text().strip()
        if directory:
            self.win.p_info.do_join(directory)


    def _pack(self):
        source = self.e_src.text().strip()
        if not os.path.isdir(source):
            QMessageBox.warning(self,'提示','请打开已解包文件目录')
            return
        try:
            output = self.win.output_path(self.e_out.text().strip())
            context = self.win.directory_binding(source)
            filesystem_output = None
            if os.path.isfile(os.path.join(source, SQ.PERM_FILE)):
                filesystem_output = self.win.output_path(self.e_filesystem_out.text().strip() or os.path.join(os.path.dirname(output), 'new.squashfs'))
        except Exception as error:
            QMessageBox.warning(self,'路径错误',str(error))
            return
        key = context.get('key') or self.cb_part.currentData()
        part = next((p for p in self.win.parts or [] if p.key==key),None)
        size = part.size if part else context.get('size')
        def job(emit):
            pack_filesystem(source,output,size=size,emit=emit,filesystem_output=filesystem_output)
            return output
        def done(rc,msg):
            if rc==0:
                write_image = filesystem_output or output
                self.e_image.setText(write_image)
                self._last_packed, self._packed_key = write_image, key
                self.lbl.setText('镜像已生成：'+output+'；待写回镜像：'+write_image)
                self.lbl.setVisible(bool(self.lbl.text()))
        self.win.run_job(job,'压缩文件目录',done)



    def _writeback_file(self, image_path, target_path, emit):
        target_path = os.path.abspath(target_path)
        directory = os.path.dirname(target_path)
        key = os.path.basename(target_path)
        workspace = os.path.isfile(os.path.join(directory, 'partitions.json'))
        if workspace:
            current, parts, meta = read_partition_workspace(directory)
            part = P.resolve_partition(parts, key)
        else:
            with open(target_path, 'rb') as stream:
                current = stream.read()
            part = P.Partition(0, key, 0, len(current))
            part.fstype = P.detect_fs(current)
        with open(image_path, 'rb') as stream:
            image = stream.read()
        if part.fstype not in ('squashfs', 'jffs2') or P.detect_fs(image) != part.fstype:
            raise ValueError('镜像与目标分区的文件系统不一致，目标须为 SquashFS 或 JFFS2 分区')
        updated = P.replace_partition(current, part, image)
        P.atomic_write(target_path, updated[part.offset:part.offset + part.size], timestamp_backup=True)
        emit('[+] 已写回 ' + target_path)
        return dict(target=target_path, workspace=workspace, directory=directory,
                    updated=updated if workspace else None)

    def _after_writeback(self, result):
        directory = result['directory']
        self.e_merge_dir.setText(directory)
        self._auto_merge_dir = directory
        if result['workspace'] and self.win._workspace_loaded and os.path.normcase(os.path.realpath(directory)) == os.path.normcase(os.path.realpath(self.win.partition_dir())):
            self.win.raw = result['updated']
            self.win.p_info.raw = result['updated']
            self.win.p_unpack.source_raw = result['updated']
            self.win.p_workspace.status.setText('已写回 ' + os.path.basename(result['target']) + '；可合并整机固件。')
            self.win.p_workspace.status.setVisible(bool(self.win.p_workspace.status.text()))
        self.lbl.setText('已写回分区文件：' + result['target'])
        self.lbl.setVisible(bool(self.lbl.text()))

    def set_source(self, directory, part=None):
        self.e_src.setText(directory)
        self._bound_context = self.win.directory_binding(directory) if self._source_kind() else {}
        key = part or self._bound_context.get('key')
        self.cb_part.setCurrentIndex(self.cb_part.findData(key) if key else -1)
        self._sync_name()
        self._sync_target_partition(key)
        if not self._source_kind():
            self.lbl.setText('请选择有效的解包目录，目录内须含一种文件系统权限清单。')
            self.lbl.setVisible(bool(self.lbl.text()))
        else:
            self.lbl.setText('来源关联分区：'+str(key) if key else '目录可独立打包；写回前请选择对应目标分区。')
            self.lbl.setVisible(bool(self.lbl.text()))



# =====================================================================
#                            主窗口
# =====================================================================
# QR module geometry generated from the original WeChat payment URI.
# The matrix contains only black/white modules, not encoded image bytes.
SUPPORT_QR_ROWS = ('000000000000000000000000000000000000000000000000000000000', '000000000000000000000000000000000000000000000000000000000', '000000000000000000000000000000000000000000000000000000000', '000000000000000000000000000000000000000000000000000000000', '000011111110110011011001010111010000000010001011111110000', '000010000010100000011001101001001011111110111010000010000', '000010111010111001110010101011111011100100011010111010000', '000010111010010101010101101010001000101011010010111010000', '000010111010001101010100101111100010100011000010111010000', '000010000010101011011000111000100110100011100010000010000', '000011111110101010101010101010101010101010101011111110000', '000000000000101111010100101000111000100110010000000000000', '000000111010100111001101011111111101011011110111001110000', '000000111101000101010110100100011101100111000111110010000', '000010000111100100000101001110100011100011111001111110000', '000010001001000100110101100010110000100100100100110100000', '000011010010010011010001100100111100001010011101001010000', '000001111000010001111011101100100101100101000111111000000', '000010111111111001110010110000111010100001101001100110000', '000001000000001110001100010100000000101111101010100110000', '000010101110000001111011111110101101011110100101011010000', '000010110000111101111101001010001001101111110011100100000', '000001000110001000110000110101000000110100000011001010000', '000010111001011110100010101101011000010101010001100100000', '000010011111101110001001010111101000001110110000001110000', '000000100100001011011110111011000111010000000010000100000', '000001111111100101110101001111110110001011101111100110000', '000001101000111111110001011000111001001010111000100000000', '000010001010111100000011111010111110011110101010100000000', '000011011000101001111000001000111011000011011000101110000', '000001111111100000110010111111110010000010001111100110000', '000011010000101101011111000010110100100101000000000100000', '000000110011101000011101001110110011001010110011101100000', '000010110001110111001011110000101110100000001111000000000', '000001011011000001100000100000010110101111111010111110000', '000010100001010010010100010011001000000011001100110010000', '000001001011010111000110011111100011111100110101001000000', '000000100100001001101110101000110100100001010101000100000', '000011010111001000111100111010001111110100101111000010000', '000000001001111110101001011110000100000000011110000100000', '000010101011111000000110111011000101011110010101010010000', '000000101000011111100011111101111010000011010111001100000', '000001000110101111001010111110110100100011000111111010000', '000001110000110101010000111011101111010010000101000110000', '000011100010101010010001001111101111000111011111100000000', '000000000000101000010101101000100100110100001000111100000', '000011111110001110000100111010101001100011001010110110000', '000010000010011110101000101000100111100010001000100010000', '000010111010101100000111001111110000000110101111101110000', '000010111010111101111010110111001110100011010010100010000', '000010111010110100011010010101000111001010101001010110000', '000010000010001100010110110101001101010100011110000010000', '000011111110011010110011010000100001011011101110011110000', '000000000000000000000000000000000000000000000000000000000', '000000000000000000000000000000000000000000000000000000000', '000000000000000000000000000000000000000000000000000000000', '000000000000000000000000000000000000000000000000000000000')


def create_app_icon():
    icon = QIcon()
    for size in (16, 24, 32, 48, 64, 128, 256):
        pix = QPixmap(size, size)
        pix.fill(Qt.transparent)
        painter = QPainter(pix)
        painter.setRenderHint(QPainter.Antialiasing)
        painter.scale(size / 256.0, size / 256.0)
        painter.setPen(Qt.NoPen)
        painter.setBrush(QColor('#176bd1'))
        painter.drawRoundedRect(8, 8, 240, 240, 50, 50)
        painter.setPen(QPen(Qt.white, 12, Qt.SolidLine, Qt.RoundCap))
        for pos in (80, 128, 176):
            painter.drawLine(pos, 52, pos, 32)
            painter.drawLine(pos, 224, pos, 204)
            painter.drawLine(32, pos, 52, pos)
            painter.drawLine(204, pos, 224, pos)
        painter.setPen(Qt.NoPen)
        painter.setBrush(Qt.white)
        painter.drawRoundedRect(54, 54, 148, 148, 19, 19)
        painter.setBrush(QColor('#176bd1'))
        painter.drawRoundedRect(71, 71, 114, 114, 9, 9)
        bolt = QPainterPath()
        bolt.moveTo(121, 84)
        for x, y in ((90, 134), (121, 134), (112, 172), (166, 110), (132, 110), (146, 84)):
            bolt.lineTo(x, y)
        bolt.closeSubpath()
        painter.setBrush(Qt.white)
        painter.drawPath(bolt)
        painter.end()
        icon.addPixmap(pix)
    return icon


ALIPAY_QR_ROWS = ('0000000000000000000000000000000000000000000000000', '0000000000000000000000000000000000000000000000000', '0000000000000000000000000000000000000000000000000', '0000000000000000000000000000000000000000000000000', '0000111111101110000001100001010110010011111110000', '0000100000100011000100011011101111011010000010000', '0000101110100001110100010110111010010010111010000', '0000101110101001011010111110111011000010111010000', '0000101110100101110000000111111110010010111010000', '0000100000100001000101111011100101010010000010000', '0000111111101010101010101010101010101011111110000', '0000000000000101000101001001011101101000000000000', '0000001011101001111011101111110011000100010010000', '0000011101001011110011000011011010101010011100000', '0000111011111000010000011010010011100011101010000', '0000101110001110010010010110100111101001000110000', '0000100101101010111001011110101101011010010110000', '0000110011001101001101000101001100111000010110000', '0000010010100111000110000110110000111011011110000', '0000010111001100100011111111000101001011000100000', '0000011011101100001010101000011011011011010000000', '0000100001010111101011101010110010101010011110000', '0000011010101010001110101011100001001100100110000', '0000111100001101001101101010010110000011000100000', '0000110011111100101101111100000000011110110010000', '0000101010001101101010111100000001001110101110000', '0000001100110001111110101011100001100110000110000', '0000000010011011000111010101001001001010101000000', '0000111001101000110101111011010011111111001100000', '0000000111001010111100001000001010000010000010000', '0000011011111010011101111101101000100100101010000', '0000100001000001101110101100101101001111000010000', '0000011111100100001000111110110011110100010010000', '0000011110011110101100100100001110110100011010000', '0000100101100110001001000000110110100000011010000', '0000011010010011010101111000010011110110110000000', '0000100110111010110000011011110101001111100000000', '0000000000001000010011111110100001101000100010000', '0000111111100111110110000101001000111010111110000', '0000100000101110000001110100111101101000100000000', '0000101110101010001011010111001000101111110000000', '0000101110100100011111111101000000111100110110000', '0000101110101110001001010001100001001001111010000', '0000100000100110100101101111110101011011010100000', '0000111111100111001000011000011011001111111110000', '0000000000000000000000000000000000000000000000000', '0000000000000000000000000000000000000000000000000', '0000000000000000000000000000000000000000000000000', '0000000000000000000000000000000000000000000000000')


def create_support_qr(max_size=564, channel="wechat"):
    rows = SUPPORT_QR_ROWS if channel == "wechat" else ALIPAY_QR_ROWS
    modules = len(rows)
    scale = max(1, int(max_size) // modules)
    pix = QPixmap(modules * scale, modules * scale)
    pix.fill(Qt.white)
    painter = QPainter(pix)
    painter.setRenderHint(QPainter.Antialiasing, False)
    painter.setPen(Qt.NoPen)
    painter.setBrush(Qt.black)
    for y, row in enumerate(rows):
        for x, black in enumerate(row):
            if black == '1':
                painter.drawRect(x * scale, y * scale, scale, scale)
    painter.end()
    return pix


class SupportDialog(QDialog):
    def __init__(self, parent=None):
        QDialog.__init__(self, parent)
        self.setWindowTitle('喜欢就支持我')
        self.channel = "wechat"
        self._qr_original = create_support_qr()
        self.setWindowFlag(Qt.WindowContextHelpButtonHint, False)
        if parent is not None:
            self.setWindowIcon(parent.windowIcon())
        layout = QVBoxLayout(self)
        layout.setContentsMargins(12, 12, 12, 12)
        channels = QHBoxLayout()
        self.channel_buttons = {}
        for key, title in (("wechat", "微信"), ("alipay", "支付宝")):
            button = QPushButton(title)
            button.setCheckable(True)
            button.setChecked(key == self.channel)
            button.clicked.connect(lambda checked=False, key=key: self.set_channel(key))
            self.channel_buttons[key] = button
            channels.addWidget(button)
        layout.addLayout(channels)
        self.qr_label = QLabel()
        self.qr_label.setAlignment(Qt.AlignCenter)
        self.qr_label.setMinimumSize(1, 1)
        self.qr_label.setSizePolicy(QSizePolicy.Ignored, QSizePolicy.Ignored)
        self.qr_label.setStyleSheet('background:white;')
        layout.addWidget(self.qr_label, 1)
        self.channel_hint = QLabel('请使用微信扫码')
        self.channel_hint.setAlignment(Qt.AlignCenter)
        layout.addWidget(self.channel_hint)
        self.close_buttons = QDialogButtonBox(QDialogButtonBox.Close)
        self.close_buttons.button(QDialogButtonBox.Close).setText('关闭')
        self.close_buttons.rejected.connect(self.reject)
        layout.addWidget(self.close_buttons)
        screen = self.screen()
        area = screen.availableGeometry() if screen is not None else None
        width = min(600, max(240, area.width()-40)) if area else 600
        height = min(640, max(260, area.height()-60)) if area else 640
        self.resize(width, height)
        self.setMinimumSize(min(280, width), min(320, height))
        self._refresh_qr()

    def set_channel(self, channel):
        if channel not in self.channel_buttons:
            raise ValueError('未知收款渠道')
        self.channel = channel
        for key, button in self.channel_buttons.items():
            button.setChecked(key == channel)
        self.channel_hint.setText('请使用%s扫码' % ('微信' if channel == 'wechat' else '支付宝'))
        self._qr_original = create_support_qr(channel=channel)
        self._refresh_qr()

    def _refresh_qr(self):
        size = self.qr_label.size().boundedTo(self._qr_original.size())
        if size.width() > 0 and size.height() > 0:
            self.qr_label.setPixmap(create_support_qr(min(size.width(), size.height()), self.channel))

    def resizeEvent(self, event):
        QDialog.resizeEvent(self, event)
        self._refresh_qr()


class MainWindow(QWidget):
    def closeEvent(self, event):
        if self._support_dialog is not None:
            self._support_dialog.close()
        QWidget.closeEvent(self, event)

    def show_support(self):
        if self._support_dialog is None:
            try:
                self._support_dialog = SupportDialog(self)
            except ValueError as exc:
                QMessageBox.warning(self, '打开二维码失败', str(exc))
                return
        self._support_dialog.show()
        self._support_dialog.raise_()
        self._support_dialog.activateWindow()

    def __init__(self):
        QWidget.__init__(self)
        self.setWindowTitle("中兴微固件工具箱通用版")
        self.setWindowIcon(create_app_icon())
        self._support_dialog = None
        self.title_font_metrics=configure_title_typography(QApplication.instance())
        self._screen_connections=[]
        self._screen_resize_pending=False
        scr=QApplication.primaryScreen()
        if scr is not None:
            area=scr.availableGeometry()
            preferred,minimum=window_sizes(area.width(),area.height(),FONT_PX)
            self.setMinimumSize(*minimum)
            self.resize(*preferred)
            self.move(area.x()+(area.width()-preferred[0])//2,area.y()+(area.height()-preferred[1])//2)
        else:
            self.resize(1000,700)
            self.setMinimumSize(600,400)

        self.raw = None
        self.parts = None
        self.fw_path = None
        self._pdir = None
        self._unpack_dir = None
        self._unpack_part = ""
        self.worker = None
        self.input_path = None
        self._workspace_loaded = False
        self._workspace_meta = {}
        self._artifact_base = BASE_DIR
        self._partition_image = None

        outer = QVBoxLayout(self)
        outer.setContentsMargins(10, 10, 10, 10)
        outer.setSpacing(10)

        # ============ 顶部：固件选择 + 分区信息 + 锚点导航 ============
        top = QGroupBox("① 输入来源 / 当前工作对象")
        tv = QVBoxLayout(top)
        tv.setSpacing(9)
        r1 = QHBoxLayout()
        r1.setSpacing(9)
        self.e_fw = QLineEdit()
        self.e_fw.setPlaceholderText("选择中兴微编程器固件（*.bin）")
        r1.addWidget(self.e_fw, 1)
        r1.addWidget(_btn('选择整机固件', self.pick_firmware, accent=True))
        r1.addWidget(_btn("重新解析", self.reparse))
        tv.addLayout(r1)

        r2 = FlowLayout()
        r2.setSpacing(8)
        self.lbl_fw = QLabel("尚未载入固件")
        self.lbl_fw.setProperty('role','sectionTitle')
        self.lbl_fw.setWordWrap(True)
        self.lbl_fw.setMinimumWidth(0)
        self.lbl_fw.setSizePolicy(QSizePolicy.Ignored,QSizePolicy.Preferred)
        tv.addWidget(self.lbl_fw)
        self.nav_btns = []
        for nm, anchor in (("分区工作区", "anchor_workspace"),
                           ("解包与编辑", "anchor_unpack"),
                           ("打包 / 写回 / 合并", "anchor_pack"),
                           ("设备信息", "anchor_info")):
            b = QPushButton(nm)
            b.setProperty("compact","true")
            b.setCheckable(True)
            b.clicked.connect(lambda _c, a=anchor: self.goto_anchor(a))
            r2.addWidget(b)
            self.nav_btns.append(b)
        r2.addStretch(1)

        self.cb_theme = SafeCombo()
        for t in ("浅色", "深色"):
            self.cb_theme.addItem(t)
        self.cb_theme.setFixedWidth(96)
        self.cb_theme.currentIndexChanged.connect(self.on_theme)
        r2.addWidget(_row('外观',self.cb_theme,lw=42))
        self.log_toggle=_btn('隐藏日志',self.toggle_log)
        self.log_toggle.setProperty('compact','true')
        r2.addWidget(self.log_toggle)
        self.support_button = _btn("喜欢就支持我", self.show_support)
        self.support_button.setProperty("compact", "true")
        r2.addWidget(self.support_button)
        tv.addLayout(r2)
        outer.addWidget(top)

        # ============ 单页集成：所有功能自上而下排布在同一滚动页 ============
        split = QSplitter(Qt.Horizontal)
        self.splitter=split
        split.setChildrenCollapsible(False)
        split.setHandleWidth(8)
        self._log_explicit=False

        self.scroll = QScrollArea()
        self.scroll.setWidgetResizable(True)
        self.scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarAsNeeded)
        self.scroll.setMinimumSize(0,0)
        page = QWidget()
        pv = QVBoxLayout(page)
        pv.setContentsMargins(2, 2, 8, 2)
        pv.setSpacing(8)

        self.p_info = InfoPage(self)
        self.p_workspace = PartitionWorkspacePage(self)
        self.p_unpack = UnpackPage(self)
        self.p_pack = PackPage(self)
        self.anchors = {"anchor_workspace": self.p_workspace, "anchor_info": self.p_info,
                        "anchor_unpack": self.p_unpack,
                        "anchor_pack": self.p_pack}
        for p in (self.p_workspace, self.p_unpack, self.p_pack, self.p_info):
            card = QFrame()
            card.setProperty("panelCard", "true")
            cv = QVBoxLayout(card)
            cv.setContentsMargins(8, 6, 8, 6)
            cv.setSpacing(6)
            p.setSizePolicy(QSizePolicy.Preferred, QSizePolicy.Maximum)
            cv.addWidget(p)
            self.anchors_holder = self.anchors
            pv.addWidget(card)
        pv.addStretch(1)
        self.scroll.setWidget(page)
        split.addWidget(self.scroll)

        self.log_panel = LogPanel("运行日志")
        right = QWidget()
        self.log_container=right
        rv = QVBoxLayout(right)
        rv.setContentsMargins(0, 0, 0, 0)
        rv.setSpacing(8)
        rv.addWidget(self.log_panel, 1)
        split.addWidget(right)
        split.setStretchFactor(0,70)
        split.setStretchFactor(1,30)
        split.setSizes([1000,420])
        outer.addWidget(split, 1)

        self.log = self.log_panel
        self.log_panel("中兴微固件工具箱")
        self.log_panel('设备信息流程：载入整机固件 → 修改设备信息 → 另存修改后的固件')
        self.log_panel('文件编辑流程：解包 → 编辑 → 压缩 → 写回分区 → 合并整机')
        self.scroll.verticalScrollBar().valueChanged.connect(self._sync_nav)
        QTimer.singleShot(0,self._adapt_layout)

    def showEvent(self,event):
        super().showEvent(event)
        handle=self.windowHandle()
        if handle is not None and not getattr(self,'_screen_hooked',False):
            self._screen_hooked=True
            handle.screenChanged.connect(self._screen_changed)
            self._connect_screen(handle.screen())
        if not getattr(self,'_initial_fit_done',False):
            self._initial_fit_done=True
            # Preserve a caller's explicitly chosen size; only keep its frame on screen.
            QTimer.singleShot(0,self._fit_current_screen)

    def _connect_screen(self,screen):
        for signal,slot in self._screen_connections:
            try:
                signal.disconnect(slot)
            except (TypeError,RuntimeError):
                pass
        self._screen_connections=[]
        if screen is not None:
            for signal in (screen.availableGeometryChanged,screen.logicalDotsPerInchChanged):
                slot=lambda *args:self._fit_current_screen()
                signal.connect(slot)
                self._screen_connections.append((signal,slot))

    def _screen_changed(self,screen):
        self._connect_screen(screen)
        self._screen_resize_pending=True
        QTimer.singleShot(0,self._fit_current_screen)

    def _fit_current_screen(self):
        if self.isMaximized() or self.isFullScreen():
            return
        screen=self.screen() or QApplication.primaryScreen()
        if screen is None:
            return
        area=screen.availableGeometry()
        frame=self.frameGeometry()
        frame_width=max(0,frame.width()-self.width())
        frame_height=max(0,frame.height()-self.height())
        preferred,minimum=window_sizes(area.width(),area.height(),FONT_PX,frame_width,frame_height)
        self.setMinimumSize(*minimum)
        margin=max(6,round(FONT_PX*.65))
        max_width=max(1,area.width()-2*margin-frame_width)
        max_height=max(1,area.height()-2*margin-frame_height)
        if self._screen_resize_pending:
            self._screen_resize_pending=False
            self.resize(*preferred)
        else:
            self.resize(min(self.width(),max_width),min(self.height(),max_height))
        frame=self.frameGeometry()
        x=max(area.left()+margin,min(frame.x(),area.right()-margin-frame.width()+1))
        y=max(area.top()+margin,min(frame.y(),area.bottom()-margin-frame.height()+1))
        self.move(x,y)

    def resizeEvent(self,event):
        super().resizeEvent(event)
        if hasattr(self,'log_container'):
            self._adapt_layout()

    def _adapt_layout(self):
        vertical=self.width()<max(800,round(1180*FONT_PX/19))
        orientation=Qt.Vertical if vertical else Qt.Horizontal
        changed=self.splitter.orientation()!=orientation
        if vertical:
            self.log_container.setMinimumSize(0,max(80,round(120*FONT_PX/19)))
        else:
            self.log_container.setMinimumSize(max(180,round(280*FONT_PX/19)),0)
        if changed:
            self.splitter.setOrientation(orientation)
            extent=self.splitter.height() if vertical else self.splitter.width()
            self.splitter.setSizes([int(extent*.7),int(extent*.3)])
        if not self._log_explicit:
            self.log_container.setVisible(not (vertical and self.height()<max(460,round(680*FONT_PX/19))))
        self.log_toggle.setText('隐藏日志' if not self.log_container.isHidden() else '显示日志')

    def toggle_log(self):
        self._log_explicit=True
        self.log_container.setVisible(self.log_container.isHidden())
        self._adapt_layout()

    # ---- 锚点跳转（单页内定位，不翻页）----
    def goto_anchor(self,name):
        page=self.scroll.widget()
        section=self.anchors.get(name)
        if section is None:
            return
        page.layout().activate()
        target=section.parentWidget() or section
        offset=target.mapTo(page,QPoint(0,0)).y()
        # 点击导航后目标必须高亮：滚动条 setValue 触发的位置反推不得覆盖本次选择
        self._nav_lock=True
        self.scroll.verticalScrollBar().setValue(max(0,offset-4))
        self._set_nav_checked(name)
        QTimer.singleShot(120, self._unlock_nav)

    def _set_nav_checked(self,name):
        """按锚点名直接设置导航按钮选中态（不依赖当前滚动位置）。"""
        if not hasattr(self,'nav_btns'):
            return
        names=('anchor_workspace','anchor_unpack','anchor_pack','anchor_info')
        if name not in names:
            return
        want=names.index(name)
        for index,button in enumerate(self.nav_btns):
            button.setChecked(index==want)

    def _unlock_nav(self):
        self._nav_lock=False

    def _sync_nav(self,_v=None):
        if getattr(self,'_nav_lock',False):
            return
        if not hasattr(self,'nav_btns'):
            return
        y=self.scroll.verticalScrollBar().value()
        best=0
        for index,name in enumerate(('anchor_workspace','anchor_unpack','anchor_pack','anchor_info')):
            section=self.anchors.get(name)
            if section is None:
                continue
            target=section.parentWidget() or section
            offset=target.mapTo(self.scroll.widget(),QPoint(0,0)).y()
            if offset<=y+20:
                best=index
        for index,button in enumerate(self.nav_btns):
            button.setChecked(index==best)

    def on_theme(self, idx):
        """外观切换（浅色/深色）。"""
        apply_theme(self, idx == 1)

    # ---- 固件 ----
    def pick_firmware(self):
        settings = QSettings('ZXW', 'FirmwareToolbox')
        history = settings.value('firmware/recent_directories', [], type=list)
        history = [p for p in history if isinstance(p, str) and os.path.isdir(p)]
        current = self.e_fw.text().strip()
        current_dir = current if os.path.isdir(current) else os.path.dirname(current)
        initial = history[0] if history else current_dir if os.path.isdir(current_dir) else BASE_DIR
        dialog = QFileDialog(self, "选择编程器固件", initial,
                             "固件 (*.bin);;所有文件 (*)")
        dialog.setFileMode(QFileDialog.ExistingFile)
        sidebar = list(dialog.sidebarUrls())
        for directory in history:
            url = QUrl.fromLocalFile(directory)
            if url not in sidebar:
                sidebar.append(url)
        dialog.setSidebarUrls(sidebar)
        if dialog.exec_() != QFileDialog.Accepted:
            return
        selected = dialog.selectedFiles()
        if not selected:
            return
        path = selected[0]
        directory = os.path.dirname(os.path.abspath(path))
        history = [directory] + [p for p in history
                                 if os.path.normcase(os.path.abspath(p)) != os.path.normcase(directory)]
        settings.setValue('firmware/recent_directories', history[:12])
        settings.setValue('dialogs/last_directory', directory)
        settings.sync()
        self.e_fw.setText(path)
        self.load_firmware(path)

    def reparse(self):
        path = self.e_fw.text().strip()
        if os.path.basename(path)=='partitions.json':
            self.load_partition_directory(os.path.dirname(path))
        elif os.path.isdir(path) and os.path.isfile(os.path.join(path,'partitions.json')):
            self.load_partition_directory(path)
        elif path:
            self.load_firmware(path)



    def load_firmware(self, path, silent=False):
        try:
            raw, parts, total = P.load_firmware(path, emit=lambda _: None)
            if len(parts)==1:
                self.load_partition_image(path)
                return
            self._install_input(raw, parts, os.path.abspath(path), 'firmware')
        except Exception as error:
            QMessageBox.warning(self, '载入失败', str(error))


    # ---- 路径辅助 ----
    def output_path(self, requested):
        if not requested:
            raise ValueError('缺少输出路径')
        path = os.path.abspath(requested)
        protected = [self.fw_path, self._partition_image, self._workspace_meta.get('source')]
        if self._workspace_loaded:
            protected += [os.path.join(self._pdir, p.key) for p in self.parts]
            protected += [os.path.join(self._pdir, n) for n in ('partitions.json','_layout.bin')]
        if any(p and os.path.normcase(os.path.realpath(p))==os.path.normcase(os.path.realpath(path)) for p in protected):
            raise ValueError('输出不得覆盖原固件、分区输入或工作区元数据；写回请使用专用按钮')
        return path


    def fw_dir(self):
        return os.path.dirname(self.fw_path) if self.fw_path else self.artifact_dir()


    def partition_dir(self):
        return self._pdir

    def set_partition_dir(self, directory):
        self._pdir = os.path.abspath(directory)
        self.p_info.e_pdir.setText(self._pdir)
        self.p_pack._sync_name()


    def set_last_unpack(self, directory, part):
        self._unpack_dir, self._unpack_part = directory, part
        if not self.input_path:
            self.input_path = directory
            self._artifact_base = os.path.dirname(os.path.abspath(directory))
            self.log_panel.output_root = self._artifact_base
            self.log_panel.log_path = os.path.join(self._artifact_base,os.path.basename(directory)+'.运行日志.txt')
        self.p_pack.set_source(directory, part=part)


    def unpack_current_dir(self):
        return self._unpack_dir or self.p_unpack.current_dir()

    def unpack_current_part(self):
        return self._unpack_part or self.p_unpack.current_part_name()

    def artifact_dir(self):
        if self._workspace_loaded and self._pdir:
            return self._pdir
        return self._artifact_base

    def _install_input(self, raw, parts, source, mode, directory=None, meta=None):
        self.input_path = source
        self.fw_path = source if mode=='firmware' else None
        self._partition_image = source if mode=='partition' else None
        self._workspace_loaded = mode=='workspace'
        self._workspace_meta = meta or {}
        self._artifact_base = directory if directory else os.path.dirname(source)
        self._pdir = directory if directory else (os.path.join(os.path.dirname(source), '固件分区') if mode=='firmware' else None)
        self.raw = raw if mode!='partition' else None
        self.parts = parts
        self._unpack_dir, self._unpack_part = None, ''
        self.p_unpack.dir = None
        self.p_unpack.entries = {}
        self.p_unpack.tbl.setRowCount(0)
        self.p_unpack.tbl_chg.setRowCount(0)
        self.p_unpack.e_out.clear()
        self.p_unpack._auto_out = ''
        self.p_pack.e_src.clear()
        self.p_pack.e_out.clear()
        self.p_pack.e_filesystem_out.clear()
        self.p_pack._auto_filesystem_out = ''
        self.p_pack.e_image.clear()
        self.p_pack._bound_context = {}
        self.e_fw.setText(source)
        self.e_fw.setToolTip(source)
        self.e_fw.setCursorPosition(0)
        self.p_info.e_pdir.setText(self._pdir or '')
        INFO.TEMP_ROOT = os.path.join(self.artifact_dir(), '.zxw-work', 'info')
        self.log_panel.output_root = self.artifact_dir()
        self.log_panel.log_path = os.path.join(self.artifact_dir(), os.path.basename(source)+'.运行日志.txt')
        modes = {'firmware':'整机固件','workspace':'已有分区工作区','partition':'独立分区镜像'}
        self.lbl_fw.setText('%s：%s | %d 个分区 | %.2f MiB' % (modes[mode],os.path.basename(directory) if directory else os.path.basename(source),len(parts),len(raw)/1048576))
        if mode!='partition':
            ok, stored, calculated, count = P.check_header_checksum(raw)
            status = '分区表校验正常' if ok else '分区表校验不适用' if stored is None else '分区表校验失配'
            self.lbl_fw.setText(self.lbl_fw.text()+' | '+status)
            self.log('[校验] '+status)
        self.p_unpack.set_parts(parts, raw)
        self.p_pack.set_parts(parts)
        self.p_info.set_firmware(self.raw, parts)
        self.p_workspace.status.setText(modes[mode]+'已载入。'+('可以编辑分区并独立合并。' if mode=='workspace' else '可选择分区解包，或打开已有文件目录。'))
        self.p_workspace.status.setVisible(bool(self.p_workspace.status.text()))
        self.p_workspace.btn_split.setEnabled(mode=='firmware')
        self.p_pack._sync_target_partition()
        self.p_pack._update_write_ready()
        self.p_pack.sync_merge_directory(self._pdir if self._workspace_loaded else '')
        self.p_pack.btn_merge.setEnabled(bool(self.p_pack.e_merge_dir.text().strip()))
        self.log('[+] '+self.lbl_fw.text())

    def load_partition_directory(self, directory):
        try:
            raw, parts, meta = read_partition_workspace(directory)
            self._install_input(raw, parts, os.path.join(os.path.abspath(directory),'partitions.json'), 'workspace', os.path.abspath(directory), meta)
            return True
        except Exception as error:
            QMessageBox.warning(self, '工作区载入失败', str(error))
            return False

    def pick_partition_image(self):
        path, _ = remember_file_dialog('open', self, '打开独立分区镜像', self.artifact_dir(), '所有文件 (*)')
        if path:
            self.load_partition_image(path)

    def load_partition_image(self, path):
        try:
            raw, parts, total = P.load_firmware(path, emit=lambda _:None)
            if len(parts)!=1 or parts[0].fstype not in ('jffs2','squashfs'):
                raise ValueError('请选择独立的 JFFS2/SquashFS 分区镜像；整机固件请从顶部载入')
            match = re.fullmatch(r'(\d+)\.([A-Za-z0-9_-]+)', os.path.basename(path))
            if match:
                part = P.Partition(int(match[1]),match[2],0,len(raw),'image')
                part.fstype = P.detect_fs(raw)
                parts = [part]
            self._install_input(raw, parts, os.path.abspath(path), 'partition')
            return True
        except Exception as error:
            QMessageBox.warning(self, '分区载入失败', str(error))
            return False

    def save_directory_binding(self, directory, key):
        part = next((p for p in self.p_unpack.parts if p.key==key), None)
        data = dict(key=key, size=part.size if part else None, workspace=self._pdir if self._workspace_loaded else None, image=self._partition_image)
        P.atomic_write(os.path.abspath(directory)+'.zxw-context.json', json.dumps(data,ensure_ascii=False,indent=2).encode('utf-8'))

    def directory_binding(self, directory):
        path = os.path.abspath(directory)+'.zxw-context.json'
        if os.path.isfile(path):
            with open(path, encoding='utf-8') as stream:
                data = json.load(stream)
            data['key'] = data.get('key',data.get('partition_key',''))
            return data
        name = os.path.basename(os.path.normpath(directory))
        for part in self.parts or []:
            if name in (part.key, self.p_unpack._dir_name(part)):
                return dict(key=part.key,size=part.size)
        return {}

    # ---- 后台任务 ----
    def run_job(self, fn, title, done_cb=None):
        if self.worker is not None and self.worker.isRunning():
            QMessageBox.information(self, "提示", "上一个任务还没结束，请稍候")
            return
        self.log_panel("")
        self.log_panel("=== %s ===" % title)
        self.worker = Worker(fn, title)
        self.worker.sig_log.connect(self.log_panel)
        self.worker.sig_done.connect(
            lambda rc, msg: self._job_done(rc, msg, title, done_cb))
        self.setEnabled(False)
        self.worker.start()

    def _job_done(self, rc, msg, title, done_cb):
        self.setEnabled(True)
        if rc == 0:
            self.log_panel("==> %s 完成：%s" % (title, msg))
        else:
            self.log_panel("==> %s 失败：%s" % (title, msg))
        self.log_panel("")
        if done_cb:
            done_cb(rc, msg)
        self.worker = None


# =====================================================================
#                    外观主题（浅色 / 深色）
# =====================================================================
DARK_COLOR = {"ok": "#4ade80", "err": "#f87171", "warn": "#fbbf24",
              "info": "#7bb7f5", "step": "#c4a6f0", "cmd": "#5eead4",
              "dim": "#9aa4b2", "text": "#e5e9ef"}

DARK_QSS = """
QWidget { background:#1c2026; color:#e5e9ef;
          font-family:'Microsoft YaHei UI','Microsoft YaHei','Segoe UI';
          font-size:%(f)dpx; }
QLabel { background:transparent; font-size:%(f)dpx; }
QGroupBox { border:1px solid #333a44; border-radius:10px; margin-top:20px;
            background:#232830; font-weight:bold; }
QGroupBox::title { subcontrol-origin:margin; left:14px; padding:3px 12px;
                   color:#7bb7f5; font-weight:bold; font-size:%(f)dpx;
                   background:#232830; border-radius:7px; }
QFrame[panelCard="true"] { background:#232830; border:1px solid #333a44;
                           border-radius:10px; }
QPushButton { background:#2b313a; border:1px solid #3b434e; border-radius:8px;
              padding:0 22px; font-size:%(f)dpx; min-height:46px;
              color:#e5e9ef; }
QPushButton:hover { background:#36404c; border:1px solid #5a8fd0; }
QPushButton:pressed { background:#1f2530; }
QPushButton:disabled, QPushButton[accent="true"]:disabled, QPushButton[danger="true"]:disabled { background:#252a31; color:#6b7480; border:1px solid #333a44; }
QPushButton[accent="true"] { background:#2f7fdd; color:#ffffff;
                             border:1px solid #2f7fdd; font-weight:bold; }
QPushButton[accent="true"]:hover { background:#3d8ce8; }
QPushButton[big="true"] { padding:0 26px; font-size:%(f)dpx;
                          font-weight:bold; min-height:58px; border-radius:10px; }
QPushButton:checked { background:#2f7fdd; color:#fff; border:1px solid #2f7fdd;
                      font-weight:bold; }
QLineEdit, QComboBox, QTextEdit, QPlainTextEdit {
        background:#191d23; border:1px solid #3b434e; border-radius:7px;
        padding:0 10px; font-size:%(f)dpx; color:#e5e9ef;
        selection-background-color:#2f5f9e; }
QLineEdit { min-height:40px; }
QComboBox { min-height:40px; }
QLineEdit:focus, QTextEdit:focus, QComboBox:focus, QPlainTextEdit:focus
        { border:1px solid #4a9bff; }
QComboBox::drop-down { border:none; width:26px; }
QComboBox QAbstractItemView { border:1px solid #3b434e; background:#232830;
                              font-size:%(f)dpx; color:#e5e9ef;
                              selection-background-color:#2f5f9e; }
QTextEdit { font-family:'Cascadia Mono','Consolas','Microsoft YaHei UI'; }
QTableWidget { background:#191d23; alternate-background-color:#1f242b;
               gridline-color:#2e353e; border:1px solid #3b434e;
               border-radius:8px; font-size:%(f)dpx; color:#e5e9ef; }
QHeaderView::section { background:#2b313a; border:none;
                       border-right:1px solid #333a44;
                       border-bottom:1px solid #333a44;
                       padding:9px 10px; font-weight:bold; color:#cfd6df;
                       font-size:%(f)dpx; }
QSplitter::handle { background:#2e353e; }
QFrame#heightGrip { background:transparent; border:none; border-radius:6px; }
QFrame#heightGrip:hover { background:#2b313a; }
QCheckBox { spacing:9px; font-size:%(f)dpx; background:transparent; }
QCheckBox::indicator { width:19px; height:19px; border:1px solid #4a5563;
                       border-radius:4px; background:#191d23; }
QCheckBox::indicator:checked { background:#2f7fdd; border:1px solid #2f7fdd; }
QScrollArea { border:none; background:transparent; }
QScrollBar:vertical { background:transparent; width:14px; margin:2px; }
QScrollBar::handle:vertical { background:#48515d; border-radius:7px; min-height:34px; }
QScrollBar::handle:vertical:hover { background:#5c6675; }
QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical { height:0; }
QScrollBar:horizontal { background:transparent; height:14px; margin:2px; }
QScrollBar::handle:horizontal { background:#48515d; border-radius:7px; min-width:34px; }
QScrollBar::add-line:horizontal, QScrollBar::sub-line:horizontal { width:0; }
QToolTip { font-size:%(f)dpx; background:#2b313a; color:#e5e9ef;
           border:1px solid #3b434e; }
""" % {"f": FONT_PX}


QSS += "\nQLabel[role='sectionTitle'] { color:#1d3f6b; font-weight:bold; }\nQLabel[role='hint'] { color:#6b7280; }"
DARK_QSS += "\nQLabel[role='sectionTitle'] { color:#a8ceff; font-weight:bold; }\nQLabel[role='hint'] { color:#b6c2d2; }"


QSS += "\nQPushButton[compact='true'] { padding:0 10px; min-height:40px; }"
DARK_QSS += "\nQPushButton[compact='true'] { padding:0 10px; min-height:40px; }"


def apply_theme(win, dark):
    """切换浅色/深色：重设全局 QSS 与日志配色。"""
    app = QApplication.instance()
    if app is not None:
        app.setStyleSheet(DARK_QSS if dark else QSS)
    COLOR.clear()
    if dark:
        COLOR.update(DARK_COLOR)
    else:
        COLOR.update({"ok": "#0a7d2c", "err": "#c0392b", "warn": "#a15c00",
                      "info": C_ACCENT, "step": "#6b3fa0", "cmd": "#006060",
                      "dim": C_SUB, "text": C_TEXT})
    lp = getattr(win, "log_panel", None)
    if lp is not None and getattr(lp, "lines", None):
        lines = list(lp.lines)
        lp.txt.clear()
        lp.lines = []
        for s in lines:
            lp.append(s)
    if dark:
        lp and lp.txt.setStyleSheet(
            "QTextEdit{background:#191d23;border:1px solid #3b434e;"
            "border-radius:4px;font-size:%dpx;}" % FONT_MONO_PX)
    elif lp is not None:
        lp.txt.setStyleSheet(
            "QTextEdit{background:#fbfcfd;border:1px solid #d4d8dd;"
            "border-radius:4px;font-size:%dpx;}" % FONT_MONO_PX)


def read_caption_font(dpi=96):
    """Read-only Windows NONCLIENTMETRICS; dpi=96 produces Qt logical pixels."""
    if sys.platform=='win32':
        try:
            import ctypes
            from ctypes import wintypes
            class LOGFONTW(ctypes.Structure):
                _fields_=[('lfHeight',wintypes.LONG),('lfWidth',wintypes.LONG),
                    ('lfEscapement',wintypes.LONG),('lfOrientation',wintypes.LONG),
                    ('lfWeight',wintypes.LONG),('lfItalic',wintypes.BYTE),
                    ('lfUnderline',wintypes.BYTE),('lfStrikeOut',wintypes.BYTE),
                    ('lfCharSet',wintypes.BYTE),('lfOutPrecision',wintypes.BYTE),
                    ('lfClipPrecision',wintypes.BYTE),('lfQuality',wintypes.BYTE),
                    ('lfPitchAndFamily',wintypes.BYTE),('lfFaceName',wintypes.WCHAR*32)]
            class NONCLIENTMETRICSW(ctypes.Structure):
                _fields_=[('cbSize',wintypes.UINT),('iBorderWidth',ctypes.c_int),
                    ('iScrollWidth',ctypes.c_int),('iScrollHeight',ctypes.c_int),
                    ('iCaptionWidth',ctypes.c_int),('iCaptionHeight',ctypes.c_int),
                    ('lfCaptionFont',LOGFONTW),('iSmCaptionWidth',ctypes.c_int),
                    ('iSmCaptionHeight',ctypes.c_int),('lfSmCaptionFont',LOGFONTW),
                    ('iMenuWidth',ctypes.c_int),('iMenuHeight',ctypes.c_int),
                    ('lfMenuFont',LOGFONTW),('lfStatusFont',LOGFONTW),
                    ('lfMessageFont',LOGFONTW),('iPaddedBorderWidth',ctypes.c_int)]
            user32=ctypes.WinDLL('user32',use_last_error=True)
            metrics=NONCLIENTMETRICSW()
            metrics.cbSize=ctypes.sizeof(metrics)
            if hasattr(user32,'SystemParametersInfoForDpi'):
                get=user32.SystemParametersInfoForDpi
                get.argtypes=[wintypes.UINT,wintypes.UINT,ctypes.c_void_p,wintypes.UINT,wintypes.UINT]
                get.restype=wintypes.BOOL
                ok=get(0x29,metrics.cbSize,ctypes.byref(metrics),0,int(dpi))
                divisor=1
            else:
                get=user32.SystemParametersInfoW
                get.argtypes=[wintypes.UINT,wintypes.UINT,ctypes.c_void_p,wintypes.UINT]
                get.restype=wintypes.BOOL
                ok=get(0x29,metrics.cbSize,ctypes.byref(metrics),0)
                # Legacy metrics are system-DPI pixels. Query a screen DC to normalize.
                gdi32=ctypes.WinDLL('gdi32',use_last_error=True)
                user32.GetDC.argtypes=[wintypes.HWND]
                user32.GetDC.restype=wintypes.HDC
                user32.ReleaseDC.argtypes=[wintypes.HWND,wintypes.HDC]
                gdi32.GetDeviceCaps.argtypes=[wintypes.HDC,ctypes.c_int]
                dc=user32.GetDC(None)
                try:
                    actual=gdi32.GetDeviceCaps(dc,90) if dc else 96
                finally:
                    if dc:user32.ReleaseDC(None,dc)
                divisor=(actual or 96)/float(dpi)
            height=abs(metrics.lfCaptionFont.lfHeight)
            if ok and 0<height<=256:
                return dict(family=metrics.lfCaptionFont.lfFaceName or 'Microsoft YaHei UI',
                    pixels=max(1,round(height/divisor)),dpi=int(dpi),source='Windows caption font')
        except (OSError,ValueError,AttributeError):
            pass
    app=QApplication.instance()
    font=QFontDatabase.systemFont(QFontDatabase.TitleFont) if hasattr(QFontDatabase,'TitleFont') else app.font() if app else QFont()
    px=font.pixelSize()
    if px<=0:
        px=round(max(1,font.pointSizeF())*int(dpi)/72)
    return dict(family=font.family() or 'Microsoft YaHei UI',pixels=max(1,px or 12),
                dpi=int(dpi),source='Qt system title font fallback')


_UI_STYLE_BASES=None


def configure_title_typography(app):
    global FONT_PX,FONT_MONO_PX,QSS,DARK_QSS,_UI_STYLE_BASES
    metrics=read_caption_font(96)
    FONT_PX=FONT_MONO_PX=metrics['pixels']
    if _UI_STYLE_BASES is None:
        _UI_STYLE_BASES=(QSS,DARK_QSS)
    def sized(style):
        # All original widget dimensions were designed for 19px body text.
        scale=FONT_PX/19.0
        def dimensions(match):
            return str(max(1,round(int(match.group(1))*scale)))+'px'
        style=re.sub(r'(\d+)px',dimensions,style)
        return re.sub(r'font-size:\s*\d+px','font-size:%dpx'%FONT_PX,style)
    QSS,DARK_QSS=map(sized,_UI_STYLE_BASES)
    font=QFont(metrics['family'])
    font.setPixelSize(FONT_PX)
    app.setFont(font)
    app.setStyleSheet(QSS)
    return metrics


def window_sizes(available_width,available_height,font_px,frame_width=16,frame_height=40):
    """Preferred/minimum client sizes in logical pixels, excluding taskbar and frame."""
    margin=max(6,round(font_px*.65))
    limit_width=max(1,int(available_width)-2*margin-max(0,frame_width))
    limit_height=max(1,int(available_height)-2*margin-max(0,frame_height))
    density=font_px/14.0
    minimum=(min(limit_width,max(440,round(700*density))),
             min(limit_height,max(300,round(460*density))))
    preferred=(min(limit_width,max(minimum[0],min(round(available_width*.82),round(1400*density)))),
               min(limit_height,max(minimum[1],min(round(available_height*.84),round(880*density)))))
    return preferred,minimum


class APP(QApplication):
    pass


def main():
    QApplication.setAttribute(Qt.AA_EnableHighDpiScaling,True)
    QApplication.setAttribute(Qt.AA_UseHighDpiPixmaps,True)
    if hasattr(QApplication,'setHighDpiScaleFactorRoundingPolicy') and hasattr(Qt,'HighDpiScaleFactorRoundingPolicy'):
        QApplication.setHighDpiScaleFactorRoundingPolicy(Qt.HighDpiScaleFactorRoundingPolicy.PassThrough)
    app = QApplication(sys.argv)
    app.setWindowIcon(create_app_icon())
    w = MainWindow()
    w.show()
    sys.exit(app.exec_())


if __name__ == "__main__":
    main()
