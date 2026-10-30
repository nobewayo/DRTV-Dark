"""Strict, size-preserving Android resource inspection (no Android rebuild)."""
import struct
from dataclasses import dataclass


def require(ok, message):
    if not ok:
        raise ValueError(message)


def chunks(data, start, end):
    p = start
    while p < end:
        require(p + 8 <= end, "Truncated chunk")
        kind, header, size = struct.unpack_from("<HHI", data, p)
        require(header >= 8 and size >= header and p + size <= end and size % 4 == 0,
                f"Invalid chunk at {p:#x}")
        yield p, kind, header, size
        p += size
    require(p == end, "Chunk boundary mismatch")


def string_pool(data, p):
    kind, header, size = struct.unpack_from("<HHI", data, p)
    require(kind == 1 and header >= 28, "Invalid string pool")
    count, styles, flags, start, style_start = struct.unpack_from("<5I", data, p + 8)
    require(header + 4 * (count + styles) <= start <= size, "Bad string offsets")
    end = p + (style_start or size)
    result = []

    def length(pos, wide):
        width, mask = (2, 0x8000) if wide else (1, 0x80)
        require(pos + width <= end, "Truncated string length")
        n = int.from_bytes(data[pos:pos + width], "little")
        pos += width
        if n & mask:
            require(pos + width <= end, "Truncated long length")
            n = ((n & ~mask) << (15 if wide else 8)) | int.from_bytes(data[pos:pos + width], "little")
            pos += width
        return n, pos

    for i in range(count):
        pos = p + start + struct.unpack_from("<I", data, p + header + 4 * i)[0]
        require(p + start <= pos < end, "String out of bounds")
        n, pos = length(pos, not flags & 0x100)
        if flags & 0x100:
            n, pos = length(pos, False)
            width, encoding = 1, "utf-8"
        else:
            width, encoding = 2, "utf-16le"
        require(pos + n * width + width <= end, "Truncated string")
        require(data[pos + n * width:pos + n * width + width] == bytes(width), "Missing string terminator")
        result.append(bytes(data[pos:pos + n * width]).decode(encoding))
    return result


@dataclass(frozen=True)
class Value:
    resource_id: int
    name: str
    config: str
    attribute: int | None
    offset: int
    type: int
    data: int


class Table:
    def __init__(self, data):
        self.data = data
        self.values = []
        self.entries = {}
        kind, header, size = struct.unpack_from("<HHI", data)
        require(kind == 2 and header >= 12 and size == len(data), "Bad table header")
        packages = 0
        globals_ = None
        for p, kind, ph, ps in chunks(data, header, size):
            if kind == 1:
                require(globals_ is None, "Duplicate global pool")
                globals_ = string_pool(data, p)
            elif kind == 0x200:
                packages += 1
                require(ph >= 284, "Short package header")
                package = struct.unpack_from("<I", data, p + 8)[0]
                types = string_pool(data, p + struct.unpack_from("<I", data, p + 268)[0])
                keys = string_pool(data, p + struct.unpack_from("<I", data, p + 276)[0])
                type_offset = struct.unpack_from("<I", data, p + 284)[0] if ph >= 288 else 0
                specs = {}
                seen_configs = set()
                for q, ct, ch, cs in chunks(data, p + ph, p + ps):
                    if ct == 0x202:
                        tid = data[q + 8]
                        count = struct.unpack_from("<I", data, q + 12)[0]
                        require(tid not in specs and ch + count * 4 <= cs, "Duplicate/malformed type spec")
                        specs[tid] = count
                    elif ct == 0x201:
                        tid, flags = data[q + 8:q + 10]
                        require(flags == 0, "Unsupported sparse/16-bit type offsets")
                        count, start = struct.unpack_from("<II", data, q + 12)
                        config_size = struct.unpack_from("<I", data, q + 20)[0]
                        require(config_size >= 4 and 20 + config_size <= ch, "Bad config size")
                        config = bytes(data[q + 20:q + 20 + config_size]).hex()
                        require((tid, config) not in seen_configs, "Duplicate type/config")
                        seen_configs.add((tid, config))
                        require(tid in specs and count <= specs[tid] and 0 < tid <= len(types), "Bad type index/count")
                        require(ch + count * 4 <= start <= cs, "Bad entry index bounds")
                        indexed = []
                        for index in range(count):
                            off = struct.unpack_from("<I", data, q + ch + 4 * index)[0]
                            if off != 0xffffffff:
                                require(off % 4 == 0 and q + start + off + 8 <= q + cs, "Bad entry offset")
                                indexed.append((off, index))
                        indexed.sort()
                        require(len({o for o, _ in indexed}) == len(indexed), "Aliased entry offsets")
                        for n, (off, index) in enumerate(indexed):
                            e = q + start + off
                            boundary = q + start + indexed[n + 1][0] if n + 1 < len(indexed) else q + cs
                            es, ef, key = struct.unpack_from("<HHI", data, e)
                            require(not ef & ~7 and not ef & 8, "Unsupported entry flags")
                            require(es >= (16 if ef & 1 else 8) and e + es <= boundary and key < len(keys), "Bad entry header")
                            rid = (package << 24) | ((tid + type_offset) << 16) | index
                            name = f"{types[tid - 1]}/{keys[key]}"
                            require((rid, config) not in self.entries, "Duplicate resource/config")
                            self.entries[rid, config] = (name, e, boundary, bool(ef & 1))
                            if ef & 1:
                                maps = struct.unpack_from("<I", data, e + 12)[0]
                                require(e + es + maps * 12 <= boundary, "Map crosses entry boundary")
                                seen_attrs = set()
                                for m in range(maps):
                                    pos = e + es + m * 12
                                    attr = struct.unpack_from("<I", data, pos)[0]
                                    require(attr not in seen_attrs, "Duplicate complex attribute")
                                    seen_attrs.add(attr)
                                    self._value(rid, name, config, attr, pos + 4, boundary)
                            else:
                                self._value(rid, name, config, None, e + es, boundary)
        require(packages == struct.unpack_from("<I", data, 8)[0] and globals_ is not None, "Package count/global pool mismatch")
        for v in self.values:
            if v.type == 3:
                require(v.data < len(globals_), "Global string index out of range")

    def _value(self, rid, name, config, attr, pos, boundary):
        require(pos + 8 <= boundary, "Value crosses entry boundary")
        size, reserved, typ, value = struct.unpack_from("<HBBI", self.data, pos)
        require(size == 8 and reserved == 0, "Invalid typed value")
        self.values.append(Value(rid, name, config, attr, pos, typ, value))


def xml_values(data):
    """Yield typed XML attributes with verified element and framework attribute IDs."""
    kind, header, size = struct.unpack_from("<HHI", data)
    require(kind == 3 and size == len(data), "Bad binary XML header")
    strings, resources, stack, result = None, [], [], []
    for p, kind, h, s in chunks(data, header, size):
        if kind == 1:
            require(strings is None, "Duplicate XML string pool")
            strings = string_pool(data, p)
        elif kind == 0x180:
            resources = list(struct.unpack_from(f"<{(s-h)//4}I", data, p + h))
        elif kind == 0x102:
            require(strings is not None and h == 16 and s >= 36, "Bad start element")
            name = struct.unpack_from("<I", data, p + 20)[0]
            start, width, count = struct.unpack_from("<HHH", data, p + 24)
            require(name < len(strings) and width == 20 and start >= 20 and 16 + start + width * count <= s, "Bad XML attributes")
            stack.append(strings[name])
            for i in range(count):
                pos = p + 16 + start + i * width
                ns, attr, raw, vs, reserved, typ, value = struct.unpack_from("<IIIHBBI", data, pos)
                require(attr < len(strings) and vs == 8 and reserved == 0, "Bad XML value")
                result.append(dict(element=strings[name], path="/".join(stack), attribute=resources[attr] if attr < len(resources) else 0,
                                   attribute_name=strings[attr], offset=pos + 12, type=typ, data=value))
        elif kind == 0x103:
            name = struct.unpack_from("<I", data, p + 20)[0]
            require(stack and name < len(strings) and stack.pop() == strings[name], "XML nesting mismatch")
    require(not stack, "Unclosed XML element")
    return result
