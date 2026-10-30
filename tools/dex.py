"""Narrow, instruction-verified UI color edits without rebuilding bytecode."""
import hashlib
from pathlib import Path
import struct
import subprocess
import tempfile
import zlib

from resources import require

ROOT = Path(__file__).resolve().parents[1]


def verify_header(data):
    require(data[:8] in (b"dex\n035\0", b"dex\n037\0", b"dex\n038\0", b"dex\n039\0"), "Unexpected DEX magic")
    require(struct.unpack_from("<III", data, 32) == (len(data), 112, 0x12345678), "Invalid DEX header")
    require(data[12:32] == hashlib.sha1(data[32:]).digest(), "Invalid DEX SHA1")
    require(struct.unpack_from("<I", data, 8)[0] == zlib.adler32(data[12:]) & 0xffffffff, "Invalid DEX Adler32")


def index(path, signatures):
    p = subprocess.run(["java", "-cp", str(ROOT / "tools/apktool.jar") + ":" + str(ROOT / "build/java"),
                        "DexIndex", str(path), *signatures], capture_output=True, text=True)
    require(p.returncode == 0, "dexlib instruction validation failed")
    result, current = {}, None
    for line in p.stdout.splitlines():
        fields = line.split("\t")
        if fields[0] == "M":
            _, signature, offset, units, tries, method_index = fields
            require(signature not in result, "Duplicate DEX method")
            current = result[signature] = {"offset": int(offset), "units": int(units), "tries": int(tries), "index": int(method_index), "instructions": []}
        elif fields[0] == "I":
            require(current is not None, "Instruction without owner")
            current["instructions"].append({"offset": int(fields[1]), "opcode": fields[2], "units": int(fields[3]),
                                             "literal": None if fields[4] == "-" else int(fields[4]), "reference": fields[5]})
    if signatures == ["--verify"]:
        require("VERIFIED\t" in p.stdout, "No DEX verification result")
    return result


def patch_dex(source, specs):
    verify_header(source)
    require(specs, "No DEX specifications")
    signatures = [s["method"] for s in specs]
    require(len(signatures) == len(set(signatures)), "Duplicate DEX method patch")
    signatures = sorted(set(signatures + [s[k] for s in specs if s["action"] == "invoke_reference" for k in ("expected", "replacement")]))
    with tempfile.TemporaryDirectory(prefix="dex-", dir=ROOT / "build") as directory:
        path = Path(directory) / "input.dex"
        path.write_bytes(source)
        methods = index(path, signatures)
        require(set(methods) == set(signatures), "Missing DEX method")
        result, touched, audit = bytearray(source), set(), []
        for spec in specs:
            method = methods[spec["method"]]
            start, end = method["offset"] + 16, method["offset"] + 16 + method["units"] * 2
            require(hashlib.sha256(source[start:end]).hexdigest() == spec["code_sha256"], "Method source changed")
            instructions = method["instructions"]
            require(instructions and instructions[0]["offset"] == start, "Method boundary mismatch")
            require(instructions[-1]["offset"] + instructions[-1]["units"] * 2 == end, "Method length mismatch")
            if spec["action"] in ("resource_constant", "resource_constants"):
                constants = [spec] if spec["action"] == "resource_constant" else spec["constants"]
                require(constants, "No DEX resource constants")
                for constant in constants:
                    matches = [i for i in instructions if i["opcode"] == "const" and i["literal"] == int(constant["expected"], 0)]
                    require(len(matches) == 1, "Missing/duplicate DEX color constant")
                    instruction = matches[0]
                    pos = instruction["offset"]
                    require(source[pos] == 0x14 and instruction["units"] == 3, "Not a const/31i instruction")
                    pos += 2
                    replacement = struct.pack("<I", int(constant["replacement"], 0))
                    span = set(range(pos, pos + 4))
                    require(not span.intersection(touched), "Overlapping DEX patches")
                    touched.update(span)
                    result[pos:pos + 4] = replacement
                    audit.append({**spec, "constant": {k: constant[k] for k in ("expected", "replacement")},
                                  "offset": pos, "original_hex": source[pos:pos + 4].hex(), "replacement_hex": replacement.hex()})
                continue
            elif spec["action"] == "skip_color_override":
                require(spec["method"].endswith(")V") and method["tries"] == 0, "Only pure void color methods without handlers may be skipped")
                pos = start
                # Replace exactly the first complete instruction. Remaining original instructions retain their boundaries.
                replacement = b"\x0e\x00" + bytes(instructions[0]["units"] * 2 - 2)
            elif spec["action"] == "invoke_reference":
                matches = [i for i in instructions if i["opcode"] == "invoke-static" and i["reference"] == spec["expected"]]
                require(len(matches) == spec["matches"], "Unexpected color getter call count")
                require(spec["expected"].split("(")[1] == spec["replacement"].split("(")[1], "Getter signatures differ")
                for instruction in matches:
                    pos = instruction["offset"] + 2
                    require(source[pos - 2] == 0x71 and struct.unpack_from("<H", source, pos)[0] == methods[spec["expected"]]["index"], "Wrong invoke-static operand")
                    span = set(range(pos, pos + 2))
                    require(not span.intersection(touched), "Overlapping getter patches")
                    touched.update(span)
                    replacement = struct.pack("<H", methods[spec["replacement"]]["index"])
                    result[pos:pos + 2] = replacement
                    audit.append({**spec, "offset": pos, "original_hex": source[pos:pos + 2].hex(), "replacement_hex": replacement.hex()})
                continue
            else:
                raise ValueError("Unknown DEX patch action")
            span = set(range(pos, pos + len(replacement)))
            require(not span.intersection(touched), "Overlapping DEX patches")
            touched.update(span)
            result[pos:pos + len(replacement)] = replacement
            audit.append({**spec, "offset": pos, "original_hex": source[pos:pos + len(replacement)].hex(), "replacement_hex": replacement.hex()})
        require(len(source) == len(result), "DEX size changed")
        require(all(a == b or i in touched for i, (a, b) in enumerate(zip(source, result))), "Undeclared DEX byte change")
        result[12:32] = hashlib.sha1(result[32:]).digest()
        struct.pack_into("<I", result, 8, zlib.adler32(result[12:]) & 0xffffffff)
        verify_header(result)
        path.write_bytes(result)
        index(path, ["--verify"])
        after = index(path, signatures)
        require({s: (m["offset"], m["units"], m["tries"]) for s, m in methods.items()} ==
                {s: (m["offset"], m["units"], m["tries"]) for s, m in after.items()}, "DEX structure changed")
    return bytes(result), audit
