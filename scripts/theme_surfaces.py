"""Scoped structural surfaces and dialog selectors after the accepted 114-site theme."""
if not __debug__: raise RuntimeError('Optimized Python is unsupported for signing/theme validation')
import struct
from product_common import ROOT,run,save,sha
from resources import Table, chunks, xml_values

XML_FILES = ('res/layout/fragment_sports_detail.xml',
             'res/layout/drshe1_view_holder.xml', 'res/layout-v22/drshe1_view_holder.xml')


def window_background(source):
    table = Table(source)
    entries = [(key, entry) for key, entry in table.entries.items() if entry[0] == 'style/ActivityTheme']
    assert len(entries) == 1
    (rid, config), (_, e, boundary, complex_) = entries[0]
    assert complex_ and not any(v.resource_id == rid and v.attribute == 0x1010054 for v in table.values)
    es = struct.unpack_from('<H', source, e)[0]
    count = struct.unpack_from('<I', source, e + 12)[0]
    assert es == 16 and count == 7
    result = bytearray(source)
    # Insert the framework windowBackground map in sorted attribute order.
    at = e + es
    result[at:at] = struct.pack('<IHBBI', 0x1010054, 8, 0, 28, 0xff121212)
    struct.pack_into('<I', result, e + 12, count + 1)
    for p, kind, ph, ps in chunks(source, 12, len(source)):
        if kind != 0x200 or not p <= e < p + ps:
            continue
        struct.pack_into('<I', result, p + 4, ps + 12)
        for q, ct, ch, cs in chunks(source, p + ph, p + ps):
            if ct != 0x201 or not q <= e < q + cs:
                continue
            n, start = struct.unpack_from('<II', source, q + 12)
            for i in range(n):
                offset = struct.unpack_from('<I', source, q + ch + i * 4)[0]
                if offset != 0xffffffff and q + start + offset >= at:
                    struct.pack_into('<I', result, q + ch + i * 4, offset + 12)
            struct.pack_into('<I', result, q + 4, cs + 12)
    struct.pack_into('<I', result, 4, len(result))
    before = {(v.resource_id, v.config, v.attribute): (v.name, v.type, v.data) for v in table.values}
    after = {(v.resource_id, v.config, v.attribute): (v.name, v.type, v.data) for v in Table(result).values}
    assert after.pop((rid, config, 0x1010054)) == ('style/ActivityTheme', 28, 0xff121212)
    assert after == before, 'Unrelated resource changed during map insertion'
    return bytes(result), dict(id='b14-window', file='resources.arsc', kind='resource', resourceId=rid,
                              name='style/ActivityTheme', config=config, attribute=0x1010054, color=0xff121212)


def extend(targets, archive, plan, out):
    source = targets['resources.arsc']
    result = bytearray(source)
    rows = [v for v in Table(source).values if v.name == 'color/bg_dialog_fullscreen']
    assert len(rows) == 1
    v = rows[0]
    assert (v.type, v.data) == (1, 0x7f0600e5)
    struct.pack_into('<HBBI', result, v.offset, 8, 0, 28, 0xff242424)
    new, window = window_background(bytes(result))
    targets['resources.arsc'] = new
    sites = [dict(id='b14-dialog', file='resources.arsc', kind='resource', resourceId=v.resource_id,
                  name=v.name, config=v.config, attribute=None, color=0xff242424), window]
    for i, name in enumerate(XML_FILES):
        source = archive.read(name)
        rows = [v for v in xml_values(source) if v['attribute'] == 0x10100d4 and
                (v['type'], v['data']) == (1, 0x7f06064f)]
        assert len(rows) == 1
        v = rows[0]; result = bytearray(source)
        color = 0xff121212 if i == 0 else 0xff242424
        struct.pack_into('<HBBI', result, v['offset'], 8, 0, 28, color)
        targets[name] = bytes(result)
        assert [n for n, (a, b) in enumerate(zip(source, result)) if a != b] and len(result) == len(source)
        sites.append(dict(id=f'b14-sports-{i}', file=name, kind='xml-background', path=v['path'],
                          offset=v['offset'], attribute=0x10100d4, color=color))
    # The native frame exposed a black unfocused button on the new dark dialog.
    # Override only these two properties, retaining BtnSecondaryLight's textAllCaps,
    # dimensions and the existing Dark selectors' focused/disabled state semantics.
    name='res/layout/custom_dialog_fragment_item_simple_layout.xml'
    source=archive.read(name);values=xml_values(source)
    assert len(values)==3 and any(v['attribute_name']=='style' and (v['type'],v['data'])==(1,0x7f150141) for v in values)
    element=[v for v in values if v['attribute']==0x10100d0];assert len(element)==1
    specs=[]
    for attr,label,ref in [(0x1010098,'textColor',0x7f060609),(0x10100d4,'background',0x7f08009d)]:
        specs.append(dict(path='TextView',element_id=element[0]['data'],attribute=attr,attribute_name=label,
                          replacement=[1,ref],source_sha256=sha(source)))
    source_path=out/'dialog-source.xml';source_path.write_bytes(source)
    save(out/'dialog-selectors.json',specs);target_path=out/'dialog-target.xml'
    js="import fs from 'node:fs/promises';import {addAttributes} from './site/xml.mjs';const [a,b,c]=process.argv.slice(1);await fs.writeFile(c,await addAttributes(new Uint8Array(await fs.readFile(a)),JSON.parse(await fs.readFile(b,'utf8'))));"
    run(['node','--input-type=module','-e',js,source_path,out/'dialog-selectors.json',target_path])
    targets[name]=target_path.read_bytes()
    for spec,label in zip(specs,('text','control')):
        rows=[v for v in xml_values(targets[name]) if v['attribute']==spec['attribute']]
        assert len(rows)==1 and (rows[0]['type'],rows[0]['data'])==tuple(spec['replacement'])
        v=rows[0];sites.append(dict(id='b14-dialog-'+label,file=name,kind='xml-reference',path='TextView',
                                  offset=v['offset'],attribute=v['attribute'],reference=v['data']))
    plan['sites'].extend(sites); plan['totalSites'] = 121
    return plan
