"""Audited compiled-resource transformations for the isolated coexistence candidate."""
if not __debug__:
    raise RuntimeError('Optimized Python is unsupported for identity validation')
import struct
from resources import chunks,string_pool,xml_values,Table
OLD="dk.dr.tvplayer"
DARK="io.github.nobewayo.drtvdark"
MAPPING={OLD:DARK,
 OLD+".templates.page.search.SearchSuggestionsProvider":DARK+".templates.page.search.SearchSuggestionsProvider",
 OLD+".firebaseinitprovider":DARK+".firebaseinitprovider",
 OLD+".firebaseperfprovider":DARK+".firebaseperfprovider",
 OLD+".DYNAMIC_RECEIVER_NOT_EXPORTED_PERMISSION":DARK+".DYNAMIC_RECEIVER_NOT_EXPORTED_PERMISSION",
 OLD+".drtv_dark_startup":DARK+".drtv_dark_startup",
 "tvrecommendation":DARK+".recommendation"}

def pool_bytes(original, values):
    _,header,_=struct.unpack_from('<HHI',original)
    count,styles,flags,start,style_start=struct.unpack_from('<5I',original,8)
    assert header==28 and styles==0 and style_start==0
    utf8=bool(flags&256)
    def length(n,wide):
        assert n<32768
        return struct.pack('<H',n) if wide else (bytes([n]) if n<128 else bytes([128|(n>>8),n&255]))
    data=bytearray();offsets=[]
    for value in values:
        offsets.append(len(data))
        raw=value.encode('utf-8' if utf8 else 'utf-16le')
        data.extend(length(len(value.encode('utf-16le'))//2,not utf8))
        if utf8:data.extend(length(len(raw),False))
        data.extend(raw);data.extend(bytes(1 if utf8 else 2))
    data.extend(bytes(-len(data)%4))
    result=bytearray(original[:28])+struct.pack('<'+'I'*len(offsets),*offsets)+data
    struct.pack_into('<I',result,4,len(result));struct.pack_into('<I',result,8,len(values))
    struct.pack_into('<I',result,16,flags&~1);struct.pack_into('<I',result,20,28+len(values)*4)
    assert string_pool(result,0)==values
    return bytes(result)

def patch_xml(source,labels=False):
    header=struct.unpack_from('<H',source,2)[0]
    parts=list(chunks(source,header,len(source)))
    pool=next((p,h,s) for p,k,h,s in parts if k==1)
    p,h,s=pool; old_strings=string_pool(source,p)
    new_strings=[MAPPING.get(v,v) for v in old_strings]
    if not labels and new_strings==old_strings:return source,[]
    body=bytearray(source);label_offsets=set()
    if labels:
        new_strings.append('DRTV Dark');index=len(new_strings)-1
        for q,k,nh,ns in parts:
            if k!=0x102:continue
            vals=[v for v in xml_values(source) if q<=v['offset']<q+ns]
            path=vals[0]['path'] if vals else ''
            selected=path=='manifest/application' or (path=='manifest/application/activity' and any(
                v['attribute_name']=='name' and v['type']==3 and old_strings[v['data']]=='axis.androidtv.sdk.app.MainActivity' for v in vals))
            if selected:
                matches=[v for v in vals if v['attribute_name']=='label'];assert len(matches)==1
                at=matches[0]['offset'];struct.pack_into('<I',body,at-4,index);body[at+3]=3;struct.pack_into('<I',body,at+4,index)
                label_offsets.add(at)
        assert len(label_offsets)==2
    new_pool=pool_bytes(source[p:p+s],new_strings)
    result=body[:p]+new_pool+body[p+s:]
    struct.pack_into('<I',result,4,len(result))
    before=xml_values(source);after=xml_values(result)
    assert len(before)==len(after)
    audit=[]
    for a,b in zip(before,after):
        assert (a['path'],a['attribute'],a['attribute_name'])==(b['path'],b['attribute'],b['attribute_name'])
        old=old_strings[a['data']] if a['type']==3 else a['data']
        expected='DRTV Dark' if a['offset'] in label_offsets else MAPPING.get(old,old) if isinstance(old,str) else old
        actual=new_strings[b['data']] if b['type']==3 else b['data']
        assert actual==expected and b['type']==(3 if a['offset'] in label_offsets else a['type'])
        if old!=actual:audit.append({'path':a['path'],'attribute':a['attribute_name'],'before':old,'after':actual})
    return bytes(result),audit

def isolate_filters(source):
    """Keep normal TV device-code auth; stop claiming official browser callbacks/URLs."""
    header=struct.unpack_from('<H',source,2)[0];parts=list(chunks(source,header,len(source)))
    p=next(p for p,k,h,s in parts if k==1);pool=string_pool(source,p);values=xml_values(source)
    stack=[];activity=None;begin=None;remove=[];export_offset=None
    for p,k,h,s in parts:
        if k==0x102:
            tag=pool[struct.unpack_from('<I',source,p+20)[0]];stack.append(tag)
            if stack==['manifest','application','activity']:
                attrs=[v for v in values if p<=v['offset']<p+s]
                activity=next(pool[v['data']] for v in attrs if v['attribute_name']=='name')
                if activity=='net.openid.appauth.RedirectUriReceiverActivity':
                    v=next(v for v in attrs if v['attribute_name']=='exported');assert (v['type'],v['data'])==(18,0xffffffff);export_offset=v['offset']
            if tag=='intent-filter' and len(stack)==4:begin=p
        elif k==0x103:
            tag=pool[struct.unpack_from('<I',source,p+20)[0]]
            if tag=='intent-filter' and len(stack)==4:
                assert begin is not None
                schemes=[pool[v['data']] for v in values if begin<=v['offset']<p+s and v['attribute_name']=='scheme']
                if activity=='net.openid.appauth.RedirectUriReceiverActivity' or (activity=='axis.androidtv.sdk.app.MainActivity' and schemes and set(schemes)<={'http','https'}):
                    remove.append((begin,p+s,activity,schemes))
                begin=None
            if stack==['manifest','application','activity']:activity=None
            assert stack.pop()==tag
    assert not stack and export_offset is not None and len(remove)==5,remove
    body=bytearray(source);struct.pack_into('<I',body,export_offset+4,0)
    result=body[:header]
    for p,k,h,s in parts:
        if not any(a<=p<b for a,b,_,_ in remove):result.extend(body[p:p+s])
    struct.pack_into('<I',result,4,len(result))
    expected=[v for v in values if not any(a<=v['offset']<b for a,b,_,_ in remove)]
    actual=xml_values(result);assert len(expected)==len(actual)
    for a,b in zip(expected,actual):
        for key in ('path','attribute','attribute_name','type'):assert a[key]==b[key]
        assert b['data']==(0 if a['offset']==export_offset else a['data'])
    return bytes(result),{'removedImplicitFilters':[{'activity':a,'schemes':s} for _,_,a,s in remove],
                          'legacyMobileCallbackExported':False,'normalTvDeviceAuthorizationUnchanged':True}

def patch_arsc(source,search_provider):
    before=Table(source);out=bytearray(source);count=0
    for p,k,h,s in chunks(source,struct.unpack_from('<H',source,2)[0],len(source)):
        if k==0x200:
            raw=source[p+12:p+268]
            assert raw.decode('utf-16le').rstrip('\0')==OLD
            replacement=DARK.encode('utf-16le');assert len(replacement)<256
            out[p+12:p+268]=replacement+bytes(256-len(replacement));count+=1
    assert count==1
    after=Table(out);assert before.values==after.values and before.entries==after.entries
    if not search_provider:return bytes(out)
    # search_provider is a string resource, not a literal in searchable.xml.
    p,h,s=next((p,h,s) for p,k,h,s in chunks(out,struct.unpack_from('<H',out,2)[0],len(out)) if k==1)
    strings=string_pool(out,p);matches=[i for i,v in enumerate(strings) if v==OLD]
    assert len(matches)==1 and matches[0]==2898
    assert {v.name for v in before.values if v.type==3 and v.data==2898}=={'string/search_provider'}
    pool=bytearray(out[p:p+s]);count,styles,flags,start,style_start=struct.unpack_from('<5I',pool,8)
    assert flags&256 and styles==1 and style_start>start
    raw=DARK.encode();assert len(raw)<128
    extra=bytes([len(DARK),len(raw)])+raw+b'\0';extra+=bytes(-len(extra)%4)
    replacement=pool[:style_start]+extra+pool[style_start:]
    struct.pack_into('<I',replacement,4,len(replacement));struct.pack_into('<I',replacement,16,flags&~1)
    struct.pack_into('<I',replacement,24,style_start+len(extra))
    struct.pack_into('<I',replacement,h+4*2898,style_start-start)
    expected=strings[:];expected[2898]=DARK
    assert string_pool(replacement,0)==expected
    out=out[:p]+replacement+out[p+s:];struct.pack_into('<I',out,4,len(out))
    after=Table(out)
    semantic=lambda t:[(v.resource_id,v.name,v.config,v.attribute,v.type,v.data) for v in t.values]
    assert semantic(before)==semantic(after)
    for key,(name,at,end,complex_) in before.entries.items():
        assert after.entries[key]==(name,at+len(extra),end+len(extra),complex_)
    return bytes(out)
