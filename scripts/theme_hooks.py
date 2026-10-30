"""Offline B13 extension of the immutable 110-site B2 recipe."""
import hashlib,struct,sys
from pathlib import Path
from product_common import ROOT,run,sha
sys.path.insert(0,str(ROOT/'tools'))
from resources import Table
from dex import index

IDENTITY_DEX_SHA256='921495f078611cad529267084012b2f91bfc33e5c5f0922cb5adc4f2fe579648'
METHODS={
 'Laxis/androidtv/sdk/app/template/pageentry/hero/viewholder/H9ViewHolder;->bindPageEntry()V':('header',1),
 'Laxis/androidtv/sdk/app/template/pageentry/editorial/viewholder/Ed1ViewHolder;->bindPageEntry()V':('promotion',1),
}
def extend(out,targets,cp,log):
    source=targets['classes4.dex'];assert sha(source)==IDENTITY_DEX_SHA256,'Exact B12 identity DEX required'
    path=out/'theme-input.dex';path.write_bytes(source)
    run(['javac','-cp',cp+':'+str(out/'java'),'-d',out/'java',ROOT/'tools/ThemeHooks.java'],log=log)
    changed=out/'theme-output.dex'
    audit=run(['java','-cp',cp+':'+str(out/'java'),'ThemeHooks',path,changed],log=log).stdout
    assert b'PASS\t2 presentation hook sites' in audit
    (out/'theme-dex-audit.txt').write_bytes(audit)
    target=changed.read_bytes();targets['classes4.dex']=target;sites=[]
    for signature,(hook,count) in METHODS.items():
        method=index(changed,[signature])[signature]
        matches=[i for i in method['instructions'] if i['reference']=='Lorg/drtvdark/watchdog/ThemeCorrections;->'+hook+'(Ljava/lang/Object;)V']
        assert len(matches)==count
        start=method['offset']+16;digest=sha(target[start:start+2*method['units']])
        for n,i in enumerate(matches,1):
            assert i['opcode']=='invoke-static/range' and i['units']==3
            sites.append({'id':f'b13-{hook}-{n}','file':'classes4.dex','kind':'dex-hook','method':signature,
                          'code':method['offset'],'units':method['units'],'methodSha256':digest,
                          'offset':i['offset'],'instruction':target[i['offset']:i['offset']+6].hex()})
    source=targets['resources.arsc'];table=Table(source);result=bytearray(source);offsets=set()
    for suffix,expected in [('text',0x7f060076),('subtext',0x7f060587)]:
        name='style/DRST1Item'+('Text' if suffix=='text' else 'SubText')
        rows=[v for v in table.values if v.name==name and v.attribute==0x1010098]
        assert len(rows)==1;v=rows[0]
        # The complete original admission and B2 payload digest already bind this table.
        assert (v.type,v.data)==(1,expected)
        sites.append({'id':'b13-sport-'+suffix,'file':'resources.arsc','kind':'resource','resourceId':v.resource_id,
                      'name':name,'config':v.config,'color':0xffeeeeee,'before':[v.type,v.data]})
        struct.pack_into('<HBBI',result,v.offset,8,0,28,0xffeeeeee);offsets.add(v.offset)
    after=Table(bytes(result));assert len(after.values)==len(table.values)
    for a,b in zip(table.values,after.values):
        if a.offset not in offsets:assert a==b,'Unrelated resource changed'
    targets['resources.arsc']=bytes(result)
    return {'schema':1,'baselineSites':110,'totalSites':114,'sites':sites,
            'authoredSourceSha256':sha((ROOT/'notifier/src/org/drtvdark/watchdog/ThemeCorrections.java').read_bytes())}
