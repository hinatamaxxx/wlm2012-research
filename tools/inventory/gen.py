# Render decoded ribbon trees as Markdown checklist rows (with image IDs and optional status annotations from a look-alike app).
import sys; sys.path.insert(0, __import__("os").path.dirname(__import__("os").path.abspath(__file__)))
import sys,json,csv,bmllib as B
KIND={0x24:'Ribbon',0x13:'ApplicationMenu',0x1a:'Tab',0x1b:'TabGroup(contextual)',0x07:'Group',0x26:'(sizing)',0x0f:'Button',0x14:'DropDownButton',
      0x12:'SplitButton',0x06:'ToggleButton',0x15:'Gallery',0x18:'MenuGroup',0x19:'(separator?)',0x25:'QAT',0x34:'QAT customize menu',0x0d:'CheckBox?'}
fn,name,annot=sys.argv[1],sys.argv[2],sys.argv[3]
B.init(fn,'out/maillang.dll.mui/strings.tsv')
cmds={}
for r in csv.DictReader(open(f'ribbons/{name}.commands.tsv'),delimiter='\t'): cmds[int(r['cmd'])]=r
large={int(k):v for k,v in json.load(open('large-image-map.json')).items()}
ev=json.load(open('ev/mailres2.dll.json'))
img={x['name']['id'] for x in ev['normalized_result']['resources'] if x['type'].get('id')==4000 and x['name']['kind']!='name'}
A=json.load(open(annot)) if annot!='-' else {}
def sid(r,k):
    v=r.get(k,'') if r else ''
    return v.split(':',1)[0] if v else ''
def txt(r,k):
    v=r.get(k,'') if r else ''
    return v.split(':',1)[1].replace('\\n',' ').strip() if v else ''
MODES={2:'mail',4:'news',8:'feeds',16:'calendar',32:'contacts',14:'mail+news+feeds',62:'all',6:'mail+news',10:'mail+feeds',126:'all',1073741824:'signed-out',2147483648:'signed-in',1048576:'IMAP account'}
rows=[]
MAILTABS={'app','qat','top','10552','12400','12800','13200'}
def walk(e,path,depth,tab='top'):
    cmd=None;attrs={}
    for pr in e['props']:
        if pr[0]=='a':
            if pr[1]==0 and pr[2] in (2,3): cmd=pr[3]
            else: attrs[pr[1]]=pr[3]
    k=KIND.get(e['type'],f"T{e['type']:#x}")
    if k=='Tab': tab=str(cmd)
    if k=='ApplicationMenu': tab='app'
    if k=='QAT': tab='qat'
    r=cmds.get(cmd)
    if k not in ('(sizing)','MenuGroup','Ribbon') and cmd is not None and cmd<65000:
        mode=MODES.get(attrs.get(0x3d),attrs.get(0x3d,'')) if 0x3d in attrs else ''
        sm=str(cmd) if cmd in img else ''
        lg=str(large.get(cmd,''))
        a=A.get(f'{tab}:{cmd}') or (A.get(str(cmd),{}) if tab in MAILTABS else {'status':'対象外 (別機能のホーム タブ)'})
        rows.append([ '　'*depth+(txt(r,'label(1)') or '(runtime label)'), k, str(cmd), sid(r,'keytip(7)') and txt(r,'keytip(7)'),
            (sid(r,'tooltipTitle(8)')+' '+txt(r,'tooltipTitle(8)')).strip(), sid(r,'tooltipDesc(9)'), sm, lg, str(mode), a.get('note',''), a.get('status','')])
    for pr in e['props']:
        if pr[0]=='list': 
            for kid in pr[2]:
                if isinstance(kid,dict): walk(kid,path,depth+(0 if k in ('(sizing)','MenuGroup','Ribbon') else 1),tab)
        if pr[0]=='ptr':
            for x in B.block(pr[1],depth):
                if x[0]=='list':
                    for kid in x[2]:
                        if isinstance(kid,dict): walk(kid,path,depth+1,tab)
import struct
root=B.b.find(b'\x16\x00\x24\x00\x10',0x40)
e,_=B.elem(root)
walk(e,'',0)
print('| 項目 | 種類 | cmd | キーヒント | ツールチップ題(ID 文字列) | 説明ID | 小画像 | 大画像 | モード | 再現側 | 判定 |')
print('|---|---|---|---|---|---|---|---|---|---|---|')
for r in rows: print('| '+' | '.join(x.replace('|','/') for x in r)+' |')
