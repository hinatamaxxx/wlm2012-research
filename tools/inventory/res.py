# Extract PE resources (by REA evidence location + sha256) and decode string tables / menus / dialogs
import json, sys, hashlib, os, struct
def key(t): return t.get('name') if t['kind']=='name' else t['id']
def items(evp):
    ev=json.load(open(evp)); src=ev['normalized_result']['artifact']['path']; data=open(src,'rb').read()
    for x in ev['normalized_result']['resources']:
        loc=x['payload']['location']; b=data[loc['offset']:loc['offset']+loc['bytes']]
        assert hashlib.sha256(b).hexdigest()==x['payload']['sha256']
        yield key(x['type']), key(x['name']), key(x['language']), b
def strings(evp):
    out={}
    for t,n,l,b in items(evp):
        if t!=6: continue
        p=0
        for i in range(16):
            ln=struct.unpack_from('<H',b,p)[0]; p+=2
            if ln: out[(n-1)*16+i]=b[p:p+ln*2].decode('utf-16le')
            p+=ln*2
    return out
def rdsz(b,p):
    e=p
    while b[e:e+2]!=b'\0\0': e+=2
    return b[p:e].decode('utf-16le'), e+2
def menu(b):
    # standard or extended menu
    ver,=struct.unpack_from('<H',b,0); lines=[]
    if ver==0:
        p=4; depth=0; stack=[]
        def walk(p,d):
            while True:
                fl,=struct.unpack_from('<H',b,p); p+=2
                if fl&0x10: 
                    txt,p=rdsz(b,p); lines.append('  '*d+'['+txt+']'); p=walk(p,d+1)
                else:
                    iid,=struct.unpack_from('<H',b,p); p+=2; txt,p=rdsz(b,p)
                    lines.append('  '*d+(f'{iid}: {txt}' if txt or iid else '----'))
                if fl&0x80: return p
        walk(p,0)
    else:
        off,=struct.unpack_from('<H',b,2); p=4+off
        def walk(p,d):
            while True:
                typ,st,iid,fl=struct.unpack_from('<IIIH',b,p); p+=14
                txt,p=rdsz(b,p); p=(p+3)&~3
                if fl&1: p+=4; lines.append('  '*d+f'[{iid}: {txt}]'); p=walk(p,d+1)
                else: lines.append('  '*d+(f'{iid}: {txt}' if typ&0x800==0 else '----'))
                if fl&0x80: return p
        walk(p,0)
    return lines
def sz_or_ord(b,p):
    w,=struct.unpack_from('<H',b,p)
    if w==0: return '',p+2
    if w==0xFFFF: return '#%d'%struct.unpack_from('<H',b,p+2)[0],p+4
    return rdsz(b,p)
def dialog(b):
    lines=[]
    if struct.unpack_from('<HH',b,0)==(1,0xFFFF):
        _,_,help,ex,st,cnt,x,y,cx,cy=struct.unpack_from('<HHIIIHhhhh',b,0); p=26
        m,p=sz_or_ord(b,p); c,p=sz_or_ord(b,p); t,p=rdsz(b,p)
        lines.append(f'DIALOGEX {cx}x{cy} "{t}"')
        if st&0x40 or st&0x48:
            pt,w,it,cs=struct.unpack_from('<HHBB',b,p); p+=6; f,p=rdsz(b,p)
        for i in range(cnt):
            p=(p+3)&~3
            hid,exs,s,x,y,cx,cy,iid=struct.unpack_from('<IIIhhhhI',b,p); p+=24
            cl,p=sz_or_ord(b,p); tx,p=sz_or_ord(b,p); n,=struct.unpack_from('<H',b,p); p+=2+n
            cls={'#128':'BUTTON','#129':'EDIT','#130':'STATIC','#131':'LISTBOX','#132':'SCROLLBAR','#133':'COMBOBOX'}.get(cl,cl)
            if cls=='BUTTON':
                bs=s&0xF; cls={0:'PUSH',1:'DEFPUSH',2:'CHECK',3:'CHECK',4:'RADIO',5:'CHECK3',6:'CHECK3',7:'GROUP',9:'RADIO',11:'OWNER'}.get(bs,'BTN')
            lines.append(f'  {iid&0xFFFF} {cls} ({x},{y},{cx},{cy}) "{tx}"')
    else:
        st,ex,cnt,x,y,cx,cy=struct.unpack_from('<IIHhhhh',b,0); p=18
        m,p=sz_or_ord(b,p); c,p=sz_or_ord(b,p); t,p=rdsz(b,p)
        lines.append(f'DIALOG {cx}x{cy} "{t}"')
        if st&0x40: p+=2; f,p=rdsz(b,p)
        for i in range(cnt):
            p=(p+3)&~3
            s,exs,x,y,cx,cy,iid=struct.unpack_from('<IIhhhhH',b,p); p+=18
            cl,p=sz_or_ord(b,p); tx,p=sz_or_ord(b,p); n,=struct.unpack_from('<H',b,p); p+=2+n
            lines.append(f'  {iid} {cl} ({x},{y},{cx},{cy}) "{tx}"')
    return lines
if __name__=='__main__':
    evp,outdir=sys.argv[1],sys.argv[2]; os.makedirs(outdir,exist_ok=True)
    s=strings(evp)
    with open(os.path.join(outdir,'strings.tsv'),'w') as f:
        for k in sorted(s): f.write(f'{k}\t'+s[k].replace('\r','').replace('\n','\\n').replace('\t','\\t')+'\n')
    with open(os.path.join(outdir,'menus.txt'),'w') as f, open(os.path.join(outdir,'dialogs.txt'),'w') as g:
        for t,n,l,b in items(evp):
            if t==4:
                f.write(f'== MENU {n}\n')
                try: f.write('\n'.join(menu(b))+'\n')
                except Exception as e: f.write(f'!! {e}\n')
            if t==5:
                g.write(f'== DIALOG {n}\n')
                try: g.write('\n'.join(dialog(b))+'\n')
                except Exception as e: g.write(f'!! {e}\n')
            if t in ('UIFILE',2110,4009,4012,14,9,'MUI'):
                d=os.path.join(outdir,'raw',str(t)); os.makedirs(d,exist_ok=True); open(os.path.join(d,f'{n}_{l}.bin'),'wb').write(b)
    print(len(s))
