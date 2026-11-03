# Decoder for Windows Ribbon compiled markup (UICC "SCBin") as embedded in maillang.dll.mui UIFILE.
# Format inferred empirically (see docs/04-ribbon-and-strings.md): element = 16 <type u16> 10 <size u16> <nprops u8> props...
import struct,sys,json
b=None
S={}
def init(path,strings):
  global b
  b=open(path,'rb').read()
  for l in open(strings):
    x=l.rstrip('\n').split('\t',1)
    if len(x)==2 and x[0].isdigit(): S[int(x[0])]=x[1]
def lab(c): return S.get(c,'')
out=[]
def prop(p,d):
    t=b[p]
    if t==0x01:
        kl=b[p+1]; key=b[p+2] if kl==1 else struct.unpack_from('<I',b,p+2)[0]; q=p+2+kl
        vt=b[q]; q+=1
        if vt==2: v=struct.unpack_from('<I',b,q)[0]; q+=4
        elif vt==3: v=struct.unpack_from('<H',b,q)[0]; q+=2
        elif vt in (4,5,9,0x2b): v=b[q]; q+=1
        else: raise Exception(f'vt {vt:#x} at {q-1:#x}')
        return ('a',key,vt,v),q
    if t==0x3e:
        ptr=struct.unpack_from('<I',b,p+1)[0]; return ('ptr',ptr),p+5
    if t==0x18:
        key=b[p+2]; n=struct.unpack_from('<H',b,p+3)[0]; q=p+5; kids=[]
        for i in range(n):
            if b[q]==0x3b: e,q=prop(q,d)
            else: e,q=elem(q,d+1)
            kids.append(e)
        return ('list',key,kids),q
    if t==0x3b:
        vt=b[p+1]; q=p+2
        if vt==2: v=struct.unpack_from('<I',b,q)[0]; q+=4
        elif vt==3: v=struct.unpack_from('<H',b,q)[0]; q+=2
        else: v=b[q]; q+=1
        return ('v',vt,v),q
    if t==0x16:
        e,q=elem(p,d+1); return ('list',-1,[e]),q
    raise Exception(f'prop tag {t:#x} at {p:#x}')
def elem(p,d=0):
    if b[p]!=0x16: raise Exception(f'not elem at {p:#x}: {b[p:p+8].hex()}')
    typ=struct.unpack_from('<H',b,p+2)[0]; size=struct.unpack_from('<H',b,p+5)[0]; n=b[p+7]; q=p+8; props=[]
    for i in range(n):
        pr,q=prop(q,d); props.append(pr)
    return {'off':p,'type':typ,'size':size,'props':props},q
def block(ptr,d):
    size=struct.unpack_from('<H',b,ptr)[0]; q=ptr+2; props=[]
    while q<ptr+size:
        pr,q=prop(q,d); props.append(pr)
    return props
def show(e,d,f):
    attrs=[];cmd=None;subs=[]
    for pr in e['props']:
        if pr[0]=='a':
            if pr[1]==0 and pr[2] in (2,3): cmd=pr[3]
            else: attrs.append(f'{pr[1]:#x}={pr[3]}')
        elif pr[0]=='ptr': subs.append(('ptr',block(pr[1],d)))
        else: subs.append(('list',pr))
    c=f'cmd={cmd} 「{lab(cmd)}」' if cmd is not None else ''
    f.write('  '*d+f'T{e["type"]:#04x} {c} {" ".join(attrs)}\n'.replace('\\n',''))
    for kind,s in subs:
        if kind=='list': lists=[s]
        else: lists=[x for x in s if x[0]=='list']; 
        if kind=='ptr':
            for x in s:
                if x[0]=='a': f.write('  '*(d+1)+f'(blk {x[1]:#x}={x[3]})\n')
        for L in lists:
            f.write('  '*(d+1)+f'<list {L[1]:#x} n={len(L[2])}>\n')
            vals=[k for k in L[2] if isinstance(k,tuple)]
            if vals: f.write('  '*(d+2)+'values: '+' '.join(f'{v[2]}' + (f'「{lab(v[2])}」' if v[1]==3 else '') for v in vals).replace('\\n','')+'\n')
            for k in L[2]:
                if not isinstance(k,tuple): show(k,d+2,f)
