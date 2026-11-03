# Driver: for each UIFILE ribbon, locate command table + root element, dump command table (TSV) and view tree.
import struct,os,subprocess,sys
D='out/maillang.dll.mui/raw/UIFILE'; S='out/maillang.dll.mui/strings.tsv'
lab={}
for l in open(S):
    x=l.rstrip('\n').split('\t',1)
    if len(x)==2 and x[0].isdigit(): lab[int(x[0])]=x[1]
os.makedirs('ribbons',exist_ok=True)
for fn in sorted(os.listdir(D)):
    b=open(os.path.join(D,fn),'rb').read(); name=fn.split('_')[0]
    for st in range(0x20,0x200):
        cnt=struct.unpack_from('<I',b,st-4)[0]
        if not 5<cnt<1000: continue
        p=st; ok=True; rows=[]
        for i in range(cnt):
            cid,n=struct.unpack_from('<IB',b,p)
            if cid>70000 or n==0 or n>12: ok=False;break
            pr=[struct.unpack_from('<BI',b,p+5+5*j) for j in range(n)]
            if any(k>20 for k,v in pr): ok=False;break
            rows.append((cid,dict(pr))); p+=5+5*n
        if ok: break
    root=b.find(b'\x16\x00\x24\x00\x10',p)
    with open(f'ribbons/{name}.commands.tsv','w') as f:
        f.write('cmd\tlabel(1)\tlabeldesc(2)\tkeytip(7)\ttooltipTitle(8)\ttooltipDesc(9)\tother\n')
        for cid,pr in rows:
            g=lambda k: f"{pr[k]}:{lab.get(pr[k],'')}" if k in pr else ''
            other=' '.join(f'{k}={v}' for k,v in pr.items() if k not in (1,2,7,8,9))
            f.write('\t'.join([str(cid),g(1),g(2),g(7),g(8),g(9),other])+'\n')
    r=subprocess.run(['python3','-I','bml2.py',os.path.join(D,fn),S,hex(root)],capture_output=True,text=True)
    open(f'ribbons/{name}.tree.txt','w').write(r.stdout)
    print(name,'cmds',len(rows),'tablestart',hex(st),'root',hex(root),r.stderr.strip()[-80:])
