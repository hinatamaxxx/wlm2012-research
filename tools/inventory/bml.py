import struct,sys
b=open(sys.argv[1],'rb').read()
p=int(sys.argv[2],0); n=0
while p+5<=len(b):
    cid,cnt=struct.unpack_from('<IB',b,p)
    if cid>70000 or cnt>12 or cnt==0: break
    props=[]; q=p+5
    for i in range(cnt):
        k,v=struct.unpack_from('<BI',b,q); q+=5; props.append((k,v))
    if any(k>20 for k,v in props): break
    print(cid,props); p=q; n+=1
print('end',hex(p),n, file=sys.stderr)
