# Helpers over REA inspect-pe-resources Evidence: list types, extract payloads by location+sha256
import json, sys, hashlib, collections, os
def load(p): return json.load(open(p))
def key(t): return t.get('name') if t['kind']=='name' else t['id']
def types(ev):
    c=collections.Counter(); s=collections.Counter()
    for x in ev['normalized_result']['resources']:
        k=key(x['type']); c[k]+=1; s[k]+=x['payload']['location']['bytes']
    return c,s
def extract(ev, typ, outdir):
    src=ev['normalized_result']['artifact']['path']; data=open(src,'rb').read(); os.makedirs(outdir,exist_ok=True); n=0
    for x in ev['normalized_result']['resources']:
        if str(key(x['type']))!=str(typ): continue
        loc=x['payload']['location']; b=data[loc['offset']:loc['offset']+loc['bytes']]
        assert hashlib.sha256(b).hexdigest()==x['payload']['sha256']
        open(os.path.join(outdir,f"{key(x['name'])}_{key(x['language'])}.bin"),'wb').write(b); n+=1
    return n
if __name__=='__main__':
    ev=load(sys.argv[2])
    if sys.argv[1]=='types':
        c,s=types(ev)
        for k,v in c.most_common(): print(k,v,s[k])
    else: print(extract(ev,sys.argv[3],sys.argv[4]))
