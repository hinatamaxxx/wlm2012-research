# Print sheet rules compactly: selector -> property=value (resolved values only)
import sys, re, xml.etree.ElementTree as ET
t = ET.parse(sys.argv[1]); pat = re.compile(sys.argv[2]) if len(sys.argv) > 2 else None
def short(v):
    m = re.search(r'\{=(.*)\}$', v)
    return (v.split('{')[0] + '=' + m.group(1)) if m else v
for r in t.iter('Rule'):
    sel = r.get('selector')
    if pat and not pat.search(sel): continue
    props = ['%s=%s' % (s.get('property'), short(s.get('value'))) for s in r.findall('Set')]
    print(r.get('order'), sel, '→', '; '.join(props))
