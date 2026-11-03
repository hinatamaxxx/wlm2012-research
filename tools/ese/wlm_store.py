"""Summarise a Windows Live Mail 2012 message store (Mail.MSMessageStore, an ESE database).

Prints, per folder, the folder's own message/unread counters (Folders table) next to the numbers
recomputed from the Messages table with MSGCOL_FLAGS bit 0x80 = read. When they agree for every
folder, the bit meaning is confirmed for that store. Subjects, addresses and bodies are not printed.

    python3 -m venv venv && venv/bin/pip install dissect.esedb
    venv/bin/python -I wlm_store.py /path/to/copy/of/Mail.MSMessageStore

Work on a copy: Windows Live Mail keeps the file open while it runs.
"""
import collections
import sys

from dissect.esedb import EseDB

READ = 0x80


def main(path):
    with open(path, 'rb') as f:
        db = EseDB(f)
        folders = {}
        for r in db.table('Folders').records():
            folders[r.get('FLDCOL_ID')] = (r.get('FLDCOL_SPECIAL'), r.get('FLDCOL_MESSAGES'), r.get('FLDCOL_UNREAD'))
        total = collections.Counter()
        unread = collections.Counter()
        for r in db.table('Messages').records():
            fid = r.get('MSGCOL_FOLDERID')
            total[fid] += 1
            if not (r.get('MSGCOL_FLAGS') or 0) & READ:
                unread[fid] += 1
    ok = True
    print('folder special  messages(stored/counted)  unread(stored/counted)')
    for fid in sorted(total):
        special, msgs, unr = folders.get(fid, (None, None, None))
        same = unr == unread[fid]
        ok &= same
        print('%6s %7s  %8s/%-8s  %8s/%-8s %s' % (fid, special, msgs, total[fid], unr, unread[fid], '' if same else '<- differs'))
    print('bit 0x80 = read: ' + ('consistent with every folder' if ok else 'NOT consistent'))
    return 0 if ok else 1


if __name__ == '__main__':
    sys.exit(main(sys.argv[1]))
