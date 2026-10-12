import os, re, glob

root = os.getcwd()
missing = []
checked = set()

for page in glob.glob('*.html') + glob.glob('tests/*.html'):
    base = os.path.dirname(page)
    with open(page, encoding='utf-8') as f:
        html = f.read()
    for m in re.findall(r'(?:src|href)=["\']([^"\']+)["\']', html):
        if m.startswith(('http', 'mailto:', '#', 'data:')) or not m.strip():
            continue
        target = os.path.normpath(os.path.join(base, m.split('?')[0].split('#')[0]))
        if target in checked:
            continue
        checked.add(target)
        if not os.path.exists(target):
            missing.append((page, m))

print('Checked', len(checked), 'unique local src/href references')
if missing:
    print('MISSING:')
    for p, m in missing:
        print('  ', p, '->', m)
else:
    print('OK: all local src/href references resolve')

missing_css = []
for css in glob.glob('assets/css/*.css'):
    with open(css, encoding='utf-8') as f:
        for u in re.findall(r'url\([\'"]?([^\'")]+)', f.read()):
            if u.startswith('data:'):
                continue
            t = os.path.normpath(os.path.join(os.path.dirname(css), u))
            if not os.path.exists(t):
                missing_css.append((css, u))
print('CSS url() refs:', 'ALL OK' if not missing_css else missing_css)

# orphan asset check (files never referenced anywhere)
print('\nRoot-level files present:')
for f in sorted(os.listdir('.')):
    if os.path.isfile(f):
        print('  ', f, os.path.getsize(f), 'bytes')
