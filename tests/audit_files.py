import os, re, glob

root = os.getcwd()

# Collect all "text" files that could reference assets
scan_exts = {'.html', '.css', '.js', '.json', '.webmanifest', '.md', '.xml', '.txt', '.py'}
text_files = []
for dirpath, dirnames, filenames in os.walk(root):
    # skip the original user assets dir from being scanned for refs (they're binary)
    for fn in filenames:
        ext = os.path.splitext(fn)[1].lower()
        if ext in scan_exts:
            text_files.append(os.path.join(dirpath, fn))

# Build a giant corpus of all reference strings
corpus = ''
for tf in text_files:
    try:
        with open(tf, encoding='utf-8', errors='ignore') as f:
            corpus += f.read() + '\n'
    except Exception:
        pass

def referenced(basename):
    """Is this basename mentioned anywhere in the corpus?"""
    return basename in corpus

# Audit every non-text (asset) file + every file, see which are never referenced
all_files = []
for dirpath, dirnames, filenames in os.walk(root):
    for fn in filenames:
        all_files.append(os.path.join(dirpath, fn))

unused = []
used = []
for fp in all_files:
    rel = os.path.relpath(fp, root).replace('\\', '/')
    base = os.path.basename(fp)
    ext = os.path.splitext(base)[1].lower()
    # The HTML pages themselves + core entry files are "used" by definition
    if rel in ('index.html', 'text.html', 'files.html', 'hash.html',
               'tools.html', 'algorithms.html', 'about.html',
               'README.md', 'LICENSE', 'robots.txt', 'sitemap.xml',
               'site.webmanifest', 'favicon.ico', 'favicon.png',
               'apple-touch-icon.png'):
        used.append(rel)
        continue
    # skip python/dev scripts in tests (they are tools, not assets)
    if rel.startswith('tests/'):
        used.append(rel)  # keep test suite intact
        continue
    if referenced(base):
        used.append(rel)
    else:
        unused.append(rel)

print('=== POTENTIALLY UNUSED (basename never referenced) ===')
for u in sorted(unused):
    sz = os.path.getsize(os.path.join(root, u))
    print(f'  {u}  ({sz} bytes)')

print(f'\nTotal files: {len(all_files)}  |  used/keep: {len(used)}  |  unused: {len(unused)}')
