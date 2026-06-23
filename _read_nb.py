import sys, json
nb = json.load(sys.stdin)
for i, c in enumerate(nb.get('cells', [])):
    src = ''.join(c.get('source', []))
    print(f'--- Cell {i} ({c.get("cell_type","?")}) ---')
    print(src[:3000])
    if len(src) > 3000:
        print('...(truncated)')
