"""Pure-Python SVG state diagrams (no Graphviz install needed)."""
from collections import deque
from math import hypot

R, W, H = 20, 190, 90

def _txt(x, y, s, cls=""):
    lines = str(s).split("\n")
    y -= (len(lines) - 1) * 12                  # grow upward so text stays above the line
    spans = "".join(f'<tspan x="{x:.0f}" dy="{0 if i == 0 else 12}">{t}</tspan>' for i, t in enumerate(lines))
    return f'<text x="{x:.0f}" y="{y:.0f}" class="{cls}">{spans}</text>'

def draw(nodes, edges, start, accepting):
    adj, merged = {}, {}
    for a, b, lab in edges:
        merged.setdefault((a, b), []).append(lab)
        adj.setdefault(a, []).append(b)
    depth, q = {start: 0}, deque([start])
    while q:                                    # BFS depth = column
        a = q.popleft()
        for b in adj.get(a, []):
            if b not in depth: depth[b] = depth[a] + 1; q.append(b)
    cols = {}
    for n in nodes: cols.setdefault(depth.get(n, 0), []).append(n)
    pos = {n: (60 + d * W, 95 + i * H) for d, ns in cols.items() for i, n in enumerate(ns)}
    width = 160 + max(cols) * W
    height = 135 + (max(len(v) for v in cols.values()) - 1) * H
    out = [f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {width} {height}" width="{width}" height="{height}">',
           '<style>.e{fill:none;stroke:currentColor;stroke-width:1.4}.n{fill:none;stroke:currentColor;stroke-width:1.6}'
           'text{fill:currentColor;font:11px ui-monospace,monospace;text-anchor:middle}'
           '.l{paint-order:stroke;stroke:var(--card,#fff);stroke-width:4px}</style>',
           '<defs><marker id="ar" markerWidth="10" markerHeight="10" refX="9" refY="5" orient="auto">'
           '<path d="M0,0 L10,5 L0,10 z" fill="currentColor"/></marker></defs>']
    for (a, b), labs in merged.items():
        label = "\n".join(sorted(set(labs)))
        (x1, y1), (x2, y2) = pos[a], pos[b]
        if a == b:                              # self loop above the node
            out.append(f'<path class="e" marker-end="url(#ar)" d="M{x1-12},{y1-R+2} C{x1-30},{y1-R-40} {x1+30},{y1-R-40} {x1+12},{y1-R+2}"/>')
            out.append(_txt(x1, y1 - R - 32, label, "l")); continue
        off = 0 if (depth[b] - depth[a] == 1 and (b, a) not in merged) else 45
        dx, dy = x2 - x1, y2 - y1
        L = hypot(dx, dy) or 1
        cx, cy = (x1 + x2) / 2 - dy / L * off, (y1 + y2) / 2 + dx / L * off
        def edge_pt(px, py):
            d = hypot(cx - px, cy - py) or 1
            return px + (cx - px) / d * (R + 2), py + (cy - py) / d * (R + 2)
        (sx, sy), (ex, ey) = edge_pt(x1, y1), edge_pt(x2, y2)
        out.append(f'<path class="e" marker-end="url(#ar)" d="M{sx:.1f},{sy:.1f} Q{cx:.1f},{cy:.1f} {ex:.1f},{ey:.1f}"/>')
        out.append(_txt(.25 * sx + .5 * cx + .25 * ex, .25 * sy + .5 * cy + .25 * ey - 4, label, "l"))
    for n, (x, y) in pos.items():
        out.append(f'<circle class="n" cx="{x}" cy="{y}" r="{R}"/>')
        if n in accepting: out.append(f'<circle class="n" cx="{x}" cy="{y}" r="{R-4}"/>')
        out.append(_txt(x, y + 4, n))
    sx, sy = pos[start]
    out.append(f'<path class="e" marker-end="url(#ar)" d="M{sx-48},{sy} L{sx-R-2},{sy}"/>')
    return "".join(out) + "</svg>"

def nfa_svg(n):
    edges = [(a, b, "ε" if s is None else s) for a, ts in n.trans.items() for s, b in ts]
    return draw(list(n.trans), edges, n.start, {n.accept})

def dfa_svg(d):                                 # dead state and moves into it are omitted
    rows = d.table()
    edges = [(r["state"], t, a) for r in rows for a, t in r["moves"].items()]
    return draw([r["state"] for r in rows], edges, d.start, d.accepting)
