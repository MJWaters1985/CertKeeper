#!/usr/bin/env python3
"""Generates CertKeeper app icon concepts as 1024x1024 SVGs (macOS Big Sur+ icon grid:
an 824pt rounded-square tile inset 100pt, with a soft drop shadow), plus a contact sheet.

    python3 make_icons.py [output-dir]
"""
import math
import os
import sys

OUT = next((a for a in sys.argv[1:] if not a.startswith("--")), os.path.dirname(os.path.abspath(__file__)))
TILE = (100, 100, 824, 824)  # x, y, w, h
RADIUS = 185


def pt(cx, cy, r, deg):
    a = math.radians(deg)
    return cx + r * math.cos(a), cy + r * math.sin(a)


def f(*xs):
    return " ".join(f"{x:.1f}" for x in xs)


def arc_arrow(cx, cy, r, start, end, width, color, head=1.0):
    """Clockwise arc from `start` to `end` degrees (y down) with an arrowhead at the end."""
    x0, y0 = pt(cx, cy, r, start)
    x1, y1 = pt(cx, cy, r, end)
    large = 1 if (end - start) % 360 > 180 else 0
    a = math.radians(end)
    tx, ty = -math.sin(a), math.cos(a)          # tangent (direction of travel)
    nx, ny = math.cos(a), math.sin(a)           # outward normal
    tip = (x1 + tx * width * 1.6 * head, y1 + ty * width * 1.6 * head)
    b1 = (x1 + nx * width * 1.15 * head, y1 + ny * width * 1.15 * head)
    b2 = (x1 - nx * width * 1.15 * head, y1 - ny * width * 1.15 * head)
    return (f'<path d="M{f(x0, y0)} A{f(r, r)} 0 {large} 1 {f(x1, y1)}" fill="none" stroke="{color}" '
            f'stroke-width="{width}" stroke-linecap="round"/>'
            f'<path d="M{f(*tip)} L{f(*b1)} L{f(*b2)} Z" fill="{color}" stroke="{color}" '
            f'stroke-width="{width * 0.35:.1f}" stroke-linejoin="round"/>')


def rosette(cx, cy, r_out, r_in, points=16):
    """Scalloped seal outline as a smooth path."""
    d = []
    n = points * 2
    for i in range(n + 1):
        r = r_out if i % 2 == 0 else r_in
        x, y = pt(cx, cy, r, -90 + i * 360 / n)
        d.append(("M" if i == 0 else "L") + f(x, y))
    return " ".join(d) + " Z"


def padlock(cx, cy, s, body, shackle, hole):
    """Padlock centred on (cx, cy); s = body width."""
    w, h = s, s * 0.8
    x, y = cx - w / 2, cy - h / 2 + s * 0.18
    sw = s * 0.17
    sr = s * 0.31
    return (f'<path d="M{f(cx - sr, y + 2)} V{f(y - sr * 0.55)} A{f(sr, sr)} 0 0 1 {f(cx + sr, y - sr * 0.55)} V{f(y + 2)}" '
            f'fill="none" stroke="{shackle}" stroke-width="{sw:.1f}" stroke-linecap="round"/>'
            f'<rect x="{x:.1f}" y="{y:.1f}" width="{w:.1f}" height="{h:.1f}" rx="{s * 0.16:.1f}" fill="{body}"/>'
            f'<circle cx="{cx:.1f}" cy="{y + h * 0.42:.1f}" r="{s * 0.085:.1f}" fill="{hole}"/>'
            f'<rect x="{cx - s * 0.035:.1f}" y="{y + h * 0.42:.1f}" width="{s * 0.07:.1f}" height="{h * 0.3:.1f}" '
            f'rx="{s * 0.035:.1f}" fill="{hole}"/>')


def tile(grad_id, stops, angle=(0, 0, 1, 1)):
    x1, y1, x2, y2 = angle
    stop_xml = "".join(f'<stop offset="{o}" stop-color="{c}"/>' for o, c in stops)
    return (f'<linearGradient id="{grad_id}" x1="{x1}" y1="{y1}" x2="{x2}" y2="{y2}">{stop_xml}</linearGradient>',
            f'<rect x="{TILE[0]}" y="{TILE[1]}" width="{TILE[2]}" height="{TILE[3]}" rx="{RADIUS}" '
            f'fill="url(#{grad_id})" filter="url(#shadow)"/>'
            # subtle top highlight, like system icons
            f'<rect x="{TILE[0]}" y="{TILE[1]}" width="{TILE[2]}" height="{TILE[3]}" rx="{RADIUS}" '
            f'fill="url(#gloss)"/>')


COMMON_DEFS = (
    '<filter id="shadow" x="-20%" y="-20%" width="140%" height="140%">'
    '<feDropShadow dx="0" dy="12" stdDeviation="14" flood-color="#000" flood-opacity="0.28"/></filter>'
    '<filter id="soft" x="-30%" y="-30%" width="160%" height="160%">'
    '<feDropShadow dx="0" dy="8" stdDeviation="10" flood-color="#000" flood-opacity="0.25"/></filter>'
    '<linearGradient id="gloss" x1="0" y1="0" x2="0" y2="1">'
    '<stop offset="0" stop-color="#fff" stop-opacity="0.18"/><stop offset="0.45" stop-color="#fff" stop-opacity="0"/>'
    '</linearGradient>'
)


# ---------------------------------------------------------------- concepts

def shield(p):
    defs, bg = tile(f"{p}bg", [(0, "#3B82F6"), (1, "#1E3A8A")])
    shield_d = "M512 238 L728 318 V520 C728 668 636 768 512 818 C388 768 296 668 296 520 V318 Z"
    return defs + (f'<linearGradient id="{p}sh" x1="0" y1="0" x2="0" y2="1">'
                   f'<stop offset="0" stop-color="#FFFFFF"/><stop offset="1" stop-color="#D6E4FF"/></linearGradient>'), (
        bg
        + arc_arrow(512, 528, 352, 196, 286, 26, "#BFDBFE")
        + arc_arrow(512, 528, 352, 16, 106, 26, "#BFDBFE")
        + f'<path d="{shield_d}" fill="url(#{p}sh)" filter="url(#soft)"/>'
        + padlock(512, 520, 190, "#1D4ED8", "#1D4ED8", "#FFFFFF")
    )


def certificate(p):
    defs, bg = tile(f"{p}bg", [(0, "#14B8A6"), (1, "#0F4C47")])
    lines = "".join(
        f'<rect x="352" y="{y}" width="{w}" height="22" rx="11" fill="#CBD5E1"/>'
        for y, w in [(372, 320), (420, 260), (468, 300), (516, 200)])
    seal = rosette(650, 648, 112, 96, 18)
    return defs + (f'<linearGradient id="{p}gold" x1="0" y1="0" x2="1" y2="1">'
                   f'<stop offset="0" stop-color="#FCD34D"/><stop offset="1" stop-color="#D97706"/></linearGradient>'), (
        bg
        + '<g transform="rotate(-7 512 512)" filter="url(#soft)">'
          '<rect x="300" y="260" width="430" height="520" rx="34" fill="#FFFFFF"/>'
          '<rect x="352" y="310" width="210" height="34" rx="17" fill="#0F766E"/>'
        + lines + '</g>'
        # ribbons
        + '<path d="M600 700 L566 860 L612 832 L640 872 L664 716 Z" fill="#B45309"/>'
          '<path d="M700 700 L734 860 L688 832 L660 872 L636 716 Z" fill="#D97706"/>'
        + f'<path d="{seal}" fill="url(#{p}gold)" filter="url(#soft)"/>'
        + '<circle cx="650" cy="648" r="76" fill="none" stroke="#FFFFFF" stroke-opacity="0.75" stroke-width="8"/>'
        + arc_arrow(650, 648, 40, 210, 480, 13, "#FFFFFF", head=1.1)
    )


def servers(p):
    defs, bg = tile(f"{p}bg", [(0, "#334155"), (1, "#0B1220")])
    units = ""
    for i, y in enumerate((262, 432, 602)):
        units += (f'<rect x="240" y="{y}" width="460" height="140" rx="30" fill="url(#{p}unit)"/>'
                  f'<rect x="282" y="{y + 52}" width="200" height="16" rx="8" fill="#475569"/>'
                  f'<rect x="282" y="{y + 80}" width="140" height="16" rx="8" fill="#475569"/>'
                  f'<circle cx="640" cy="{y + 70}" r="16" fill="{"#22C55E" if i != 1 else "#38BDF8"}"/>')
    return defs + (f'<linearGradient id="{p}unit" x1="0" y1="0" x2="0" y2="1">'
                   f'<stop offset="0" stop-color="#E2E8F0"/><stop offset="1" stop-color="#94A3B8"/></linearGradient>'
                   f'<linearGradient id="{p}badge" x1="0" y1="0" x2="0" y2="1">'
                   f'<stop offset="0" stop-color="#4ADE80"/><stop offset="1" stop-color="#15803D"/></linearGradient>'), (
        bg + units
        + f'<circle cx="696" cy="694" r="168" fill="url(#{p}badge)" stroke="#0B1220" stroke-width="18" filter="url(#soft)"/>'
        + arc_arrow(696, 694, 128, 200, 330, 16, "#DCFCE7")
        + arc_arrow(696, 694, 128, 20, 150, 16, "#DCFCE7")
        + padlock(696, 690, 104, "#FFFFFF", "#FFFFFF", "#15803D")
    )


def key(p):
    defs, bg = tile(f"{p}bg", [(0, "#8B5CF6"), (1, "#3730A3")])
    # key along a 45° diagonal: ring (bow) top-left, shaft to bottom-right with teeth
    teeth = ('<rect x="0" y="-26" width="420" height="52" rx="26"/>'
             '<rect x="300" y="10" width="44" height="92" rx="12"/>'
             '<rect x="368" y="10" width="44" height="64" rx="12"/>')
    return defs + (f'<linearGradient id="{p}metal" x1="0" y1="0" x2="1" y2="1">'
                   f'<stop offset="0" stop-color="#FEF3C7"/><stop offset="1" stop-color="#F59E0B"/></linearGradient>'), (
        bg
        + f'<g fill="url(#{p}metal)" filter="url(#soft)" transform="translate(500 500) rotate(45)">{teeth}</g>'
        + f'<circle cx="400" cy="400" r="141" fill="none" stroke="url(#{p}metal)" stroke-width="58" filter="url(#soft)"/>'
        + arc_arrow(400, 400, 66, 150, 400, 22, "#FDE68A", head=1.0)
    )


def globe(p):
    defs, bg = tile(f"{p}bg", [(0, "#22D3EE"), (1, "#0E7490")])
    cx, cy, r = 470, 470, 250
    meridians = "".join(
        f'<ellipse cx="{cx}" cy="{cy}" rx="{r * k:.0f}" ry="{r}" fill="none" stroke="#E0F2FE" stroke-width="16"/>'
        for k in (0.36, 0.75))
    parallels = "".join(
        f'<path d="M{f(cx - math.sqrt(r * r - dy * dy), cy + dy)} H{f(cx + math.sqrt(r * r - dy * dy))}" '
        f'stroke="#E0F2FE" stroke-width="16"/>' for dy in (-125, 0, 125))
    return defs + (f'<linearGradient id="{p}badge" x1="0" y1="0" x2="0" y2="1">'
                   f'<stop offset="0" stop-color="#FFFFFF"/><stop offset="1" stop-color="#E2E8F0"/></linearGradient>'), (
        bg
        + f'<g filter="url(#soft)"><circle cx="{cx}" cy="{cy}" r="{r}" fill="#0891B2" stroke="#E0F2FE" stroke-width="18"/>'
        + meridians + parallels + f'<path d="M{cx} {cy - r} V{cy + r}" stroke="#E0F2FE" stroke-width="16"/></g>'
        + f'<rect x="560" y="560" width="250" height="250" rx="62" fill="url(#{p}badge)" filter="url(#soft)"/>'
        + padlock(685, 680, 120, "#0E7490", "#0E7490", "#FFFFFF")
    )


CONCEPTS = [
    ("1-shield", "Shield", "A padlocked shield inside rotation arrows: protection that renews itself.", shield),
    ("2-certificate", "Certificate", "A certificate with a gold seal; the arrows in the seal show renewal.", certificate),
    ("3-servers", "Server Rack", "A server stack with a renewing-lock badge: certificates across your hosts.", servers),
    ("4-key", "Renewing Key", "A brass key whose ring holds a refresh arrow: keys that rotate.", key),
    ("5-globe", "Secure Web", "A globe with a lock badge: HTTPS for every hostname you own.", globe),
]


def svg(defs, body, size=1024, view="0 0 1024 1024"):
    return (f'<svg xmlns="http://www.w3.org/2000/svg" width="{size}" height="{size}" viewBox="{view}">'
            f'<defs>{COMMON_DEFS}{defs}</defs>{body}</svg>\n')


def main():
    os.makedirs(OUT, exist_ok=True)
    cells = []
    for i, (slug, title, _, make) in enumerate(CONCEPTS):
        defs, body = make(f"c{i}")
        with open(os.path.join(OUT, f"icon-{slug}.svg"), "w") as fh:
            fh.write(svg(defs, body))
        cells.append((title, defs, body))

    # contact sheet: square 3x2 grid (Quick Look renders previews square)
    cell, pad, caption = 1024, 80, 170
    cols = 3
    rows = (len(cells) + cols - 1) // cols
    side = cols * cell + (cols + 1) * pad
    top = (side - rows * (cell + caption) - (rows - 1) * pad) / 2
    parts = [f'<rect width="{side}" height="{side}" fill="#F5F5F7"/>']
    all_defs = ""
    for i, (title, defs, body) in enumerate(cells):
        row, col = divmod(i, cols)
        in_row = min(cols, len(cells) - row * cols)
        x0 = (side - (in_row * cell + (in_row - 1) * pad)) / 2  # centre short rows
        x = x0 + col * (cell + pad)
        y = top + row * (cell + caption + pad)
        all_defs += defs
        parts.append(f'<g transform="translate({x} {y})">{body}</g>')
        parts.append(f'<text x="{x + cell / 2}" y="{y + cell + caption - 40}" text-anchor="middle" '
                     f'font-family="-apple-system, Helvetica" font-size="72" font-weight="600" fill="#1D1D1F">'
                     f'{i + 1}. {title}</text>')
    with open(os.path.join(OUT, "contact-sheet.svg"), "w") as fh:
        fh.write(f'<svg xmlns="http://www.w3.org/2000/svg" width="{side}" height="{side}" viewBox="0 0 {side} {side}">'
                 f'<defs>{COMMON_DEFS}{all_defs}</defs>{"".join(parts)}</svg>\n')
    print(f"wrote {len(cells)} icons and contact-sheet.svg to {OUT}")


if __name__ == "__main__" and "--icon" not in sys.argv:
    main()


# ------------------------------------------------- Icon Composer (.icon) for the chosen concept
#
# macOS 26+ app icons are layered: the system applies the rounded-square mask, Liquid Glass
# highlights, depth and shadow. So these layers are flat-coloured, full-bleed (the 1024 canvas
# *is* the icon shape — no inset tile) and carry no baked-in shadows or gloss.

def _p(hex_color, alpha=1.0):
    r, g, b = (int(hex_color[i:i + 2], 16) / 255 for i in (1, 3, 5))
    return f"extended-srgb:{r:.5f},{g:.5f},{b:.5f},{alpha:.5f}"


def _layer_svg(body):
    # Concept artwork was drawn on the 824pt tile inset at 100pt; scale it to fill the canvas.
    k = 1024 / 824
    return ('<svg xmlns="http://www.w3.org/2000/svg" width="1024" height="1024" viewBox="0 0 1024 1024">'
            f'<g transform="translate(512 512) scale({k:.4f}) translate(-512 -512)">{body}</g></svg>\n')


def certificate_layers():
    lines = "".join(f'<rect x="352" y="{y}" width="{w}" height="30" rx="15" fill="#B9C6D3"/>'
                    for y, w in [(392, 310), (452, 250), (512, 290)])  # fewer, bolder: reads at 32px
    paper = ('<g transform="rotate(-7 512 512)">'
             '<rect x="300" y="260" width="430" height="520" rx="38" fill="#FFFFFF"/>'
             '<rect x="352" y="312" width="210" height="40" rx="20" fill="#0F766E"/>' + lines + '</g>')
    ribbons = ('<path d="M600 700 L566 860 L612 832 L640 872 L664 716 Z" fill="#B45309"/>'
               '<path d="M700 700 L734 860 L688 832 L660 872 L636 716 Z" fill="#D97706"/>')
    seal = (f'<path d="{rosette(650, 648, 112, 96, 18)}" fill="#F5A524"/>'
            '<circle cx="650" cy="648" r="76" fill="none" stroke="#FFFFFF" stroke-opacity="0.85" stroke-width="9"/>'
            + arc_arrow(650, 648, 40, 210, 480, 14, "#FFFFFF", head=1.1))
    return {"paper.svg": _layer_svg(paper), "ribbons.svg": _layer_svg(ribbons), "seal.svg": _layer_svg(seal)}


def write_icon_bundle(path):
    import json
    assets = os.path.join(path, "Assets")
    os.makedirs(assets, exist_ok=True)
    for name, content in certificate_layers().items():
        with open(os.path.join(assets, name), "w") as fh:
            fh.write(content)
    doc = {
        "fill": {
            "linear-gradient": [_p("#2DD4BF"), _p("#0B5A53")],
            "orientation": {"start": {"x": 0.5, "y": 0}, "stop": {"x": 0.5, "y": 1}},
        },
        # Front-most group first.
        "groups": [
            {
                "name": "Seal",
                "layers": [
                    {"name": "Seal", "image-name": "seal.svg", "glass": True},
                    {"name": "Ribbons", "image-name": "ribbons.svg", "glass": True},
                ],
                "shadow": {"kind": "neutral", "opacity": 0.5},
                "translucency": {"enabled": False, "value": 0.4},
                "specular": True,
            },
            {
                "name": "Certificate",
                "layers": [{"name": "Paper", "image-name": "paper.svg", "glass": False}],
                "shadow": {"kind": "neutral", "opacity": 0.5},
                "translucency": {"enabled": False, "value": 0.4},
                "specular": True,
            },
        ],
        "supported-platforms": {"squares": "shared"},
    }
    with open(os.path.join(path, "icon.json"), "w") as fh:
        json.dump(doc, fh, indent=2)
        fh.write("\n")
    print(f"wrote {path}")


if __name__ == "__main__" and "--icon" in sys.argv:
    write_icon_bundle(os.path.join(os.path.dirname(os.path.abspath(__file__)), "CertKeeper.icon"))
