"""Context encoding for LLM: XML (default), TOON, or JSON."""

import json
from typing import Any


def _xml_attr(key: str, value: str) -> str:
    """Escape and format an XML attribute."""
    escaped = value.replace("&", "&amp;").replace('"', "&quot;").replace("<", "&lt;")
    return f'{key}="{escaped}"'


def _semi_join(items: list[str]) -> str:
    return ";".join(items)


def encode_xml(techniques: list, mitigations: list[dict], d3fend: list[dict]) -> str:
    """Encode RAG context as terse XML (most token-efficient)."""
    lines = ["<ctx>", "<techniques>"]
    for t in techniques:
        attrs = [
            _xml_attr("id", t.attack_id),
            _xml_attr("n", t.name),
            _xml_attr("tac", _semi_join(t.tactics)),
            _xml_attr("sim", f"{t.similarity:.2f}"),
            _xml_attr("plat", _semi_join(t.platforms)),
        ]
        if t.description:
            desc = t.description[:200].replace("\n", " ")
            attrs.append(_xml_attr("desc", desc))
        lines.append(f"<t {' '.join(attrs)}/>")
    lines.append("</techniques>")

    # Software
    sw_map: dict[str, dict] = {}
    for t in techniques:
        for s in t.software:
            sid = s["attack_id"]
            if sid not in sw_map:
                sw_map[sid] = {"id": sid, "name": s["name"], "type": s["type"], "techs": []}
            sw_map[sid]["techs"].append(t.attack_id)
    if sw_map:
        lines.append("<software>")
        for sw in sorted(sw_map.values(), key=lambda x: len(x["techs"]), reverse=True)[:10]:
            lines.append(f'<sw {_xml_attr("id", sw["id"])} {_xml_attr("n", sw["name"])} '
                         f'{_xml_attr("type", sw["type"])} {_xml_attr("techs", _semi_join(sw["techs"][:5]))}/>')
        lines.append("</software>")

    # Mitigations
    lines.append("<mitigations>")
    for m in mitigations:
        inh = "true" if m.get("inherited") else "false"
        lines.append(f'<m {_xml_attr("id", m["attack_id"])} {_xml_attr("n", m["name"])} '
                     f'{_xml_attr("addr", _semi_join(m.get("addresses", [])))} '
                     f'{_xml_attr("inh", inh)}/>')
    lines.append("</mitigations>")

    # D3FEND
    if d3fend:
        lines.append("<d3fend>")
        for d in d3fend:
            defn = (d.get("definition", "") or "")[:100].replace("\n", " ")
            lines.append(f'<d {_xml_attr("id", d["d3fend_id"])} {_xml_attr("n", d["name"])} '
                         f'{_xml_attr("via", d.get("via_mitigation", ""))} '
                         f'{_xml_attr("addr", _semi_join(d.get("addresses", [])))} '
                         f'{_xml_attr("def", defn)}/>')
        lines.append("</d3fend>")

    # Detection strategies
    det_map: dict[str, list[str]] = {}
    for t in techniques:
        for d in t.detection_strategies:
            dn = d.get("name", d.get("attack_id", ""))
            if dn not in det_map:
                det_map[dn] = []
            det_map[dn].append(t.attack_id)
    if det_map:
        lines.append("<detections>")
        for name, techs in sorted(det_map.items(), key=lambda x: len(x[1]), reverse=True)[:10]:
            lines.append(f'<det {_xml_attr("n", name)} {_xml_attr("techs", _semi_join(techs[:5]))}/>')
        lines.append("</detections>")

    # Data sources
    ds_map: dict[str, list[str]] = {}
    for t in techniques:
        for ds in t.data_sources:
            if ds not in ds_map:
                ds_map[ds] = []
            ds_map[ds].append(t.attack_id)
    if ds_map:
        lines.append("<datasources>")
        for ds, techs in sorted(ds_map.items(), key=lambda x: len(x[1]), reverse=True)[:10]:
            lines.append(f'<ds {_xml_attr("n", ds)} {_xml_attr("techs", _semi_join(techs[:5]))}/>')
        lines.append("</datasources>")

    lines.append("</ctx>")
    return "\n".join(lines)


def encode_toon(techniques: list, mitigations: list[dict], d3fend: list[dict]) -> str:
    """Encode RAG context as TOON format (real toon-format library)."""
    from toon_format import encode

    data: dict[str, Any] = {}

    # Techniques
    data["techniques"] = [
        {"id": t.attack_id, "name": t.name, "tactics": ";".join(t.tactics),
         "sim": f"{t.similarity:.2f}", "plat": ";".join(t.platforms),
         "desc": (t.description[:200].replace("\n", " ") if t.description else "")}
        for t in techniques
    ]

    # Software (deduplicated, top 10 by technique coverage)
    sw_map: dict[str, dict] = {}
    for t in techniques:
        for s in t.software:
            sid = s["attack_id"]
            if sid not in sw_map:
                sw_map[sid] = {"id": sid, "name": s["name"], "type": s["type"], "techs": []}
            sw_map[sid]["techs"].append(t.attack_id)
    if sw_map:
        data["software"] = [
            {"id": sw["id"], "name": sw["name"], "type": sw["type"],
             "techs": ";".join(sw["techs"][:5])}
            for sw in sorted(sw_map.values(), key=lambda x: len(x["techs"]), reverse=True)[:10]
        ]

    # Mitigations
    data["mitigations"] = [
        {"id": m["attack_id"], "name": m["name"],
         "addr": ";".join(m.get("addresses", [])),
         "inh": "true" if m.get("inherited") else "false"}
        for m in mitigations
    ]

    # D3FEND
    if d3fend:
        data["d3fend"] = [
            {"id": d["d3fend_id"], "name": d["name"],
             "via": d.get("via_mitigation", ""),
             "addr": ";".join(d.get("addresses", [])),
             "def": (d.get("definition", "") or "")[:100].replace("\n", " ")}
            for d in d3fend
        ]

    # Detection strategies (deduplicated by name, top 10)
    det_map: dict[str, list[str]] = {}
    for t in techniques:
        for det in t.detection_strategies:
            dn = det.get("name", "")
            if dn not in det_map:
                det_map[dn] = []
            det_map[dn].append(t.attack_id)
    if det_map:
        data["detections"] = [
            {"name": name, "techs": ";".join(techs[:5])}
            for name, techs in sorted(det_map.items(), key=lambda x: len(x[1]), reverse=True)[:10]
        ]

    # Data sources (deduplicated, top 10)
    ds_map: dict[str, list[str]] = {}
    for t in techniques:
        for ds in t.data_sources:
            if ds not in ds_map:
                ds_map[ds] = []
            ds_map[ds].append(t.attack_id)
    if ds_map:
        data["datasources"] = [
            {"name": ds, "techs": ";".join(techs[:5])}
            for ds, techs in sorted(ds_map.items(), key=lambda x: len(x[1]), reverse=True)[:10]
        ]

    return encode(data)


def encode_json(techniques: list, mitigations: list[dict], d3fend: list[dict]) -> str:
    """Encode RAG context as JSON."""
    data = {
        "techniques": [
            {"attack_id": t.attack_id, "name": t.name, "tactics": t.tactics,
             "similarity": round(t.similarity, 2), "platforms": t.platforms,
             "description": t.description[:200] if t.description else ""}
            for t in techniques
        ],
        "mitigations": mitigations,
        "d3fend": d3fend,
    }
    return json.dumps(data, indent=2)


ENCODERS = {"xml": encode_xml, "toon": encode_toon, "json": encode_json}


def encode_context(
    techniques: list, mitigations: list[dict], d3fend: list[dict],
    fmt: str = "xml",
) -> str:
    """Encode RAG context in the specified format."""
    encoder = ENCODERS.get(fmt, encode_xml)
    return encoder(techniques, mitigations, d3fend)
