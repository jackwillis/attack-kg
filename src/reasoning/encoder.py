"""Context encoding for LLM: XML (default), TOON, or JSON."""

import json
from typing import Any


def _xml_attr(key: str, value: str) -> str:
    """Escape and format an XML attribute."""
    escaped = value.replace("&", "&amp;").replace('"', "&quot;").replace("<", "&lt;")
    return f'{key}="{escaped}"'


def _semi_join(items: list[str]) -> str:
    return ";".join(items)


def _build_sw_map(techniques: list) -> dict[str, dict]:
    sw_map: dict[str, dict] = {}
    for t in techniques:
        for s in t.software:
            sid = s["attack_id"]
            if sid not in sw_map:
                sw_map[sid] = {"id": sid, "name": s["name"], "type": s["type"], "techs": []}
            sw_map[sid]["techs"].append(t.attack_id)
    return sw_map


def _build_ds_map(techniques: list) -> dict[str, list[str]]:
    ds_map: dict[str, list[str]] = {}
    for t in techniques:
        for ds in t.data_sources:
            if ds not in ds_map:
                ds_map[ds] = []
            ds_map[ds].append(t.attack_id)
    return ds_map


def encode_xml(
    techniques: list, mitigations: list[dict], d3fend: list[dict],
    finding_type: str = "",
) -> str:
    """Encode RAG context as terse XML (most token-efficient)."""
    lines = ["<ctx>", "<techniques>"]
    for t in techniques:
        attrs = [_xml_attr("id", t.attack_id)]
        if t.name:
            attrs.append(_xml_attr("n", t.name))
        if t.tactics:
            attrs.append(_xml_attr("tac", _semi_join(t.tactics)))
        attrs.append(_xml_attr("sim", f"{t.similarity:.2f}"))
        if t.platforms:
            attrs.append(_xml_attr("plat", _semi_join(t.platforms)))
        if t.description:
            desc = t.description[:200].replace("\n", " ")
            attrs.append(_xml_attr("desc", desc))
        lines.append(f"<t {' '.join(attrs)}/>")
    lines.append("</techniques>")

    # Software (skip for vulnerability findings — not actionable)
    if finding_type != "vulnerability":
        sw_map = _build_sw_map(techniques)
        if sw_map:
            lines.append("<software>")
            for sw in sorted(sw_map.values(), key=lambda x: len(x["techs"]), reverse=True)[:5]:
                lines.append(f'<sw {_xml_attr("id", sw["id"])} {_xml_attr("n", sw["name"])} '
                             f'{_xml_attr("type", sw["type"])} {_xml_attr("techs", _semi_join(sw["techs"][:5]))}/>')
            lines.append("</software>")

    # Mitigations
    lines.append("<mitigations>")
    for m in mitigations:
        m_attrs = [_xml_attr("id", m["attack_id"]), _xml_attr("n", m["name"]),
                   _xml_attr("addr", _semi_join(m.get("addresses", [])))]
        if m.get("inherited"):
            m_attrs.append('inh="true"')
        lines.append(f'<m {" ".join(m_attrs)}/>')
    lines.append("</mitigations>")

    # D3FEND (without definition — name + via link is enough)
    if d3fend:
        lines.append("<d3fend>")
        for d in d3fend:
            lines.append(f'<d {_xml_attr("id", d["d3fend_id"])} {_xml_attr("n", d["name"])} '
                         f'{_xml_attr("via", d.get("via_mitigation", ""))} '
                         f'{_xml_attr("addr", _semi_join(d.get("addresses", [])))}/>')
        lines.append("</d3fend>")

    # Data sources (supersedes detection strategies for detection recommendations)
    ds_map = _build_ds_map(techniques)
    if ds_map:
        lines.append("<datasources>")
        for ds, techs in sorted(ds_map.items(), key=lambda x: len(x[1]), reverse=True)[:10]:
            lines.append(f'<ds {_xml_attr("n", ds)} {_xml_attr("techs", _semi_join(techs[:5]))}/>')
        lines.append("</datasources>")

    lines.append("</ctx>")
    return "\n".join(lines)


def encode_toon(
    techniques: list, mitigations: list[dict], d3fend: list[dict],
    finding_type: str = "",
) -> str:
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

    # Software (skip for vulnerability findings)
    if finding_type != "vulnerability":
        sw_map = _build_sw_map(techniques)
        if sw_map:
            data["software"] = [
                {"id": sw["id"], "name": sw["name"], "type": sw["type"],
                 "techs": ";".join(sw["techs"][:5])}
                for sw in sorted(sw_map.values(), key=lambda x: len(x["techs"]), reverse=True)[:5]
            ]

    # Mitigations
    data["mitigations"] = [
        {"id": m["attack_id"], "name": m["name"],
         "addr": ";".join(m.get("addresses", [])),
         "inh": "true" if m.get("inherited") else "false"}
        for m in mitigations
    ]

    # D3FEND (without definition)
    if d3fend:
        data["d3fend"] = [
            {"id": d["d3fend_id"], "name": d["name"],
             "via": d.get("via_mitigation", ""),
             "addr": ";".join(d.get("addresses", []))}
            for d in d3fend
        ]

    # Data sources (supersedes detection strategies)
    ds_map = _build_ds_map(techniques)
    if ds_map:
        data["datasources"] = [
            {"name": ds, "techs": ";".join(techs[:5])}
            for ds, techs in sorted(ds_map.items(), key=lambda x: len(x[1]), reverse=True)[:10]
        ]

    return encode(data)


def encode_json(
    techniques: list, mitigations: list[dict], d3fend: list[dict],
    finding_type: str = "",
) -> str:
    """Encode RAG context as JSON."""
    # Data sources (deduplicated)
    ds_map = _build_ds_map(techniques)

    data: dict[str, Any] = {
        "techniques": [
            {"attack_id": t.attack_id, "name": t.name, "tactics": t.tactics,
             "similarity": round(t.similarity, 2), "platforms": t.platforms,
             "description": t.description[:200] if t.description else ""}
            for t in techniques
        ],
        "mitigations": mitigations,
        "d3fend": [{k: v for k, v in d.items() if k != "definition"} for d in d3fend],
        "data_sources": [{"name": n, "techniques": t[:5]} for n, t in
                         sorted(ds_map.items(), key=lambda x: len(x[1]), reverse=True)[:10]],
    }

    # Software (skip for vulnerability findings)
    if finding_type != "vulnerability":
        sw_map = _build_sw_map(techniques)
        data["software"] = list(sw_map.values())[:5]

    return json.dumps(data, indent=2)


ENCODERS = {"xml": encode_xml, "toon": encode_toon, "json": encode_json}


def encode_context(
    techniques: list, mitigations: list[dict], d3fend: list[dict],
    fmt: str = "xml", finding_type: str = "",
) -> str:
    """Encode RAG context in the specified format."""
    encoder = ENCODERS.get(fmt, encode_xml)
    return encoder(techniques, mitigations, d3fend, finding_type=finding_type)
