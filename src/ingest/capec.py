"""Download and convert CAPEC data for CWE->CAPEC->ATT&CK mapping chains."""

import gzip
from pathlib import Path
from typing import Any
from xml.etree import ElementTree

import httpx
from rich.console import Console

console = Console()

CAPEC_URL = "https://capec.mitre.org/data/xml/capec_latest.xml"

A = "https://attack.mitre.org/"


def download_capec(data_dir: Path, force: bool = False) -> Path:
    """Download CAPEC XML data."""
    out = data_dir / "capec_latest.xml"
    if out.exists() and not force:
        console.print(f"[green]Cached:[/green] {out}")
        return out
    console.print("[blue]Downloading CAPEC data...[/blue]")
    with httpx.Client(timeout=60.0, follow_redirects=True) as client:
        resp = client.get(CAPEC_URL)
        resp.raise_for_status()
        content = resp.content
        # CAPEC may serve gzipped content
        if content[:2] == b'\x1f\x8b':
            content = gzip.decompress(content)
        out.write_bytes(content)
    console.print(f"[green]Downloaded:[/green] {out}")
    return out


def parse_capec(xml_path: Path) -> dict[str, Any]:
    """Parse CAPEC XML and extract CWE->CAPEC->ATT&CK mapping chains.

    Returns dict with:
        capec_to_attack: {capec_id: [attack_technique_ids]}
        cwe_to_capec: {cwe_id: [capec_ids]}
        capec_info: {capec_id: {name, description}}
    """
    tree = ElementTree.parse(xml_path)
    root = tree.getroot()

    capec_to_attack: dict[str, list[str]] = {}
    cwe_to_capec: dict[str, list[str]] = {}
    capec_info: dict[str, dict[str, str]] = {}

    # Detect namespace from root tag
    ns_prefix = ""
    if root.tag.startswith("{"):
        ns_prefix = root.tag.split("}")[0] + "}"

    for ap in root.iter(f"{ns_prefix}Attack_Pattern"):
        capec_id = ap.get("ID")
        if not capec_id:
            continue
        capec_id = f"CAPEC-{capec_id}"
        name = ap.get("Name", "")
        status = ap.get("Status", "")
        if status in ("Deprecated", "Obsolete"):
            continue

        # Get description
        desc_el = ap.find(f"{ns_prefix}Description")
        desc = ""
        if desc_el is not None:
            desc = ElementTree.tostring(desc_el, encoding="unicode", method="text").strip()[:500]

        capec_info[capec_id] = {"name": name, "description": desc}

        # Extract ATT&CK technique mappings from Taxonomy_Mappings
        for tm in ap.iter(f"{ns_prefix}Taxonomy_Mapping"):
            taxonomy = tm.get("Taxonomy_Name", "")
            if "ATT&CK" in taxonomy or "ATTACK" in taxonomy.upper():
                entry_id_el = tm.find(f"{ns_prefix}Entry_ID")
                if entry_id_el is not None and entry_id_el.text:
                    tid = entry_id_el.text.strip()
                    # CAPEC stores IDs without "T" prefix (e.g. "1574.010")
                    if not tid.startswith("T"):
                        tid = f"T{tid}"
                    capec_to_attack.setdefault(capec_id, []).append(tid)

        # Extract CWE relationships
        for rel in ap.iter(f"{ns_prefix}Related_Weakness"):
            cwe_id_attr = rel.get("CWE_ID")
            if cwe_id_attr:
                cwe_id = f"CWE-{cwe_id_attr}"
                cwe_to_capec.setdefault(cwe_id, []).append(capec_id)

    console.print(f"[green]CAPEC: {len(capec_info)} patterns, "
                  f"{len(capec_to_attack)} with ATT&CK mappings, "
                  f"{len(cwe_to_capec)} CWE mappings[/green]")
    return {
        "capec_to_attack": capec_to_attack,
        "cwe_to_capec": cwe_to_capec,
        "capec_info": capec_info,
    }


def _nt_escape(s: str) -> str:
    return (s.replace("\\", "\\\\").replace('"', '\\"')
             .replace("\n", "\\n").replace("\r", "\\r").replace("\t", "\\t"))


def capec_to_ntriples(mappings: dict[str, Any]) -> str:
    """Convert CAPEC mappings to N-Triples for loading into Oxigraph."""
    RDF_TYPE = "http://www.w3.org/1999/02/22-rdf-syntax-ns#type"
    RDFS_LABEL = "http://www.w3.org/2000/01/rdf-schema#label"
    triples: list[str] = []

    for capec_id, techs in mappings["capec_to_attack"].items():
        capec_num = capec_id.replace("CAPEC-", "")
        uri = f"{A}capec/{capec_num}"
        triples.append(f'<{uri}> <{RDF_TYPE}> <{A}CAPEC> .\n')
        info = mappings["capec_info"].get(capec_id, {})
        name = _nt_escape(info.get("name", capec_id))
        triples.append(f'<{uri}> <{RDFS_LABEL}> "{name}" .\n')
        triples.append(f'<{uri}> <{A}capecId> "{_nt_escape(capec_id)}" .\n')
        if info.get("description"):
            triples.append(f'<{uri}> <{A}description> "{_nt_escape(info["description"])}" .\n')
        for tid in techs:
            tech_uri = f"{A}technique/{tid}"
            triples.append(f'<{uri}> <{A}mapsToTechnique> <{tech_uri}> .\n')
            triples.append(f'<{tech_uri}> <{A}mappedFromCAPEC> <{uri}> .\n')

    for cwe_id, capecs in mappings["cwe_to_capec"].items():
        cwe_num = cwe_id.replace("CWE-", "")
        cwe_uri = f"{A}cwe/{cwe_num}"
        triples.append(f'<{cwe_uri}> <{RDF_TYPE}> <{A}CWE> .\n')
        triples.append(f'<{cwe_uri}> <{A}cweId> "{_nt_escape(cwe_id)}" .\n')
        for capec_id in capecs:
            capec_num = capec_id.replace("CAPEC-", "")
            capec_uri = f"{A}capec/{capec_num}"
            triples.append(f'<{cwe_uri}> <{A}mapsToCAPEC> <{capec_uri}> .\n')

    console.print(f"[green]Generated {len(triples)} CAPEC/CWE triples[/green]")
    return "".join(triples)


def parse_capec_for_embedding(mappings: dict[str, Any]) -> list[dict[str, Any]]:
    """Convert parsed CAPEC mappings into documents for ChromaDB embedding.

    One document per (CAPEC pattern, ATT&CK technique) pair.
    Returns list of dicts with: id, text, metadata.
    """
    docs: list[dict[str, Any]] = []
    seen: set[str] = set()
    for capec_id, techs in mappings["capec_to_attack"].items():
        info = mappings["capec_info"].get(capec_id, {})
        name = info.get("name", capec_id)
        desc = info.get("description", "")
        for attack_id in techs:
            doc_id = f"capec:{capec_id}:{attack_id}"
            if doc_id in seen:
                continue
            seen.add(doc_id)
            text = f"Attack Pattern: {name}\nID: {capec_id}\nTechnique: {attack_id}"
            if desc:
                text += f"\nDescription: {desc}"
            docs.append({
                "id": doc_id,
                "text": text,
                "metadata": {
                    "type": "capec",
                    "capec_id": capec_id,
                    "attack_id": attack_id,
                    "name": name,
                },
            })
    console.print(f"[green]CAPEC embedding: {len(docs)} documents[/green]")
    return docs


def convert_capec_file(xml_path: Path, output_path: Path) -> Path:
    """Parse CAPEC XML and convert to N-Triples."""
    mappings = parse_capec(xml_path)
    nt = capec_to_ntriples(mappings)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(nt)
    console.print(f"[green]Saved CAPEC triples to {output_path}[/green]")
    return output_path
