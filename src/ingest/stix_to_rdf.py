"""Convert MITRE ATT&CK STIX 2.1 to RDF N-Triples (no rdflib dependency)."""

import json
from pathlib import Path
from typing import Any

from rich.console import Console
from rich.progress import Progress, BarColumn, TextColumn, TaskProgressColumn

console = Console()

A = "https://attack.mitre.org/"
RDF_TYPE = "http://www.w3.org/1999/02/22-rdf-syntax-ns#type"
RDFS_LABEL = "http://www.w3.org/2000/01/rdf-schema#label"


def _nt_escape(s: str) -> str:
    """Escape a string for N-Triples literal."""
    return (s.replace("\\", "\\\\").replace('"', '\\"')
             .replace("\n", "\\n").replace("\r", "\\r").replace("\t", "\\t"))


def _triple(s: str, p: str, o: str) -> str:
    """Format a URI-URI-URI triple."""
    return f"<{s}> <{p}> <{o}> .\n"


def _triple_lit(s: str, p: str, value: str, datatype: str | None = None) -> str:
    """Format a URI-URI-Literal triple."""
    escaped = _nt_escape(value)
    if datatype:
        return f'<{s}> <{p}> "{escaped}"^^<{datatype}> .\n'
    return f'<{s}> <{p}> "{escaped}" .\n'


def _get_attack_id(obj: dict[str, Any]) -> str | None:
    for ref in obj.get("external_references", []):
        if ref.get("source_name") == "mitre-attack":
            return ref.get("external_id")
    return None


def _get_attack_url(obj: dict[str, Any]) -> str | None:
    for ref in obj.get("external_references", []):
        if ref.get("source_name") == "mitre-attack":
            return ref.get("url")
    return None


class StixToNTriples:
    """Two-pass STIX → N-Triples converter."""

    def __init__(self):
        self.stix_to_uri: dict[str, str] = {}
        self._triples: list[str] = []
        # Detection strategy → data component names chain (built between passes)
        self._detstrat_dc_names: dict[str, set[str]] = {}

    def _add(self, s: str, p: str, o: str):
        self._triples.append(_triple(s, p, o))

    def _add_lit(self, s: str, p: str, v: str, dt: str | None = None):
        if v:
            self._triples.append(_triple_lit(s, p, v, dt))

    def _add_type(self, uri: str, rdf_type: str):
        self._add(uri, RDF_TYPE, f"{A}{rdf_type}")

    def convert(self, bundle: dict[str, Any]) -> str:
        objects = bundle.get("objects", [])
        entities = [o for o in objects if o.get("type") != "relationship"]
        rels = [o for o in objects if o.get("type") == "relationship"]

        console.print(f"Converting {len(entities)} entities and {len(rels)} relationships")

        with Progress(TextColumn("{task.description}"), BarColumn(),
                      TaskProgressColumn(), console=console) as prog:
            task = prog.add_task("Entities...", total=len(entities))
            for obj in entities:
                if not obj.get("revoked") and not obj.get("x_mitre_deprecated"):
                    self._process_entity(obj)
                prog.advance(task)

        # Build detection strategy → data component names chain
        # (needed before relationship processing to populate dataSource triples)
        self._build_datasource_chain(objects)

        with Progress(TextColumn("{task.description}"), BarColumn(),
                      TaskProgressColumn(), console=console) as prog:
            task = prog.add_task("Relationships...", total=len(rels))
            for rel in rels:
                self._process_relationship(rel)
                prog.advance(task)

        result = "".join(self._triples)
        console.print(f"[green]Generated {len(self._triples)} triples[/green]")
        return result

    def _process_entity(self, obj: dict[str, Any]):
        handlers = {
            "attack-pattern": self._technique,
            "intrusion-set": self._group,
            "malware": self._software,
            "tool": self._software,
            "course-of-action": self._mitigation,
            "x-mitre-tactic": self._tactic,
            "x-mitre-data-source": self._data_source,
            "x-mitre-data-component": self._data_component,
            "campaign": self._campaign,
            "x-mitre-detection-strategy": self._detection_strategy,
            "x-mitre-analytic": self._analytic,
        }
        handler = handlers.get(obj.get("type"))
        if handler:
            handler(obj)

    def _base_entity(self, obj: dict, uri: str, rdf_type: str):
        self._add_type(uri, rdf_type)
        self.stix_to_uri[obj["id"]] = uri
        attack_id = _get_attack_id(obj)
        if attack_id:
            self._add_lit(uri, f"{A}attackId", attack_id)
        self._add_lit(uri, f"{A}stixId", obj["id"])
        self._add_lit(uri, RDFS_LABEL, obj.get("name", ""))
        self._add_lit(uri, f"{A}description", obj.get("description", ""))
        url = _get_attack_url(obj)
        if url:
            self._add_lit(uri, f"{A}url", url)

    def _technique(self, obj: dict):
        aid = _get_attack_id(obj)
        if not aid:
            return
        uri = f"{A}technique/{aid}"
        self._base_entity(obj, uri, "Technique")
        self._add_lit(uri, f"{A}detection", obj.get("x_mitre_detection", ""))
        for p in obj.get("x_mitre_platforms", []):
            self._add_lit(uri, f"{A}platform", p)
        for ds in obj.get("x_mitre_data_sources", []):
            self._add_lit(uri, f"{A}dataSource", ds)
        for phase in obj.get("kill_chain_phases", []):
            if phase.get("kill_chain_name") == "mitre-attack":
                self._add(uri, f"{A}tactic", f"{A}tactic/{phase['phase_name']}")
        for domain in obj.get("x_mitre_domains", []):
            self._add_lit(uri, f"{A}domain", domain)

    def _group(self, obj: dict):
        aid = _get_attack_id(obj)
        if not aid:
            return
        uri = f"{A}group/{aid}"
        self._base_entity(obj, uri, "Group")
        for alias in obj.get("aliases", []):
            self._add_lit(uri, f"{A}alias", alias)

    def _software(self, obj: dict):
        aid = _get_attack_id(obj)
        if not aid:
            return
        uri = f"{A}software/{aid}"
        rdf_type = "Malware" if obj.get("type") == "malware" else "Tool"
        self._base_entity(obj, uri, rdf_type)
        self._add_type(uri, "Software")
        for p in obj.get("x_mitre_platforms", []):
            self._add_lit(uri, f"{A}platform", p)
        for alias in obj.get("x_mitre_aliases", []):
            self._add_lit(uri, f"{A}alias", alias)

    def _mitigation(self, obj: dict):
        aid = _get_attack_id(obj)
        if not aid:
            return
        self._base_entity(obj, f"{A}mitigation/{aid}", "Mitigation")

    def _tactic(self, obj: dict):
        shortname = obj.get("x_mitre_shortname")
        if not shortname:
            return
        uri = f"{A}tactic/{shortname}"
        self._add_type(uri, "Tactic")
        self.stix_to_uri[obj["id"]] = uri
        self._add_lit(uri, f"{A}stixId", obj["id"])
        self._add_lit(uri, RDFS_LABEL, obj.get("name", ""))
        aid = _get_attack_id(obj)
        if aid:
            self._add_lit(uri, f"{A}attackId", aid)

    def _data_source(self, obj: dict):
        aid = _get_attack_id(obj)
        if not aid:
            return
        self._base_entity(obj, f"{A}datasource/{aid}", "DataSource")

    def _data_component(self, obj: dict):
        safe = obj["name"].lower().replace(" ", "-").replace("/", "-")
        uri = f"{A}datacomponent/{safe}"
        self._add_type(uri, "DataComponent")
        self.stix_to_uri[obj["id"]] = uri
        self._add_lit(uri, f"{A}stixId", obj["id"])
        self._add_lit(uri, RDFS_LABEL, obj.get("name", ""))

    def _campaign(self, obj: dict):
        aid = _get_attack_id(obj)
        if not aid:
            return
        uri = f"{A}campaign/{aid}"
        self._base_entity(obj, uri, "Campaign")
        if "first_seen" in obj:
            self._add_lit(uri, f"{A}firstSeen", obj["first_seen"])
        if "last_seen" in obj:
            self._add_lit(uri, f"{A}lastSeen", obj["last_seen"])

    def _detection_strategy(self, obj: dict):
        aid = _get_attack_id(obj)
        if not aid:
            return
        self._base_entity(obj, f"{A}detection/{aid}", "DetectionStrategy")

    def _analytic(self, obj: dict):
        aid = _get_attack_id(obj)
        if not aid:
            aid = obj["id"].split("--")[1][:8]
        self._base_entity(obj, f"{A}analytic/{aid}", "Analytic")

    def _build_datasource_chain(self, objects: list[dict]):
        """Build detection_strategy → data component names via analytics chain.

        STIX 2.1 chain: detection_strategy → x_mitre_analytic_refs → analytics
        → x_mitre_log_source_references → x_mitre_data_component_ref → data component name.
        """
        dc_names: dict[str, str] = {}
        for obj in objects:
            if obj.get("type") == "x-mitre-data-component" and not obj.get("revoked"):
                dc_names[obj["id"]] = obj.get("name", "")

        analytic_dcs: dict[str, set[str]] = {}
        for obj in objects:
            if obj.get("type") == "x-mitre-analytic" and not obj.get("x_mitre_deprecated"):
                names: set[str] = set()
                for ls in obj.get("x_mitre_log_source_references", []):
                    dc_ref = ls.get("x_mitre_data_component_ref", "")
                    if dc_ref in dc_names:
                        names.add(dc_names[dc_ref])
                analytic_dcs[obj["id"]] = names

        for obj in objects:
            if obj.get("type") == "x-mitre-detection-strategy" and not obj.get("x_mitre_deprecated"):
                names = set()
                for aref in obj.get("x_mitre_analytic_refs", []):
                    names.update(analytic_dcs.get(aref, set()))
                if names:
                    self._detstrat_dc_names[obj["id"]] = names

        total_dc = sum(len(v) for v in self._detstrat_dc_names.values())
        console.print(f"[dim]Data source chain: {len(self._detstrat_dc_names)} strategies → {total_dc} data component links[/dim]")

    def _process_relationship(self, rel: dict):
        src = self.stix_to_uri.get(rel.get("source_ref", ""))
        tgt = self.stix_to_uri.get(rel.get("target_ref", ""))
        if not src or not tgt:
            return
        pred_map = {
            "uses": "uses", "mitigates": "mitigates",
            "subtechnique-of": "subtechniqueOf", "detects": "detects",
            "attributed-to": "attributedTo",
        }
        pred = pred_map.get(rel.get("relationship_type"))
        if not pred:
            return
        self._add(src, f"{A}{pred}", tgt)
        # Inverse predicates for easier querying
        inverses = {
            "uses": "usedBy", "mitigates": "mitigatedBy",
            "detects": "detectedBy", "attributed-to": "hasCampaign",
        }
        inv = inverses.get(rel.get("relationship_type"))
        if inv:
            self._add(tgt, f"{A}{inv}", src)

        # For detects relationships, propagate data component names to technique
        if rel.get("relationship_type") == "detects":
            src_stix = rel.get("source_ref", "")
            for dc_name in self._detstrat_dc_names.get(src_stix, set()):
                self._add_lit(tgt, f"{A}dataSource", dc_name)

    def save(self, path: Path | str):
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        with open(path, "w") as f:
            f.writelines(self._triples)
        console.print(f"[green]Saved {len(self._triples)} triples to {path}[/green]")


def convert_stix_file(stix_path: Path, output_path: Path) -> Path:
    """Load STIX JSON and convert to N-Triples."""
    with open(stix_path) as f:
        bundle = json.load(f)
    converter = StixToNTriples()
    converter.convert(bundle)
    converter.save(output_path)
    return output_path
