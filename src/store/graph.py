"""RDF graph store backed by pyoxigraph."""

from pathlib import Path
from typing import Any

from rich.console import Console

console = Console()

A = "https://attack.mitre.org/"

PREFIXES = """
PREFIX attack: <https://attack.mitre.org/>
PREFIX rdfs: <http://www.w3.org/2000/01/rdf-schema#>
PREFIX d3f: <http://d3fend.mitre.org/ontologies/d3fend.owl#>
"""


class AttackGraph:
    """RDF graph interface for ATT&CK + D3FEND knowledge base."""

    def __init__(self, store_path: Path | str | None = None):
        import pyoxigraph
        self._store = (
            pyoxigraph.Store(str(Path(store_path).resolve()))
            if store_path
            else pyoxigraph.Store()
        )
        if store_path:
            Path(store_path).mkdir(parents=True, exist_ok=True)

    def load_file(self, path: Path | str, fmt: str = "nt", clear: bool = False) -> int:
        """Load an RDF file into the store. Always additive unless clear=True."""
        import pyoxigraph, time
        path = Path(path)
        before = len(self._store)
        if clear and before > 0:
            self._store.clear()
            before = 0
        formats = {
            "nt": pyoxigraph.RdfFormat.N_TRIPLES,
            "ttl": pyoxigraph.RdfFormat.TURTLE,
            "xml": pyoxigraph.RdfFormat.RDF_XML,
        }
        rdf_fmt = formats.get(fmt, pyoxigraph.RdfFormat.N_TRIPLES)
        start = time.time()
        with open(path, "rb") as f:
            self._store.bulk_load(f, rdf_fmt, to_graph=pyoxigraph.DefaultGraph())
        loaded = len(self._store) - before
        console.print(f"[green]Loaded {loaded} triples in {time.time()-start:.1f}s[/green]")
        return loaded

    def query(self, sparql: str) -> list[dict[str, Any]]:
        results = self._store.query(PREFIXES + sparql)
        if not hasattr(results, "variables"):
            return []
        variables = list(results.variables)
        rows = []
        for solution in results:
            row = {}
            for var in variables:
                val = solution[var]
                if val is not None:
                    row[str(var).lstrip("?")] = str(val.value) if hasattr(val, "value") else str(val)
            rows.append(row)
        return rows

    def __len__(self) -> int:
        return len(self._store)

    # --- Technique queries ---

    def _tech_uri(self, attack_id: str) -> str:
        return f"<https://attack.mitre.org/technique/{attack_id}>"

    def get_technique(self, attack_id: str) -> dict[str, Any] | None:
        uri = self._tech_uri(attack_id)
        rows = self.query(f"""
        SELECT ?name ?description ?detection
               (GROUP_CONCAT(DISTINCT ?tactic; separator=",") AS ?tactics)
               (GROUP_CONCAT(DISTINCT ?platform; separator=",") AS ?platforms)
        WHERE {{
            {uri} rdfs:label ?name .
            OPTIONAL {{ {uri} attack:description ?description }}
            OPTIONAL {{ {uri} attack:detection ?detection }}
            OPTIONAL {{ {uri} attack:tactic ?tu . ?tu rdfs:label ?tactic }}
            OPTIONAL {{ {uri} attack:platform ?platform }}
        }}
        GROUP BY ?name ?description ?detection
        """)
        if not rows:
            return None
        r = rows[0]
        return {
            "attack_id": attack_id,
            "name": r.get("name", ""),
            "description": r.get("description", ""),
            "detection": r.get("detection", ""),
            "tactics": [t for t in r.get("tactics", "").split(",") if t],
            "platforms": [p for p in r.get("platforms", "").split(",") if p],
        }

    def get_mitigations_with_inheritance(self, attack_id: str) -> list[dict[str, Any]]:
        uri = self._tech_uri(attack_id)
        if "." in attack_id:
            parent_uri = self._tech_uri(attack_id.split(".")[0])
            sparql = f"""
            SELECT DISTINCT ?attackId ?name ?source WHERE {{
                {{
                    ?m a attack:Mitigation ; attack:mitigates {uri} ;
                       attack:attackId ?attackId ; rdfs:label ?name .
                    BIND("direct" AS ?source)
                }}
                UNION
                {{
                    ?m a attack:Mitigation ; attack:mitigates {parent_uri} ;
                       attack:attackId ?attackId ; rdfs:label ?name .
                    BIND("inherited" AS ?source)
                }}
            }} ORDER BY ?name
            """
        else:
            sparql = f"""
            SELECT ?attackId ?name WHERE {{
                ?m a attack:Mitigation ; attack:mitigates {uri} ;
                   attack:attackId ?attackId ; rdfs:label ?name .
            }} ORDER BY ?name
            """
        return [
            {"attack_id": r["attackId"], "name": r["name"],
             "inherited": r.get("source") == "inherited"}
            for r in self.query(sparql)
        ]

    def get_software_for_technique(self, attack_id: str) -> list[dict[str, str]]:
        uri = self._tech_uri(attack_id)
        rows = self.query(f"""
        SELECT ?attackId ?name ?type WHERE {{
            ?sw attack:uses {uri} ; attack:attackId ?attackId ;
                rdfs:label ?name ; a ?type .
            FILTER(?type IN (attack:Malware, attack:Tool))
        }} ORDER BY ?name
        """)
        return [
            {"attack_id": r["attackId"], "name": r["name"],
             "type": "Malware" if "Malware" in r.get("type", "") else "Tool"}
            for r in rows
        ]

    def get_groups_for_technique(self, attack_id: str) -> list[dict[str, str]]:
        uri = self._tech_uri(attack_id)
        return [
            {"attack_id": r["attackId"], "name": r["name"]}
            for r in self.query(f"""
            SELECT ?attackId ?name WHERE {{
                ?g a attack:Group ; attack:uses {uri} ;
                   attack:attackId ?attackId ; rdfs:label ?name .
            }} ORDER BY ?name
            """)
        ]

    def get_detection_strategies(self, attack_id: str) -> list[dict[str, str]]:
        uri = self._tech_uri(attack_id)
        return [
            {"attack_id": r["attackId"], "name": r["name"]}
            for r in self.query(f"""
            SELECT ?attackId ?name WHERE {{
                ?d a attack:DetectionStrategy ; attack:detects {uri} ;
                   attack:attackId ?attackId ; rdfs:label ?name .
            }} ORDER BY ?attackId
            """)
        ]

    def get_data_sources(self, attack_id: str) -> list[str]:
        uri = self._tech_uri(attack_id)
        return [r["ds"] for r in self.query(f"""
        SELECT DISTINCT ?ds WHERE {{ {uri} attack:dataSource ?ds . }} ORDER BY ?ds
        """)]

    def get_campaigns_for_technique(self, attack_id: str) -> list[dict[str, str]]:
        uri = self._tech_uri(attack_id)
        return [
            {"attack_id": r["attackId"], "name": r["name"]}
            for r in self.query(f"""
            SELECT ?attackId ?name WHERE {{
                ?c a attack:Campaign ; attack:uses {uri} ;
                   attack:attackId ?attackId ; rdfs:label ?name .
            }} ORDER BY ?name
            """)
        ]

    def get_subtechniques(self, parent_id: str) -> list[dict[str, str]]:
        uri = self._tech_uri(parent_id)
        return [
            {"attack_id": r["attackId"], "name": r["name"]}
            for r in self.query(f"""
            SELECT ?attackId ?name WHERE {{
                ?t attack:subtechniqueOf {uri} ;
                   attack:attackId ?attackId ; rdfs:label ?name .
            }} ORDER BY ?attackId
            """)
        ]

    # --- Co-occurrence ---

    def get_cooccurring_techniques(
        self, attack_id: str, min_count: int = 2, limit: int = 20
    ) -> list[dict[str, Any]]:
        """Get co-occurring techniques with source type weighting.

        Returns techniques that appear alongside attack_id in campaigns/groups,
        with separate campaign and group counts for differential weighting.
        """
        uri = self._tech_uri(attack_id)
        # Campaign co-occurrence (weighted higher — more specific)
        campaign_rows = self.query(f"""
        SELECT ?rid ?rname (COUNT(DISTINCT ?c) AS ?cnt)
               (MIN(?firstSeen) AS ?earliest) (MAX(?lastSeen) AS ?latest)
        WHERE {{
            ?c a attack:Campaign ; attack:uses {uri} ; attack:uses ?related .
            ?related a attack:Technique ;
                     attack:attackId ?rid ; rdfs:label ?rname .
            OPTIONAL {{ ?c attack:firstSeen ?firstSeen }}
            OPTIONAL {{ ?c attack:lastSeen ?lastSeen }}
            FILTER(?rid != "{attack_id}")
        }}
        GROUP BY ?rid ?rname
        HAVING(COUNT(DISTINCT ?c) >= 1)
        ORDER BY DESC(?cnt) LIMIT {limit}
        """)
        # Group co-occurrence
        group_rows = self.query(f"""
        SELECT ?rid ?rname (COUNT(DISTINCT ?g) AS ?cnt)
        WHERE {{
            ?g a attack:Group ; attack:uses {uri} ; attack:uses ?related .
            ?related a attack:Technique ;
                     attack:attackId ?rid ; rdfs:label ?rname .
            FILTER(?rid != "{attack_id}")
        }}
        GROUP BY ?rid ?rname
        HAVING(COUNT(DISTINCT ?g) >= {min_count})
        ORDER BY DESC(?cnt) LIMIT {limit}
        """)
        # Merge results with source info
        merged: dict[str, dict[str, Any]] = {}
        for r in campaign_rows:
            aid = r["rid"]
            merged[aid] = {
                "attack_id": aid, "name": r["rname"],
                "campaign_count": int(r["cnt"]), "group_count": 0,
                "latest_campaign": r.get("latest", ""),
            }
        for r in group_rows:
            aid = r["rid"]
            if aid in merged:
                merged[aid]["group_count"] = int(r["cnt"])
            else:
                merged[aid] = {
                    "attack_id": aid, "name": r["rname"],
                    "campaign_count": 0, "group_count": int(r["cnt"]),
                    "latest_campaign": "",
                }
        # Sort by weighted count (campaigns 1.5x, groups 1.0x)
        for v in merged.values():
            v["count"] = v["campaign_count"] + v["group_count"]
        results = sorted(merged.values(), key=lambda x: x["count"], reverse=True)
        return results[:limit]

    # --- CAPEC / CWE ---

    def get_techniques_for_cwe(self, cwe_id: str) -> list[dict[str, str]]:
        """Map CWE -> CAPEC -> ATT&CK techniques."""
        cwe_num = cwe_id.replace("CWE-", "").replace("cwe-", "")
        return [
            {"attack_id": r["tid"], "name": r.get("tname", ""),
             "via_capec": r.get("capecId", "")}
            for r in self.query(f"""
            SELECT ?tid ?tname ?capecId WHERE {{
                <{A}cwe/{cwe_num}> attack:mapsToCAPEC ?capec .
                ?capec attack:mapsToTechnique ?tech .
                ?tech attack:attackId ?tid .
                OPTIONAL {{ ?tech rdfs:label ?tname }}
                OPTIONAL {{ ?capec attack:capecId ?capecId }}
            }}
            """)
        ]

    def get_techniques_for_capec(self, capec_id: str) -> list[dict[str, str]]:
        """Map CAPEC -> ATT&CK techniques."""
        capec_num = capec_id.replace("CAPEC-", "").replace("capec-", "")
        return [
            {"attack_id": r["tid"], "name": r.get("tname", "")}
            for r in self.query(f"""
            SELECT ?tid ?tname WHERE {{
                <{A}capec/{capec_num}> attack:mapsToTechnique ?tech .
                ?tech attack:attackId ?tid .
                OPTIONAL {{ ?tech rdfs:label ?tname }}
            }}
            """)
        ]

    # --- D3FEND ---

    def get_d3fend_for_mitigation(self, mitigation_id: str) -> list[dict[str, Any]]:
        return [
            {"d3fend_id": r["did"], "name": r["name"],
             "definition": r.get("definition", "")}
            for r in self.query(f"""
            SELECT DISTINCT ?did ?name ?definition WHERE {{
                ?tech d3f:d3fend-id ?did ; rdfs:label ?name .
                {{ ?tech d3f:related d3f:{mitigation_id} . }}
                UNION
                {{ d3f:{mitigation_id} d3f:related ?tech . }}
                OPTIONAL {{ ?tech d3f:definition ?definition }}
                FILTER(STRSTARTS(?did, "D3-"))
            }} ORDER BY ?name
            """)
        ]

    def get_d3fend_for_technique(self, attack_id: str) -> list[dict[str, Any]]:
        mitigations = self.get_mitigations_with_inheritance(attack_id)
        results, seen = [], set()
        for mit in mitigations:
            for d3f in self.get_d3fend_for_mitigation(mit["attack_id"]):
                if d3f["d3fend_id"] not in seen:
                    seen.add(d3f["d3fend_id"])
                    results.append({**d3f, "via_mitigation": mit["attack_id"]})
        return results

    # --- Stats ---

    def get_stats(self) -> dict[str, int]:
        rows = self.query("""
        SELECT
            (COUNT(DISTINCT ?t) AS ?techniques) (COUNT(DISTINCT ?g) AS ?groups)
            (COUNT(DISTINCT ?s) AS ?software) (COUNT(DISTINCT ?m) AS ?mitigations)
        WHERE {
            { ?t a attack:Technique } UNION { ?g a attack:Group }
            UNION { ?s a attack:Software } UNION { ?m a attack:Mitigation }
        }
        """)
        if rows:
            return {k: int(v) for k, v in rows[0].items()}
        return {}
