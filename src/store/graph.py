"""RDF Graph store backed by Oxigraph."""

from pathlib import Path
from typing import Any

from rich.console import Console
from rich.table import Table

console = Console()


class AttackGraph:
    """
    RDF graph interface for ATT&CK knowledge base.

    Uses pyoxigraph directly for performance. Avoids oxrdflib which has issues.
    """

    def __init__(self, store_path: Path | str | None = None):
        """
        Initialize the graph store.

        Args:
            store_path: Path for persistent storage. If None, uses in-memory store.
        """
        import pyoxigraph

        self.store_path = Path(store_path) if store_path else None

        if self.store_path:
            self.store_path.mkdir(parents=True, exist_ok=True)
            self._store = pyoxigraph.Store(str(self.store_path))
            console.print(f"[green]Using Oxigraph store at:[/green] {self.store_path}")
        else:
            self._store = pyoxigraph.Store()

    def load_from_file(self, path: Path | str, format: str = "nt", force: bool = False) -> int:
        """
        Load triples from a file into the graph.

        Args:
            path: Path to RDF file
            format: RDF serialization format (nt, turtle)
            force: Reload even if store already has data

        Returns:
            Number of triples loaded
        """
        import time
        import pyoxigraph

        path = Path(path)
        before = len(self._store)

        # Skip loading if store already has data
        if before > 0 and not force:
            console.print(f"[green]Store already has {before} triples, skipping load[/green]")
            console.print(f"[dim](use --force to reload)[/dim]")
            return 0

        # Clear if forcing reload
        if force and before > 0:
            console.print(f"[yellow]Clearing {before} existing triples...[/yellow]")
            self._store.clear()

        console.print(f"[blue]Loading {path}...[/blue]")
        start = time.time()

        # Map format to pyoxigraph RdfFormat
        formats = {
            "nt": pyoxigraph.RdfFormat.N_TRIPLES,
            "ntriples": pyoxigraph.RdfFormat.N_TRIPLES,
            "turtle": pyoxigraph.RdfFormat.TURTLE,
            "ttl": pyoxigraph.RdfFormat.TURTLE,
            "xml": pyoxigraph.RdfFormat.RDF_XML,
        }
        rdf_format = formats.get(format, pyoxigraph.RdfFormat.N_TRIPLES)

        # Load into default graph
        with open(path, "rb") as f:
            self._store.bulk_load(f, rdf_format, to_graph=pyoxigraph.DefaultGraph())

        after = len(self._store)
        parse_time = time.time() - start
        loaded = after - before
        console.print(f"[green]Loaded {loaded} triples in {parse_time:.1f}s[/green]")
        return loaded

    def query(self, sparql: str, context: str | None = None) -> list[dict[str, Any]]:
        """
        Execute a SPARQL SELECT query.

        Args:
            sparql: SPARQL query string
            context: Optional context for logging (e.g., "get_technique")

        Returns:
            List of result rows as dictionaries
        """
        from src.logging import log_sparql_query, log_sparql_result

        query_id = log_sparql_query(sparql, context=context)

        results = self._store.query(sparql)

        # Handle SELECT queries
        if hasattr(results, 'variables'):
            variables = list(results.variables)  # Keep as Variable objects
            rows = []
            for solution in results:
                row = {}
                for var in variables:
                    val = solution[var]  # Access with Variable object
                    if val is not None:
                        # Get the variable name without '?' prefix
                        var_name = str(var).lstrip('?')
                        # Extract value from Literal/NamedNode
                        row[var_name] = str(val.value) if hasattr(val, 'value') else str(val)
                rows.append(row)

            log_sparql_result(query_id, rows)
            return rows

        log_sparql_result(query_id, [])
        return []

    def query_to_list(self, sparql: str) -> list[dict[str, Any]]:
        """Alias for query() for compatibility."""
        return self.query(sparql)

    def print_query_results(self, sparql: str, title: str = "Query Results") -> None:
        """Execute a query and print results as a formatted table."""
        rows = self.query(sparql)

        if not rows:
            console.print(f"[yellow]No results for query[/yellow]")
            return

        # Get all keys from first row
        columns = list(rows[0].keys()) if rows else []

        table = Table(title=title)
        for col in columns:
            table.add_column(col)

        for row in rows:
            table.add_row(*[str(row.get(col, "")) for col in columns])

        console.print(table)

    def __len__(self) -> int:
        """Return the number of triples in the graph."""
        return len(self._store)

    # -------------------------------------------------------------------------
    # Convenience query methods for ATT&CK
    # -------------------------------------------------------------------------

    def get_technique(self, attack_id: str) -> dict[str, Any] | None:
        """Get a technique by its ATT&CK ID (e.g., T1110.003)."""
        # Use full URI to handle dots in technique IDs
        tech_uri = f"<https://attack.mitre.org/technique/{attack_id}>"
        sparql = f"""
        PREFIX attack: <https://attack.mitre.org/>
        PREFIX rdfs: <http://www.w3.org/2000/01/rdf-schema#>

        SELECT ?name ?description ?detection
               (GROUP_CONCAT(DISTINCT ?tactic; separator=",") AS ?tactics)
        WHERE {{
            {tech_uri} rdfs:label ?name .
            OPTIONAL {{ {tech_uri} attack:description ?description }}
            OPTIONAL {{ {tech_uri} attack:detection ?detection }}
            OPTIONAL {{ {tech_uri} attack:tactic ?tacticUri .
                        ?tacticUri rdfs:label ?tactic }}
        }}
        GROUP BY ?name ?description ?detection
        """
        results = self.query(sparql)
        if results:
            tactics_str = results[0].get("tactics", "")
            return {
                "attack_id": attack_id,
                "name": results[0].get("name", ""),
                "description": results[0].get("description", ""),
                "detection": results[0].get("detection", ""),
                "tactics": [t.strip() for t in tactics_str.split(",") if t.strip()] if tactics_str else [],
            }
        return None

    def get_techniques_for_tactic(self, tactic: str) -> list[dict[str, str]]:
        """Get all techniques for a given tactic."""
        tactic_uri = f"<https://attack.mitre.org/tactic/{tactic}>"
        sparql = f"""
        PREFIX attack: <https://attack.mitre.org/>
        PREFIX rdfs: <http://www.w3.org/2000/01/rdf-schema#>

        SELECT ?attackId ?name WHERE {{
            ?technique a attack:Technique ;
                       attack:tactic {tactic_uri} ;
                       attack:attackId ?attackId ;
                       rdfs:label ?name .
        }}
        ORDER BY ?attackId
        """
        return [{"attack_id": r["attackId"], "name": r["name"]} for r in self.query(sparql)]

    def get_groups_using_technique(self, attack_id: str) -> list[dict[str, str]]:
        """Get threat groups that use a specific technique."""
        tech_uri = f"<https://attack.mitre.org/technique/{attack_id}>"
        sparql = f"""
        PREFIX attack: <https://attack.mitre.org/>
        PREFIX rdfs: <http://www.w3.org/2000/01/rdf-schema#>

        SELECT ?attackId ?name WHERE {{
            ?group a attack:Group ;
                   attack:uses {tech_uri} ;
                   attack:attackId ?attackId ;
                   rdfs:label ?name .
        }}
        ORDER BY ?name
        """
        return [{"attack_id": r["attackId"], "name": r["name"]} for r in self.query(sparql)]

    def get_mitigation(self, attack_id: str) -> dict[str, Any] | None:
        """Get a mitigation by its ATT&CK ID (e.g., M1032)."""
        mit_uri = f"<https://attack.mitre.org/mitigation/{attack_id}>"
        sparql = f"""
        PREFIX attack: <https://attack.mitre.org/>
        PREFIX rdfs: <http://www.w3.org/2000/01/rdf-schema#>

        SELECT ?name ?description WHERE {{
            {mit_uri} rdfs:label ?name .
            OPTIONAL {{ {mit_uri} attack:description ?description }}
        }}
        """
        results = self.query(sparql)
        if results:
            return {
                "attack_id": attack_id,
                "name": results[0].get("name", ""),
                "description": results[0].get("description", ""),
            }
        return None

    def get_mitigations_for_technique(self, attack_id: str) -> list[dict[str, str]]:
        """Get mitigations for a specific technique."""
        tech_uri = f"<https://attack.mitre.org/technique/{attack_id}>"
        sparql = f"""
        PREFIX attack: <https://attack.mitre.org/>
        PREFIX rdfs: <http://www.w3.org/2000/01/rdf-schema#>

        SELECT ?attackId ?name WHERE {{
            ?mitigation a attack:Mitigation ;
                        attack:mitigates {tech_uri} ;
                        attack:attackId ?attackId ;
                        rdfs:label ?name .
        }}
        ORDER BY ?name
        """
        return [{"attack_id": r["attackId"], "name": r["name"]} for r in self.query(sparql)]

    def get_mitigations_with_inheritance(self, attack_id: str) -> list[dict[str, Any]]:
        """
        Get mitigations for a technique, including parent mitigations for subtechniques.

        For subtechniques (e.g., T1059.001), this returns both:
        - Direct mitigations that specifically target the subtechnique
        - Inherited mitigations from the parent technique (e.g., T1059)

        Args:
            attack_id: ATT&CK technique ID (e.g., T1059.001 or T1059)

        Returns:
            List of mitigations with 'inherited' flag indicating source
        """
        tech_uri = f"<https://attack.mitre.org/technique/{attack_id}>"

        # Check if this is a subtechnique
        if "." in attack_id:
            parent_id = attack_id.split(".")[0]
            parent_uri = f"<https://attack.mitre.org/technique/{parent_id}>"

            # UNION query: direct mitigations + parent mitigations
            sparql = f"""
            PREFIX attack: <https://attack.mitre.org/>
            PREFIX rdfs: <http://www.w3.org/2000/01/rdf-schema#>

            SELECT DISTINCT ?attackId ?name ?source WHERE {{
                {{
                    ?mitigation a attack:Mitigation ;
                                attack:mitigates {tech_uri} ;
                                attack:attackId ?attackId ;
                                rdfs:label ?name .
                    BIND("direct" AS ?source)
                }}
                UNION
                {{
                    ?mitigation a attack:Mitigation ;
                                attack:mitigates {parent_uri} ;
                                attack:attackId ?attackId ;
                                rdfs:label ?name .
                    BIND("inherited" AS ?source)
                }}
            }}
            ORDER BY ?name
            """
        else:
            # Parent technique - just get direct mitigations
            sparql = f"""
            PREFIX attack: <https://attack.mitre.org/>
            PREFIX rdfs: <http://www.w3.org/2000/01/rdf-schema#>

            SELECT ?attackId ?name WHERE {{
                ?mitigation a attack:Mitigation ;
                            attack:mitigates {tech_uri} ;
                            attack:attackId ?attackId ;
                            rdfs:label ?name .
            }}
            ORDER BY ?name
            """

        results = self.query(sparql)
        return [
            {
                "attack_id": r["attackId"],
                "name": r["name"],
                "inherited": r.get("source") == "inherited",
            }
            for r in results
        ]

    def get_software_using_technique(self, attack_id: str) -> list[dict[str, str]]:
        """Get software (malware/tools) that use a specific technique."""
        tech_uri = f"<https://attack.mitre.org/technique/{attack_id}>"
        sparql = f"""
        PREFIX attack: <https://attack.mitre.org/>
        PREFIX rdfs: <http://www.w3.org/2000/01/rdf-schema#>

        SELECT ?attackId ?name ?type WHERE {{
            ?software attack:uses {tech_uri} ;
                      attack:attackId ?attackId ;
                      rdfs:label ?name ;
                      a ?type .
            FILTER(?type IN (attack:Malware, attack:Tool))
        }}
        ORDER BY ?name
        """
        return [
            {
                "attack_id": r["attackId"],
                "name": r["name"],
                "type": "Malware" if "Malware" in r.get("type", "") else "Tool",
            }
            for r in self.query(sparql)
        ]

    def get_subtechniques(self, parent_id: str) -> list[dict[str, str]]:
        """Get sub-techniques of a parent technique."""
        parent_uri = f"<https://attack.mitre.org/technique/{parent_id}>"
        sparql = f"""
        PREFIX attack: <https://attack.mitre.org/>
        PREFIX rdfs: <http://www.w3.org/2000/01/rdf-schema#>

        SELECT ?attackId ?name WHERE {{
            ?technique attack:subtechniqueOf {parent_uri} ;
                       attack:attackId ?attackId ;
                       rdfs:label ?name .
        }}
        ORDER BY ?attackId
        """
        return [{"attack_id": r["attackId"], "name": r["name"]} for r in self.query(sparql)]

    def get_techniques_for_group(self, group_id: str) -> list[dict[str, str]]:
        """Get all techniques used by a threat group."""
        group_uri = f"<https://attack.mitre.org/group/{group_id}>"
        sparql = f"""
        PREFIX attack: <https://attack.mitre.org/>
        PREFIX rdfs: <http://www.w3.org/2000/01/rdf-schema#>

        SELECT ?attackId ?name WHERE {{
            {group_uri} attack:uses ?technique .
            ?technique a attack:Technique ;
                       attack:attackId ?attackId ;
                       rdfs:label ?name .
        }}
        ORDER BY ?attackId
        """
        return [{"attack_id": r["attackId"], "name": r["name"]} for r in self.query(sparql)]

    def find_group_by_name(self, name: str) -> list[dict[str, str]]:
        """Find groups by name or alias (case-insensitive contains)."""
        # Escape quotes in name
        name = name.replace('"', '\\"')
        sparql = f"""
        PREFIX attack: <https://attack.mitre.org/>
        PREFIX rdfs: <http://www.w3.org/2000/01/rdf-schema#>

        SELECT DISTINCT ?attackId ?name WHERE {{
            ?group a attack:Group ;
                   attack:attackId ?attackId ;
                   rdfs:label ?name .
            {{
                FILTER(CONTAINS(LCASE(?name), LCASE("{name}")))
            }}
            UNION
            {{
                ?group attack:alias ?alias .
                FILTER(CONTAINS(LCASE(?alias), LCASE("{name}")))
            }}
        }}
        ORDER BY ?name
        """
        return [{"attack_id": r["attackId"], "name": r["name"]} for r in self.query(sparql)]

    def get_all_tactics(self) -> list[dict[str, str]]:
        """Get all tactics in kill chain order."""
        sparql = """
        PREFIX attack: <https://attack.mitre.org/>
        PREFIX rdfs: <http://www.w3.org/2000/01/rdf-schema#>

        SELECT ?attackId ?name ?shortname WHERE {
            ?tactic a attack:Tactic ;
                    rdfs:label ?name .
            OPTIONAL { ?tactic attack:attackId ?attackId }
            BIND(REPLACE(STR(?tactic), "https://attack.mitre.org/tactic/", "") AS ?shortname)
        }
        ORDER BY ?attackId
        """
        return [
            {
                "attack_id": r.get("attackId", ""),
                "name": r["name"],
                "shortname": r.get("shortname", ""),
            }
            for r in self.query(sparql)
        ]

    def get_stats(self) -> dict[str, int]:
        """Get count statistics for the knowledge base."""
        sparql = """
        PREFIX attack: <https://attack.mitre.org/>

        SELECT
            (COUNT(DISTINCT ?technique) AS ?techniques)
            (COUNT(DISTINCT ?group) AS ?groups)
            (COUNT(DISTINCT ?software) AS ?software)
            (COUNT(DISTINCT ?mitigation) AS ?mitigations)
            (COUNT(DISTINCT ?tactic) AS ?tactics)
            (COUNT(DISTINCT ?campaign) AS ?campaigns)
            (COUNT(DISTINCT ?datasource) AS ?datasources)
            (COUNT(DISTINCT ?detection) AS ?detections)
        WHERE {
            { ?technique a attack:Technique }
            UNION { ?group a attack:Group }
            UNION { ?software a attack:Software }
            UNION { ?mitigation a attack:Mitigation }
            UNION { ?tactic a attack:Tactic }
            UNION { ?campaign a attack:Campaign }
            UNION { ?datasource a attack:DataSource }
            UNION { ?detection a attack:DetectionStrategy }
        }
        """
        results = self.query(sparql)
        if results:
            return {
                "techniques": int(results[0].get("techniques", 0)),
                "groups": int(results[0].get("groups", 0)),
                "software": int(results[0].get("software", 0)),
                "mitigations": int(results[0].get("mitigations", 0)),
                "tactics": int(results[0].get("tactics", 0)),
                "campaigns": int(results[0].get("campaigns", 0)),
                "data_sources": int(results[0].get("datasources", 0)),
                "detection_strategies": int(results[0].get("detections", 0)),
                "total_triples": len(self._store),
            }
        return {"total_triples": len(self._store)}

    # -------------------------------------------------------------------------
    # Campaign queries
    # -------------------------------------------------------------------------

    def get_campaign(self, attack_id: str) -> dict[str, Any] | None:
        """Get a campaign by its ATT&CK ID (e.g., C0027)."""
        camp_uri = f"<https://attack.mitre.org/campaign/{attack_id}>"
        sparql = f"""
        PREFIX attack: <https://attack.mitre.org/>
        PREFIX rdfs: <http://www.w3.org/2000/01/rdf-schema#>

        SELECT ?name ?description ?firstSeen ?lastSeen ?url WHERE {{
            {camp_uri} rdfs:label ?name .
            OPTIONAL {{ {camp_uri} attack:description ?description }}
            OPTIONAL {{ {camp_uri} attack:firstSeen ?firstSeen }}
            OPTIONAL {{ {camp_uri} attack:lastSeen ?lastSeen }}
            OPTIONAL {{ {camp_uri} attack:url ?url }}
        }}
        """
        results = self.query(sparql)
        if results:
            return {
                "attack_id": attack_id,
                "name": results[0].get("name", ""),
                "description": results[0].get("description", ""),
                "first_seen": results[0].get("firstSeen", ""),
                "last_seen": results[0].get("lastSeen", ""),
                "url": results[0].get("url", ""),
            }
        return None

    def get_all_campaigns(self) -> list[dict[str, str]]:
        """Get all campaigns."""
        sparql = """
        PREFIX attack: <https://attack.mitre.org/>
        PREFIX rdfs: <http://www.w3.org/2000/01/rdf-schema#>

        SELECT ?attackId ?name ?firstSeen ?lastSeen WHERE {
            ?campaign a attack:Campaign ;
                      attack:attackId ?attackId ;
                      rdfs:label ?name .
            OPTIONAL { ?campaign attack:firstSeen ?firstSeen }
            OPTIONAL { ?campaign attack:lastSeen ?lastSeen }
        }
        ORDER BY ?attackId
        """
        return [
            {
                "attack_id": r["attackId"],
                "name": r["name"],
                "first_seen": r.get("firstSeen", ""),
                "last_seen": r.get("lastSeen", ""),
            }
            for r in self.query(sparql)
        ]

    def get_campaigns_using_technique(self, attack_id: str) -> list[dict[str, str]]:
        """Get campaigns that use a specific technique."""
        tech_uri = f"<https://attack.mitre.org/technique/{attack_id}>"
        sparql = f"""
        PREFIX attack: <https://attack.mitre.org/>
        PREFIX rdfs: <http://www.w3.org/2000/01/rdf-schema#>

        SELECT ?attackId ?name ?firstSeen ?lastSeen WHERE {{
            ?campaign a attack:Campaign ;
                      attack:uses {tech_uri} ;
                      attack:attackId ?attackId ;
                      rdfs:label ?name .
            OPTIONAL {{ ?campaign attack:firstSeen ?firstSeen }}
            OPTIONAL {{ ?campaign attack:lastSeen ?lastSeen }}
        }}
        ORDER BY ?firstSeen
        """
        return [
            {
                "attack_id": r["attackId"],
                "name": r["name"],
                "first_seen": r.get("firstSeen", ""),
                "last_seen": r.get("lastSeen", ""),
            }
            for r in self.query(sparql)
        ]

    def get_techniques_for_campaign(self, attack_id: str) -> list[dict[str, str]]:
        """Get all techniques used in a campaign."""
        camp_uri = f"<https://attack.mitre.org/campaign/{attack_id}>"
        sparql = f"""
        PREFIX attack: <https://attack.mitre.org/>
        PREFIX rdfs: <http://www.w3.org/2000/01/rdf-schema#>

        SELECT ?attackId ?name WHERE {{
            {camp_uri} attack:uses ?technique .
            ?technique a attack:Technique ;
                       attack:attackId ?attackId ;
                       rdfs:label ?name .
        }}
        ORDER BY ?attackId
        """
        return [{"attack_id": r["attackId"], "name": r["name"]} for r in self.query(sparql)]

    def get_group_for_campaign(self, attack_id: str) -> dict[str, str] | None:
        """Get the threat group attributed to a campaign."""
        camp_uri = f"<https://attack.mitre.org/campaign/{attack_id}>"
        sparql = f"""
        PREFIX attack: <https://attack.mitre.org/>
        PREFIX rdfs: <http://www.w3.org/2000/01/rdf-schema#>

        SELECT ?attackId ?name WHERE {{
            {camp_uri} attack:attributedTo ?group .
            ?group a attack:Group ;
                   attack:attackId ?attackId ;
                   rdfs:label ?name .
        }}
        """
        results = self.query(sparql)
        if results:
            return {"attack_id": results[0]["attackId"], "name": results[0]["name"]}
        return None

    def get_campaigns_for_group(self, group_id: str) -> list[dict[str, str]]:
        """Get all campaigns attributed to a threat group."""
        group_uri = f"<https://attack.mitre.org/group/{group_id}>"
        sparql = f"""
        PREFIX attack: <https://attack.mitre.org/>
        PREFIX rdfs: <http://www.w3.org/2000/01/rdf-schema#>

        SELECT ?attackId ?name ?firstSeen ?lastSeen WHERE {{
            ?campaign attack:attributedTo {group_uri} ;
                      attack:attackId ?attackId ;
                      rdfs:label ?name .
            OPTIONAL {{ ?campaign attack:firstSeen ?firstSeen }}
            OPTIONAL {{ ?campaign attack:lastSeen ?lastSeen }}
        }}
        ORDER BY ?firstSeen
        """
        return [
            {
                "attack_id": r["attackId"],
                "name": r["name"],
                "first_seen": r.get("firstSeen", ""),
                "last_seen": r.get("lastSeen", ""),
            }
            for r in self.query(sparql)
        ]

    # -------------------------------------------------------------------------
    # Detection and data source queries
    # -------------------------------------------------------------------------

    def get_detection_strategies_for_technique(self, attack_id: str) -> list[dict[str, str]]:
        """Get detection strategies for a specific technique."""
        tech_uri = f"<https://attack.mitre.org/technique/{attack_id}>"
        sparql = f"""
        PREFIX attack: <https://attack.mitre.org/>
        PREFIX rdfs: <http://www.w3.org/2000/01/rdf-schema#>

        SELECT ?attackId ?name ?description WHERE {{
            ?detection a attack:DetectionStrategy ;
                       attack:detects {tech_uri} ;
                       attack:attackId ?attackId ;
                       rdfs:label ?name .
            OPTIONAL {{ ?detection attack:description ?description }}
        }}
        ORDER BY ?attackId
        """
        return [
            {
                "attack_id": r["attackId"],
                "name": r["name"],
                "description": r.get("description", ""),
            }
            for r in self.query(sparql)
        ]

    def get_data_sources_for_technique(self, attack_id: str) -> list[str]:
        """Get data sources needed to detect a technique."""
        tech_uri = f"<https://attack.mitre.org/technique/{attack_id}>"
        sparql = f"""
        PREFIX attack: <https://attack.mitre.org/>

        SELECT DISTINCT ?dataSource WHERE {{
            {tech_uri} attack:dataSource ?dataSource .
        }}
        ORDER BY ?dataSource
        """
        return [r["dataSource"] for r in self.query(sparql)]

    def get_all_data_sources(self) -> list[dict[str, str]]:
        """Get all data sources."""
        sparql = """
        PREFIX attack: <https://attack.mitre.org/>
        PREFIX rdfs: <http://www.w3.org/2000/01/rdf-schema#>

        SELECT ?attackId ?name ?description WHERE {
            ?ds a attack:DataSource ;
                attack:attackId ?attackId ;
                rdfs:label ?name .
            OPTIONAL { ?ds attack:description ?description }
        }
        ORDER BY ?attackId
        """
        return [
            {
                "attack_id": r["attackId"],
                "name": r["name"],
                "description": r.get("description", ""),
            }
            for r in self.query(sparql)
        ]

    def get_techniques_by_data_source(self, data_source: str) -> list[dict[str, str]]:
        """Get techniques detectable by a specific data source."""
        # Escape quotes in data source name
        data_source = data_source.replace('"', '\\"')
        sparql = f"""
        PREFIX attack: <https://attack.mitre.org/>
        PREFIX rdfs: <http://www.w3.org/2000/01/rdf-schema#>

        SELECT DISTINCT ?attackId ?name WHERE {{
            ?technique a attack:Technique ;
                       attack:dataSource ?ds ;
                       attack:attackId ?attackId ;
                       rdfs:label ?name .
            FILTER(CONTAINS(LCASE(?ds), LCASE("{data_source}")))
        }}
        ORDER BY ?attackId
        """
        return [{"attack_id": r["attackId"], "name": r["name"]} for r in self.query(sparql)]

    # -------------------------------------------------------------------------
    # Enhanced entity queries
    # -------------------------------------------------------------------------

    def get_technique_full(self, attack_id: str) -> dict[str, Any] | None:
        """Get full technique details including all metadata."""
        tech_uri = f"<https://attack.mitre.org/technique/{attack_id}>"
        sparql = f"""
        PREFIX attack: <https://attack.mitre.org/>
        PREFIX rdfs: <http://www.w3.org/2000/01/rdf-schema#>

        SELECT ?name ?description ?detection ?url ?version
               (GROUP_CONCAT(DISTINCT ?platform; separator=",") AS ?platforms)
               (GROUP_CONCAT(DISTINCT ?dataSource; separator="|") AS ?dataSources)
               (GROUP_CONCAT(DISTINCT ?domain; separator=",") AS ?domains)
        WHERE {{
            {tech_uri} rdfs:label ?name .
            OPTIONAL {{ {tech_uri} attack:description ?description }}
            OPTIONAL {{ {tech_uri} attack:detection ?detection }}
            OPTIONAL {{ {tech_uri} attack:url ?url }}
            OPTIONAL {{ {tech_uri} attack:version ?version }}
            OPTIONAL {{ {tech_uri} attack:platform ?platform }}
            OPTIONAL {{ {tech_uri} attack:dataSource ?dataSource }}
            OPTIONAL {{ {tech_uri} attack:domain ?domain }}
        }}
        GROUP BY ?name ?description ?detection ?url ?version
        """
        results = self.query(sparql)
        if not results:
            return None

        r = results[0]
        platforms = r.get("platforms", "")
        data_sources = r.get("dataSources", "")
        domains = r.get("domains", "")

        return {
            "attack_id": attack_id,
            "name": r.get("name", ""),
            "description": r.get("description", ""),
            "detection": r.get("detection", ""),
            "url": r.get("url", ""),
            "version": r.get("version", ""),
            "platforms": [p.strip() for p in platforms.split(",") if p.strip()] if platforms else [],
            "data_sources": [d.strip() for d in data_sources.split("|") if d.strip()] if data_sources else [],
            "domains": [d.strip() for d in domains.split(",") if d.strip()] if domains else [],
        }

    def get_group_full(self, attack_id: str) -> dict[str, Any] | None:
        """Get full group details including description and aliases."""
        group_uri = f"<https://attack.mitre.org/group/{attack_id}>"
        sparql = f"""
        PREFIX attack: <https://attack.mitre.org/>
        PREFIX rdfs: <http://www.w3.org/2000/01/rdf-schema#>

        SELECT ?name ?description ?url
               (GROUP_CONCAT(DISTINCT ?alias; separator=",") AS ?aliases)
               (GROUP_CONCAT(DISTINCT ?contributor; separator="|") AS ?contributors)
        WHERE {{
            {group_uri} rdfs:label ?name .
            OPTIONAL {{ {group_uri} attack:description ?description }}
            OPTIONAL {{ {group_uri} attack:url ?url }}
            OPTIONAL {{ {group_uri} attack:alias ?alias }}
            OPTIONAL {{ {group_uri} attack:contributor ?contributor }}
        }}
        GROUP BY ?name ?description ?url
        """
        results = self.query(sparql)
        if not results:
            return None

        r = results[0]
        aliases = r.get("aliases", "")
        contributors = r.get("contributors", "")

        return {
            "attack_id": attack_id,
            "name": r.get("name", ""),
            "description": r.get("description", ""),
            "url": r.get("url", ""),
            "aliases": [a.strip() for a in aliases.split(",") if a.strip()] if aliases else [],
            "contributors": [c.strip() for c in contributors.split("|") if c.strip()] if contributors else [],
        }

    def get_software_full(self, attack_id: str) -> dict[str, Any] | None:
        """Get full software details including description, platforms, and aliases."""
        software_uri = f"<https://attack.mitre.org/software/{attack_id}>"
        sparql = f"""
        PREFIX attack: <https://attack.mitre.org/>
        PREFIX rdfs: <http://www.w3.org/2000/01/rdf-schema#>

        SELECT ?name ?description ?url ?type
               (GROUP_CONCAT(DISTINCT ?platform; separator=",") AS ?platforms)
               (GROUP_CONCAT(DISTINCT ?alias; separator=",") AS ?aliases)
        WHERE {{
            {software_uri} rdfs:label ?name ;
                           a ?type .
            FILTER(?type IN (attack:Malware, attack:Tool))
            OPTIONAL {{ {software_uri} attack:description ?description }}
            OPTIONAL {{ {software_uri} attack:url ?url }}
            OPTIONAL {{ {software_uri} attack:platform ?platform }}
            OPTIONAL {{ {software_uri} attack:alias ?alias }}
        }}
        GROUP BY ?name ?description ?url ?type
        """
        results = self.query(sparql)
        if not results:
            return None

        r = results[0]
        platforms = r.get("platforms", "")
        aliases = r.get("aliases", "")

        return {
            "attack_id": attack_id,
            "name": r.get("name", ""),
            "description": r.get("description", ""),
            "url": r.get("url", ""),
            "type": "Malware" if "Malware" in r.get("type", "") else "Tool",
            "platforms": [p.strip() for p in platforms.split(",") if p.strip()] if platforms else [],
            "aliases": [a.strip() for a in aliases.split(",") if a.strip()] if aliases else [],
        }

    def get_mitigation_full(self, attack_id: str) -> dict[str, Any] | None:
        """Get full mitigation details including description."""
        mit_uri = f"<https://attack.mitre.org/mitigation/{attack_id}>"
        sparql = f"""
        PREFIX attack: <https://attack.mitre.org/>
        PREFIX rdfs: <http://www.w3.org/2000/01/rdf-schema#>

        SELECT ?name ?description ?url WHERE {{
            {mit_uri} rdfs:label ?name .
            OPTIONAL {{ {mit_uri} attack:description ?description }}
            OPTIONAL {{ {mit_uri} attack:url ?url }}
        }}
        """
        results = self.query(sparql)
        if not results:
            return None

        r = results[0]
        return {
            "attack_id": attack_id,
            "name": r.get("name", ""),
            "description": r.get("description", ""),
            "url": r.get("url", ""),
        }

    # -------------------------------------------------------------------------
    # Cross-entity queries
    # -------------------------------------------------------------------------

    def get_techniques_by_platform(self, platform: str) -> list[dict[str, str]]:
        """Get all techniques targeting a specific platform."""
        platform = platform.replace('"', '\\"')
        sparql = f"""
        PREFIX attack: <https://attack.mitre.org/>
        PREFIX rdfs: <http://www.w3.org/2000/01/rdf-schema#>

        SELECT ?attackId ?name WHERE {{
            ?technique a attack:Technique ;
                       attack:platform "{platform}" ;
                       attack:attackId ?attackId ;
                       rdfs:label ?name .
        }}
        ORDER BY ?attackId
        """
        return [{"attack_id": r["attackId"], "name": r["name"]} for r in self.query(sparql)]

    def get_all_platforms(self) -> list[str]:
        """Get all unique platforms in the dataset."""
        sparql = """
        PREFIX attack: <https://attack.mitre.org/>

        SELECT DISTINCT ?platform WHERE {
            ?entity attack:platform ?platform .
        }
        ORDER BY ?platform
        """
        return [r["platform"] for r in self.query(sparql)]

    def get_techniques_by_tactic_with_details(self, tactic: str) -> list[dict[str, Any]]:
        """Get all techniques for a tactic with full details."""
        tactic_uri = f"<https://attack.mitre.org/tactic/{tactic}>"
        sparql = f"""
        PREFIX attack: <https://attack.mitre.org/>
        PREFIX rdfs: <http://www.w3.org/2000/01/rdf-schema#>

        SELECT ?attackId ?name ?description
               (GROUP_CONCAT(DISTINCT ?platform; separator=",") AS ?platforms)
        WHERE {{
            ?technique a attack:Technique ;
                       attack:tactic {tactic_uri} ;
                       attack:attackId ?attackId ;
                       rdfs:label ?name .
            OPTIONAL {{ ?technique attack:description ?description }}
            OPTIONAL {{ ?technique attack:platform ?platform }}
        }}
        GROUP BY ?attackId ?name ?description
        ORDER BY ?attackId
        """
        results = []
        for r in self.query(sparql):
            platforms = r.get("platforms", "")
            results.append({
                "attack_id": r["attackId"],
                "name": r["name"],
                "description": r.get("description", ""),
                "platforms": [p.strip() for p in platforms.split(",") if p.strip()] if platforms else [],
            })
        return results

    def find_software_by_name(self, name: str) -> list[dict[str, str]]:
        """Find software by name or alias (case-insensitive contains)."""
        name = name.replace('"', '\\"')
        sparql = f"""
        PREFIX attack: <https://attack.mitre.org/>
        PREFIX rdfs: <http://www.w3.org/2000/01/rdf-schema#>

        SELECT DISTINCT ?attackId ?name ?type WHERE {{
            ?software a ?type ;
                      attack:attackId ?attackId ;
                      rdfs:label ?name .
            FILTER(?type IN (attack:Malware, attack:Tool))
            {{
                FILTER(CONTAINS(LCASE(?name), LCASE("{name}")))
            }}
            UNION
            {{
                ?software attack:alias ?alias .
                FILTER(CONTAINS(LCASE(?alias), LCASE("{name}")))
            }}
        }}
        ORDER BY ?name
        """
        return [
            {
                "attack_id": r["attackId"],
                "name": r["name"],
                "type": "Malware" if "Malware" in r.get("type", "") else "Tool",
            }
            for r in self.query(sparql)
        ]

    def get_common_techniques(self, entity_ids: list[str], entity_type: str = "group") -> list[dict[str, Any]]:
        """Find techniques used by all specified entities (groups or software)."""
        if not entity_ids or len(entity_ids) < 2:
            return []

        # Build URIs based on entity type
        if entity_type == "group":
            uris = [f"<https://attack.mitre.org/group/{eid}>" for eid in entity_ids]
        else:
            uris = [f"<https://attack.mitre.org/software/{eid}>" for eid in entity_ids]

        # Build SPARQL with intersection pattern
        patterns = []
        for i, uri in enumerate(uris):
            patterns.append(f"{uri} attack:uses ?technique .")

        sparql = f"""
        PREFIX attack: <https://attack.mitre.org/>
        PREFIX rdfs: <http://www.w3.org/2000/01/rdf-schema#>

        SELECT ?attackId ?name WHERE {{
            {" ".join(patterns)}
            ?technique attack:attackId ?attackId ;
                       rdfs:label ?name .
        }}
        ORDER BY ?attackId
        """
        return [{"attack_id": r["attackId"], "name": r["name"]} for r in self.query(sparql)]

    # -------------------------------------------------------------------------
    # D3FEND integration
    # -------------------------------------------------------------------------

    def load_d3fend(self, path: Path | str, force: bool = False) -> int:
        """
        Load D3FEND TTL ontology into the store.

        Args:
            path: Path to D3FEND TTL file
            force: Force reload even if D3FEND data exists

        Returns:
            Number of triples loaded
        """
        import time
        import pyoxigraph

        path = Path(path)
        before = len(self._store)

        # Check if D3FEND is already loaded by looking for D3FEND namespace
        check_sparql = """
        PREFIX d3f: <http://d3fend.mitre.org/ontologies/d3fend.owl#>
        SELECT (COUNT(*) AS ?count) WHERE {
            ?s ?p ?o .
            FILTER(STRSTARTS(STR(?s), "http://d3fend.mitre.org"))
        }
        """
        existing = self.query(check_sparql)
        existing_count = int(existing[0].get("count", 0)) if existing else 0

        if existing_count > 0 and not force:
            console.print(f"[green]D3FEND already loaded ({existing_count} triples), skipping[/green]")
            console.print(f"[dim](use --force to reload)[/dim]")
            return 0

        console.print(f"[blue]Loading D3FEND from {path}...[/blue]")
        start = time.time()

        # Load TTL format into default graph
        with open(path, "rb") as f:
            self._store.bulk_load(f, pyoxigraph.RdfFormat.TURTLE, to_graph=pyoxigraph.DefaultGraph())

        after = len(self._store)
        parse_time = time.time() - start
        loaded = after - before
        console.print(f"[green]Loaded {loaded} D3FEND triples in {parse_time:.1f}s[/green]")
        return loaded

    def get_d3fend_technique(self, d3fend_id: str) -> dict[str, Any] | None:
        """
        Get D3FEND technique details by ID (e.g., D3-MFA).

        Args:
            d3fend_id: D3FEND technique ID (e.g., D3-MFA, D3-AL)

        Returns:
            Dictionary with technique details or None if not found
        """
        sparql = f"""
        PREFIX d3f: <http://d3fend.mitre.org/ontologies/d3fend.owl#>
        PREFIX rdfs: <http://www.w3.org/2000/01/rdf-schema#>

        SELECT ?name ?definition ?category WHERE {{
            ?tech d3f:d3fend-id "{d3fend_id}" ;
                  rdfs:label ?name .
            OPTIONAL {{ ?tech d3f:definition ?definition }}
            OPTIONAL {{
                ?tech rdfs:subClassOf ?parent .
                ?parent rdfs:label ?category .
            }}
        }}
        LIMIT 1
        """
        results = self.query(sparql)
        if results:
            r = results[0]
            return {
                "d3fend_id": d3fend_id,
                "name": r.get("name", ""),
                "definition": r.get("definition", ""),
                "category": r.get("category", ""),
            }
        return None

    def get_d3fend_for_mitigation(self, mitigation_id: str) -> list[dict[str, Any]]:
        """
        Get D3FEND techniques linked to an ATT&CK mitigation.

        D3FEND uses the mitigation ID in its 'related' predicate to link
        defensive techniques to ATT&CK mitigations.

        Args:
            mitigation_id: ATT&CK mitigation ID (e.g., M1032)

        Returns:
            List of D3FEND techniques with their details
        """
        # D3FEND references mitigations via d3f:related predicate
        # The mitigation is represented as d3f:{mitigation_id}
        sparql = f"""
        PREFIX d3f: <http://d3fend.mitre.org/ontologies/d3fend.owl#>
        PREFIX rdfs: <http://www.w3.org/2000/01/rdf-schema#>

        SELECT DISTINCT ?d3fendId ?name ?definition WHERE {{
            ?tech d3f:d3fend-id ?d3fendId ;
                  rdfs:label ?name .
            {{
                ?tech d3f:related d3f:{mitigation_id} .
            }}
            UNION
            {{
                d3f:{mitigation_id} d3f:related ?tech .
            }}
            OPTIONAL {{ ?tech d3f:definition ?definition }}
            FILTER(STRSTARTS(?d3fendId, "D3-"))
        }}
        ORDER BY ?name
        """
        results = self.query(sparql)
        return [
            {
                "d3fend_id": r["d3fendId"],
                "name": r["name"],
                "definition": r.get("definition", ""),
            }
            for r in results
        ]

    def get_d3fend_for_technique(self, attack_id: str) -> list[dict[str, Any]]:
        """
        Get D3FEND countermeasures for an ATT&CK technique.

        This works by:
        1. Getting mitigations for the technique (with inheritance for subtechniques)
        2. For each mitigation, finding linked D3FEND techniques

        Args:
            attack_id: ATT&CK technique ID (e.g., T1110.003)

        Returns:
            List of D3FEND techniques with via_mitigation context
        """
        from src.logging import log_d3fend_lookup

        # Get mitigations with inheritance for subtechniques
        mitigations = self.get_mitigations_with_inheritance(attack_id)

        d3fend_results = []
        seen_d3fend_ids = set()

        for mit in mitigations:
            mit_id = mit["attack_id"]
            d3fend_techniques = self.get_d3fend_for_mitigation(mit_id)

            for d3f in d3fend_techniques:
                d3fend_id = d3f["d3fend_id"]
                if d3fend_id not in seen_d3fend_ids:
                    seen_d3fend_ids.add(d3fend_id)
                    d3fend_results.append({
                        **d3f,
                        "via_mitigation": mit_id,
                        "via_mitigation_name": mit["name"],
                        "inherited": mit.get("inherited", False),
                    })
                else:
                    # Add additional mitigation reference
                    for existing in d3fend_results:
                        if existing["d3fend_id"] == d3fend_id:
                            if "additional_mitigations" not in existing:
                                existing["additional_mitigations"] = []
                            existing["additional_mitigations"].append({
                                "mitigation_id": mit_id,
                                "name": mit["name"],
                            })
                            break

        log_d3fend_lookup(attack_id, mitigations, d3fend_results)
        return d3fend_results

    # -------------------------------------------------------------------------
    # Co-occurrence analysis
    # -------------------------------------------------------------------------

    def get_cooccurring_techniques(
        self,
        attack_id: str,
        min_cooccurrence: int = 2,
        limit: int = 20,
    ) -> list[dict[str, Any]]:
        """
        Get techniques that frequently co-occur with the given technique.

        Co-occurrence is determined by how often techniques appear together
        in the same campaigns or are used by the same threat groups.

        Args:
            attack_id: ATT&CK technique ID (e.g., T1110.003)
            min_cooccurrence: Minimum number of shared campaigns/groups
            limit: Maximum number of results

        Returns:
            List of co-occurring techniques with occurrence counts
        """
        tech_uri = f"<https://attack.mitre.org/technique/{attack_id}>"

        # Query for techniques that co-occur via campaigns OR groups
        sparql = f"""
        PREFIX attack: <https://attack.mitre.org/>
        PREFIX rdfs: <http://www.w3.org/2000/01/rdf-schema#>

        SELECT ?relatedId ?relatedName (COUNT(DISTINCT ?container) AS ?count)
        WHERE {{
            # Find campaigns or groups that use the seed technique
            ?container attack:uses {tech_uri} .

            # Find other techniques used by the same campaigns/groups
            ?container attack:uses ?related .

            ?related a attack:Technique ;
                     attack:attackId ?relatedId ;
                     rdfs:label ?relatedName .

            # Exclude the seed technique itself
            FILTER(?relatedId != "{attack_id}")
        }}
        GROUP BY ?relatedId ?relatedName
        HAVING(COUNT(DISTINCT ?container) >= {min_cooccurrence})
        ORDER BY DESC(?count)
        LIMIT {limit}
        """

        results = self.query(sparql, context="get_cooccurring_techniques")
        return [
            {
                "attack_id": r["relatedId"],
                "name": r["relatedName"],
                "cooccurrence_count": int(r["count"]),
            }
            for r in results
        ]

    def get_all_d3fend_techniques(self, limit: int = 100) -> list[dict[str, str]]:
        """
        Get all D3FEND techniques.

        Args:
            limit: Maximum number of results

        Returns:
            List of D3FEND techniques with basic info
        """
        sparql = f"""
        PREFIX d3f: <http://d3fend.mitre.org/ontologies/d3fend.owl#>
        PREFIX rdfs: <http://www.w3.org/2000/01/rdf-schema#>

        SELECT ?d3fendId ?name WHERE {{
            ?tech d3f:d3fend-id ?d3fendId ;
                  rdfs:label ?name .
            FILTER(STRSTARTS(?d3fendId, "D3-"))
        }}
        ORDER BY ?d3fendId
        LIMIT {limit}
        """
        return [
            {"d3fend_id": r["d3fendId"], "name": r["name"]}
            for r in self.query(sparql)
        ]

    def get_d3fend_stats(self) -> dict[str, int]:
        """Get count of D3FEND entities loaded."""
        sparql = """
        PREFIX d3f: <http://d3fend.mitre.org/ontologies/d3fend.owl#>

        SELECT (COUNT(DISTINCT ?tech) AS ?techniques) WHERE {
            ?tech d3f:d3fend-id ?id .
            FILTER(STRSTARTS(?id, "D3-"))
        }
        """
        results = self.query(sparql)
        if results:
            return {"d3fend_techniques": int(results[0].get("techniques", 0))}
        return {"d3fend_techniques": 0}
