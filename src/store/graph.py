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

    def query(self, sparql: str) -> list[dict[str, Any]]:
        """
        Execute a SPARQL SELECT query.

        Args:
            sparql: SPARQL query string

        Returns:
            List of result rows as dictionaries
        """
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
            return rows

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

        SELECT ?name ?description ?detection WHERE {{
            {tech_uri} rdfs:label ?name .
            OPTIONAL {{ {tech_uri} attack:description ?description }}
            OPTIONAL {{ {tech_uri} attack:detection ?detection }}
        }}
        """
        results = self.query(sparql)
        if results:
            return {
                "attack_id": attack_id,
                "name": results[0].get("name", ""),
                "description": results[0].get("description", ""),
                "detection": results[0].get("detection", ""),
            }
        return None

    def get_techniques_for_tactic(self, tactic: str) -> list[dict[str, str]]:
        """Get all techniques for a given tactic."""
        sparql = f"""
        PREFIX attack: <https://attack.mitre.org/>
        PREFIX rdfs: <http://www.w3.org/2000/01/rdf-schema#>

        SELECT ?attackId ?name WHERE {{
            ?technique a attack:Technique ;
                       attack:tactic attack:tactic/{tactic} ;
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
        WHERE {
            { ?technique a attack:Technique }
            UNION { ?group a attack:Group }
            UNION { ?software a attack:Software }
            UNION { ?mitigation a attack:Mitigation }
            UNION { ?tactic a attack:Tactic }
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
                "total_triples": len(self._store),
            }
        return {"total_triples": len(self._store)}
