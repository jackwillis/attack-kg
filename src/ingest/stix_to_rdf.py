"""Convert MITRE ATT&CK STIX 2.1 data to RDF triples."""

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from rdflib import Graph, Literal, Namespace, URIRef
from rdflib.namespace import RDF, RDFS, XSD
from rich.console import Console
from rich.progress import Progress, BarColumn, TextColumn, TaskProgressColumn

console = Console()

# Define namespaces
ATTACK = Namespace("https://attack.mitre.org/")
STIX = Namespace("http://stix.mitre.org/")


@dataclass
class StixToRdfConverter:
    """
    Converts MITRE ATT&CK STIX bundle to RDF graph.

    The conversion happens in two passes:
    1. First pass: Create all entities and build STIX ID → URI mapping
    2. Second pass: Resolve relationships using the mapping

    Attributes:
        graph: The RDF graph being built
        stix_to_uri: Mapping from STIX IDs to RDF URIs
    """

    graph: Graph = field(default_factory=Graph)
    stix_to_uri: dict[str, URIRef] = field(default_factory=dict)

    def __post_init__(self) -> None:
        """Bind namespaces to the graph."""
        self.graph.bind("attack", ATTACK)
        self.graph.bind("stix", STIX)
        self.graph.bind("rdfs", RDFS)

    def convert(self, bundle: dict[str, Any]) -> Graph:
        """
        Convert a complete STIX bundle to RDF.

        Args:
            bundle: STIX bundle dictionary

        Returns:
            Populated RDF graph
        """
        objects = bundle.get("objects", [])

        # Separate objects and relationships
        entities = [o for o in objects if o.get("type") != "relationship"]
        relationships = [o for o in objects if o.get("type") == "relationship"]

        console.print(f"\n[bold]Converting {len(entities)} entities and {len(relationships)} relationships[/bold]")

        # Pass 1: Process all entities
        with Progress(
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TaskProgressColumn(),
            console=console,
        ) as progress:
            task = progress.add_task("Processing entities...", total=len(entities))

            for obj in entities:
                self._process_entity(obj)
                progress.advance(task)

        # Pass 2: Process relationships (now that we have URI mappings)
        with Progress(
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TaskProgressColumn(),
            console=console,
        ) as progress:
            task = progress.add_task("Processing relationships...", total=len(relationships))

            for rel in relationships:
                self._process_relationship(rel)
                progress.advance(task)

        console.print(f"[green]Created {len(self.graph)} triples[/green]")
        return self.graph

    def _get_attack_id(self, obj: dict[str, Any]) -> str | None:
        """Extract ATT&CK ID (e.g., T1110.003) from STIX object."""
        for ref in obj.get("external_references", []):
            if ref.get("source_name") == "mitre-attack":
                return ref.get("external_id")
        return None

    def _get_attack_url(self, obj: dict[str, Any]) -> str | None:
        """Extract ATT&CK URL from external references."""
        for ref in obj.get("external_references", []):
            if ref.get("source_name") == "mitre-attack":
                return ref.get("url")
        return None

    def _process_entity(self, obj: dict[str, Any]) -> None:
        """Route entity to appropriate handler based on STIX type."""
        # Skip revoked or deprecated objects
        if obj.get("revoked", False) or obj.get("x_mitre_deprecated", False):
            return

        handlers = {
            "attack-pattern": self._process_technique,
            "intrusion-set": self._process_group,
            "malware": self._process_malware,
            "tool": self._process_tool,
            "course-of-action": self._process_mitigation,
            "x-mitre-tactic": self._process_tactic,
            "x-mitre-data-source": self._process_data_source,
            "x-mitre-data-component": self._process_data_component,
            "identity": self._process_identity,
            "marking-definition": None,  # Skip marking definitions
            "x-mitre-matrix": None,  # Skip matrix definitions
            "x-mitre-collection": None,  # Skip collection metadata
        }

        obj_type = obj.get("type")
        handler = handlers.get(obj_type)

        if handler is not None:
            handler(obj)
        elif obj_type not in handlers:
            # Unknown type - log for investigation
            console.print(f"[yellow]Unknown STIX type: {obj_type}[/yellow]")

    def _process_technique(self, obj: dict[str, Any]) -> None:
        """Convert attack-pattern (Technique) to RDF."""
        attack_id = self._get_attack_id(obj)
        if not attack_id:
            return

        uri = ATTACK[f"technique/{attack_id}"]
        self.stix_to_uri[obj["id"]] = uri

        g = self.graph
        g.add((uri, RDF.type, ATTACK.Technique))
        g.add((uri, ATTACK.attackId, Literal(attack_id)))
        g.add((uri, ATTACK.stixId, Literal(obj["id"])))
        g.add((uri, RDFS.label, Literal(obj["name"])))

        if "description" in obj:
            g.add((uri, ATTACK.description, Literal(obj["description"])))

        if "x_mitre_detection" in obj:
            g.add((uri, ATTACK.detection, Literal(obj["x_mitre_detection"])))

        # Platforms
        for platform in obj.get("x_mitre_platforms", []):
            g.add((uri, ATTACK.platform, Literal(platform)))

        # Data sources (as text for now)
        for ds in obj.get("x_mitre_data_sources", []):
            g.add((uri, ATTACK.dataSource, Literal(ds)))

        # Kill chain phases (tactics)
        for phase in obj.get("kill_chain_phases", []):
            if phase.get("kill_chain_name") == "mitre-attack":
                tactic_name = phase["phase_name"]
                g.add((uri, ATTACK.tactic, ATTACK[f"tactic/{tactic_name}"]))

        # Is this a sub-technique?
        if obj.get("x_mitre_is_subtechnique", False):
            g.add((uri, ATTACK.isSubtechnique, Literal(True, datatype=XSD.boolean)))
            # Parent technique will be linked via relationship

        # URL to ATT&CK website
        url = self._get_attack_url(obj)
        if url:
            g.add((uri, ATTACK.url, Literal(url, datatype=XSD.anyURI)))

    def _process_group(self, obj: dict[str, Any]) -> None:
        """Convert intrusion-set (Threat Group) to RDF."""
        attack_id = self._get_attack_id(obj)
        if not attack_id:
            return

        uri = ATTACK[f"group/{attack_id}"]
        self.stix_to_uri[obj["id"]] = uri

        g = self.graph
        g.add((uri, RDF.type, ATTACK.Group))
        g.add((uri, ATTACK.attackId, Literal(attack_id)))
        g.add((uri, ATTACK.stixId, Literal(obj["id"])))
        g.add((uri, RDFS.label, Literal(obj["name"])))

        if "description" in obj:
            g.add((uri, ATTACK.description, Literal(obj["description"])))

        # Aliases
        for alias in obj.get("aliases", []):
            g.add((uri, ATTACK.alias, Literal(alias)))

    def _process_malware(self, obj: dict[str, Any]) -> None:
        """Convert malware to RDF."""
        attack_id = self._get_attack_id(obj)
        if not attack_id:
            return

        uri = ATTACK[f"software/{attack_id}"]
        self.stix_to_uri[obj["id"]] = uri

        g = self.graph
        g.add((uri, RDF.type, ATTACK.Malware))
        g.add((uri, RDF.type, ATTACK.Software))  # Superclass
        g.add((uri, ATTACK.attackId, Literal(attack_id)))
        g.add((uri, ATTACK.stixId, Literal(obj["id"])))
        g.add((uri, RDFS.label, Literal(obj["name"])))

        if "description" in obj:
            g.add((uri, ATTACK.description, Literal(obj["description"])))

        for platform in obj.get("x_mitre_platforms", []):
            g.add((uri, ATTACK.platform, Literal(platform)))

        for alias in obj.get("x_mitre_aliases", []):
            g.add((uri, ATTACK.alias, Literal(alias)))

    def _process_tool(self, obj: dict[str, Any]) -> None:
        """Convert tool to RDF."""
        attack_id = self._get_attack_id(obj)
        if not attack_id:
            return

        uri = ATTACK[f"software/{attack_id}"]
        self.stix_to_uri[obj["id"]] = uri

        g = self.graph
        g.add((uri, RDF.type, ATTACK.Tool))
        g.add((uri, RDF.type, ATTACK.Software))  # Superclass
        g.add((uri, ATTACK.attackId, Literal(attack_id)))
        g.add((uri, ATTACK.stixId, Literal(obj["id"])))
        g.add((uri, RDFS.label, Literal(obj["name"])))

        if "description" in obj:
            g.add((uri, ATTACK.description, Literal(obj["description"])))

        for platform in obj.get("x_mitre_platforms", []):
            g.add((uri, ATTACK.platform, Literal(platform)))

        for alias in obj.get("x_mitre_aliases", []):
            g.add((uri, ATTACK.alias, Literal(alias)))

    def _process_mitigation(self, obj: dict[str, Any]) -> None:
        """Convert course-of-action (Mitigation) to RDF."""
        attack_id = self._get_attack_id(obj)
        if not attack_id:
            return

        uri = ATTACK[f"mitigation/{attack_id}"]
        self.stix_to_uri[obj["id"]] = uri

        g = self.graph
        g.add((uri, RDF.type, ATTACK.Mitigation))
        g.add((uri, ATTACK.attackId, Literal(attack_id)))
        g.add((uri, ATTACK.stixId, Literal(obj["id"])))
        g.add((uri, RDFS.label, Literal(obj["name"])))

        if "description" in obj:
            g.add((uri, ATTACK.description, Literal(obj["description"])))

    def _process_tactic(self, obj: dict[str, Any]) -> None:
        """Convert x-mitre-tactic to RDF."""
        # Tactics use x_mitre_shortname as their ID (e.g., "initial-access")
        shortname = obj.get("x_mitre_shortname")
        if not shortname:
            return

        uri = ATTACK[f"tactic/{shortname}"]
        self.stix_to_uri[obj["id"]] = uri

        g = self.graph
        g.add((uri, RDF.type, ATTACK.Tactic))
        g.add((uri, ATTACK.stixId, Literal(obj["id"])))
        g.add((uri, RDFS.label, Literal(obj["name"])))

        if "description" in obj:
            g.add((uri, ATTACK.description, Literal(obj["description"])))

        # External ID (e.g., TA0001)
        attack_id = self._get_attack_id(obj)
        if attack_id:
            g.add((uri, ATTACK.attackId, Literal(attack_id)))

    def _process_data_source(self, obj: dict[str, Any]) -> None:
        """Convert x-mitre-data-source to RDF."""
        attack_id = self._get_attack_id(obj)
        if not attack_id:
            return

        uri = ATTACK[f"datasource/{attack_id}"]
        self.stix_to_uri[obj["id"]] = uri

        g = self.graph
        g.add((uri, RDF.type, ATTACK.DataSource))
        g.add((uri, ATTACK.attackId, Literal(attack_id)))
        g.add((uri, ATTACK.stixId, Literal(obj["id"])))
        g.add((uri, RDFS.label, Literal(obj["name"])))

        if "description" in obj:
            g.add((uri, ATTACK.description, Literal(obj["description"])))

    def _process_data_component(self, obj: dict[str, Any]) -> None:
        """Convert x-mitre-data-component to RDF."""
        # Data components don't have ATT&CK IDs, use STIX ID
        stix_id = obj["id"]
        # Create a safe URI from the name
        safe_name = obj["name"].lower().replace(" ", "-").replace("/", "-")
        uri = ATTACK[f"datacomponent/{safe_name}"]
        self.stix_to_uri[stix_id] = uri

        g = self.graph
        g.add((uri, RDF.type, ATTACK.DataComponent))
        g.add((uri, ATTACK.stixId, Literal(stix_id)))
        g.add((uri, RDFS.label, Literal(obj["name"])))

        if "description" in obj:
            g.add((uri, ATTACK.description, Literal(obj["description"])))

    def _process_identity(self, obj: dict[str, Any]) -> None:
        """Process identity objects (usually just MITRE itself)."""
        # We don't need to track identities for our use case
        # Just register the mapping in case it's referenced
        uri = STIX[f"identity/{obj['id']}"]
        self.stix_to_uri[obj["id"]] = uri

    def _process_relationship(self, rel: dict[str, Any]) -> None:
        """Convert STIX relationship to RDF predicate."""
        source_id = rel.get("source_ref")
        target_id = rel.get("target_ref")
        rel_type = rel.get("relationship_type")

        # Look up URIs
        source_uri = self.stix_to_uri.get(source_id)
        target_uri = self.stix_to_uri.get(target_id)

        # Skip if either endpoint wasn't processed (revoked, deprecated, etc.)
        if not source_uri or not target_uri:
            return

        # Map STIX relationship types to RDF predicates
        predicate_map = {
            "uses": ATTACK.uses,
            "mitigates": ATTACK.mitigates,
            "subtechnique-of": ATTACK.subtechniqueOf,
            "detects": ATTACK.detects,
            "attributed-to": ATTACK.attributedTo,
            "targets": ATTACK.targets,
            "revoked-by": ATTACK.revokedBy,
        }

        predicate = predicate_map.get(rel_type)
        if predicate:
            self.graph.add((source_uri, predicate, target_uri))

            # For "uses" relationships, add inverse for easier querying
            if rel_type == "uses":
                self.graph.add((target_uri, ATTACK.usedBy, source_uri))

            # For "mitigates", add inverse
            if rel_type == "mitigates":
                self.graph.add((target_uri, ATTACK.mitigatedBy, source_uri))

    def save(self, path: Path | str, format: str = "turtle") -> None:
        """
        Save the graph to a file.

        Args:
            path: Output file path
            format: RDF serialization format (turtle, xml, n3, nt, json-ld)
        """
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)

        self.graph.serialize(destination=str(path), format=format)
        console.print(f"[green]Saved graph to:[/green] {path}")

    def load(self, path: Path | str, format: str = "turtle") -> Graph:
        """
        Load a graph from a file.

        Args:
            path: Input file path
            format: RDF serialization format

        Returns:
            The loaded graph
        """
        path = Path(path)
        self.graph.parse(source=str(path), format=format)
        console.print(f"[green]Loaded graph from:[/green] {path} ({len(self.graph)} triples)")
        return self.graph
