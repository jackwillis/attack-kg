"""Graph browser state and navigation logic."""

from dataclasses import dataclass, field
from typing import Any

from rich.console import Console

from src.store.graph import AttackGraph
from src.query.hybrid import HybridQueryEngine

console = Console()


# Entity type detection from ID prefix
ENTITY_TYPE_PREFIXES = {
    "T": "technique",
    "G": "group",
    "S": "software",
    "M": "mitigation",
    "C": "campaign",
    "TA": "tactic",
    "DS": "data_source",
}


def detect_entity_type(attack_id: str) -> str | None:
    """Detect entity type from ATT&CK ID prefix."""
    attack_id = attack_id.upper()

    # Check two-character prefixes first (TA, DS)
    if attack_id.startswith("TA"):
        return "tactic"
    if attack_id.startswith("DS"):
        return "data_source"

    # Check single-character prefixes
    if attack_id and attack_id[0] in ENTITY_TYPE_PREFIXES:
        return ENTITY_TYPE_PREFIXES[attack_id[0]]

    return None


@dataclass
class BrowserState:
    """State for the graph browser navigation."""

    current_id: str | None = None
    current_type: str | None = None
    current_name: str | None = None
    history: list[tuple[str, str, str]] = field(default_factory=list)  # (id, type, name)

    def push(self, attack_id: str, entity_type: str, name: str) -> None:
        """Push current location to history and update current."""
        if self.current_id is not None:
            self.history.append((self.current_id, self.current_type, self.current_name))
        self.current_id = attack_id
        self.current_type = entity_type
        self.current_name = name

    def pop(self) -> bool:
        """Pop from history and restore previous location. Returns True if successful."""
        if self.history:
            self.current_id, self.current_type, self.current_name = self.history.pop()
            return True
        # Go to root if no history
        if self.current_id is not None:
            self.current_id = None
            self.current_type = None
            self.current_name = None
            return True
        return False

    def clear(self) -> None:
        """Clear to root."""
        self.current_id = None
        self.current_type = None
        self.current_name = None
        self.history.clear()

    def get_prompt(self) -> str:
        """Get the current location as a path-like prompt."""
        if self.current_id is None:
            return "/"
        return f"/{self.current_type}/{self.current_id}"

    def get_breadcrumb(self) -> str:
        """Get full path as breadcrumb trail."""
        parts = []
        for hid, htype, hname in self.history:
            parts.append(f"{htype}/{hid}")
        if self.current_id:
            parts.append(f"{self.current_type}/{self.current_id}")
        return " > ".join(parts) if parts else "/"


class GraphBrowser:
    """
    Interactive graph browser for navigating the ATT&CK knowledge graph.

    Provides filesystem-like navigation (cd, ls, pwd) through entities
    and their relationships.
    """

    def __init__(
        self,
        graph: AttackGraph,
        hybrid: HybridQueryEngine,
    ):
        """
        Initialize the graph browser.

        Args:
            graph: The ATT&CK graph store
            hybrid: The hybrid query engine for enriched queries
        """
        self.graph = graph
        self.hybrid = hybrid
        self.state = BrowserState()

    def cd(self, target: str) -> tuple[bool, dict[str, Any] | None]:
        """
        Navigate to an entity.

        Args:
            target: Entity ID (T1110, G0016, etc.) or ".." to go back

        Returns:
            Tuple of (success, entity_info or None)
        """
        target = target.strip()

        # Handle special navigation
        if target in ("..", "back"):
            success = self.state.pop()
            if success and self.state.current_id:
                # Fetch current entity info
                entity = self.hybrid.get_entity(self.state.current_id, self.state.current_type)
                return True, entity
            return success, None

        if target == "/":
            self.state.clear()
            return True, None

        # Detect entity type
        entity_type = detect_entity_type(target)
        if not entity_type:
            return False, None

        # Normalize the ID (uppercase)
        attack_id = target.upper()

        # Fetch the entity
        entity = self.hybrid.get_entity(attack_id, entity_type)
        if entity is None:
            return False, None

        # Update state
        name = entity.get("name", attack_id)
        self.state.push(attack_id, entity_type, name)

        return True, entity

    def back(self) -> tuple[bool, dict[str, Any] | None]:
        """
        Return to previous node.

        Returns:
            Tuple of (success, entity_info or None)
        """
        return self.cd("..")

    def pwd(self) -> str:
        """Get current location as a path string."""
        return self.state.get_prompt()

    def breadcrumb(self) -> str:
        """Get full path as breadcrumb trail."""
        return self.state.get_breadcrumb()

    def ls(self) -> dict[str, Any] | None:
        """
        Get connections from current node.

        Returns:
            Dictionary with relationships, or None if at root
        """
        if self.state.current_id is None:
            # At root - show summary of entity types
            return self._get_root_summary()

        return self.hybrid.get_relationships(
            self.state.current_id,
            self.state.current_type,
        )

    def info(self) -> dict[str, Any] | None:
        """
        Get full details of current node.

        Returns:
            Entity details or None if at root
        """
        if self.state.current_id is None:
            return self._get_root_summary()

        return self.hybrid.get_entity(
            self.state.current_id,
            self.state.current_type,
        )

    def search(self, query: str, top_k: int = 10) -> dict[str, list[dict[str, Any]]]:
        """
        Search across all entity types.

        Args:
            query: Search text (natural language or keywords)
            top_k: Maximum results per type

        Returns:
            Dictionary with results organized by entity type
        """
        return self.hybrid.search_entities(query, top_k=top_k)

    def ask(self, question: str, llm: Any) -> str:
        """
        LLM query in context of current node.

        Args:
            question: User's question
            llm: LLM backend instance

        Returns:
            LLM response
        """
        # Build context based on current location
        if self.state.current_id is None:
            # At root - general ATT&CK question
            context = self._build_root_context(question)
        else:
            # In an entity - contextual question
            context = self._build_entity_context(question)

        # Query LLM
        try:
            response = llm.query(context)
            return response
        except Exception as e:
            return f"Error querying LLM: {e}"

    def _get_root_summary(self) -> dict[str, Any]:
        """Get summary of the knowledge base for root view."""
        stats = self.graph.get_stats()
        return {
            "location": "root",
            "entity_type": None,
            "summary": {
                "techniques": stats.get("techniques", 0),
                "groups": stats.get("groups", 0),
                "software": stats.get("software", 0),
                "mitigations": stats.get("mitigations", 0),
                "campaigns": stats.get("campaigns", 0),
                "tactics": stats.get("tactics", 0),
                "data_sources": stats.get("data_sources", 0),
                "total_triples": stats.get("total_triples", 0),
            },
        }

    def _build_root_context(self, question: str) -> str:
        """Build LLM context for a question at root level."""
        stats = self.graph.get_stats()
        return f"""You are an expert on the MITRE ATT&CK framework, answering questions about cyber threats and attack techniques.

Knowledge Base Summary:
- {stats.get('techniques', 0)} techniques
- {stats.get('groups', 0)} threat groups
- {stats.get('software', 0)} malware/tools
- {stats.get('mitigations', 0)} mitigations
- {stats.get('campaigns', 0)} campaigns

User Question: {question}

Provide a helpful, concise answer about ATT&CK. If relevant, mention specific technique IDs (T####), group IDs (G####), or software IDs (S####) that the user can navigate to with 'cd <ID>'."""

    def _build_entity_context(self, question: str) -> str:
        """Build LLM context for a question about the current entity."""
        entity = self.info()
        relationships = self.ls()

        # Format entity details
        entity_info = self._format_entity_for_context(entity)
        relationship_info = self._format_relationships_for_context(relationships)

        return f"""You are answering a question about ATT&CK entity {self.state.current_id} ({self.state.current_name}).

Entity Type: {self.state.current_type}

Entity Details:
{entity_info}

Relationships:
{relationship_info}

User Question: {question}

Provide a helpful, specific answer in the context of this entity. Reference specific related entities by their IDs when relevant."""

    def _format_entity_for_context(self, entity: dict[str, Any] | None) -> str:
        """Format entity details for LLM context."""
        if not entity:
            return "No entity details available."

        lines = []
        for key, value in entity.items():
            if key in ("description", "detection") and value:
                # Truncate long text
                text = value[:1000] + "..." if len(value) > 1000 else value
                lines.append(f"- {key}: {text}")
            elif isinstance(value, list) and value:
                lines.append(f"- {key}: {', '.join(str(v) for v in value[:10])}")
            elif value and not isinstance(value, (list, dict)):
                lines.append(f"- {key}: {value}")

        return "\n".join(lines) if lines else "No details available."

    def _format_relationships_for_context(self, relationships: dict[str, Any] | None) -> str:
        """Format relationships for LLM context."""
        if not relationships:
            return "No relationships available."

        lines = []
        for key, value in relationships.items():
            if key in ("entity_id", "entity_type"):
                continue
            if isinstance(value, list) and value:
                items = [f"{item.get('attack_id', '')} {item.get('name', '')}" for item in value[:5]]
                if len(value) > 5:
                    items.append(f"... and {len(value) - 5} more")
                lines.append(f"- {key}: {', '.join(items)}")
            elif isinstance(value, dict) and value:
                lines.append(f"- {key}: {value.get('attack_id', '')} {value.get('name', '')}")

        return "\n".join(lines) if lines else "No relationships found."

    @property
    def current_id(self) -> str | None:
        """Get current entity ID."""
        return self.state.current_id

    @property
    def current_type(self) -> str | None:
        """Get current entity type."""
        return self.state.current_type

    @property
    def current_name(self) -> str | None:
        """Get current entity name."""
        return self.state.current_name

    @property
    def at_root(self) -> bool:
        """Check if at root level."""
        return self.state.current_id is None
