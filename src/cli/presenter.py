"""Entity presenters for rich formatted output in the graph browser."""

from typing import Any

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

console = Console()


class EntityPresenter:
    """Base presenter with common formatting."""

    def present(self, entity: dict[str, Any], full: bool = False) -> None:
        """Present an entity with rich formatting."""
        raise NotImplementedError

    def _truncate(self, text: str, max_len: int = 200) -> str:
        """Truncate text with ellipsis."""
        if not text:
            return ""
        if len(text) <= max_len:
            return text
        return text[:max_len].rsplit(" ", 1)[0] + "..."

    def _format_list(self, items: list[str], max_items: int = 5) -> str:
        """Format a list with optional truncation."""
        if not items:
            return "[dim]none[/dim]"
        if len(items) <= max_items:
            return ", ".join(items)
        return ", ".join(items[:max_items]) + f" (+{len(items) - max_items} more)"


class TechniquePresenter(EntityPresenter):
    """Present technique entities."""

    def present(self, entity: dict[str, Any], full: bool = False) -> None:
        attack_id = entity.get("attack_id", "")
        name = entity.get("name", "Unknown")

        # Header
        console.print(f"\n[bold cyan]{attack_id}[/bold cyan] - [bold]{name}[/bold]")
        console.print("━" * 50)

        # Tactics and platforms
        tactics = entity.get("tactics", [])
        platforms = entity.get("platforms", [])

        if tactics:
            console.print(f"[yellow]Tactics:[/yellow] {', '.join(tactics)}")
        if platforms:
            console.print(f"[yellow]Platforms:[/yellow] {', '.join(platforms)}")

        # Description (truncated unless full)
        description = entity.get("description", "")
        if description:
            if full:
                console.print(f"\n[dim]{description}[/dim]")
            else:
                console.print(f"\n[dim]{self._truncate(description, 300)}[/dim]")

        # Detection info (only in full view)
        if full:
            detection = entity.get("detection", "")
            if detection:
                console.print(f"\n[yellow]Detection:[/yellow]")
                console.print(f"[dim]{detection}[/dim]")

            data_sources = entity.get("data_sources", [])
            if data_sources:
                console.print(f"\n[yellow]Data Sources:[/yellow] {self._format_list(data_sources, 10)}")

            url = entity.get("url", "")
            if url:
                console.print(f"\n[blue]URL:[/blue] {url}")


class GroupPresenter(EntityPresenter):
    """Present threat group entities."""

    def present(self, entity: dict[str, Any], full: bool = False) -> None:
        attack_id = entity.get("attack_id", "")
        name = entity.get("name", "Unknown")
        aliases = entity.get("aliases", [])

        # Header with aliases
        alias_str = f" ({', '.join(aliases[:3])})" if aliases else ""
        console.print(f"\n[bold magenta]{attack_id}[/bold magenta] - [bold]{name}[/bold]{alias_str}")
        console.print("━" * 50)

        # Description
        description = entity.get("description", "")
        if description:
            if full:
                console.print(f"\n[dim]{description}[/dim]")
            else:
                console.print(f"\n[dim]{self._truncate(description, 300)}[/dim]")

        if full:
            if aliases and len(aliases) > 3:
                console.print(f"\n[yellow]All Aliases:[/yellow] {', '.join(aliases)}")

            url = entity.get("url", "")
            if url:
                console.print(f"\n[blue]URL:[/blue] {url}")


class SoftwarePresenter(EntityPresenter):
    """Present software (malware/tool) entities."""

    def present(self, entity: dict[str, Any], full: bool = False) -> None:
        attack_id = entity.get("attack_id", "")
        name = entity.get("name", "Unknown")
        sw_type = entity.get("type", "Software")
        platforms = entity.get("platforms", [])
        aliases = entity.get("aliases", [])

        # Header
        type_color = "red" if sw_type == "Malware" else "green"
        alias_str = f" ({', '.join(aliases[:2])})" if aliases else ""
        console.print(f"\n[bold {type_color}]{attack_id}[/bold {type_color}] - [bold]{name}[/bold]{alias_str}")
        console.print(f"[{type_color}][{sw_type}][/{type_color}]")
        console.print("━" * 50)

        if platforms:
            console.print(f"[yellow]Platforms:[/yellow] {', '.join(platforms)}")

        description = entity.get("description", "")
        if description:
            if full:
                console.print(f"\n[dim]{description}[/dim]")
            else:
                console.print(f"\n[dim]{self._truncate(description, 300)}[/dim]")

        if full:
            url = entity.get("url", "")
            if url:
                console.print(f"\n[blue]URL:[/blue] {url}")


class MitigationPresenter(EntityPresenter):
    """Present mitigation entities."""

    def present(self, entity: dict[str, Any], full: bool = False) -> None:
        attack_id = entity.get("attack_id", "")
        name = entity.get("name", "Unknown")

        console.print(f"\n[bold green]{attack_id}[/bold green] - [bold]{name}[/bold]")
        console.print("━" * 50)

        description = entity.get("description", "")
        if description:
            if full:
                console.print(f"\n[dim]{description}[/dim]")
            else:
                console.print(f"\n[dim]{self._truncate(description, 300)}[/dim]")

        if full:
            url = entity.get("url", "")
            if url:
                console.print(f"\n[blue]URL:[/blue] {url}")


class CampaignPresenter(EntityPresenter):
    """Present campaign entities."""

    def present(self, entity: dict[str, Any], full: bool = False) -> None:
        attack_id = entity.get("attack_id", "")
        name = entity.get("name", "Unknown")
        first_seen = entity.get("first_seen", "")
        last_seen = entity.get("last_seen", "")

        console.print(f"\n[bold yellow]{attack_id}[/bold yellow] - [bold]{name}[/bold]")
        console.print("━" * 50)

        if first_seen or last_seen:
            date_range = f"{first_seen or '?'} - {last_seen or 'present'}"
            console.print(f"[yellow]Active:[/yellow] {date_range}")

        description = entity.get("description", "")
        if description:
            if full:
                console.print(f"\n[dim]{description}[/dim]")
            else:
                console.print(f"\n[dim]{self._truncate(description, 300)}[/dim]")

        if full:
            url = entity.get("url", "")
            if url:
                console.print(f"\n[blue]URL:[/blue] {url}")


class TacticPresenter(EntityPresenter):
    """Present tactic entities."""

    def present(self, entity: dict[str, Any], full: bool = False) -> None:
        attack_id = entity.get("attack_id", "")
        name = entity.get("name", "Unknown")
        shortname = entity.get("shortname", "")

        console.print(f"\n[bold blue]{attack_id}[/bold blue] - [bold]{name}[/bold]")
        if shortname:
            console.print(f"[dim]({shortname})[/dim]")
        console.print("━" * 50)


class DataSourcePresenter(EntityPresenter):
    """Present data source entities."""

    def present(self, entity: dict[str, Any], full: bool = False) -> None:
        attack_id = entity.get("attack_id", "")
        name = entity.get("name", "Unknown")

        console.print(f"\n[bold cyan]{attack_id}[/bold cyan] - [bold]{name}[/bold]")
        console.print("━" * 50)

        description = entity.get("description", "")
        if description:
            if full:
                console.print(f"\n[dim]{description}[/dim]")
            else:
                console.print(f"\n[dim]{self._truncate(description, 300)}[/dim]")


# Presenter registry
_PRESENTERS: dict[str, EntityPresenter] = {
    "technique": TechniquePresenter(),
    "group": GroupPresenter(),
    "software": SoftwarePresenter(),
    "mitigation": MitigationPresenter(),
    "campaign": CampaignPresenter(),
    "tactic": TacticPresenter(),
    "data_source": DataSourcePresenter(),
}


def get_presenter(entity_type: str) -> EntityPresenter:
    """Get the appropriate presenter for an entity type."""
    return _PRESENTERS.get(entity_type, EntityPresenter())


def present_entity(entity: dict[str, Any], entity_type: str, full: bool = False) -> None:
    """Render an entity with the appropriate presenter."""
    presenter = get_presenter(entity_type)
    presenter.present(entity, full=full)


def present_connections(
    relationships: dict[str, Any],
    entity_type: str,
    entity_name: str,
) -> None:
    """Render connections from an entity as a navigable list."""
    console.print(f"\n[bold]Connections from {entity_name}:[/bold]")
    console.print("━" * 50)

    has_connections = False

    # Define connection display order and labels based on entity type
    if entity_type == "technique":
        connection_types = [
            ("groups", "Groups", "magenta"),
            ("mitigations", "Mitigations", "green"),
            ("software", "Software", "yellow"),
            ("campaigns", "Campaigns", "yellow"),
            ("subtechniques", "Sub-techniques", "cyan"),
            ("detection_strategies", "Detection Strategies", "blue"),
        ]
        if relationships.get("parent_technique"):
            parent = relationships["parent_technique"]
            console.print(f"  [cyan]Parent:[/cyan] {parent['attack_id']} {parent['name']}")
            has_connections = True

    elif entity_type == "group":
        connection_types = [
            ("techniques", "Techniques", "cyan"),
            ("software", "Software", "yellow"),
            ("campaigns", "Campaigns", "yellow"),
        ]

    elif entity_type == "software":
        connection_types = [
            ("techniques", "Techniques", "cyan"),
            ("used_by_groups", "Used by Groups", "magenta"),
        ]

    elif entity_type == "mitigation":
        connection_types = [
            ("mitigates_techniques", "Mitigates Techniques", "cyan"),
        ]

    elif entity_type == "campaign":
        connection_types = [
            ("techniques", "Techniques", "cyan"),
            ("attributed_to", "Attributed to", "magenta"),
        ]
    else:
        connection_types = []

    for key, label, color in connection_types:
        items = relationships.get(key, [])

        # Handle single item (e.g., attributed_to)
        if isinstance(items, dict):
            items = [items] if items else []

        if items:
            has_connections = True
            count = len(items)
            console.print(f"\n  [{color}]{label} ({count}):[/{color}]")

            # Show first few items
            for item in items[:8]:
                attack_id = item.get("attack_id", "")
                name = item.get("name", "")
                item_type = item.get("type", "")
                type_suffix = f" [{item_type}]" if item_type else ""
                console.print(f"    [dim]→[/dim] [cyan]{attack_id}[/cyan] {name}{type_suffix}")

            if count > 8:
                console.print(f"    [dim]... and {count - 8} more[/dim]")

    if not has_connections:
        console.print("\n  [dim]No connections found[/dim]")

    console.print(f"\n[dim]Use 'cd <ID>' to navigate, 'info' for full details[/dim]")


def present_search_results(results: dict[str, list[dict[str, Any]]]) -> None:
    """Render multi-type search results."""
    has_results = False

    # Techniques (semantic search results)
    techniques = results.get("techniques", [])
    if techniques:
        has_results = True
        console.print("\n[bold cyan]Techniques[/bold cyan] (semantic match):")
        table = Table(show_header=True, header_style="bold", box=None, padding=(0, 1))
        table.add_column("ID", style="cyan", width=12)
        table.add_column("Name", style="white")
        table.add_column("Score", justify="right", width=6)
        table.add_column("Tactics", style="dim")

        for t in techniques[:10]:
            tactics = ", ".join(t.get("tactics", [])[:2])
            if len(t.get("tactics", [])) > 2:
                tactics += "..."
            score = f"{t.get('similarity', 0):.2f}"
            table.add_row(t["attack_id"], t["name"], score, tactics)

        console.print(table)
        if len(techniques) > 10:
            console.print(f"  [dim]... and {len(techniques) - 10} more[/dim]")

    # Groups
    groups = results.get("groups", [])
    if groups:
        has_results = True
        console.print("\n[bold magenta]Groups[/bold magenta] (text match):")
        for g in groups[:5]:
            console.print(f"  [magenta]{g['attack_id']}[/magenta]  {g['name']}")
        if len(groups) > 5:
            console.print(f"  [dim]... and {len(groups) - 5} more[/dim]")

    # Software
    software = results.get("software", [])
    if software:
        has_results = True
        console.print("\n[bold yellow]Software[/bold yellow] (text match):")
        for s in software[:5]:
            sw_type = s.get("type", "")
            console.print(f"  [yellow]{s['attack_id']}[/yellow]  {s['name']} [{sw_type}]")
        if len(software) > 5:
            console.print(f"  [dim]... and {len(software) - 5} more[/dim]")

    # Mitigations
    mitigations = results.get("mitigations", [])
    if mitigations:
        has_results = True
        console.print("\n[bold green]Mitigations[/bold green] (text match):")
        for m in mitigations[:5]:
            console.print(f"  [green]{m['attack_id']}[/green]  {m['name']}")
        if len(mitigations) > 5:
            console.print(f"  [dim]... and {len(mitigations) - 5} more[/dim]")

    # Campaigns
    campaigns = results.get("campaigns", [])
    if campaigns:
        has_results = True
        console.print("\n[bold yellow]Campaigns[/bold yellow] (text match):")
        for c in campaigns[:5]:
            date_str = f" ({c.get('first_seen', '')})" if c.get('first_seen') else ""
            console.print(f"  [yellow]{c['attack_id']}[/yellow]  {c['name']}{date_str}")
        if len(campaigns) > 5:
            console.print(f"  [dim]... and {len(campaigns) - 5} more[/dim]")

    if not has_results:
        console.print("\n[yellow]No results found[/yellow]")
    else:
        console.print(f"\n[dim]Use 'cd <ID>' to navigate to an entity[/dim]")
