"""TOON format encoder for token-efficient LLM context.

TOON (Token-Oriented Object Notation) is a tabular format that reduces
token usage by 30-60% compared to JSON while maintaining readability.

Format:
- CSV-like tabular format for uniform arrays
- YAML-style indentation for nested objects
- Compact but human-readable
"""

from typing import Any


def encode_table(headers: list[str], rows: list[list[str]], title: str = "") -> str:
    """
    Encode data as a TOON table.

    Args:
        headers: Column header names
        rows: List of row data (each row is a list of values)
        title: Optional table title

    Returns:
        TOON-formatted table string
    """
    lines = []

    if title:
        lines.append(title)

    # Header row
    lines.append(", ".join(headers))

    # Data rows
    for row in rows:
        # Escape commas and quotes in values
        escaped = []
        for val in row:
            val_str = str(val) if val is not None else ""
            # If value contains comma or quote, escape it
            if "," in val_str or '"' in val_str:
                val_str = '"' + val_str.replace('"', '""') + '"'
            escaped.append(val_str)
        lines.append(", ".join(escaped))

    return "\n".join(lines)


def techniques_to_toon(techniques: list[Any], include_description: bool = False) -> str:
    """
    Convert techniques to TOON tabular format.

    Args:
        techniques: List of EnrichedTechnique objects
        include_description: Whether to include truncated descriptions

    Returns:
        TOON-formatted techniques table

    Example output:
        CANDIDATE TECHNIQUES
        attack_id, name, tactics, similarity, platforms
        T1110.003, Password Spraying, Credential Access, 0.87, Windows;Linux;Azure AD
    """
    if not techniques:
        return "CANDIDATE TECHNIQUES\nNo techniques found."

    if include_description:
        headers = ["attack_id", "name", "tactics", "similarity", "platforms", "description"]
    else:
        headers = ["attack_id", "name", "tactics", "similarity", "platforms"]

    rows = []
    for tech in techniques:
        # Join multi-value fields with semicolons
        tactics = ";".join(tech.tactics) if tech.tactics else ""
        platforms = ";".join(tech.platforms) if tech.platforms else ""
        similarity = f"{tech.similarity:.2f}"

        if include_description:
            desc = tech.description[:200] + "..." if len(tech.description) > 200 else tech.description
            desc = desc.replace("\n", " ").strip()
            rows.append([tech.attack_id, tech.name, tactics, similarity, platforms, desc])
        else:
            rows.append([tech.attack_id, tech.name, tactics, similarity, platforms])

    return encode_table(headers, rows, "CANDIDATE TECHNIQUES")


def mitigations_to_toon(mitigations: list[dict[str, Any]]) -> str:
    """
    Convert mitigations to TOON tabular format.

    Args:
        mitigations: List of mitigation dicts with attack_id, name, addresses, inherited

    Returns:
        TOON-formatted mitigations table

    Example output:
        AVAILABLE MITIGATIONS
        mitigation_id, name, addresses, inherited
        M1032, Multi-factor Authentication, T1110.003;T1078, false
    """
    if not mitigations:
        return "AVAILABLE MITIGATIONS\nNo mitigations found."

    headers = ["mitigation_id", "name", "addresses", "inherited"]
    rows = []

    for mit in mitigations:
        addresses = ";".join(mit.get("addresses", []))
        inherited = "true" if mit.get("inherited", False) else "false"
        rows.append([mit.get("attack_id", ""), mit.get("name", ""), addresses, inherited])

    return encode_table(headers, rows, "AVAILABLE MITIGATIONS")


def d3fend_to_toon(d3fend_techniques: list[dict[str, Any]]) -> str:
    """
    Convert D3FEND techniques to TOON tabular format.

    Args:
        d3fend_techniques: List of D3FEND technique dicts

    Returns:
        TOON-formatted D3FEND table

    Example output:
        D3FEND TECHNIQUES
        d3fend_id, name, via_mitigation, addresses, definition
        D3-MFA, Multi-factor Authentication, M1032, T1110.003, Require multiple forms of...
    """
    if not d3fend_techniques:
        return "D3FEND TECHNIQUES\nNo D3FEND techniques found (D3FEND may not be loaded)."

    headers = ["d3fend_id", "name", "via_mitigation", "addresses", "definition"]
    rows = []

    for d3f in d3fend_techniques:
        addresses = ";".join(d3f.get("addresses", []))
        definition = d3f.get("definition", "")
        if len(definition) > 100:
            definition = definition[:100] + "..."
        definition = definition.replace("\n", " ").strip()
        rows.append([
            d3f.get("d3fend_id", ""),
            d3f.get("name", ""),
            d3f.get("via_mitigation", ""),
            addresses,
            definition,
        ])

    return encode_table(headers, rows, "D3FEND TECHNIQUES")


def groups_to_toon(groups: list[dict[str, Any]]) -> str:
    """
    Convert threat groups to TOON tabular format.

    Args:
        groups: List of group dicts with attack_id, name

    Returns:
        TOON-formatted groups table
    """
    if not groups:
        return "KNOWN GROUPS\nNo groups found."

    headers = ["group_id", "name", "related_techniques"]
    rows = []

    for group in groups[:10]:  # Limit to top 10
        related = ";".join(group.get("related_techniques", []))
        rows.append([group.get("attack_id", ""), group.get("name", ""), related])

    return encode_table(headers, rows, "KNOWN GROUPS")


def data_sources_to_toon(techniques: list[Any]) -> str:
    """
    Extract and format data sources from techniques for detection context.

    Args:
        techniques: List of EnrichedTechnique objects

    Returns:
        TOON-formatted data sources table
    """
    # Collect unique data sources across all techniques
    data_sources: dict[str, list[str]] = {}
    for tech in techniques:
        for ds in tech.data_sources:
            if ds not in data_sources:
                data_sources[ds] = []
            data_sources[ds].append(tech.attack_id)

    if not data_sources:
        return "DATA SOURCES\nNo data sources found."

    headers = ["data_source", "techniques"]
    rows = []

    # Sort by coverage (most techniques first)
    for ds in sorted(data_sources.keys(), key=lambda x: len(data_sources[x]), reverse=True)[:10]:
        techs = ";".join(data_sources[ds][:5])  # Limit techniques shown
        rows.append([ds, techs])

    return encode_table(headers, rows, "DATA SOURCES")


def kill_chain_to_toon(
    detected_tactics: list[str],
    adjacent_tactics: list[str],
    adjacent_techniques: list[Any],
) -> str:
    """
    Format kill chain context in TOON format.

    Args:
        detected_tactics: Tactics detected in the finding
        adjacent_tactics: Next likely tactics in kill chain
        adjacent_techniques: Techniques from adjacent tactics

    Returns:
        TOON-formatted kill chain context
    """
    lines = ["KILL CHAIN CONTEXT"]
    lines.append(f"detected_tactics: {';'.join(detected_tactics)}")
    lines.append(f"next_likely_tactics: {';'.join(adjacent_tactics)}")

    if adjacent_techniques:
        lines.append("")
        lines.append("ADJACENT TECHNIQUES (from next phases)")
        headers = ["attack_id", "name", "tactic", "priority"]
        rows = []
        for tech in adjacent_techniques:
            tactic = tech.tactics[0] if tech.tactics else ""
            rows.append([tech.attack_id, tech.name, tactic, "consider"])
        lines.append(encode_table(headers, rows))

    return "\n".join(lines)


def build_toon_context(
    techniques: list[Any],
    mitigations: list[dict[str, Any]],
    d3fend_techniques: list[dict[str, Any]],
    include_description: bool = True,
    include_data_sources: bool = True,
    adjacent_techniques: list[Any] | None = None,
    kill_chain_context: str = "",
) -> str:
    """
    Build complete TOON-formatted context for LLM.

    This is the main function to call for building RAG context.

    Args:
        techniques: List of EnrichedTechnique objects
        mitigations: Consolidated mitigations dict
        d3fend_techniques: D3FEND techniques dict
        include_description: Include technique descriptions
        include_data_sources: Include data sources section
        adjacent_techniques: Kill chain adjacent techniques
        kill_chain_context: Kill chain context string

    Returns:
        Complete TOON-formatted context string
    """
    sections = []

    # Candidate techniques
    sections.append(techniques_to_toon(techniques, include_description=include_description))

    # Mitigations
    sections.append(mitigations_to_toon(mitigations))

    # D3FEND
    sections.append(d3fend_to_toon(d3fend_techniques))

    # Data sources for detection
    if include_data_sources and techniques:
        sections.append(data_sources_to_toon(techniques))

    # Kill chain context
    if adjacent_techniques:
        detected = set()
        for tech in techniques:
            for tactic in tech.tactics:
                detected.add(tactic.lower().replace(" ", "-"))

        adjacent_tactics = []
        if kill_chain_context:
            # Parse from context string
            parts = kill_chain_context.split("Next likely: ")
            if len(parts) > 1:
                adjacent_tactics = [t.strip() for t in parts[1].split(",")]

        if detected or adjacent_tactics:
            sections.append(kill_chain_to_toon(
                list(detected),
                adjacent_tactics,
                adjacent_techniques,
            ))

    return "\n\n".join(sections)


def estimate_token_savings(json_context: str, toon_context: str) -> dict[str, Any]:
    """
    Estimate token savings from using TOON vs JSON.

    This is a rough estimate based on character count.
    Actual token counts depend on the tokenizer used.

    Args:
        json_context: Original JSON-formatted context
        toon_context: TOON-formatted context

    Returns:
        Dict with character counts and estimated savings
    """
    json_chars = len(json_context)
    toon_chars = len(toon_context)
    savings = ((json_chars - toon_chars) / json_chars * 100) if json_chars > 0 else 0

    return {
        "json_chars": json_chars,
        "toon_chars": toon_chars,
        "char_savings_pct": round(savings, 1),
        # Rough token estimate (avg 4 chars per token)
        "json_tokens_est": json_chars // 4,
        "toon_tokens_est": toon_chars // 4,
    }
