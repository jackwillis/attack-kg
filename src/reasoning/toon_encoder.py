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


def software_to_toon(techniques: list[Any]) -> str:
    """
    Extract and format software (malware/tools) from techniques.

    Args:
        techniques: List of EnrichedTechnique objects

    Returns:
        TOON-formatted software table
    """
    # Collect unique software across all techniques
    software_map: dict[str, dict[str, Any]] = {}
    for tech in techniques:
        for sw in tech.software:
            sw_id = sw.get("attack_id", "")
            if sw_id not in software_map:
                software_map[sw_id] = {
                    "attack_id": sw_id,
                    "name": sw.get("name", ""),
                    "type": sw.get("type", ""),
                    "techniques": [tech.attack_id],
                }
            else:
                software_map[sw_id]["techniques"].append(tech.attack_id)

    if not software_map:
        return "RELATED SOFTWARE\nNo software found."

    headers = ["software_id", "name", "type", "implements_techniques"]
    rows = []

    # Sort by number of techniques (most relevant first), limit to top 10
    sorted_software = sorted(
        software_map.values(),
        key=lambda x: len(x["techniques"]),
        reverse=True
    )[:10]

    for sw in sorted_software:
        techs = ";".join(sw["techniques"][:5])  # Limit techniques shown
        rows.append([sw["attack_id"], sw["name"], sw["type"], techs])

    return encode_table(headers, rows, "RELATED SOFTWARE")


def campaigns_to_toon(techniques: list[Any]) -> str:
    """
    Extract and format campaigns from techniques.

    Args:
        techniques: List of EnrichedTechnique objects

    Returns:
        TOON-formatted campaigns table
    """
    # Collect unique campaigns across all techniques
    campaign_map: dict[str, dict[str, Any]] = {}
    for tech in techniques:
        for camp in tech.campaigns:
            camp_id = camp.get("attack_id", "")
            if camp_id not in campaign_map:
                campaign_map[camp_id] = {
                    "attack_id": camp_id,
                    "name": camp.get("name", ""),
                    "techniques": [tech.attack_id],
                }
            else:
                campaign_map[camp_id]["techniques"].append(tech.attack_id)

    if not campaign_map:
        return "RELATED CAMPAIGNS\nNo campaigns found."

    headers = ["campaign_id", "name", "uses_techniques"]
    rows = []

    # Sort by number of techniques (most relevant first), limit to top 5
    sorted_campaigns = sorted(
        campaign_map.values(),
        key=lambda x: len(x["techniques"]),
        reverse=True
    )[:5]

    for camp in sorted_campaigns:
        techs = ";".join(camp["techniques"][:5])
        rows.append([camp["attack_id"], camp["name"], techs])

    return encode_table(headers, rows, "RELATED CAMPAIGNS")


def detection_strategies_to_toon(techniques: list[Any]) -> str:
    """
    Extract and format detection strategies from techniques.

    Args:
        techniques: List of EnrichedTechnique objects

    Returns:
        TOON-formatted detection strategies table
    """
    # Collect unique detection strategies across all techniques
    strategy_map: dict[str, dict[str, Any]] = {}
    for tech in techniques:
        for det in tech.detection_strategies:
            det_id = det.get("attack_id", det.get("name", ""))
            if det_id and det_id not in strategy_map:
                strategy_map[det_id] = {
                    "id": det_id,
                    "name": det.get("name", det_id),
                    "techniques": [tech.attack_id],
                }
            elif det_id:
                strategy_map[det_id]["techniques"].append(tech.attack_id)

    if not strategy_map:
        return "DETECTION STRATEGIES\nNo detection strategies found."

    headers = ["strategy", "detects_techniques"]
    rows = []

    # Sort by coverage (most techniques first), limit to top 10
    sorted_strategies = sorted(
        strategy_map.values(),
        key=lambda x: len(x["techniques"]),
        reverse=True
    )[:10]

    for det in sorted_strategies:
        techs = ";".join(det["techniques"][:5])
        rows.append([det["name"], techs])

    return encode_table(headers, rows, "DETECTION STRATEGIES")


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


def build_toon_context(
    techniques: list[Any],
    mitigations: list[dict[str, Any]],
    d3fend_techniques: list[dict[str, Any]],
    include_description: bool = True,
    include_data_sources: bool = True,
    include_software: bool = True,
    include_campaigns: bool = False,  # Off by default - rarely useful for remediation
    include_detection_strategies: bool = True,
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
        include_software: Include related software (malware/tools)
        include_campaigns: Include related campaigns
        include_detection_strategies: Include detection strategies

    Returns:
        Complete TOON-formatted context string
    """
    sections = []

    # Candidate techniques
    sections.append(techniques_to_toon(techniques, include_description=include_description))

    # Related software (malware/tools that implement these techniques)
    if include_software and techniques:
        software_section = software_to_toon(techniques)
        if "No software found" not in software_section:
            sections.append(software_section)

    # Related campaigns
    if include_campaigns and techniques:
        campaigns_section = campaigns_to_toon(techniques)
        if "No campaigns found" not in campaigns_section:
            sections.append(campaigns_section)

    # Mitigations
    sections.append(mitigations_to_toon(mitigations))

    # D3FEND
    sections.append(d3fend_to_toon(d3fend_techniques))

    # Detection strategies
    if include_detection_strategies and techniques:
        detection_section = detection_strategies_to_toon(techniques)
        if "No detection strategies found" not in detection_section:
            sections.append(detection_section)

    # Data sources for detection
    if include_data_sources and techniques:
        sections.append(data_sources_to_toon(techniques))

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
