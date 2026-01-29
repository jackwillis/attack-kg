"""SPARQL query templates for common ATT&CK queries."""

from dataclasses import dataclass
from typing import Any


@dataclass
class QueryTemplate:
    """A reusable SPARQL query template."""

    name: str
    description: str
    sparql: str
    parameters: list[str]

    def format(self, **kwargs) -> str:
        """Format the query with provided parameters."""
        return self.sparql.format(**kwargs)


# Common prefixes for all queries
PREFIXES = """
PREFIX attack: <https://attack.mitre.org/>
PREFIX rdfs: <http://www.w3.org/2000/01/rdf-schema#>
PREFIX xsd: <http://www.w3.org/2001/XMLSchema#>
"""


# ============================================================================
# Technique Queries
# ============================================================================

TECHNIQUE_BY_ID = QueryTemplate(
    name="technique_by_id",
    description="Get technique details by ATT&CK ID",
    parameters=["attack_id"],
    sparql=PREFIXES + """
SELECT ?name ?description ?detection WHERE {{
    attack:technique/{attack_id} rdfs:label ?name .
    OPTIONAL {{ attack:technique/{attack_id} attack:description ?description }}
    OPTIONAL {{ attack:technique/{attack_id} attack:detection ?detection }}
}}
""",
)

TECHNIQUES_FOR_TACTIC = QueryTemplate(
    name="techniques_for_tactic",
    description="Get all techniques for a given tactic",
    parameters=["tactic"],
    sparql=PREFIXES + """
SELECT ?attackId ?name WHERE {{
    ?technique a attack:Technique ;
               attack:tactic attack:tactic/{tactic} ;
               attack:attackId ?attackId ;
               rdfs:label ?name .
}}
ORDER BY ?attackId
""",
)

SUBTECHNIQUES = QueryTemplate(
    name="subtechniques",
    description="Get sub-techniques of a parent technique",
    parameters=["parent_id"],
    sparql=PREFIXES + """
SELECT ?attackId ?name WHERE {{
    ?technique attack:subtechniqueOf attack:technique/{parent_id} ;
               attack:attackId ?attackId ;
               rdfs:label ?name .
}}
ORDER BY ?attackId
""",
)

TECHNIQUE_PLATFORMS = QueryTemplate(
    name="technique_platforms",
    description="Get platforms for a technique",
    parameters=["attack_id"],
    sparql=PREFIXES + """
SELECT ?platform WHERE {{
    attack:technique/{attack_id} attack:platform ?platform .
}}
""",
)

TECHNIQUES_BY_PLATFORM = QueryTemplate(
    name="techniques_by_platform",
    description="Get techniques that apply to a platform",
    parameters=["platform"],
    sparql=PREFIXES + """
SELECT ?attackId ?name WHERE {{
    ?technique a attack:Technique ;
               attack:platform "{platform}" ;
               attack:attackId ?attackId ;
               rdfs:label ?name .
}}
ORDER BY ?attackId
""",
)


# ============================================================================
# Group Queries
# ============================================================================

GROUP_BY_ID = QueryTemplate(
    name="group_by_id",
    description="Get group details by ATT&CK ID",
    parameters=["group_id"],
    sparql=PREFIXES + """
SELECT ?name ?description
       (GROUP_CONCAT(DISTINCT ?alias; separator=", ") AS ?aliases)
WHERE {{
    attack:group/{group_id} rdfs:label ?name .
    OPTIONAL {{ attack:group/{group_id} attack:description ?description }}
    OPTIONAL {{ attack:group/{group_id} attack:alias ?alias }}
}}
GROUP BY ?name ?description
""",
)

GROUPS_USING_TECHNIQUE = QueryTemplate(
    name="groups_using_technique",
    description="Get groups that use a specific technique",
    parameters=["attack_id"],
    sparql=PREFIXES + """
SELECT ?attackId ?name WHERE {{
    ?group a attack:Group ;
           attack:uses attack:technique/{attack_id} ;
           attack:attackId ?attackId ;
           rdfs:label ?name .
}}
ORDER BY ?name
""",
)

TECHNIQUES_FOR_GROUP = QueryTemplate(
    name="techniques_for_group",
    description="Get techniques used by a group",
    parameters=["group_id"],
    sparql=PREFIXES + """
SELECT ?attackId ?name WHERE {{
    attack:group/{group_id} attack:uses ?technique .
    ?technique a attack:Technique ;
               attack:attackId ?attackId ;
               rdfs:label ?name .
}}
ORDER BY ?attackId
""",
)

GROUP_BY_NAME = QueryTemplate(
    name="group_by_name",
    description="Find groups by name or alias",
    parameters=["name"],
    sparql=PREFIXES + """
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
""",
)


# ============================================================================
# Mitigation Queries
# ============================================================================

MITIGATIONS_FOR_TECHNIQUE = QueryTemplate(
    name="mitigations_for_technique",
    description="Get mitigations for a technique",
    parameters=["attack_id"],
    sparql=PREFIXES + """
SELECT ?attackId ?name ?description WHERE {{
    ?mitigation a attack:Mitigation ;
                attack:mitigates attack:technique/{attack_id} ;
                attack:attackId ?attackId ;
                rdfs:label ?name .
    OPTIONAL {{ ?mitigation attack:description ?description }}
}}
ORDER BY ?name
""",
)

TECHNIQUES_FOR_MITIGATION = QueryTemplate(
    name="techniques_for_mitigation",
    description="Get techniques addressed by a mitigation",
    parameters=["mitigation_id"],
    sparql=PREFIXES + """
SELECT ?attackId ?name WHERE {{
    attack:mitigation/{mitigation_id} attack:mitigates ?technique .
    ?technique a attack:Technique ;
               attack:attackId ?attackId ;
               rdfs:label ?name .
}}
ORDER BY ?attackId
""",
)


# ============================================================================
# Software Queries
# ============================================================================

SOFTWARE_USING_TECHNIQUE = QueryTemplate(
    name="software_using_technique",
    description="Get software that uses a technique",
    parameters=["attack_id"],
    sparql=PREFIXES + """
SELECT ?attackId ?name ?type WHERE {{
    ?software attack:uses attack:technique/{attack_id} ;
              attack:attackId ?attackId ;
              rdfs:label ?name ;
              a ?type .
    FILTER(?type IN (attack:Malware, attack:Tool))
}}
ORDER BY ?name
""",
)

TECHNIQUES_FOR_SOFTWARE = QueryTemplate(
    name="techniques_for_software",
    description="Get techniques used by software",
    parameters=["software_id"],
    sparql=PREFIXES + """
SELECT ?attackId ?name WHERE {{
    attack:software/{software_id} attack:uses ?technique .
    ?technique a attack:Technique ;
               attack:attackId ?attackId ;
               rdfs:label ?name .
}}
ORDER BY ?attackId
""",
)


# ============================================================================
# Tactic Queries
# ============================================================================

ALL_TACTICS = QueryTemplate(
    name="all_tactics",
    description="Get all tactics",
    parameters=[],
    sparql=PREFIXES + """
SELECT ?attackId ?name ?shortname WHERE {{
    ?tactic a attack:Tactic ;
            rdfs:label ?name .
    OPTIONAL {{ ?tactic attack:attackId ?attackId }}
    BIND(REPLACE(STR(?tactic), "https://attack.mitre.org/tactic/", "") AS ?shortname)
}}
ORDER BY ?attackId
""",
)


# ============================================================================
# Analytics / Statistics
# ============================================================================

COUNT_BY_TYPE = QueryTemplate(
    name="count_by_type",
    description="Get counts of each entity type",
    parameters=[],
    sparql=PREFIXES + """
SELECT
    (COUNT(DISTINCT ?technique) AS ?techniques)
    (COUNT(DISTINCT ?group) AS ?groups)
    (COUNT(DISTINCT ?software) AS ?software)
    (COUNT(DISTINCT ?mitigation) AS ?mitigations)
    (COUNT(DISTINCT ?tactic) AS ?tactics)
WHERE {{
    OPTIONAL {{ ?technique a attack:Technique }}
    OPTIONAL {{ ?group a attack:Group }}
    OPTIONAL {{ ?software a attack:Software }}
    OPTIONAL {{ ?mitigation a attack:Mitigation }}
    OPTIONAL {{ ?tactic a attack:Tactic }}
}}
""",
)

MOST_USED_TECHNIQUES = QueryTemplate(
    name="most_used_techniques",
    description="Get techniques used by most groups",
    parameters=["limit"],
    sparql=PREFIXES + """
SELECT ?attackId ?name (COUNT(?group) AS ?groupCount) WHERE {{
    ?group a attack:Group ;
           attack:uses ?technique .
    ?technique a attack:Technique ;
               attack:attackId ?attackId ;
               rdfs:label ?name .
}}
GROUP BY ?attackId ?name
ORDER BY DESC(?groupCount)
LIMIT {limit}
""",
)

GROUPS_WITH_MOST_TECHNIQUES = QueryTemplate(
    name="groups_with_most_techniques",
    description="Get groups that use the most techniques",
    parameters=["limit"],
    sparql=PREFIXES + """
SELECT ?attackId ?name (COUNT(?technique) AS ?techCount) WHERE {{
    ?group a attack:Group ;
           attack:uses ?technique ;
           attack:attackId ?attackId ;
           rdfs:label ?name .
    ?technique a attack:Technique .
}}
GROUP BY ?attackId ?name
ORDER BY DESC(?techCount)
LIMIT {limit}
""",
)

TECHNIQUES_WITH_DETECTION = QueryTemplate(
    name="techniques_with_detection",
    description="Get techniques that have detection guidance",
    parameters=[],
    sparql=PREFIXES + """
SELECT ?attackId ?name WHERE {{
    ?technique a attack:Technique ;
               attack:detection ?detection ;
               attack:attackId ?attackId ;
               rdfs:label ?name .
    FILTER(STRLEN(?detection) > 0)
}}
ORDER BY ?attackId
""",
)


# ============================================================================
# Complex / Path Queries
# ============================================================================

COMMON_TECHNIQUES_BETWEEN_GROUPS = QueryTemplate(
    name="common_techniques_between_groups",
    description="Find techniques used by two groups",
    parameters=["group1", "group2"],
    sparql=PREFIXES + """
SELECT ?attackId ?name WHERE {{
    attack:group/{group1} attack:uses ?technique .
    attack:group/{group2} attack:uses ?technique .
    ?technique a attack:Technique ;
               attack:attackId ?attackId ;
               rdfs:label ?name .
}}
ORDER BY ?attackId
""",
)

GROUPS_SHARING_TECHNIQUE = QueryTemplate(
    name="groups_sharing_technique",
    description="Find groups that share any technique with a given group",
    parameters=["group_id"],
    sparql=PREFIXES + """
SELECT DISTINCT ?otherGroupId ?otherGroupName
       (COUNT(?sharedTech) AS ?sharedCount)
WHERE {{
    attack:group/{group_id} attack:uses ?sharedTech .
    ?otherGroup attack:uses ?sharedTech ;
                attack:attackId ?otherGroupId ;
                rdfs:label ?otherGroupName .
    FILTER(?otherGroup != attack:group/{group_id})
}}
GROUP BY ?otherGroupId ?otherGroupName
ORDER BY DESC(?sharedCount)
""",
)


# Registry of all templates for easy access
TEMPLATES = {
    "technique_by_id": TECHNIQUE_BY_ID,
    "techniques_for_tactic": TECHNIQUES_FOR_TACTIC,
    "subtechniques": SUBTECHNIQUES,
    "technique_platforms": TECHNIQUE_PLATFORMS,
    "techniques_by_platform": TECHNIQUES_BY_PLATFORM,
    "group_by_id": GROUP_BY_ID,
    "groups_using_technique": GROUPS_USING_TECHNIQUE,
    "techniques_for_group": TECHNIQUES_FOR_GROUP,
    "group_by_name": GROUP_BY_NAME,
    "mitigations_for_technique": MITIGATIONS_FOR_TECHNIQUE,
    "techniques_for_mitigation": TECHNIQUES_FOR_MITIGATION,
    "software_using_technique": SOFTWARE_USING_TECHNIQUE,
    "techniques_for_software": TECHNIQUES_FOR_SOFTWARE,
    "all_tactics": ALL_TACTICS,
    "count_by_type": COUNT_BY_TYPE,
    "most_used_techniques": MOST_USED_TECHNIQUES,
    "groups_with_most_techniques": GROUPS_WITH_MOST_TECHNIQUES,
    "techniques_with_detection": TECHNIQUES_WITH_DETECTION,
    "common_techniques_between_groups": COMMON_TECHNIQUES_BETWEEN_GROUPS,
    "groups_sharing_technique": GROUPS_SHARING_TECHNIQUE,
}


def get_template(name: str) -> QueryTemplate | None:
    """Get a query template by name."""
    return TEMPLATES.get(name)


def list_templates() -> list[dict[str, str]]:
    """List all available query templates."""
    return [
        {"name": t.name, "description": t.description, "parameters": t.parameters}
        for t in TEMPLATES.values()
    ]
