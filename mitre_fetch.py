import requests
import json

# --- CONFIG ---
SUPABASE_URL = "URL"
SUPABASE_KEY = "KEY"

HEADERS = {
    "apikey": SUPABASE_KEY,
    "Authorization": f"Bearer {SUPABASE_KEY}",
    "Content-Type": "application/json",
    "Prefer": "return=representation"
}

REST_URL = f"{SUPABASE_URL}/rest/v1/mitre_attack"
GROUPS_URL = f"{SUPABASE_URL}/rest/v1/mitre_groups"
GROUP_TECHNIQUES_URL = f"{SUPABASE_URL}/rest/v1/mitre_group_techniques"


def get_mitre_external_id(external_references, source_name="mitre-attack"):
    return next(
        (r.get("external_id") for r in external_references if r.get("source_name") == source_name),
        None
    )


# 1) Fetch MITRE ATT&CK data
print("Fetching MITRE ATT&CK data...")
url = "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"
data = requests.get(url).json()

objects = data["objects"]

# 2) Extract attack-pattern objects
patterns = [obj for obj in objects if obj.get("type") == "attack-pattern"]

# 3) Keep first 20 and extract fields
rows = []
attack_pattern_lookup = {}

for p in patterns[:20]:
    ext = p.get("external_references", [])
    tid = get_mitre_external_id(ext, "mitre-attack")

    if tid and p.get("id"):
        attack_pattern_lookup[p.get("id")] = tid

    tactics = ", ".join(
        phase["phase_name"] for phase in p.get("kill_chain_phases", [])
    )

    rows.append({
        "technique_id": tid,
        "technique_name": p.get("name", ""),
        "tactic": tactics or None,
        "description": (p.get("description", "") or "")[:500],
        "severity": None,
    })

# 4) Insert into Supabase - mitre_attack
print(f"Inserting {len(rows)} techniques...")
response = requests.post(REST_URL, headers=HEADERS, json=rows)
print("mitre_attack status:", response.status_code)
print(response.text)


# -----------------------------
# NEW PART: load MITRE groups
# -----------------------------

# 5) Extract intrusion-set objects (groups)
groups = [obj for obj in objects if obj.get("type") == "intrusion-set"]

group_rows = []
group_lookup = {}

for g in groups:
    ext = g.get("external_references", [])
    gid = get_mitre_external_id(ext, "mitre-attack")

    if gid and g.get("id"):
        group_lookup[g.get("id")] = gid

    if gid:
        group_rows.append({
            "group_id": gid,
            "group_name": g.get("name", ""),
            "description": (g.get("description", "") or "")[:1000],
            "country": None
        })

print(f"Inserting {len(group_rows)} groups...")
group_response = requests.post(GROUPS_URL, headers=HEADERS, json=group_rows)
print("mitre_groups status:", group_response.status_code)
print(group_response.text)


# ----------------------------------------
# NEW PART: load group-technique relations
# ----------------------------------------

relationships = [obj for obj in objects if obj.get("type") == "relationship"]

relationship_rows = []

for rel in relationships:
    source_ref = rel.get("source_ref")
    target_ref = rel.get("target_ref")
    relationship_type = rel.get("relationship_type")

    # group -> technique
    if source_ref in group_lookup and target_ref in attack_pattern_lookup:
        relationship_rows.append({
            "group_id": group_lookup[source_ref],
            "technique_id": attack_pattern_lookup[target_ref],
            "relationship_type": relationship_type
        })

# remove duplicates
seen = set()
unique_relationship_rows = []

for row in relationship_rows:
    key = (row["group_id"], row["technique_id"], row["relationship_type"])
    if key not in seen:
        seen.add(key)
        unique_relationship_rows.append(row)

print(f"Inserting {len(unique_relationship_rows)} group-technique relationships...")
rel_response = requests.post(GROUP_TECHNIQUES_URL, headers=HEADERS, json=unique_relationship_rows)
print("mitre_group_techniques status:", rel_response.status_code)
print(rel_response.text)
