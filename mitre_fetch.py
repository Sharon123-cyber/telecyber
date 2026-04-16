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

# 1) Fetch MITRE ATT&CK data
print("Fetching MITRE ATT&CK data...")
url = "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"
data = requests.get(url).json()

# 2) Extract attack-pattern objects
patterns = [obj for obj in data["objects"] if obj.get("type") == "attack-pattern"]

# 3) Keep first 20 and extract fields
rows = []
for p in patterns[:20]:
    ext = p.get("external_references", [])
    tid = next((r["external_id"] for r in ext if r.get("source_name") == "mitre-attack"), None)
    
    tactics = ", ".join(
        phase["phase_name"] for phase in p.get("kill_chain_phases", [])
    )
    
    rows.append({
        "technique_id": tid,
        "technique_name": p.get("name", ""),
        "tactic": tactics or None,
        "description": (p.get("description", "") or "")[:500],  # trim long text
        "severity": None,
    })

# 4) Insert into Supabase
print(f"Inserting {len(rows)} techniques...")
response = requests.post(REST_URL, headers=HEADERS, json=rows)
print(response.status_code)
print(response.text)