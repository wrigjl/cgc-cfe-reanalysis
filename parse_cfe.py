import re
import os
import json

HERE = os.path.dirname(os.path.abspath(__file__))
CB_LIST = os.path.join(HERE, "cfe-cbs.txt")
RAW_DIR = os.path.join(HERE, "cfe-raw")

def extract_team(html_fragment):
    """Extract team name from an <a> tag fragment."""
    m = re.search(r'/team/cfe/([^/]+)/', html_fragment)
    if m:
        return m.group(1)
    return None

def parse_cb(cb_name):
    filepath = os.path.join(RAW_DIR, f"{cb_name}.html")
    with open(filepath) as f:
        html = f.read()

    result = {
        "cb": cb_name,
        "patches": {},
        "original_exploited": False,
        "pov_details": [],
    }

    # --- Parse deployed patches ---
    # Pattern: "Round N : <a ...>TeamName</a>" in the "Deployed patches" section
    # Find the deployed patches section
    patch_idx = html.find("Deployed patches")
    if patch_idx < 0:
        patch_idx = html.find("Replacement Binary")
    
    if patch_idx >= 0:
        # Look from patches section to POV section (or end)
        pov_idx = html.find("pov_detail", patch_idx)
        if pov_idx < 0:
            pov_idx = len(html)
        patch_section = html[patch_idx:pov_idx]
        
        # Find all "Round N" followed by team link
        for m in re.finditer(r'Round\s+(\d+)\s*:\s*<a[^>]*/team/cfe/([^/]+)/', patch_section):
            round_num = int(m.group(1))
            team = m.group(2)
            if team not in result["patches"] or round_num < result["patches"][team]:
                result["patches"][team] = round_num

    # --- Parse POV table ---
    pov_table_idx = html.find('id="sorted1"')
    if pov_table_idx < 0:
        return result
    
    pov_html = html[pov_table_idx:]
    
    # Find all table rows in tbody
    tbody_idx = pov_html.find("<tbody>")
    if tbody_idx < 0:
        return result
    tbody_end = pov_html.find("</tbody>", tbody_idx)
    if tbody_end < 0:
        tbody_end = len(pov_html)
    tbody = pov_html[tbody_idx:tbody_end]
    
    # Extract rows
    rows = re.findall(r'<tr>(.*?)</tr>', tbody, re.DOTALL)
    
    for row in rows:
        cells = re.findall(r'<td[^>]*>(.*?)</td>', row, re.DOTALL)
        if len(cells) < 4:
            continue
        
        # Cell 0: Round number
        round_match = re.search(r'(\d+)', cells[0])
        if not round_match:
            continue
        round_num = int(round_match.group(1))
        
        # Cell 1: Source team
        source = extract_team(cells[1])
        # Cell 2: Destination team  
        dest = extract_team(cells[2])
        # Cell 3: Result
        result_text = re.sub(r'<[^>]+>', '', cells[3]).strip()
        
        if not source or not dest:
            continue
        
        is_success = "success" in result_text.lower() or result_text.strip() == "1"
        
        if is_success:
            first_patch = result["patches"].get(dest, 999)
            if round_num < first_patch:
                result["original_exploited"] = True
                result["pov_details"].append({
                    "round": round_num,
                    "source": source,
                    "dest": dest,
                })
    
    return result

# Load CB list
with open(CB_LIST) as f:
    cbs = [line.strip() for line in f if line.strip()]

all_results = []
exploited = []
not_exploited = []

for cb in cbs:
    try:
        r = parse_cb(cb)
        all_results.append(r)
        if r["original_exploited"]:
            exploited.append(r)
        else:
            not_exploited.append(r)
    except Exception as e:
        print(f"ERROR parsing {cb}: {e}")
        import traceback; traceback.print_exc()

print(f"Total CBs: {len(cbs)}")
print(f"Original binary exploited: {len(exploited)}")
print(f"Not exploited: {len(not_exploited)}")
print()
print("Exploited CBs:")
for r in exploited:
    teams = sorted(set(p["source"] for p in r["pov_details"]))
    print(f"  {r['cb']} — by {', '.join(teams)}")

# Save JSON
with open(os.path.join(HERE, "cfe-parse-results.json"), "w") as f:
    json.dump(all_results, f, indent=2, default=str)

