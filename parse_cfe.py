import re
import os
import json
import html as html_lib
from collections import Counter

HERE = os.path.dirname(os.path.abspath(__file__))
CB_LIST = os.path.join(HERE, "cfe-cbs.txt")
RAW_DIR = os.path.join(HERE, "cfe-raw")
CORPUS_DIR = os.environ.get(
    "CGC_CORPUS_DIR", os.path.join(HERE, "..", "cgc-challenge-corpus")
)

# Cross-CB CWE-id -> description lookup, populated from the LL archive HTML
# Known Vulnerabilities blocks as they are parsed. The cgccorpus README files
# also list CWE descriptions but in inconsistent formats across CB authors,
# whereas the LL HTML uses a uniform <a>CWE-NNN</a> - description pattern.
CWE_DESCRIPTIONS = {}

def extract_team(html_fragment):
    """Extract team name from an <a> tag fragment."""
    m = re.search(r'/team/cfe/([^/]+)/', html_fragment)
    if m:
        return m.group(1)
    return None

def collect_cwe_descriptions(html_text):
    """Update CWE_DESCRIPTIONS from a CB's LL archive Known Vulnerabilities block."""
    m = re.search(r'<h4>\s*Known Vulnerabilities\s*</h4>(.*?)</ul>',
                  html_text, re.DOTALL)
    if not m:
        return
    block = m.group(1)
    for am in re.finditer(
        r'<a href="http://cwe\.mitre\.org[^"]*">(CWE-\d+)</a>\s*-?\s*([^<]+)',
        block,
    ):
        cwe_id = am.group(1)
        desc = html_lib.unescape(am.group(2)).strip().rstrip('.').strip()
        if cwe_id not in CWE_DESCRIPTIONS:
            CWE_DESCRIPTIONS[cwe_id] = desc

def parse_corpus_cwes(cb_name):
    """Read CWE IDs from a CB's cgccorpus README, in order, deduped.

    The paper's CWE-distribution claims (Sec. 2.4, Sec. 4) use the
    cgc-challenge-corpus per-CB README files, where the *first-listed*
    CWE under "CWE classification" (or equivalent header --- CROMU,
    KPRCA, NRFIN, and CADET each use slightly different markup) is
    treated as the binary's primary classification. We extract the
    full list in order; the first element is the primary.

    Requires the cgc-challenge-corpus repo to be checked out at
    CORPUS_DIR (default: ../cgc-challenge-corpus, override via the
    CGC_CORPUS_DIR environment variable).
    """
    path = os.path.join(CORPUS_DIR, cb_name, "README.md")
    if not os.path.exists(path):
        return []
    with open(path) as f:
        text = f.read()
    seen = []
    for m in re.finditer(r'CWE-(\d+)', text):
        cwe_id = "CWE-" + m.group(1)
        if cwe_id not in seen:
            seen.append(cwe_id)
    return seen

def parse_cb(cb_name):
    filepath = os.path.join(RAW_DIR, f"{cb_name}.html")
    with open(filepath) as f:
        html = f.read()

    collect_cwe_descriptions(html)
    cwes = parse_corpus_cwes(cb_name)

    result = {
        "cb": cb_name,
        "primary_cwe": cwes[0] if cwes else None,
        "cwes": cwes,
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
    print(f"  {r['cb']} -- by {', '.join(teams)}")

# CWE distribution across all CBs and across the exploited subset.
# "primary" counts each CB once, by its first-listed CWE (the methodology
# matching Sec. 2.4 and Sec. 4 of the paper). "all" counts each CB once
# per distinct CWE it lists; percentages sum well over 100% because
# the typical CB lists ~2 CWEs.
def print_cwe_table(label, records, mode="primary"):
    total = len(records)
    counter = Counter()
    for r in records:
        if mode == "primary":
            if r["primary_cwe"]:
                counter[r["primary_cwe"]] += 1
        else:
            for c in r["cwes"]:
                counter[c] += 1
    print(f"\nCWE distribution across {total} {label} ({mode}):")
    if total == 0:
        return
    for cwe_id, count in counter.most_common():
        pct = 100.0 * count / total
        desc = CWE_DESCRIPTIONS.get(cwe_id, "")
        print(f"  {cwe_id:<8} {count:>3} CBs ({pct:5.1f}%)  {desc}")

cbs_without_cwes = [r["cb"] for r in all_results if not r["cwes"]]
if cbs_without_cwes:
    print(f"\nWARNING: {len(cbs_without_cwes)} CBs had no CWE classification in")
    print(f"  cgc-challenge-corpus (looked under {CORPUS_DIR}):")
    for cb in cbs_without_cwes:
        print(f"  {cb}")

distinct_primary = len({r["primary_cwe"] for r in all_results if r["primary_cwe"]})
print(f"\nDistinct primary CWEs across {len(all_results)} CBs: {distinct_primary}")

print_cwe_table("CBs (all)", all_results, mode="primary")
print_cwe_table("exploited CBs", exploited, mode="primary")

# Save JSON
with open(os.path.join(HERE, "cfe-parse-results.json"), "w") as f:
    json.dump(all_results, f, indent=2, default=str)

