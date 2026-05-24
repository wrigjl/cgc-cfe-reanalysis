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

def parse_rounds_enabled(html_text):
    """Extract the list of competition rounds a CB was enabled in.

    The Rounds Enabled <h4> block in the LL archive HTML contains a
    comma-separated sequence of <a href="/cgc/cgc-corpus/round/N/">N</a>
    links. The window is contiguous in every CFE binary we have seen
    (typically 15 rounds wide), so the list and (last-first+1) agree;
    we return the explicit list to preserve the raw record.
    """
    m = re.search(r'<h4>\s*Rounds Enabled\s*</h4>(.*?)<h4',
                  html_text, re.DOTALL)
    if not m:
        return []
    block = m.group(1)
    return sorted({int(rm.group(1))
                   for rm in re.finditer(r'/round/(\d+)/', block)})

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
    rounds_enabled = parse_rounds_enabled(html)

    result = {
        "cb": cb_name,
        "primary_cwe": cwes[0] if cwes else None,
        "cwes": cwes,
        "rounds_enabled": rounds_enabled,
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

# Timing analysis: how soon after enablement was each exploited CB
# cracked, both in absolute rounds and as a fraction of its enabled
# window? Backs Sec. 4 claims: "Half of the exploited binaries were
# cracked within five rounds of deployment; the rest [...] within
# the first third of their enabled window."
def timing_for(r):
    if not r["pov_details"] or not r["rounds_enabled"]:
        return None
    first_enabled = min(r["rounds_enabled"])
    first_pov = min(p["round"] for p in r["pov_details"])
    window = len(r["rounds_enabled"])
    rounds_in = first_pov - first_enabled  # 0-indexed: 0 = same round as deploy
    return {
        "cb": r["cb"],
        "first_enabled": first_enabled,
        "first_pov": first_pov,
        "window": window,
        "rounds_in": rounds_in,
        "frac_in": rounds_in / window if window else None,
    }

timings = [t for t in (timing_for(r) for r in exploited) if t]
timings.sort(key=lambda t: t["rounds_in"])

print("\nTiming for exploited CBs (rounds_in = first POV round - first enabled round):")
print(f"  {'CB':<14} {'enabled':>8} {'first_pov':>10} {'window':>7} {'rounds_in':>10} {'frac_in':>8}")
for t in timings:
    print(f"  {t['cb']:<14} {t['first_enabled']:>8} {t['first_pov']:>10} "
          f"{t['window']:>7} {t['rounds_in']:>10} {t['frac_in']:>8.2f}")

if timings:
    in5 = [t for t in timings if t["rounds_in"] <= 5]
    in_third = [t for t in timings if t["frac_in"] <= 1/3]
    print(f"\n  exploited within 5 rounds of deployment: {len(in5)}/{len(timings)}"
          f" ({100*len(in5)/len(timings):.1f}%)")
    print(f"  exploited within first third of enabled window: "
          f"{len(in_third)}/{len(timings)} "
          f"({100*len(in_third)/len(timings):.1f}%)")
    rounds_in_list = [t["rounds_in"] for t in timings]
    sorted_ri = sorted(rounds_in_list)
    n = len(sorted_ri)
    median = (sorted_ri[n//2] if n % 2 else (sorted_ri[n//2 - 1] + sorted_ri[n//2]) / 2)
    print(f"  median rounds_in among exploited: {median}")
    print(f"  max rounds_in among exploited: {max(rounds_in_list)}")

ne_with_window = [r for r in not_exploited if r["rounds_enabled"]]
if ne_with_window:
    windows = [len(r["rounds_enabled"]) for r in ne_with_window]
    print(f"\nNon-exploited CBs: {len(ne_with_window)} had enabled windows "
          f"(min/median/max window = {min(windows)}/"
          f"{sorted(windows)[len(windows)//2]}/{max(windows)} rounds); "
          f"none were exploited regardless of window length.")

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

