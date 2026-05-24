# cgc-cfe-reanalysis

Reanalysis of the DARPA Cyber Grand Challenge Cyber Final Event (CFE)
archive, supporting empirical claims in Wright, "The Cognition Gap:
What the Cyber Grand Challenge Revealed About Autonomous Cyber
Reasoning" (IEEE Security & Privacy magazine, 2026 submission).

## What this reproduces

The scripts here download per-CB HTML pages from the MIT Lincoln
Laboratory CFE archive, extract deployed patches and successful
proof-of-vulnerability (POV) outcomes per round, and join the two to
flag binaries whose *original* shipped version was exploited before
the defender's first patch.

Paper claims fully reproduced by `cfe-parse-results.json`:

- Section 4: "of the 82 challenge sets fielded in the final event,
  competitors produced working proofs of vulnerability for only 20" ---
  count of CBs where `original_exploited` is `true`.
- Section 4: "the most prolific attacker exploited 15 of 82 original
  binaries, while one finalist exploited none at all." --- aggregate
  of `pov_details[*].source` per CB.

Partially reproduced (raw inputs here, additional analysis required):

- Section 4 timing claims ("Half of the exploited binaries were
  cracked within five rounds of deployment; the rest [...] within
  the first third of their enabled window") --- round of first
  successful POV per CB is in `pov_details[*].round`, but the
  "rounds of deployment" and "enabled window" framings require
  joining against each CB's enablement timeline. That step is not
  yet automated here.
- Sections 2.4 and 4 CWE-distribution claims ("stack-based buffer
  overflows alone accounted for roughly a fifth of the challenges";
  "the 20 exploited binaries were dominated by classic memory
  corruption") --- require cross-referencing CB names against each
  CB's CWE classification from the cgccorpus README files at
  <https://github.com/CyberGrandChallenge/>. That join is also not
  yet automated here.

## Reproduce

```
./fetch_cfe.sh          # downloads cfe-raw/{CB}.html for all 82 binaries
python3 parse_cfe.py    # prints summary, writes cfe-parse-results.json
```

The fetch is idempotent: `fetch_cfe.sh` only downloads pages it does
not already have in `cfe-raw/`.

## Dependencies

- POSIX shell with `curl` (for `fetch_cfe.sh`)
- Python 3.6+ standard library (for `parse_cfe.py`; no third-party
  packages required)
- Roughly 5 MB of disk for the raw HTML cache

## Files

| Path | Description |
|---|---|
| `cfe-cbs.txt` | 82 CFE final-event challenge binary names, one per line |
| `fetch_cfe.sh` | Downloads each CB's HTML page from `archive.ll.mit.edu/cgc/cgc-corpus/challenges/<CB>/` |
| `parse_cfe.py` | Parses HTML, extracts patches and POVs, writes JSON |
| `cfe-raw/` | (generated) per-CB HTML pages from the LL archive |
| `cfe-parse-results.json` | (generated) structured per-CB results |

## Output schema

`cfe-parse-results.json` is a list of records, one per CB:

```
{
  "cb": "CROMU_00046",
  "patches": { "<team>": <first_patch_round>, ... },
  "original_exploited": true,
  "pov_details": [
    { "round": 12, "source": "<attacker>", "dest": "<defender>" },
    ...
  ]
}
```

Only POVs that landed *before* the defender's first patch in `patches`
are included in `pov_details`; later POVs against patched binaries are
excluded so that `original_exploited` reflects exploitability of the
shipped binary rather than of any later replacement.

## Source data and stability

The CFE archive is hosted by MIT Lincoln Laboratory at
<https://archive.ll.mit.edu/cgc/>. The original competition binaries
and scoring data are also mirrored at
<https://github.com/CyberGrandChallenge/>. `parse_cfe.py` parses the
LL archive's rendered HTML; if MIT LL changes the page layout, the
regex extraction in `parse_cfe.py` will need updating. The GitHub
mirror is more stable for raw artifacts but does not include the
rendered per-round scoring view this script depends on.
