# cgc-cfe-reanalysis

Reanalysis of the DARPA Cyber Grand Challenge Cyber Final Event (CFE)
archive, supporting empirical claims in Wright, "The Cognition Gap:
What the Cyber Grand Challenge Revealed About Autonomous Cyber
Reasoning" (IEEE Security & Privacy magazine, 2026 submission).

## What this reproduces

The scripts here pull two sources together:

1. The MIT Lincoln Laboratory CFE archive HTML, for per-round deployed
   patches and successful proof-of-vulnerability (POV) outcomes.
2. The `cgc-challenge-corpus` per-CB README files, for each CB's CWE
   classification.

These are joined so that for every CB we know whether its *original*
shipped version was exploited (before the defender's first patch),
which teams exploited it, and its primary CWE classification.

Paper claims fully reproduced by `cfe-parse-results.json`:

- Section 4: "of the 82 challenge sets fielded in the final event,
  competitors produced working proofs of vulnerability for only 20" ---
  count of CBs where `original_exploited` is `true`.
- Section 4: "the most prolific attacker exploited 15 of 82 original
  binaries, while one finalist exploited none at all." --- aggregate
  of `pov_details[*].source` per CB.
- Section 2.4: "the 82 challenge sets [...] spanned 29 distinct CWE
  vulnerability categories" --- count of distinct values of
  `primary_cwe` across the corpus.
- Section 2.4: "stack-based buffer overflows (CWE-121) alone accounted
  for roughly a fifth of the challenges" --- 19 of 82 CBs (23.2%) have
  `primary_cwe == "CWE-121"`.
- Section 4: "the 20 exploited binaries were dominated by classic
  memory corruption" --- the distribution of `primary_cwe` across CBs
  where `original_exploited` is `true` is concentrated in CWE-121,
  CWE-122, CWE-119, CWE-120, CWE-131, CWE-193, CWE-125, CWE-126,
  CWE-135, CWE-788, and CWE-190 (17 of 20 exploited CBs).
- Section 4 timing framings --- each CB's enabled-window
  (`rounds_enabled`) is now extracted from the LL archive HTML and
  the script computes `rounds_in = first_pov_round -
  first_enabled_round` and `frac_in = rounds_in / window` per
  exploited CB. The summary tallies how many exploited CBs were
  cracked within five rounds of deployment and within the first
  third of their enabled window, and confirms that the 62
  non-exploited CBs were never exploited regardless of window
  length. The reproduced numbers match the paper's Section 4 timing
  claims: 13 of 20 exploited CBs (two-thirds) fell within five
  rounds of deployment, the longest-lived exploited CB held out for
  13 rounds, and the 62 never-exploited CBs had enabled windows of
  15--25 rounds.

## Reproduce

```
./fetch_cfe.sh          # downloads cfe-raw/{CB}.html for all 82 binaries
python3 parse_cfe.py    # prints summary, writes cfe-parse-results.json
```

The fetch is idempotent: `fetch_cfe.sh` only downloads pages it does
not already have in `cfe-raw/`.

`parse_cfe.py` also reads `../cgc-challenge-corpus/<CB>/README.md` for
CWE classifications. Override the corpus path with
`CGC_CORPUS_DIR=/path/to/corpus python3 parse_cfe.py` if the corpus
lives elsewhere.

## Dependencies

- POSIX shell with `curl` (for `fetch_cfe.sh`)
- Python 3.6+ standard library (for `parse_cfe.py`; no third-party
  packages required)
- A local checkout of `cgc-challenge-corpus` from
  <https://github.com/CyberGrandChallenge/>, expected at
  `../cgc-challenge-corpus` by default
- Roughly 5 MB of disk for the raw HTML cache

## Files

| Path | Description |
|---|---|
| `cfe-cbs.txt` | 82 CFE final-event challenge binary names, one per line |
| `fetch_cfe.sh` | Downloads each CB's HTML page from `archive.ll.mit.edu/cgc/cgc-corpus/challenges/<CB>/` |
| `parse_cfe.py` | Parses HTML and corpus READMEs, writes JSON |
| `cfe-raw/` | (generated) per-CB HTML pages from the LL archive |
| `cfe-parse-results.json` | (generated) structured per-CB results |

## Output schema

`cfe-parse-results.json` is a list of records, one per CB:

```
{
  "cb": "CROMU_00046",
  "primary_cwe": "CWE-119",
  "cwes": ["CWE-119"],
  "rounds_enabled": [52, 53, 54, ..., 66],
  "patches": { "<team>": <first_patch_round>, ... },
  "original_exploited": true,
  "pov_details": [
    { "round": 58, "source": "<attacker>", "dest": "<defender>" },
    ...
  ]
}
```

- `primary_cwe` is the first CWE listed in the CB's cgccorpus README
  (the methodology that matches the paper's Section 2.4 / Section 4
  CWE-distribution claims).
- `cwes` is the full ordered, deduplicated list of CWE IDs that appear
  in the CB's cgccorpus README; the typical CB lists ~2.
- `rounds_enabled` is the sorted list of competition rounds during
  which this CB was active. Windows are contiguous in every CFE
  binary observed and run 15--25 rounds; `min(rounds_enabled)` is
  the deployment round.
- Only POVs that landed *before* the defender's first patch in
  `patches` are included in `pov_details`; later POVs against patched
  binaries are excluded so that `original_exploited` reflects
  exploitability of the shipped binary rather than of any later
  replacement.

## Source data and stability

The CFE archive is hosted by MIT Lincoln Laboratory at
<https://archive.ll.mit.edu/cgc/>. The original competition binaries
and scoring data, including per-CB README files with CWE classifications,
are mirrored at <https://github.com/CyberGrandChallenge/>. If MIT LL
changes the archive HTML layout, the regex extraction in `parse_cfe.py`
will need updating; the cgccorpus mirror is more stable.
