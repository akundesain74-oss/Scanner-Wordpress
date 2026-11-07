# ANDIKZZ WORDPRESS v9.0

Passive website and WordPress intelligence for systems you own or are authorized to assess.

## v9.0 changes — Anti-Guess System

### New: `modules/vulnerability/confidence.py`
- `ConfidenceScorer` assigns two scores to every finding:
  - **`data_quality`**: `synthetic` / `community` / `verified` — from the advisory source
  - **`scan_confidence`**: `low` / `medium` / `high` — from evidence strength in the scan
- Every finding includes an `anti_guess_note` explaining exactly why it was flagged

### New: `modules/vulnerability/wpscan_feed.py`
- Optional live pull from [WPScan Vulnerability Database](https://wpscan.com/api/v3)
- Set `WPSCAN_API_KEY` env var for authenticated tier (25 req/day free without key)
- Graceful fallback to local DB on any network/auth/rate-limit error — never crashes

### Updated: `modules/vulnerability/matcher.py`
- Passes context to `ConfidenceScorer` to derive scan confidence from fingerprint evidence
- Includes `source_url` in match results

### Updated: `modules/vulnerability/module.py`
- Fetches live WPScan data per observed slug before falling back to local DB
- Prints `⚠ ANTI-GUESS WARNING` to terminal when synthetic findings are present

### Updated: `output/html_report.py`
- Color-coded `data_quality` badges on every finding card
- Color-coded `scan_confidence` badges
- Red `SYNTHETIC` banner on findings from test fixtures

### Updated: `data/vulnerability/advisories.json`
- Added `"data_quality": "synthetic"` to all test fixtures

## Run
```bash
python main.py
```

For WPScan live data:
```bash
WPSCAN_API_KEY=your_token python main.py
```

Reports:
- `output/report.json`
- `output/report.html`

## Tests
```bash
python -m tests.run_all
```

## Use only on targets you own or have explicit permission to assess.
