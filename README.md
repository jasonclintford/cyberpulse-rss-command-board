# CyberPulse RSS Command Board

CyberPulse is a static cybersecurity RSS dashboard that runs entirely in the browser.
It aggregates security news and vulnerability feeds, groups stories by category, and includes a source-by-source page for reviewing each website individually.

## Features

- Static frontend only (`index.html`, `styles.css`, `app.js`)
- Cybersecurity-focused default feed catalog
- Dashboard view with:
  - Category sections
  - 24h activity pulse
  - Category load and threat keyword charts
  - EPSS watchlist
  - NVD CVE ingestion for vulnerability tracking
- Sources view with:
  - One card per website/feed
  - Source health state
  - Per-source expand/collapse
  - Source category filtering and search
- Browser persistence:
  - Cookie storage for feed configuration
  - `localStorage` fallback when cookie size is exceeded
- Feed config portability:
  - Export to JSON
  - Import from JSON

## Run Locally

```bash
cd static-rss-feed-bulletin-board
python3 -m http.server 4173
```

Open:

- `http://127.0.0.1:4173/#dashboard`
- `http://127.0.0.1:4173/#sources`

## Usage

1. Use **Refresh** to reload feeds and telemetry.
2. Use **Add Feed** to add a new RSS source and category.
3. Use **Dashboard/Sources** to switch between category view and website view.
4. Use **Export/Import** to move your feed configuration between browsers.

## Project Structure

- `index.html`: page layout and templates
- `styles.css`: visual design and responsive layout
- `app.js`: feed loading, parsing, state, rendering, and telemetry logic
