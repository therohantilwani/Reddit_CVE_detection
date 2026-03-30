# Reddit CVE Detection

A Python-based tool to fetch and analyze CVE-related posts from Reddit using the releasetrain.io API. It extracts CVE identifiers, normalizes data, joins with NVD data, and provides an interactive HTML dashboard for vulnerability tracking.

## Features

- Fetches CVE-related Reddit posts from the releasetrain.io API
- Extracts CVE identifiers using regex across all post fields
- Generates normalized CSV files with timestamps and URLs
- Creates audit trails for CVE text locations
- Produces summary statistics (e.g., CVE counts, earliest post times)
- Enriches data with NVD (National Vulnerability Database) information
- **Interactive HTML dashboard** with:
  - Lead time analysis (Reddit vs NVD publication dates)
  - CVSS severity distribution charts
  - Subreddit breakdown
  - **Vendor/Company filtering** (Apple, Google, Linux, Docker, Microsoft, etc.)
  - Sortable and filterable CVE table
  - Direct links to Reddit posts

## Installation

1. **Clone the repository**:
   ```
   git clone https://github.com/therohantilwani/Reddit_CVE_detection.git
   cd Reddit_CVE_detection
   ```

2. **Set up a virtual environment**:
   ```
   python -m venv .venv
   # Activate: .venv\Scripts\Activate.ps1 (Windows) or source .venv/bin/activate (macOS/Linux)
   ```

3. **Install dependencies**:
   ```
   pip install -r requirements.txt
   ```

## Usage

1. **Fetch Reddit CVE data**:
   ```
   python cve.py
   ```
   This generates:
   - `reddit_cve_raw.json` (raw API data)
   - `reddit_cve_posts.csv` (normalized posts with CVE extractions)
   - `reddit_cve_key_audit.csv` (audit of CVE text locations)
   - `cve_summary.csv` (CVE statistics)

2. **Enrich with NVD data** (recommended):
   ```
   python nvd_join.py
   ```
   This generates:
   - `cve_lead_time.csv` (joined CVE data with NVD dates, CVSS scores, and vendor information)
   - `nvd_fetch_failures.csv` (CVEs that couldn't be fetched from NVD)

   **Note:** This script queries the NVD API and may take several minutes for large datasets. For better rate limits, set your NVD API key:
   ```
   export NVD_API_KEY="your_api_key"
   python nvd_join.py
   ```

3. **View dashboard**:
   ```
   python -m http.server 8501
   ```
   Then open **http://localhost:8501** in your browser.

## Dashboard Features

- **Lead Time Analysis**: See which CVEs were discussed on Reddit before official NVD listing
- **Filter by Vendor**: Filter CVEs by affected company/product (Apple, Google, Linux, Docker, Microsoft, etc.)
- **Severity Filters**: Filter by CVSS severity (Critical, High, Medium, Low)
- **Search**: Search by CVE ID or subreddit
- **Sortable Columns**: Click column headers to sort
- **Direct Links**: Click any CVE ID to go directly to the Reddit post

## Project Structure

```
├── cve.py                    # Main script for fetching Reddit CVE posts
├── nvd_join.py               # Script for joining with NVD data (adds vendors, CVSS scores)
├── index.html                # Interactive HTML dashboard
├── requirements.txt          # Python dependencies
├── reddit_cve_raw.json       # Raw API data (generated)
├── reddit_cve_posts.csv      # Normalized posts (generated)
├── reddit_cve_key_audit.csv  # CVE location audit (generated)
├── cve_summary.csv           # CVE statistics (generated)
├── cve_lead_time.csv         # Joined NVD data (generated)
└── nvd_fetch_failures.csv    # NVD fetch failures (generated)
```

## Dependencies

- Python 3.8+
- requests - HTTP library for API calls
- pandas - Data manipulation (optional, not required for core functionality)
- chart.js - Charts in dashboard (loaded via CDN)
- papaparse - CSV parsing in dashboard (loaded via CDN)

## Contributing

1. Fork the repository
2. Create a feature branch: `git checkout -b feature-name`
3. Commit changes: `git commit -m 'Add feature'`
4. Push to branch: `git push origin feature-name`
5. Open a Pull Request

## License



## Contact

Rohan Jagdish Tilwani (r_tilwani@u.pacific.edu)
