# Reddit CVE Detection

A Python-based tool to fetch and analyze CVE-related posts from Reddit using the releasetrain.io API. It extracts CVE identifiers, normalizes data, and generates summaries for vulnerability tracking.

## Features

- Fetches CVE-related Reddit posts from the releasetrain.io API
- Extracts CVE identifiers using regex
- Generates normalized CSV files with timestamps and URLs
- Creates audit trails for CVE text locations
- Produces summary statistics (e.g., CVE counts, earliest post times)
- Includes an HTML dashboard for data visualization
- Supports joining with NVD (National Vulnerability Database) data for enriched analysis

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

2. **Enrich with NVD data** (optional):
   ```
   python nvd_join.py
   ```
   This may generate additional files like `cve_lead_time.csv` and `nvd_fetch_failures.csv`.

3. **View results**:
   Open `index.html` in your web browser to visualize the data.

## Dependencies

- Python 3.8+
- Libraries listed in `requirements.txt` (e.g., `requests`)

## Project Structure

- `cve.py`: Main script for fetching and processing Reddit CVE posts
- `nvd_join.py`: Script for joining with NVD data
- `index.html`: HTML dashboard for data visualization
- `requirements.txt`: Python dependencies
- Data files: Various CSV/JSON outputs from the scripts

## Contributing

1. Fork the repository
2. Create a feature branch: `git checkout -b feature-name`
3. Commit changes: `git commit -m 'Add feature'`
4. Push to branch: `git push origin feature-name`
5. Open a Pull Request

## License


## Contact

Rohan Jagdish Tilwani (r_tilwani@u.pacific.edu)
