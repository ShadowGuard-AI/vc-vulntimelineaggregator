# vc-VulnTimelineAggregator
A command-line tool that takes a list of vulnerability IDs (CVEs), fetches their records from the NIST NVD, searches ExploitDB for related exploits, and logs a chronological timeline of each vulnerability's published and last modified dates. With an asset inventory (a CSV or JSON file listing assets with hostname and ip_address, plus optional software, vendor, or product fields), it generates a report highlighting assets whose named fields appear in a CVE description, and can prioritize remediation based on CVSS scores (v3 when present, otherwise v2) and exploit availability. CVEs that could not be retrieved are listed in the report as such when at least one other CVE was retrieved; if none could be retrieved, the run exits non-zero. Every row of an asset inventory must carry hostname and ip_address, and an empty inventory file is rejected.

## Install
`git clone https://github.com/ShadowGuard-AI/vc-vulntimelineaggregator`

## Usage
`python3 main.py -v CVE-2023-1234 [CVE-...] [-a <assets.csv|assets.json>] [-o <report file>] [-e <search term>] [-p]`

## Parameters
- `-h`: Show help message and exit
- `-v`: List of vulnerability IDs (CVEs) to analyze.
- `-a`: Path to the asset inventory file (CSV or JSON). With no `-o`, the report is written to vulnerability_report.txt.
- `-o`: Path to the output report file.
- `-e`: Search term to use when querying ExploitDB
- `-p`: Prioritize remediation based on CVSS scores and exploit availability.

## License
MIT. See LICENSE.
