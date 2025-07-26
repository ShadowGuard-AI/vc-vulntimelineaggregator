# vc-VulnTimelineAggregator
A command-line tool that takes a list of vulnerability IDs or security event logs and aggregates relevant information from various sources (e.g., security blogs, threat intelligence feeds, vendor advisories) to create a chronological timeline of events related to each vulnerability. - Focused on Automated correlation of publicly available vulnerability information (CVEs, exploits) from various sources (NIST, ExploitDB, vendor advisories) with internal asset inventories (obtained from a simple CSV or JSON file). Generates reports highlighting assets with known vulnerabilities and prioritizes remediation based on exploit availability and CVSS scores.  Focus is on rapidly identifying and reporting high-risk vulnerabilities impacting specific assets.

## Install
`git clone https://github.com/ShadowGuardAI/vc-vulntimelineaggregator`

## Usage
`./vc-vulntimelineaggregator [params]`

## Parameters
- `-h`: Show help message and exit
- `-v`: No description provided
- `-a`: No description provided
- `-o`: No description provided
- `-e`: Search term to use when querying ExploitDB
- `-p`: Prioritize remediation based on CVSS scores and exploit availability.

## License
Copyright (c) ShadowGuardAI
