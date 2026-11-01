import argparse
import logging
import json
import csv
import requests
from bs4 import BeautifulSoup
import os
import re
import sys
from datetime import datetime

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Constants
NIST_BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
EXPLOITDB_URL = "https://www.exploit-db.com/"  # Can be improved with API if available

def setup_argparse():
    """
    Sets up the argument parser for the command-line interface.
    """
    parser = argparse.ArgumentParser(
        description="vc-VulnTimelineAggregator: Aggregates vulnerability information and creates timelines."
    )

    # Vulnerability ID input (CVE or list of CVEs)
    parser.add_argument(
        "-v", "--vulnerability_ids",
        nargs="+",
        help="List of vulnerability IDs (CVEs) to analyze. Example: CVE-2023-1234 CVE-2024-5678"
    )

    # Asset inventory file (CSV or JSON)
    parser.add_argument(
        "-a", "--asset_inventory",
        help="Path to the asset inventory file (CSV or JSON).  Required for asset-based reporting."
    )

    # Output file (optional)
    parser.add_argument(
        "-o", "--output_file",
        help="Path to the output file (e.g., report.txt or report.json)."
    )

    # ExploitDB Search Term
    parser.add_argument(
        "-e", "--exploitdb_search_term",
        help="Search term to use when querying ExploitDB"
    )

    # Prioritize Remediation
    parser.add_argument(
        "-p", "--prioritize",
        action="store_true",
        help="Prioritize remediation based on CVSS scores and exploit availability."
    )

    return parser.parse_args()


def load_asset_inventory(asset_inventory_file):
    """
    Loads the asset inventory from a CSV or JSON file.
    Supports both CSV and JSON formats.  Basic validation is included.
    :param asset_inventory_file: Path to the asset inventory file.
    :return: A dictionary representing the asset inventory, or None if an error occurs.
    """
    try:
        if asset_inventory_file.lower().endswith(".csv"):
            with open(asset_inventory_file, 'r') as csvfile:
                reader = csv.DictReader(csvfile)
                inventory = list(reader)  # Store all records as a list of dictionaries
                #Basic check for required keys
                if not inventory or not all(key in inventory[0] for key in ['hostname', 'ip_address']):
                    logging.error("Asset inventory CSV file is missing required columns (hostname, ip_address).")
                    return None

        elif asset_inventory_file.lower().endswith(".json"):
            with open(asset_inventory_file, 'r') as jsonfile:
                inventory = json.load(jsonfile)  # Expects a list of dictionaries
                #Basic check for required keys
                if not isinstance(inventory, list) or not all(isinstance(item, dict) for item in inventory) or \
                   not all(key in inventory[0] for key in ['hostname', 'ip_address']):
                    logging.error("Asset inventory JSON file must be a list of dictionaries and include hostname, ip_address.")
                    return None
        else:
            logging.error("Unsupported asset inventory file format. Only CSV and JSON are supported.")
            return None

        logging.info(f"Successfully loaded asset inventory from {asset_inventory_file}")
        return inventory
    except FileNotFoundError:
        logging.error(f"Asset inventory file not found: {asset_inventory_file}")
        return None
    except json.JSONDecodeError:
        logging.error(f"Error decoding JSON from asset inventory file: {asset_inventory_file}")
        return None
    except csv.Error as e:
         logging.error(f"Error reading CSV file: {asset_inventory_file} - {e}")
         return None
    except Exception as e:
        logging.error(f"An unexpected error occurred while loading the asset inventory: {e}")
        return None


def get_cve_details(cve_id):
    """
    Retrieves vulnerability details from the NIST NVD API.
    :param cve_id: The CVE ID to search for.
    :return: A dictionary containing the CVE details, or None if an error occurs.
    """
    try:
        url = f"{NIST_BASE_URL}?cveId={cve_id}"
        response = requests.get(url, timeout=30)
        response.raise_for_status()  # Raise HTTPError for bad responses (4xx or 5xx)

        data = response.json()

        # Check if the 'vulnerabilities' key exists and is a list
        if 'vulnerabilities' in data and isinstance(data['vulnerabilities'], list) and data['vulnerabilities']:
            cve_item = data['vulnerabilities'][0]['cve']
            return cve_item  # Return the cve detail if found
        else:
            logging.warning(f"CVE {cve_id} not found or invalid response format from NIST.")
            return None  # CVE not found or invalid format
    except requests.exceptions.RequestException as e:
        logging.error(f"Error fetching CVE details from NIST for {cve_id}: {e}")
        return None
    except json.JSONDecodeError:
        logging.error(f"Error decoding JSON response from NIST for {cve_id}")
        return None
    except Exception as e:
        logging.error(f"An unexpected error occurred while retrieving CVE details for {cve_id}: {e}")
        return None

_EXPLOITDB_CACHE = {}

def search_exploitdb(search_term):
    if search_term in _EXPLOITDB_CACHE:
        return _EXPLOITDB_CACHE[search_term]
    result = _search_exploitdb_uncached(search_term)
    _EXPLOITDB_CACHE[search_term] = result
    return result


def _search_exploitdb_uncached(search_term):
    """
    Searches ExploitDB for exploits related to the given search term.
    This implementation uses web scraping since there's no official ExploitDB API.
    :param search_term: The search term (e.g., CVE ID or vulnerability name).
    :return: A list of exploit URLs or an empty list if no exploits are found or an error occurs.
    """
    try:
        # Basic input validation to prevent injection
        if not re.match(r"^[a-zA-Z0-9\-_]+$", search_term):
            logging.warning(f"Invalid search term: {search_term}.  Only alphanumeric characters, hyphens, and underscores are allowed.")
            return []

        search_url = f"{EXPLOITDB_URL}?q={search_term}"
        response = requests.get(search_url, timeout=30)
        response.raise_for_status() # Raise HTTPError for bad responses

        soup = BeautifulSoup(response.content, 'html.parser')
        #The selecter for the exploit links might change.
        exploit_links = soup.select('a[href*="/exploits/"]')  # Adapt the selector based on ExploitDB's structure

        exploit_urls = []
        for link in exploit_links:
            href = link['href']
            if href.startswith("/"):
                exploit_urls.append(EXPLOITDB_URL + href[1:])
            else:
                exploit_urls.append(href)
        logging.info(f"Found {len(exploit_urls)} exploits for {search_term} on ExploitDB.")
        return exploit_urls

    except requests.exceptions.RequestException as e:
        logging.error(f"Error searching ExploitDB for {search_term}: {e}")
        return []
    except Exception as e:
        logging.error(f"An unexpected error occurred while searching ExploitDB for {search_term}: {e}")
        return []

def generate_timeline(cve_details):
    """
    Generates a chronological timeline of events related to a vulnerability.
    This function can be expanded to include more event sources.
    :param cve_details: A dictionary containing the CVE details from NIST.
    :return: A list of tuples, where each tuple contains a date and a description of the event.
    """
    timeline = []
    if not cve_details:
        return timeline
    published_date = None
    last_modified_date = None
    if 'published' in cve_details and cve_details['published']:
        published_date = datetime.fromisoformat(cve_details['published'].replace('Z', '+00:00'))
        timeline.append((published_date, "Vulnerability Published (NIST)"))
    if 'lastModified' in cve_details and cve_details['lastModified']:
        last_modified_date = datetime.fromisoformat(cve_details['lastModified'].replace('Z', '+00:00'))
        timeline.append((last_modified_date, "Vulnerability Last Modified (NIST)"))
    if 'descriptions' in cve_details and cve_details['descriptions']:
        description = cve_details['descriptions'][0]['value']
        event_date = published_date or last_modified_date
        if event_date is not None:
            timeline.append((event_date, f"Description: {description}"))
    timeline.sort(key=lambda x: x[0])
    return timeline


MAX_DESCRIPTION_CHARS = 500

def _cap_description(text):
    text = text or ""
    if len(text) > MAX_DESCRIPTION_CHARS:
        return text[:MAX_DESCRIPTION_CHARS] + " [truncated]"
    return text


def generate_report(vulnerability_data, asset_inventory, output_file, prioritize=False, asset_inventory_file=None):
    """Build the report once, sort the built entries if prioritized, and write it. Returns True on a written report."""
    if output_file and asset_inventory_file:
        if os.path.realpath(output_file) == os.path.realpath(asset_inventory_file):
            logging.error("Refusing to write the report over the asset inventory file.")
            return False
    entries = []
    exploit_cache = {}
    for cve_id, cve_details in (vulnerability_data or {}).items():
        if not cve_details:
            entries.append({'cve_id': cve_id, 'cve_details': None, 'score': 0.0, 'exploit_available': False})
            continue
        description = _cap_description(cve_details.get('descriptions', [{}])[0].get('value', 'No description available'))
        cvss_v3_severity = cvss_v2_severity = cvss_v3_score = cvss_v2_score = None
        metrics = cve_details.get('metrics', {})
        if metrics.get('cvssMetricV31'):
            d = metrics['cvssMetricV31'][0]['cvssData']; cvss_v3_severity, cvss_v3_score = d.get('baseSeverity'), d.get('baseScore')
        elif metrics.get('cvssMetricV30'):
            d = metrics['cvssMetricV30'][0]['cvssData']; cvss_v3_severity, cvss_v3_score = d.get('baseSeverity'), d.get('baseScore')
        elif metrics.get('cvssMetricV2'):
            d = metrics['cvssMetricV2'][0]['cvssData']; cvss_v2_severity, cvss_v2_score = d.get('baseSeverity'), d.get('baseScore')
        if cve_id not in exploit_cache:
            exploit_cache[cve_id] = search_exploitdb(cve_id)
        exploit_urls = exploit_cache[cve_id]
        affected = identify_affected_assets(cve_details, asset_inventory) if asset_inventory else []
        entries.append({'cve_id': cve_id, 'cve_details': cve_details, 'description': description,
                        'cvss_v3_severity': cvss_v3_severity, 'cvss_v3_score': cvss_v3_score,
                        'cvss_v2_severity': cvss_v2_severity, 'cvss_v2_score': cvss_v2_score,
                        'exploit_urls': exploit_urls, 'exploit_available': bool(exploit_urls),
                        'affected_assets': affected,
                        'recommendations': generate_remediation_recommendations(cve_details, affected),
                        'score': cvss_v3_score if cvss_v3_score else 0.0})
    if prioritize:
        entries.sort(key=lambda x: (x['score'], x['exploit_available']), reverse=True)
    report_lines = ["Prioritized Vulnerability Report:\n" if prioritize else "Vulnerability Report:\n"]
    if not entries:
        report_lines.append("No vulnerability data to report.")
    unmatchable = count_unmatchable_assets(asset_inventory) if asset_inventory else 0
    if asset_inventory is not None:
        report_lines.append(f"Assets with no matchable software, vendor, or product field: {unmatchable}")
    for e in entries:
        report_lines.append(f"CVE ID: {e['cve_id']}" + (" (PRIORITIZED)" if prioritize else ""))
        if not e['cve_details']:
            report_lines.append("  Could not retrieve CVE details.")
            report_lines.append("-" * 40); continue
        report_lines.append(f"  Description: {e['description']}")
        report_lines.append(f"  CVSS v3 Severity: {e['cvss_v3_severity']}, Score: {e['cvss_v3_score']}")
        report_lines.append(f"  CVSS v2 Severity: {e['cvss_v2_severity']}, Score: {e['cvss_v2_score']}")
        if e['exploit_urls']:
            report_lines.append("  Exploits Available:")
            for url in e['exploit_urls']:
                report_lines.append(f"    - {url}")
        else:
            report_lines.append("  No exploits found on ExploitDB.")
        if e['affected_assets']:
            report_lines.append("  Affected Assets:")
            for asset in e['affected_assets']:
                report_lines.append(f"    - Hostname: {asset['hostname']}, IP Address: {asset['ip_address']}")
        else:
            report_lines.append("  No affected assets identified based on current matching logic.")
        if e['recommendations']:
            report_lines.append("  Remediation Recommendations:")
            for r in e['recommendations']:
                report_lines.append(f"    - {_cap_description(r)}")
        else:
            report_lines.append("  No specific remediation recommendations available.")
        report_lines.append("-" * 40)
    if not output_file:
        for line in report_lines:
            print(line)
        return True
    try:
        with open(output_file, 'w') as f:
            for line in report_lines:
                f.write(line + '\n')
        logging.info(f"Report generated and saved to {output_file}")
        return True
    except Exception as ex:
        logging.error(f"Error writing report to file: {ex}")
        return False


def count_unmatchable_assets(asset_inventory):
    count = 0
    for asset in asset_inventory or []:
        usable = False
        for field in ('software', 'vendor', 'product'):
            v = asset.get(field)
            if isinstance(v, str) and len(v.strip()) >= 4:
                usable = True
        if not usable:
            count += 1
    return count


def identify_affected_assets(cve_details, asset_inventory):
    """
    Identifies assets affected by a given vulnerability based on the asset inventory.
    This is a placeholder and requires a more sophisticated implementation based on the
    specifics of your asset inventory and vulnerability information.

    :param cve_details: The CVE details dictionary.
    :param asset_inventory: The asset inventory dictionary.
    :return: A list of assets (dictionaries) that are potentially affected by the vulnerability.
    """

    if not asset_inventory:
        logging.warning("Asset inventory is empty.  Cannot identify affected assets.")
        return []

    affected_assets = []
    description = cve_details.get('descriptions', [{}])[0].get('value', '').lower()
    named_fields = ('software', 'vendor', 'product', 'hostname')
    for asset in asset_inventory:
        matched = False
        for field in named_fields:
            value = asset.get(field)
            if not isinstance(value, str):
                continue
            value = value.strip().lower()
            if len(value) < 4:
                continue
            if value in description:
                matched = True
                break
        if matched:
            affected_assets.append(asset)
    return affected_assets


def generate_remediation_recommendations(cve_details, affected_assets):
    """
    Generates remediation recommendations based on the vulnerability details and affected assets.
    This is a placeholder and requires a more sophisticated implementation based on the specifics
    of your environment and vulnerability information.

    :param cve_details: The CVE details dictionary.
    :param affected_assets: A list of affected assets (dictionaries).
    :return: A list of remediation recommendations (strings).
    """
    recommendations = []

    if not affected_assets:
        recommendations.append("No specific remediation recommendations available as no assets are identified.")
        return recommendations

    # Simple example: Suggest patching or upgrading the affected software
    description = cve_details.get('descriptions', [{}])[0].get('value', '') #Get description
    recommendations.append(f"Review the vulnerability description: {description}")

    #Check if any specific vendor advisory is available
    if 'references' in cve_details:
      for ref in cve_details['references']:
        if 'url' in ref and "advisory" in ref['url'].lower():
          recommendations.append(f"Consult the following vendor advisory: {ref['url']}")
          break #Only add the first advisory

    recommendations.append("Apply the latest security patches or upgrade to a secure version of the affected software.")

    return recommendations

def main():
    """
    Main function to execute the vulnerability timeline aggregator.
    """
    args = setup_argparse()

    if not args.vulnerability_ids:
        logging.error("Please provide at least one vulnerability ID using the -v or --vulnerability_ids option.")
        sys.exit(1)

    if args.output_file and args.asset_inventory and os.path.realpath(args.output_file) == os.path.realpath(args.asset_inventory):
        logging.error("Refusing to write the report over the asset inventory file.")
        sys.exit(1)

    vulnerability_data = {}

    for cve_id in args.vulnerability_ids:
        cve_details = get_cve_details(cve_id)
        if cve_details:
            vulnerability_data[cve_id] = cve_details
            timeline = generate_timeline(cve_details)
            logging.info(f"Timeline for {cve_id}:")
            for date, event in timeline:
                logging.info(f"  {date}: {event}")
        else:
            logging.warning(f"Could not retrieve details for {cve_id}.")

    if not vulnerability_data:
        logging.error("No CVE records were retrieved; no report can be generated.")
        sys.exit(1)

    asset_inventory = None
    if args.asset_inventory:
        asset_inventory = load_asset_inventory(args.asset_inventory)
        if asset_inventory is None:
            logging.error("Asset inventory could not be loaded.")
            sys.exit(1)

    if args.output_file:
        ok = generate_report(vulnerability_data, asset_inventory, args.output_file, args.prioritize, asset_inventory_file=args.asset_inventory)
        if not ok:
            sys.exit(1)
    elif args.asset_inventory:
        ok = generate_report(vulnerability_data, asset_inventory, "vulnerability_report.txt", args.prioritize, asset_inventory_file=args.asset_inventory)
        if not ok:
            sys.exit(1)
    else:
        logging.info("Vulnerability data retrieved; no output file requested, timelines above are the result.")

    if args.exploitdb_search_term:
        exploits = search_exploitdb(args.exploitdb_search_term)
        if exploits:
            logging.info(f"Exploits found for {args.exploitdb_search_term}:")
            for exploit_url in exploits:
                logging.info(f"  - {exploit_url}")
        else:
            logging.info(f"No exploits found for {args.exploitdb_search_term}.")

#Example usage
if __name__ == "__main__":
    # Example Usage:
    #   python main.py -v CVE-2023-1234 CVE-2024-5678 -a assets.csv -o report.txt
    #   python main.py -v CVE-2023-1234 -e "vulnerability name"
    #   python main.py -v CVE-2023-1234 -a assets.json -p  #Prioritize remediation

    main()