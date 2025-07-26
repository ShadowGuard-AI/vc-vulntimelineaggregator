import argparse
import logging
import json
import csv
import requests
from bs4 import BeautifulSoup
import pandas as pd
import os
import re
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
        response = requests.get(url)
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

def search_exploitdb(search_term):
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

        search_url = f"{EXPLOITDB_URL}?q={search_term}"  # Construct the search URL
        response = requests.get(search_url)
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

    # Add initial discovery date from NIST
    if 'published' in cve_details:
        published_date = datetime.fromisoformat(cve_details['published'].replace('Z', '+00:00'))
        timeline.append((published_date, f"Vulnerability Published (NIST)"))

    # Add last modified date from NIST
    if 'lastModified' in cve_details:
        last_modified_date = datetime.fromisoformat(cve_details['lastModified'].replace('Z', '+00:00'))
        timeline.append((last_modified_date, f"Vulnerability Last Modified (NIST)"))

    # Add description
    if 'descriptions' in cve_details and cve_details['descriptions']:
      description = cve_details['descriptions'][0]['value']
      timeline.append((published_date, f"Description: {description}"))

    timeline.sort(key=lambda x: x[0])  # Sort by date
    return timeline


def generate_report(vulnerability_data, asset_inventory, output_file, prioritize=False):
    """
    Generates a report of vulnerabilities, affected assets, and remediation recommendations.

    :param vulnerability_data: A dictionary where keys are CVE IDs and values are CVE details.
    :param asset_inventory:  A list of dictionaries containing asset information.
    :param output_file: The path to the output file.
    :param prioritize: Boolean value to indicate prioritization of remediation.
    :return: None
    """
    report_lines = []

    if not vulnerability_data:
        report_lines.append("No vulnerability data to report.")
    else:
        report_lines.append("Vulnerability Report:\n")

        # Prepare a list to hold data for prioritization
        vulnerability_list = []

        for cve_id, cve_details in vulnerability_data.items():
            report_lines.append(f"CVE ID: {cve_id}")
            if cve_details:
                # Extract relevant information from CVE details
                description = cve_details.get('descriptions', [{}])[0].get('value', 'No description available')
                cvss_v3_severity = None
                cvss_v2_severity = None
                cvss_v3_score = None
                cvss_v2_score = None

                if 'metrics' in cve_details:
                    if 'cvssMetricV31' in cve_details['metrics'] and cve_details['metrics']['cvssMetricV31']:
                        cvss_v3_severity = cve_details['metrics']['cvssMetricV31'][0]['cvssData']['baseSeverity']
                        cvss_v3_score = cve_details['metrics']['cvssMetricV31'][0]['cvssData']['baseScore']
                    elif 'cvssMetricV30' in cve_details['metrics'] and cve_details['metrics']['cvssMetricV30']:
                        cvss_v3_severity = cve_details['metrics']['cvssMetricV30'][0]['cvssData']['baseSeverity']
                        cvss_v3_score = cve_details['metrics']['cvssMetricV30'][0]['cvssData']['baseScore']
                    elif 'cvssMetricV2' in cve_details['metrics'] and cve_details['metrics']['cvssMetricV2']:
                        cvss_v2_severity = cve_details['metrics']['cvssMetricV2'][0]['cvssData']['baseSeverity']
                        cvss_v2_score = cve_details['metrics']['cvssMetricV2'][0]['cvssData']['baseScore']

                report_lines.append(f"  Description: {description}")
                report_lines.append(f"  CVSS v3 Severity: {cvss_v3_severity}, Score: {cvss_v3_score}")
                report_lines.append(f"  CVSS v2 Severity: {cvss_v2_severity}, Score: {cvss_v2_score}")

                # Search ExploitDB
                exploit_urls = search_exploitdb(cve_id)
                if exploit_urls:
                    report_lines.append("  Exploits Available:")
                    for url in exploit_urls:
                        report_lines.append(f"    - {url}")
                else:
                    report_lines.append("  No exploits found on ExploitDB.")


                # Identify affected assets (placeholder - needs actual logic)
                affected_assets = identify_affected_assets(cve_details, asset_inventory) #Placeholder

                if affected_assets:
                    report_lines.append("  Affected Assets:")
                    for asset in affected_assets:
                        report_lines.append(f"    - Hostname: {asset['hostname']}, IP Address: {asset['ip_address']}")
                else:
                    report_lines.append("  No affected assets identified based on current matching logic.")


                # Remediation recommendations (placeholder - needs actual logic)
                remediation_recommendations = generate_remediation_recommendations(cve_details, affected_assets) #Placeholder

                if remediation_recommendations:
                    report_lines.append("  Remediation Recommendations:")
                    for recommendation in remediation_recommendations:
                        report_lines.append(f"    - {recommendation}")
                else:
                    report_lines.append("  No specific remediation recommendations available.")

                report_lines.append("-" * 40)

                # Add to the list for prioritization
                vulnerability_list.append({
                    'cve_id': cve_id,
                    'cve_details': cve_details,
                    'cvss_v3_score': cvss_v3_score if cvss_v3_score else 0.0, #Use a default value
                    'exploit_available': bool(exploit_urls),
                    'affected_assets': affected_assets
                })


            else:
                report_lines.append("  Could not retrieve CVE details.")
                report_lines.append("-" * 40)

        # Prioritize if requested
        if prioritize:
            # Sort by CVSS score (highest first) and then by exploit availability (True first)
            vulnerability_list.sort(key=lambda x: (x['cvss_v3_score'], x['exploit_available']), reverse=True)
            report_lines = ["Prioritized Vulnerability Report:\n"]  # Reset report lines

            for vuln in vulnerability_list:
                cve_id = vuln['cve_id']
                cve_details = vuln['cve_details']

                report_lines.append(f"CVE ID: {cve_id} (PRIORITIZED)") #Mark it as prioritized
                # Extract relevant information from CVE details
                description = cve_details.get('descriptions', [{}])[0].get('value', 'No description available')
                cvss_v3_severity = None
                cvss_v2_severity = None
                cvss_v3_score = None
                cvss_v2_score = None

                if 'metrics' in cve_details:
                    if 'cvssMetricV31' in cve_details['metrics'] and cve_details['metrics']['cvssMetricV31']:
                        cvss_v3_severity = cve_details['metrics']['cvssMetricV31'][0]['cvssData']['baseSeverity']
                        cvss_v3_score = cve_details['metrics']['cvssMetricV31'][0]['cvssData']['baseScore']
                    elif 'cvssMetricV30' in cve_details['metrics'] and cve_details['metrics']['cvssMetricV30']:
                        cvss_v3_severity = cve_details['metrics']['cvssMetricV30'][0]['cvssData']['baseSeverity']
                        cvss_v3_score = cve_details['metrics']['cvssMetricV30'][0]['cvssData']['baseScore']
                    elif 'cvssMetricV2' in cve_details['metrics'] and cve_details['metrics']['cvssMetricV2']:
                        cvss_v2_severity = cve_details['metrics']['cvssMetricV2'][0]['cvssData']['baseSeverity']
                        cvss_v2_score = cve_details['metrics']['cvssMetricV2'][0]['cvssData']['baseScore']

                report_lines.append(f"  Description: {description}")
                report_lines.append(f"  CVSS v3 Severity: {cvss_v3_severity}, Score: {cvss_v3_score}")
                report_lines.append(f"  CVSS v2 Severity: {cvss_v2_severity}, Score: {cvss_v2_score}")


                # Search ExploitDB
                exploit_urls = search_exploitdb(cve_id) # Redundant but keeps output complete
                if exploit_urls:
                    report_lines.append("  Exploits Available:")
                    for url in exploit_urls:
                        report_lines.append(f"    - {url}")
                else:
                    report_lines.append("  No exploits found on ExploitDB.")

                # Identify affected assets
                affected_assets = identify_affected_assets(cve_details, asset_inventory)  # Placeholder

                if affected_assets:
                    report_lines.append("  Affected Assets:")
                    for asset in affected_assets:
                        report_lines.append(f"    - Hostname: {asset['hostname']}, IP Address: {asset['ip_address']}")
                else:
                    report_lines.append("  No affected assets identified based on current matching logic.")

                # Remediation recommendations
                remediation_recommendations = generate_remediation_recommendations(cve_details, affected_assets)  # Placeholder

                if remediation_recommendations:
                    report_lines.append("  Remediation Recommendations:")
                    for recommendation in remediation_recommendations:
                        report_lines.append(f"    - {recommendation}")
                else:
                    report_lines.append("  No specific remediation recommendations available.")

                report_lines.append("-" * 40)


    # Write the report to the output file
    try:
        with open(output_file, 'w') as f:
            for line in report_lines:
                f.write(line + '\n')
        logging.info(f"Report generated and saved to {output_file}")
    except Exception as e:
        logging.error(f"Error writing report to file: {e}")



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

    # Simple example: Check if the CVE description mentions a software or vendor
    # present in the asset inventory.  This is a very basic approach.
    description = cve_details.get('descriptions', [{}])[0].get('value', '').lower() #Lower case for case-insensitive matching
    for asset in asset_inventory:
        hostname = asset.get('hostname', '').lower() #Lower case for case-insensitive matching
        ip_address = asset.get('ip_address', '')

        if hostname in description or any(software.lower() in description for software in asset.values() if isinstance(software, str)):
            affected_assets.append(asset) #Adding the full asset dictionary

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
        return

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

    asset_inventory = None
    if args.asset_inventory:
        asset_inventory = load_asset_inventory(args.asset_inventory)


    if args.asset_inventory and vulnerability_data:
        if not asset_inventory:
            logging.error("Asset inventory could not be loaded, skipping report generation.")
        else:
           generate_report(vulnerability_data, asset_inventory, args.output_file or "vulnerability_report.txt", args.prioritize)
    elif args.asset_inventory and not vulnerability_data:
        logging.warning("Asset inventory provided, but no vulnerability data. Skipping report generation.")
    elif not args.asset_inventory and vulnerability_data:
        logging.info("Vulnerability data available, but no asset inventory provided.  Skipping asset-based reporting.")

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