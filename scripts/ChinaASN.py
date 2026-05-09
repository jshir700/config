'''
Generate ChinaASN.list in Clash rule format.
Scrapes China ASN data from bgp.he.net and outputs as Clash rules.

AUTHOR: jshir700
REPO: https://github.com/jshir700/config
REFERENCE: https://github.com/missuo/ASN-China
'''
import requests
from lxml import etree
from datetime import datetime, timezone, timedelta
import os

# Ordered list of all known Clash rule types for statistics output
RULE_TYPES = [
    "DOMAIN",
    "DOMAIN-SUFFIX",
    "DOMAIN-KEYWORD",
    "DOMAIN-WILDCARD",
    "DOMAIN-REGEX",
    "GEOSITE",
    "IP-CIDR",
    "IP-CIDR6",
    "IP-SUFFIX",
    "IP-ASN",
    "GEOIP",
    "SRC-GEOIP",
    "SRC-IP-ASN",
    "SRC-IP-CIDR",
    "SRC-IP-SUFFIX",
    "DST-PORT",
    "SRC-PORT",
    "IN-PORT",
    "IN-TYPE",
    "IN-USER",
    "IN-NAME",
    "PROCESS-PATH",
    "PROCESS-PATH-WILDCARD",
    "PROCESS-PATH-REGEX",
    "PROCESS-NAME",
    "PROCESS-NAME-WILDCARD",
    "PROCESS-NAME-REGEX",
    "UID",
    "NETWORK",
    "DSCP",
    "RULE-SET",
    "AND",
    "OR",
    "NOT",
    "SUB-RULE",
    "MATCH",
]


def count_rules_by_type(rules):
    """Count occurrences of each rule type from a list of rule strings."""
    counts = {}
    for rule in rules:
        for t in RULE_TYPES:
            if t == "MATCH":
                if rule.strip() == "MATCH":
                    counts[t] = counts.get(t, 0) + 1
                    break
            elif rule.startswith(t + ","):
                counts[t] = counts.get(t, 0) + 1
                break
    return counts


def generate_clash_asn():
    url = "https://bgp.he.net/country/CN"
    headers = {
        "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/107.0.0.0 Safari/537.36"
    }

    r = requests.get(url=url, headers=headers).text
    tree = etree.HTML(r)
    asns = tree.xpath('//*[@id="asns"]/tbody/tr')

    # Extract ASN numbers
    asn_numbers = []
    for asn in asns:
        asn_number = asn.xpath('td[1]/a')[0].text.replace('AS', '')
        asn_numbers.append(asn_number)

    # Deduplicate while preserving order
    seen = set()
    unique_asns = []
    for num in asn_numbers:
        if num not in seen:
            seen.add(num)
            unique_asns.append(num)

    total = len(unique_asns)

    # Build rule lines
    rule_lines = []
    for asn_num in unique_asns:
        rule_lines.append("IP-ASN,{},no-resolve".format(asn_num))

    # Count rule types
    type_counts = count_rules_by_type(rule_lines)

    # Use Beijing Time (UTC+8)
    beijing_tz = timezone(timedelta(hours=8))
    beijing_time = datetime.now(beijing_tz).strftime("%Y-%m-%d %H:%M:%S")

    # Ensure output directory exists
    output_dir = "Clash/filter/auto"
    os.makedirs(output_dir, exist_ok=True)
    output_path = os.path.join(output_dir, "ChinaASN.list")

    with open(output_path, "w") as f:
        f.write("# NAME: ChinaASN\n")
        f.write("# AUTHOR: jshir700\n")
        f.write("# REPO: https://github.com/jshir700/config\n")
        f.write("# REFERENCE: https://github.com/missuo/ASN-China\n")
        f.write("# UPDATED: {}\n".format(beijing_time))
        # Write non-zero type counts between UPDATED and TOTAL
        for t in RULE_TYPES:
            if type_counts.get(t, 0) > 0:
                f.write("# {}: {}\n".format(t, type_counts[t]))
        f.write("# TOTAL: {}\n".format(total))
        for line in rule_lines:
            f.write(line + "\n")

    print("Generated {} with {} ASN entries".format(output_path, total))


generate_clash_asn()
