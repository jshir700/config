'''
Aggregate Scholar academic website rules from multiple sources and deduplicate.

Data Sources:
  - https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/Clash/Ruleset/Scholar.list
  - https://raw.githubusercontent.com/LM-Firefly/Rules/master/PROXY/Scholar.list
  - https://raw.githubusercontent.com/dler-io/Rules/main/Clash/Provider/Scholar.yaml
  - https://raw.githubusercontent.com/LM-Firefly/Rules/master/Clash-RuleSet-Classical/PROXY/Scholar.yaml
  - https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/Clash/Providers/Ruleset/Scholar.yaml
  - https://raw.githubusercontent.com/ke1ewang/Profiles/refs/heads/main/Surge/Ruleset/Extra/Scholar.list
  - https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/refs/heads/master/rule/Clash/Scholar/Scholar.list

AUTHOR: jshir700
REPO: https://github.com/jshir700/config
'''
import requests
import re
from datetime import datetime, timezone, timedelta
import os

# Five data source URLs
SOURCES = [
    "https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/Clash/Ruleset/Scholar.list",
    "https://raw.githubusercontent.com/LM-Firefly/Rules/master/PROXY/Scholar.list",
    "https://raw.githubusercontent.com/dler-io/Rules/main/Clash/Provider/Scholar.yaml",
    "https://raw.githubusercontent.com/LM-Firefly/Rules/master/Clash-RuleSet-Classical/PROXY/Scholar.yaml",
    "https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/Clash/Providers/Ruleset/Scholar.yaml",
    "https://raw.githubusercontent.com/ke1ewang/Profiles/refs/heads/main/Surge/Ruleset/Extra/Scholar.list",
    "https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/refs/heads/master/rule/Clash/Scholar/Scholar.list",
]

HEADERS = {
    "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/107.0.0.0 Safari/537.36"
}

# All known Clash rule type prefixes (with trailing comma for matching)
RULE_PREFIXES = (
    "DOMAIN,", "DOMAIN-SUFFIX,", "DOMAIN-KEYWORD,", "DOMAIN-WILDCARD,", "DOMAIN-REGEX,",
    "GEOSITE,", "IP-CIDR,", "IP-CIDR6,", "IP-SUFFIX,", "IP-ASN,", "GEOIP,",
    "SRC-GEOIP,", "SRC-IP-ASN,", "SRC-IP-CIDR,", "SRC-IP-SUFFIX,",
    "DST-PORT,", "SRC-PORT,", "IN-PORT,", "IN-TYPE,", "IN-USER,", "IN-NAME,",
    "PROCESS-PATH,", "PROCESS-PATH-WILDCARD,", "PROCESS-PATH-REGEX,",
    "PROCESS-NAME,", "PROCESS-NAME-WILDCARD,", "PROCESS-NAME-REGEX,",
    "UID,", "NETWORK,", "DSCP,", "RULE-SET,", "AND,", "OR,", "NOT,", "SUB-RULE,",
)

# Ordered list for statistics output (MATCH is last, no comma)
RULE_TYPES = [
    "DOMAIN", "DOMAIN-SUFFIX", "DOMAIN-KEYWORD", "DOMAIN-WILDCARD", "DOMAIN-REGEX",
    "GEOSITE", "IP-CIDR", "IP-CIDR6", "IP-SUFFIX", "IP-ASN", "GEOIP",
    "SRC-GEOIP", "SRC-IP-ASN", "SRC-IP-CIDR", "SRC-IP-SUFFIX",
    "DST-PORT", "SRC-PORT", "IN-PORT", "IN-TYPE", "IN-USER", "IN-NAME",
    "PROCESS-PATH", "PROCESS-PATH-WILDCARD", "PROCESS-PATH-REGEX",
    "PROCESS-NAME", "PROCESS-NAME-WILDCARD", "PROCESS-NAME-REGEX",
    "UID", "NETWORK", "DSCP", "RULE-SET", "AND", "OR", "NOT", "SUB-RULE",
    "MATCH",
]


def is_rule_line(line):
    """Check if a line is a valid rule (not a comment/empty)."""
    line = line.strip()
    if not line or line.startswith("#"):
        return False
    # MATCH is a standalone rule type (no comma, no value)
    if line == "MATCH":
        return True
    return line.startswith(RULE_PREFIXES)


def parse_list_content(text):
    """Parse .list format content and extract all rules."""
    rules = set()
    for line in text.splitlines():
        if is_rule_line(line):
            rules.add(line.strip())
    return rules


def parse_yaml_content(text):
    """Parse .yaml format content and extract rules from payload section."""
    rules = set()
    in_payload = False
    for line in text.splitlines():
        stripped = line.strip()
        # Check for payload section start
        if stripped == "payload:":
            in_payload = True
            continue
        if in_payload:
            # Remove YAML list prefix "- "
            if stripped.startswith("- "):
                rule = stripped[2:].strip()
                # Skip commented rules (e.g., # - DOMAIN-SUFFIX,...)
                if rule.startswith("#") or rule.startswith("- #"):
                    continue
                # Extract rule before inline comment
                if "#" in rule:
                    rule = rule.split("#")[0].strip()
                if is_rule_line(rule):
                    rules.add(rule)
            elif stripped.startswith("#") or stripped == "":
                continue
            else:
                # Exit payload section on non-payload content
                break
    return rules


def download_and_extract(url):
    """Download and parse a single data source."""
    try:
        r = requests.get(url=url, headers=HEADERS, timeout=30)
        r.raise_for_status()
        text = r.text

        if url.endswith(".yaml"):
            return parse_yaml_content(text)
        else:
            return parse_list_content(text)
    except Exception as e:
        print("Download failed [{}]: {}".format(url, e))
        return set()


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


def generate_scholar_list():
    """Aggregate all sources, deduplicate, and generate Scholar.list."""
    all_rules = set()
    source_count = 0

    for url in SOURCES:
        rules = download_and_extract(url)
        all_rules.update(rules)
        if rules:
            source_count += 1
        print("Fetched {} rules from: {}".format(len(rules), url))

    # Sort alphabetically
    sorted_rules = sorted(all_rules)
    total = len(sorted_rules)

    # Count rule types
    type_counts = count_rules_by_type(sorted_rules)

    # Use Beijing Time (UTC+8)
    beijing_tz = timezone(timedelta(hours=8))
    beijing_time = datetime.now(beijing_tz).strftime("%Y-%m-%d %H:%M:%S")

    # Ensure output directory exists
    output_dir = "Clash/filter/auto"
    os.makedirs(output_dir, exist_ok=True)
    output_path = os.path.join(output_dir, "Scholar.list")

    with open(output_path, "w") as f:
        f.write("# NAME: Scholar\n")
        f.write("# AUTHOR: jshir700\n")
        f.write("# REPO: https://github.com/jshir700/config\n")
        f.write("# REFERENCE: https://github.com/ACL4SSR/ACL4SSR, https://github.com/LM-Firefly/Rules, https://github.com/dler-io/Rules, https://github.com/ke1ewang/Profiles, https://github.com/blackmatrix7/ios_rule_script\n")
        f.write("# UPDATED: {}\n".format(beijing_time))
        # Write non-zero type counts between UPDATED and TOTAL
        for t in RULE_TYPES:
            if type_counts.get(t, 0) > 0:
                f.write("# {}: {}\n".format(t, type_counts[t]))
        f.write("# TOTAL: {}\n".format(total))
        for rule in sorted_rules:
            f.write(rule + "\n")

    print("\nDone! Aggregated {} rules from {} sources -> {}".format(total, source_count, output_path))


generate_scholar_list()
