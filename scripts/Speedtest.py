'''
Aggregate Speedtest rules from multiple sources and deduplicate.

Data Sources:
  - https://kelee.one/Tool/Clash/Rule/SpeedtestChina.yaml
  - https://kelee.one/Tool/Clash/Rule/SpeedtestInternational.yaml
  - https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/.../Speedtest.list
  - https://raw.githubusercontent.com/GeQ1an/Rules/.../QuantumultX/Filter/Speedtest.list
  - https://raw.githubusercontent.com/dler-io/Rules/.../Clash/Provider/Speedtest.yaml

NOTE: kelee.one blocks direct downloads (returns 404 with default User-Agent).
Must use a Loon-like User-Agent to bypass protection.

AUTHOR: jshir700
REPO: https://github.com/jshir700/config
'''
import requests
from datetime import datetime, timezone, timedelta
import os

# Five data source URLs
SOURCES = [
    "https://kelee.one/Tool/Clash/Rule/SpeedtestChina.yaml",
    "https://kelee.one/Tool/Clash/Rule/SpeedtestInternational.yaml",
    "https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/refs/heads/master/rule/Clash/Speedtest/Speedtest.list",
    "https://raw.githubusercontent.com/GeQ1an/Rules/master/QuantumultX/Filter/Speedtest.list",
    "https://raw.githubusercontent.com/dler-io/Rules/main/Clash/Provider/Speedtest.yaml",
]

# Loon User-Agent to bypass kelee.one anti-leech protection
LOON_HEADERS = {
    "User-Agent": "Loon/953 CFNetwork/3860.500.112 Darwin/25.4.0"
}

# Normal User-Agent for GitHub raw content
DEFAULT_HEADERS = {
    "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36"
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

# Mapping from Quantumult X rule types to Clash rule types
QUANTUMULTX_TO_CLASH = {
    "HOST": "DOMAIN",
    "HOST-SUFFIX": "DOMAIN-SUFFIX",
    "HOST-KEYWORD": "DOMAIN-KEYWORD",
    "HOST-WILDCARD": "DOMAIN-WILDCARD",
    "HOST-REGEX": "DOMAIN-REGEX",
    "IP-CIDR": "IP-CIDR",
    "IP-CIDR6": "IP-CIDR6",
    "GEOIP": "GEOIP",
}


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
                # Skip commented rules
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


def parse_quantumultx_content(text):
    """Parse Quantumult X format content and convert to Clash rule format.

    Quantumult X format: RULE_TYPE,value,policy
    Clash format: RULE_TYPE,value

    Example: HOST-SUFFIX,google.com,Proxy -> DOMAIN-SUFFIX,google.com
    """
    rules = set()
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        parts = stripped.split(",")
        if len(parts) < 2:
            continue
        qx_type = parts[0].strip()
        if qx_type in QUANTUMULTX_TO_CLASH:
            clash_type = QUANTUMULTX_TO_CLASH[qx_type]
            value = parts[1].strip()
            clash_rule = "{},{}".format(clash_type, value)
            if is_rule_line(clash_rule):
                rules.add(clash_rule)
    return rules


def download_and_extract(url):
    """Download and parse a single data source."""
    try:
        # Use Loon UA for kelee.one, default UA for GitHub
        if "kelee.one" in url:
            headers = LOON_HEADERS
        else:
            headers = DEFAULT_HEADERS

        r = requests.get(url=url, headers=headers, timeout=60)
        r.raise_for_status()
        text = r.text

        # Determine parser based on URL and content
        if "QuantumultX" in url:
            rules = parse_quantumultx_content(text)
        elif url.endswith(".yaml"):
            rules = parse_yaml_content(text)
        else:
            rules = parse_list_content(text)

        print("Downloaded {} ({} bytes, {} rules) from: {}".format(
            url.split("/")[-1], len(text), len(rules), url))
        return rules
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


def generate_speedtest_list():
    """Aggregate all sources, deduplicate, and generate Speedtest.list."""
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
    output_path = os.path.join(output_dir, "Speedtest.list")

    with open(output_path, "w") as f:
        f.write("# NAME: Speedtest\n")
        f.write("# AUTHOR: jshir700\n")
        f.write("# REPO: https://github.com/jshir700/config\n")
        f.write("# REFERENCE: https://kelee.one, https://github.com/blackmatrix7/ios_rule_script, https://github.com/GeQ1an/Rules, https://github.com/dler-io/Rules\n")
        f.write("# UPDATED: {}\n".format(beijing_time))
        # Write non-zero type counts between UPDATED and TOTAL
        for t in RULE_TYPES:
            if type_counts.get(t, 0) > 0:
                f.write("# {}: {}\n".format(t, type_counts[t]))
        f.write("# TOTAL: {}\n".format(total))
        for rule in sorted_rules:
            f.write(rule + "\n")

    print("\nDone! Aggregated {} rules from {} sources -> {}".format(total, source_count, output_path))


generate_speedtest_list()
