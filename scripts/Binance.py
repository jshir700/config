'''
Aggregate Binance rules from multiple sources and deduplicate.

Data Sources:
  - https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/.../Binance.list
  - https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/Clash/Ruleset/Binance.list
  - https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/Clash/Providers/Ruleset/Binance.yaml
  - https://raw.githubusercontent.com/StricklandF/Filter/main/Binance.list

AUTHOR: jshir700
REPO: https://github.com/jshir700/config
'''
import requests
from datetime import datetime, timezone, timedelta
import os

# Four data sources: (url, parser_type, headers)
# parser_type: "list" = Clash .list, "yaml" = Clash .yaml payload, "surge" = Surge/Quantumult X format
SOURCES = [
    ("https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/refs/heads/master/rule/Clash/Binance/Binance.list", "list"),
    ("https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/Clash/Ruleset/Binance.list", "list"),
    ("https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/Clash/Providers/Ruleset/Binance.yaml", "yaml"),
    ("https://raw.githubusercontent.com/StricklandF/Filter/main/Binance.list", "surge"),
]

HEADERS = {
    "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36"
}

# Mapping from Surge/Quantumult X rule types to Clash rule types (lowercase keys)
SURGE_TO_CLASH = {
    "host": "DOMAIN",
    "host-suffix": "DOMAIN-SUFFIX",
    "host-keyword": "DOMAIN-KEYWORD",
    "host-wildcard": "DOMAIN-WILDCARD",
    "host-regex": "DOMAIN-REGEX",
    "ip-cidr": "IP-CIDR",
    "ip-cidr6": "IP-CIDR6",
    "geoip": "GEOIP",
    "ip-asn": "IP-ASN",
    "dst-port": "DST-PORT",
    "src-port": "SRC-PORT",
}

# All known Clash rule type prefixes
RULE_PREFIXES = (
    "DOMAIN,", "DOMAIN-SUFFIX,", "DOMAIN-KEYWORD,", "DOMAIN-WILDCARD,", "DOMAIN-REGEX,",
    "GEOSITE,", "IP-CIDR,", "IP-CIDR6,", "IP-SUFFIX,", "IP-ASN,", "GEOIP,",
    "SRC-GEOIP,", "SRC-IP-ASN,", "SRC-IP-CIDR,", "SRC-IP-SUFFIX,",
    "DST-PORT,", "SRC-PORT,", "IN-PORT,", "IN-TYPE,", "IN-USER,", "IN-NAME,",
    "PROCESS-PATH,", "PROCESS-PATH-WILDCARD,", "PROCESS-PATH-REGEX,",
    "PROCESS-NAME,", "PROCESS-NAME-WILDCARD,", "PROCESS-NAME-REGEX,",
    "UID,", "NETWORK,", "DSCP,", "RULE-SET,", "AND,", "OR,", "NOT,", "SUB-RULE,",
)

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
    """Check if a line is a valid Clash rule."""
    line = line.strip()
    if not line or line.startswith("#"):
        return False
    if line == "MATCH":
        return True
    return line.startswith(RULE_PREFIXES)


def parse_list_content(text):
    """Parse Clash .list format (one rule per line)."""
    rules = set()
    for line in text.splitlines():
        if is_rule_line(line):
            rules.add(line.strip())
    return rules


def parse_yaml_content(text):
    """Parse Clash .yaml payload section."""
    rules = set()
    in_payload = False
    for line in text.splitlines():
        stripped = line.strip()
        if stripped == "payload:":
            in_payload = True
            continue
        if in_payload:
            if stripped.startswith("- "):
                rule = stripped[2:].strip()
                if rule.startswith("#") or rule.startswith("- #"):
                    continue
                if "#" in rule:
                    rule = rule.split("#")[0].strip()
                if is_rule_line(rule):
                    rules.add(rule)
            elif stripped.startswith("#") or stripped == "":
                continue
            else:
                break
    return rules


def parse_surge_content(text):
    """Parse Surge/Quantumult X format: RULE_TYPE,value,policy -> RULE_TYPE,value.

    Handles both uppercase (HOST-SUFFIX) and lowercase (host-suffix) types
    by normalizing to lowercase for mapping lookup.
    """
    rules = set()
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or stripped.startswith("//") or stripped.startswith("/*"):
            continue
        # Surge module sections like [Rule], [MITM], etc.
        if stripped.startswith("[") and stripped.endswith("]"):
            continue
        parts = stripped.split(",")
        if len(parts) < 2:
            continue
        raw_type = parts[0].strip().lower()
        if raw_type in SURGE_TO_CLASH:
            clash_type = SURGE_TO_CLASH[raw_type]
            value = parts[1].strip()
            clash_rule = "{},{}".format(clash_type, value)
            if is_rule_line(clash_rule):
                rules.add(clash_rule)
    return rules


def download_and_extract(url, parser_type):
    """Download and parse a single data source."""
    try:
        r = requests.get(url=url, headers=HEADERS, timeout=60)
        r.raise_for_status()
        text = r.text

        if parser_type == "list":
            rules = parse_list_content(text)
        elif parser_type == "yaml":
            rules = parse_yaml_content(text)
        elif parser_type == "surge":
            rules = parse_surge_content(text)
        else:
            rules = set()

        print("Downloaded {} ({} bytes, {} rules) from: {}".format(
            url.split("/")[-1], len(text), len(rules), url))
        return rules
    except Exception as e:
        print("Download failed [{}]: {}".format(url, e))
        return set()


def count_rules_by_type(rules):
    """Count occurrences of each rule type."""
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


def generate_binance_list():
    """Aggregate all sources, deduplicate, and generate Binance.list."""
    all_rules = set()
    source_count = 0

    for url, parser_type in SOURCES:
        rules = download_and_extract(url, parser_type)
        all_rules.update(rules)
        if rules:
            source_count += 1
        print("Fetched {} rules from: {}".format(len(rules), url))

    sorted_rules = sorted(all_rules)
    total = len(sorted_rules)
    type_counts = count_rules_by_type(sorted_rules)

    beijing_tz = timezone(timedelta(hours=8))
    beijing_time = datetime.now(beijing_tz).strftime("%Y-%m-%d %H:%M:%S")

    output_dir = "Clash/filter/auto"
    os.makedirs(output_dir, exist_ok=True)
    output_path = os.path.join(output_dir, "Binance.list")

    with open(output_path, "w") as f:
        f.write("# NAME: Binance\n")
        f.write("# AUTHOR: jshir700\n")
        f.write("# REPO: https://github.com/jshir700/config\n")
        f.write("# REFERENCE: https://github.com/blackmatrix7/ios_rule_script, https://github.com/ACL4SSR/ACL4SSR, https://github.com/StricklandF/Filter\n")
        f.write("# UPDATED: {}\n".format(beijing_time))
        for t in RULE_TYPES:
            if type_counts.get(t, 0) > 0:
                f.write("# {}: {}\n".format(t, type_counts[t]))
        f.write("# TOTAL: {}\n".format(total))
        for rule in sorted_rules:
            f.write(rule + "\n")

    print("\nDone! Aggregated {} rules from {} sources -> {}".format(total, source_count, output_path))


generate_binance_list()
