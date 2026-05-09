'''
Aggregate ad blocking rules from multiple sources and deduplicate.

18 data sources covering Clash, Surge, Quantumult X, and custom formats.

AUTHOR: jshir700
REPO: https://github.com/jshir700/config
'''
import requests
from datetime import datetime, timezone, timedelta
import os

# 18 data sources (hywang9 returns 404, skipped)
# Format: (url, parser_type)
# parser_type: "list" = Clash .list, "yaml" = Clash .yaml payload,
#               "surge" = Surge/QX format (type,value,policy),
#               "loyalsoldier" = special '+.domain' payload,
#               "sgmodule" = Surge module (.sgmodule)
SOURCES = [
    ("https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/Clash/BanProgramAD.list", "list"),
    ("https://raw.githubusercontent.com/NobyDa/Script/master/Surge/AdRule.list", "list"),
    # hywang9/Profiles/.../Hijacking.list returns 404, skipped
    ("https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/Clash/BanProgramAD.list", "list"),  # duplicate of #1
    ("https://raw.githubusercontent.com/limbopro/Adblock4limbo/refs/heads/main/Adblock4limbo_surge.list", "surge"),
    ("https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/Clash/BanEasyList.list", "list"),
    ("https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/Clash/BanEasyListChina.list", "list"),
    ("https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/refs/heads/master/rule/Clash/Advertising/Advertising.list", "list"),
    ("https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/refs/heads/master/rule/Clash/ZhihuAds/ZhihuAds.list", "list"),
    ("https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/Clash/BanEasyPrivacy.list", "list"),
    ("https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/refs/heads/master/rule/Clash/EasyPrivacy/EasyPrivacy.list", "list"),
    ("https://raw.githubusercontent.com/scomper/surge-list/master/reject.list", "list"),
    ("https://raw.githubusercontent.com/scomper/surge-list/master/adblock.list", "list"),
    ("https://raw.githubusercontent.com/sve1r/Rules-For-Quantumult-X/develop/Rules/Advertising/AdReject.list", "surge"),
    ("https://raw.githubusercontent.com/sve1r/Rules-For-Quantumult-X/develop/Rules/Advertising/Hijacking.list", "surge"),
    ("https://raw.githubusercontent.com/yjqiang/surge_scripts/main/modules/hupu/hupu.sgmodule", "sgmodule"),
    ("https://raw.githubusercontent.com/Loyalsoldier/clash-rules/release/reject.txt", "loyalsoldier"),
    ("https://raw.githubusercontent.com/zqzess/rule_for_quantumultX/master/QuantumultX/rules/AdBlock.list", "surge"),
]

HEADERS = {
    "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36"
}

# Surge/Quantumult X to Clash type mapping (lowercase keys)
# Also covers Clash-formatted lines with policy suffix (e.g. DOMAIN-SUFFIX,domain,reject)
SURGE_TO_CLASH = {
    "host": "DOMAIN",
    "host-suffix": "DOMAIN-SUFFIX",
    "host-keyword": "DOMAIN-KEYWORD",
    "host-wildcard": "DOMAIN-WILDCARD",
    "host-regex": "DOMAIN-REGEX",
    "domain": "DOMAIN",
    "domain-suffix": "DOMAIN-SUFFIX",
    "domain-keyword": "DOMAIN-KEYWORD",
    "domain-wildcard": "DOMAIN-WILDCARD",
    "domain-regex": "DOMAIN-REGEX",
    "ip-cidr": "IP-CIDR",
    "ip-cidr6": "IP-CIDR6",
    "geoip": "GEOIP",
    "ip-asn": "IP-ASN",
    "src-ip-cidr": "SRC-IP-CIDR",
    "src-port": "SRC-PORT",
    "dst-port": "DST-PORT",
    "url-regex": "URL-REGEX",
    "process-name": "PROCESS-NAME",
    "user-agent": "USER-AGENT",
}

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
    """Parse Clash .list format (one rule per line, no policy)."""
    rules = set()
    for line in text.splitlines():
        if is_rule_line(line):
            rules.add(line.strip())
    return rules


def parse_yaml_content(text):
    """Parse standard Clash .yaml payload section."""
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
    """Parse Surge/Quantumult X/Clash-with-policy format.

    Handles formats like:
      host-suffix,google.com,Proxy         -> DOMAIN-SUFFIX,google.com
      HOST-SUFFIX,google.com,AdBlock       -> DOMAIN-SUFFIX,google.com
      DOMAIN-SUFFIX,google.com,reject      -> DOMAIN-SUFFIX,google.com
      URL-REGEX,^https?://ads\.example,REJECT -> (skipped if URL-REGEX not in RULE_PREFIXES)
    """
    rules = set()
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or stripped.startswith("//"):
            continue
        if stripped.startswith("/*") or stripped.startswith("*/"):
            continue
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


def parse_sgmodule_content(text):
    """Parse Surge module (.sgmodule) format, extracting [Rule] section."""
    rules = set()
    in_rule_section = False
    for line in text.splitlines():
        stripped = line.strip()
        if stripped.startswith("[") and stripped.endswith("]"):
            section_name = stripped[1:-1].lower()
            in_rule_section = (section_name == "rule")
            continue
        if not in_rule_section:
            continue
        if not stripped or stripped.startswith("#") or stripped.startswith("//"):
            continue
        if stripped.startswith("/*") or stripped.startswith("*/"):
            continue
        # Parse as Surge format (type,value,policy)
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


def parse_loyalsoldier_content(text):
    """Parse Loyalsoldier reject.txt format.

    This is a YAML payload with entries like: '- '+.domain'
    where '+.' prefix means DOMAIN-SUFFIX (catch-all subdomain).
    """
    rules = set()
    in_payload = False
    for line in text.splitlines():
        stripped = line.strip()
        if stripped == "payload:":
            in_payload = True
            continue
        if in_payload:
            if stripped.startswith("- "):
                entry = stripped[2:].strip()
                if entry.startswith("'") and entry.endswith("'"):
                    entry = entry[1:-1]
                if entry.startswith("+."):
                    domain = entry[2:]
                    rule = "DOMAIN-SUFFIX,{}".format(domain)
                    if is_rule_line(rule):
                        rules.add(rule)
                elif is_rule_line(entry):
                    rules.add(entry)
            elif stripped.startswith("#") or stripped == "":
                continue
            else:
                break
    return rules


def download_and_extract(url, parser_type):
    """Download and parse a single data source."""
    try:
        r = requests.get(url=url, headers=HEADERS, timeout=120)
        r.raise_for_status()
        text = r.text

        parser_map = {
            "list": parse_list_content,
            "yaml": parse_yaml_content,
            "surge": parse_surge_content,
            "sgmodule": parse_sgmodule_content,
            "loyalsoldier": parse_loyalsoldier_content,
        }
        parser = parser_map.get(parser_type, parse_list_content)
        rules = parser(text)

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


def generate_banad_list():
    """Aggregate all sources, deduplicate, and generate BanAD.list."""
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
    output_path = os.path.join(output_dir, "BanAD.list")

    with open(output_path, "w") as f:
        f.write("# NAME: BanAD\n")
        f.write("# AUTHOR: jshir700\n")
        f.write("# REPO: https://github.com/jshir700/config\n")
        f.write("# REFERENCE: https://github.com/ACL4SSR/ACL4SSR, https://github.com/NobyDa/Script, https://github.com/limbopro/Adblock4limbo, https://github.com/blackmatrix7/ios_rule_script, https://github.com/scomper/surge-list, https://github.com/sve1r/Rules-For-Quantumult-X, https://github.com/yjqiang/surge_scripts, https://github.com/Loyalsoldier/clash-rules, https://github.com/zqzess/rule_for_quantumultX\n")
        f.write("# UPDATED: {}\n".format(beijing_time))
        for t in RULE_TYPES:
            if type_counts.get(t, 0) > 0:
                f.write("# {}: {}\n".format(t, type_counts[t]))
        f.write("# TOTAL: {}\n".format(total))
        for rule in sorted_rules:
            f.write(rule + "\n")

    print("\nDone! Aggregated {} rules from {} sources -> {}".format(total, source_count, output_path))


generate_banad_list()
