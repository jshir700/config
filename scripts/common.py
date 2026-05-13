"""
Shared utilities for Clash rule generation.

Common parsers, downloaders, and utilities used by GenerateAll.py.

AUTHOR: jshir700
REPO: https://github.com/jshir700/config
"""

import re
import requests
import ipaddress
from datetime import datetime, timezone, timedelta
import os


# ---------------------------------------------------------------------------
# HTTP Headers
# ---------------------------------------------------------------------------

DEFAULT_HEADERS = {
    "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
                  "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/107.0.0.0 Safari/537.36"
}

LOON_HEADERS = {
    "User-Agent": "Loon/953 CFNetwork/3860.500.112 Darwin/25.4.0"
}


# ---------------------------------------------------------------------------
# Rule type definitions (Clash official + extended)
# ---------------------------------------------------------------------------

RULE_TYPES = [
    "DOMAIN", "DOMAIN-SUFFIX", "DOMAIN-KEYWORD", "DOMAIN-WILDCARD", "DOMAIN-REGEX",
    "GEOSITE", "IP-CIDR", "IP-CIDR6", "IP-SUFFIX", "IP-ASN", "GEOIP",
    "SRC-GEOIP", "SRC-IP-ASN", "SRC-IP-CIDR", "SRC-IP-SUFFIX",
    "DST-PORT", "SRC-PORT", "IN-PORT", "IN-TYPE", "IN-USER", "IN-NAME",
    "PROCESS-PATH", "PROCESS-PATH-WILDCARD", "PROCESS-PATH-REGEX",
    "PROCESS-NAME", "PROCESS-NAME-WILDCARD", "PROCESS-NAME-REGEX",
    "UID", "NETWORK", "DSCP", "RULE-SET", "AND", "OR", "NOT", "SUB-RULE",
    "USER-AGENT", "URL-REGEX",
    "MATCH",
]

RULE_PREFIXES = tuple(t + "," for t in RULE_TYPES if t != "MATCH")

# Also accept Loon-specific prefixes during parsing
LOON_PREFIXES = ("DEST-PORT,", "PROTOCOL,")


# ---------------------------------------------------------------------------
# Loon equivalent mapping (for rules that differ between mihomo and Loon)
# ---------------------------------------------------------------------------

# Clash -> Loon
LOON_EQUIVALENT = {
    "DST-PORT": "DEST-PORT",
    "NETWORK": "PROTOCOL",
    "MATCH": "final",
    "DOMAIN-REGEX": "URL-REGEX",
}

# Loon -> Clash (reverse mapping)
LOON_TO_CLASH = {
    "DEST-PORT": "DST-PORT",
    "PROTOCOL": "NETWORK",
    "final": "MATCH",
    "URL-REGEX": "DOMAIN-REGEX",
}


# ---------------------------------------------------------------------------
# Format conversion mappings
# ---------------------------------------------------------------------------

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
    "ip6-cidr": "IP-CIDR6",
    "geoip": "GEOIP",
    "ip-asn": "IP-ASN",
    "user-agent": "USER-AGENT",
    "url-regex": "DOMAIN-REGEX",
    "src-ip-cidr": "SRC-IP-CIDR",
    "src-port": "SRC-PORT",
    "dst-port": "DST-PORT",
    "process-name": "PROCESS-NAME",
    "protocol": "NETWORK",
    # Loon type equivalents (for parsing Loon rules in sgmodule/surge sources)
    "dest-port": "DST-PORT",
}

QUANTUMULTX_TO_CLASH = {
    "HOST": "DOMAIN",
    "HOST-SUFFIX": "DOMAIN-SUFFIX",
    "HOST-KEYWORD": "DOMAIN-KEYWORD",
    "HOST-WILDCARD": "DOMAIN-WILDCARD",
    "HOST-REGEX": "DOMAIN-REGEX",
    "IP-CIDR": "IP-CIDR",
    "IP-CIDR6": "IP-CIDR6",
    "IP6-CIDR": "IP-CIDR6",
    "GEOIP": "GEOIP",
    "USER-AGENT": "USER-AGENT",
    "URL-REGEX": "URL-REGEX",
}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def is_rule_line(line):
    """Check if a line is a valid Clash or Loon rule."""
    line = line.strip()
    if not line or line.startswith("#"):
        return False
    if line in ("MATCH", "final"):
        return True
    return line.startswith(RULE_PREFIXES) or line.startswith(LOON_PREFIXES)


def is_loon_rule_line(line):
    """Check if a line is a valid Loon rule."""
    line = line.strip()
    if not line or line.startswith("#"):
        return False
    if line == "final":
        return True
    return line.startswith((
        "DEST-PORT,", "PROTOCOL,",
        "DOMAIN,", "DOMAIN-SUFFIX,", "DOMAIN-KEYWORD,", "DOMAIN-WILDCARD,", "DOMAIN-REGEX,",
        "IP-CIDR,", "IP-CIDR6,", "GEOIP,", "IP-ASN,",
        "USER-AGENT,", "URL-REGEX,",
    ))


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


def get_loon_equivalent(rule):
    """Return the Loon equivalent line for a mihomo (Clash) rule, or None.

    Converts Clash-specific types (DST-PORT, NETWORK, MATCH) to Loon equivalents.
    """
    rule = rule.strip()
    if rule == "MATCH":
        return "final"
    for mihomo_type, loon_type in LOON_EQUIVALENT.items():
        if mihomo_type == "MATCH":
            continue
        if rule.startswith(mihomo_type + ","):
            return rule.replace(mihomo_type + ",", loon_type + ",", 1)
    return None


def get_clash_equivalent(rule):
    """Return the Clash equivalent line for a Loon-specific rule, or None.

    Converts Loon-specific types (DEST-PORT, PROTOCOL, final) to Clash equivalents.
    """
    rule = rule.strip()
    if rule == "final":
        return "MATCH"
    for loon_type, clash_type in LOON_TO_CLASH.items():
        if loon_type == "final":
            continue
        if rule.startswith(loon_type + ","):
            return rule.replace(loon_type + ",", clash_type + ",", 1)
    return None


def write_rule_list(output_path, name, sorted_rules, ref_line=None):
    """Write a .list file with header, type counts, sorted rules, and Loon equivalents.

    For every Clash-specific rule (DST-PORT, NETWORK, MATCH), the Loon equivalent
    is written on the next line. For every Loon-specific rule (DEST-PORT, PROTOCOL, final),
    the Clash equivalent is written on the next line. This ensures bidirectional compatibility.

    Duplicates are avoided: if an equivalent line already exists in sorted_rules (i.e.,
    both the Clash rule and its Loon equivalent are independently present in the input
    set), the equivalent is NOT written again, since the primary write of that line
    already covers it.
    """
    # Deduplicate IP-CIDR/IP-CIDR6 rules preferring no-resolve
    sorted_rules = deduplicate_ip_cidr(sorted_rules)
    rules_set = set(sorted_rules)  # fast lookup for dedup
    total = len(sorted_rules)
    type_counts = count_rules_by_type(sorted_rules)

    beijing_tz = timezone(timedelta(hours=8))
    beijing_time = datetime.now(beijing_tz).strftime("%Y-%m-%d %H:%M:%S")

    os.makedirs(os.path.dirname(output_path), exist_ok=True)

    with open(output_path, "w") as f:
        f.write("# NAME: {}\n".format(name))
        f.write("# AUTHOR: jshir700\n")
        f.write("# REPO: https://github.com/jshir700/config\n")
        if ref_line:
            f.write(ref_line + "\n")
        f.write("# UPDATED: {}\n".format(beijing_time))
        for t in RULE_TYPES:
            if type_counts.get(t, 0) > 0:
                f.write("# {}: {}\n".format(t, type_counts[t]))
        f.write("# TOTAL: {}\n".format(total))
        for rule in sorted_rules:
            # Write the rule itself
            f.write(rule + "\n")
            # Clash -> Loon: write Loon equivalent for Clash-specific types
            loon_line = get_loon_equivalent(rule)
            if loon_line is not None:
                # Only write equivalent if it's not already in the input set
                if loon_line not in rules_set:
                    f.write(loon_line + "\n")
            # Loon -> Clash: if this rule is already in Loon format,
            # write the Clash equivalent on the next line too
            else:
                clash_line = get_clash_equivalent(rule)
                if clash_line is not None:
                    if clash_line not in rules_set:
                        f.write(clash_line + "\n")

    return total, type_counts


# ---------------------------------------------------------------------------
# IP-CIDR deduplication: prefer no-resolve variants
# ---------------------------------------------------------------------------

def deduplicate_ip_cidr(rules):
    """Deduplicate IP-CIDR/IP-CIDR6 rules, preferring 'no-resolve' variants.

    For duplicate CIDR rules (same type + same IP range), keeps the one with
    'no-resolve'. If no variant has 'no-resolve', adds 'no-resolve' to the kept rule.

    Args:
        rules: iterable of rule strings (e.g., list or set).

    Returns:
        list of deduplicated rule strings.
    """
    result = set()
    cidr_map = {}  # (rule_type, cidr_value) -> best_rule_string

    for rule in rules:
        if rule.startswith(("IP-CIDR,", "IP-CIDR6,")):
            parts = rule.split(",")
            rule_type = parts[0]  # IP-CIDR or IP-CIDR6
            cidr_value = parts[1]  # e.g. "10.0.0.0/8"
            has_no_resolve = "no-resolve" in parts

            key = (rule_type, cidr_value)
            if key in cidr_map:
                existing = cidr_map[key]
                existing_has_no_resolve = "no-resolve" in existing.split(",")
                if has_no_resolve and not existing_has_no_resolve:
                    cidr_map[key] = rule  # prefer no-resolve
            else:
                cidr_map[key] = rule
        else:
            result.add(rule)

    for key, best_rule in cidr_map.items():
        parts = best_rule.split(",")
        has_no_resolve = "no-resolve" in parts
        if not has_no_resolve:
            best_rule += ",no-resolve"
        result.add(best_rule)

    return sorted(result)


# ---------------------------------------------------------------------------
# Subsumption check for China.list exclusion
# ---------------------------------------------------------------------------

def wildcard_to_regex(pattern):
    """Convert a DOMAIN-WILDCARD pattern to a compiled regex.

    Supports * (zero or more chars) and ? (exactly one char).
    """
    regex_parts = ["^"]
    for c in pattern:
        if c == "*":
            regex_parts.append(".*")
        elif c == "?":
            regex_parts.append(".")
        else:
            regex_parts.append(re.escape(c))
    regex_parts.append("$")
    return re.compile("".join(regex_parts))


def _extract_cidr_value(rule_str):
    """Extract the pure CIDR value from a rule string, stripping ,no-resolve suffix."""
    # rule_str is like "10.0.0.0/8,no-resolve" or just "10.0.0.0/8"
    return rule_str.split(",")[0]


def remove_subsumed_rules(china_rules, exclude_set):
    """Remove China rules that would be matched by broader rules in exclude_set.

    Beyond exact-match removal, handles:
      - DOMAIN-SUFFIX,domain: removes any China rule whose value is
        a subdomain of or equal to that domain
      - DOMAIN-KEYWORD,keyword: removes any China rule whose value
        contains keyword
      - DOMAIN-WILDCARD,pattern: removes any China rule whose value
        matches the wildcard pattern (supports * and ?)
      - IP-CIDR/IP-CIDR6: removes China CIDRs that fall within any
        exclude CIDR range (using subnet_of)

    Args:
        china_rules: set of China rule strings
        exclude_set: set of rule strings from other lists

    Returns:
        set of China rules with subsumed entries removed
    """
    # Step 1: Exact match removal
    china_rules = china_rules - exclude_set

    # Step 2: Build lookup structures
    # All domain-based c_types in China that should be checked
    DOMAIN_TYPES = ("DOMAIN", "DOMAIN-SUFFIX", "DOMAIN-KEYWORD", "DOMAIN-WILDCARD")

    exclude_suffixes = set()
    exclude_cidr_v4 = []   # IPv4 networks
    exclude_cidr_v6 = []   # IPv6 networks
    exclude_keywords = []
    exclude_wildcard_regexes = []  # (compiled_regex, raw_pattern)

    for rule in exclude_set:
        if rule.startswith("DOMAIN-SUFFIX,"):
            exclude_suffixes.add(rule.split(",", 1)[1])
        elif rule.startswith("DOMAIN-KEYWORD,"):
            exclude_keywords.append(rule.split(",", 1)[1])
        elif rule.startswith("DOMAIN-WILDCARD,"):
            pattern = rule.split(",", 1)[1]
            exclude_wildcard_regexes.append((wildcard_to_regex(pattern), pattern))
        elif rule.startswith(("IP-CIDR,", "IP-CIDR6,")):
            try:
                cidr_str = _extract_cidr_value(rule.split(",", 1)[1])
                net = ipaddress.ip_network(cidr_str, strict=False)
                if isinstance(net, ipaddress.IPv4Network):
                    exclude_cidr_v4.append(net)
                else:
                    exclude_cidr_v6.append(net)
            except ValueError:
                pass

    # Step 3: Check each China rule for subsumption
    rules_to_remove = set()

    for china_rule in china_rules:
        try:
            c_type, c_value = china_rule.split(",", 1)
        except ValueError:
            continue  # standalone MATCH etc.

        removed = False

        if c_type not in DOMAIN_TYPES and c_type not in ("IP-CIDR", "IP-CIDR6"):
            continue  # skip types we don't check

        # --- Domain-based subsumption ---
        if c_type in DOMAIN_TYPES:

            # DOMAIN-SUFFIX subsumption: is China's value a subdomain of (or equal to)
            # any exclude suffix?
            if exclude_suffixes:
                parts = c_value.split(".")
                for i in range(len(parts)):
                    suffix = ".".join(parts[i:])
                    if suffix in exclude_suffixes:
                        rules_to_remove.add(china_rule)
                        removed = True
                        break

            if removed:
                continue

            # DOMAIN-KEYWORD subsumption: does China's value contain any exclude keyword?
            if exclude_keywords:
                for kw in exclude_keywords:
                    if kw in c_value:
                        rules_to_remove.add(china_rule)
                        removed = True
                        break

            if removed:
                continue

            # DOMAIN-WILDCARD subsumption: does China's value match any exclude wildcard?
            if exclude_wildcard_regexes:
                for regex, _ in exclude_wildcard_regexes:
                    if regex.match(c_value):
                        rules_to_remove.add(china_rule)
                        removed = True
                        break

            if removed:
                continue

        # --- IP-CIDR / IP-CIDR6 subsumption ---
        if c_type in ("IP-CIDR", "IP-CIDR6") and (exclude_cidr_v4 or exclude_cidr_v6):
            try:
                cidr_str = _extract_cidr_value(c_value)
                c_net = ipaddress.ip_network(cidr_str, strict=False)
                # Only check against networks of the same IP version
                networks_to_check = exclude_cidr_v4 if isinstance(c_net, ipaddress.IPv4Network) else exclude_cidr_v6
                for net in networks_to_check:
                    if c_net.subnet_of(net):
                        rules_to_remove.add(china_rule)
                        break
            except ValueError:
                pass

    china_rules -= rules_to_remove
    return china_rules


# ---------------------------------------------------------------------------
# Universal fallback parser (second-pass detection)
# ---------------------------------------------------------------------------

def fallback_parse_line(line):
    """Try to parse an unrecognized line via heuristic detection (second pass).

    Tries, in order:
      - Bare CIDR (e.g. '1.2.3.0/24')
      - +.domain  (Loyalsoldier prefix → DOMAIN-SUFFIX)
      - *.domain  (Domain wildcard → DOMAIN-SUFFIX)
      - .domain   (Surge leading dot → DOMAIN-SUFFIX)
      - Bare domain (contains a dot → DOMAIN)
      - Bare AS number (e.g. 'AS1234')
      - Bare IP address (no mask → IP-CIDR)

    Returns:
        Clash rule string, or None if nothing matched.
    """
    stripped = line.strip()
    if not stripped or stripped.startswith("#"):
        return None

    # Bare CIDR (e.g. "1.2.3.0/24" or "2001::/32")
    if "/" in stripped and "," not in stripped:
        return "IP-CIDR,{}".format(stripped)

    # Loyalsoldier-style: '+.domain.com' -> DOMAIN-SUFFIX,domain.com
    if stripped.startswith("+."):
        return "DOMAIN-SUFFIX,{}".format(stripped[2:])

    # Domain wildcard: '*.domain.com' -> DOMAIN-SUFFIX,domain.com
    # Clash/mihomo domain wildcard * matches exactly one subdomain level,
    # which is equivalent to DOMAIN-SUFFIX behavior
    if stripped.startswith("*."):
        return "DOMAIN-SUFFIX,{}".format(stripped[2:])

    # Surge-style leading dot: '.domain.com' -> DOMAIN-SUFFIX,domain.com
    if stripped.startswith("."):
        return "DOMAIN-SUFFIX,{}".format(stripped[1:])

    # Bare domain (contains a dot, no comma)
    if "." in stripped and "," not in stripped:
        return "DOMAIN,{}".format(stripped)

    # Bare AS number (with or without "AS" prefix)
    upper = stripped.upper()
    if upper.startswith("AS") and len(upper) > 2 and upper[2:].isdigit():
        return "IP-ASN,{}".format(upper)
    if stripped.isdigit() and len(stripped) <= 12:
        # Plain numeric ASN (no "AS" prefix), e.g. "132203"
        return "IP-ASN,AS{}".format(stripped)

    # Bare IP address (single address, no mask)
    try:
        ipaddress.ip_address(stripped)
        return "IP-CIDR,{}".format(stripped)
    except ValueError:
        pass

    return None


# ---------------------------------------------------------------------------
# Format-specific parsers
# Each returns (set_of_rules, unrecognized_count).
# "unrecognized" = non-empty, non-comment lines that the primary parser
#   AND fallback could NOT convert to a valid rule.
# ---------------------------------------------------------------------------

def parse_list_content(text):
    """Parse Clash .list format (one rule per line), with fallback."""
    rules = set()
    total_meaningful = 0
    unrecognized = 0
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        total_meaningful += 1
        if is_rule_line(stripped):
            rules.add(stripped)
        else:
            fb = fallback_parse_line(stripped)
            if fb is not None and is_rule_line(fb):
                rules.add(fb)
            else:
                unrecognized += 1
    return rules, unrecognized


def parse_bare_domain_list(text):
    """Parse lists containing bare domain lines, with fallback.

    Handles formats like:
      - '.domain.tld' -> DOMAIN-SUFFIX,domain.tld
      - '*.domain.tld' -> DOMAIN-SUFFIX,domain.tld (domain wildcard)
      - 'domain.tld'  -> DOMAIN,domain.tld
    """
    rules = set()
    total_meaningful = 0
    unrecognized = 0
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        total_meaningful += 1
        parsed = False
        if stripped.startswith("*."):
            # Domain wildcard: *.domain.com -> DOMAIN-SUFFIX,domain.com
            rule = "DOMAIN-SUFFIX,{}".format(stripped[2:])
            if is_rule_line(rule):
                rules.add(rule)
                parsed = True
        elif stripped.startswith("."):
            rule = "DOMAIN-SUFFIX,{}".format(stripped[1:])
            if is_rule_line(rule):
                rules.add(rule)
                parsed = True
        elif "." in stripped and "," not in stripped and "/" not in stripped:
            rule = "DOMAIN,{}".format(stripped)
            if is_rule_line(rule):
                rules.add(rule)
                parsed = True
        if not parsed:
            fb = fallback_parse_line(stripped)
            if fb is not None and is_rule_line(fb):
                rules.add(fb)
            else:
                unrecognized += 1
    return rules, unrecognized


def parse_yaml_content(text):
    """Parse Clash .yaml payload section, with fallback.

    Handles:
      - Standard Clash rules: '- DOMAIN,example.com'
      - Bare domains: "- 'domain.com'" or "- domain.com" -> DOMAIN,domain.com
      - +.prefixed: "- '+.domain.com'" or "- +.domain.com" -> DOMAIN-SUFFIX,domain.com
      - Bare CIDRs: "- '1.0.0.0/24'" or "- 1.0.0.0/24" -> IP-CIDR,1.0.0.0/24
    """
    rules = set()
    total_meaningful = 0
    unrecognized = 0
    in_payload = False
    for line in text.splitlines():
        stripped = line.strip()
        if stripped == "payload:":
            in_payload = True
            continue
        if in_payload:
            if stripped.startswith("- "):
                entry = stripped[2:].strip()
                # Remove surrounding quotes
                if entry.startswith("'") and entry.endswith("'"):
                    entry = entry[1:-1]
                elif entry.startswith('"') and entry.endswith('"'):
                    entry = entry[1:-1]
                if entry.startswith("#") or entry.startswith("- #"):
                    continue
                total_meaningful += 1
                if "#" in entry:
                    entry = entry.split("#")[0].strip()
                parsed = False
                # Standard Clash rule
                if is_rule_line(entry):
                    rules.add(entry)
                    parsed = True
                elif "/" not in entry and "," not in entry and "." in entry:
                    # Bare domain
                    if entry.startswith("+."):
                        # Loyalsoldier-style: +.domain -> DOMAIN-SUFFIX,domain
                        rule = "DOMAIN-SUFFIX,{}".format(entry[2:])
                    elif entry.startswith("*."):
                        # Domain wildcard: *.domain -> DOMAIN-SUFFIX,domain
                        rule = "DOMAIN-SUFFIX,{}".format(entry[2:])
                    else:
                        rule = "DOMAIN,{}".format(entry)
                    if is_rule_line(rule):
                        rules.add(rule)
                        parsed = True
                elif "/" in entry and "," not in entry:
                    # Bare CIDR
                    rule = "IP-CIDR,{}".format(entry)
                    if is_rule_line(rule):
                        rules.add(rule)
                        parsed = True
                if not parsed:
                    fb = fallback_parse_line(entry)
                    if fb is not None and is_rule_line(fb):
                        rules.add(fb)
                    else:
                        unrecognized += 1
            elif stripped.startswith("#") or stripped == "":
                continue
            else:
                break
    return rules, unrecognized


def parse_surge_content(text):
    """Parse Surge format (type,value,policy), lowercased, with fallback."""
    rules = set()
    total_meaningful = 0
    unrecognized = 0
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or stripped.startswith("//") or stripped.startswith(";"):
            continue
        if stripped.startswith("/*") or stripped.startswith("*/"):
            continue
        if stripped.startswith("[") and stripped.endswith("]"):
            continue
        total_meaningful += 1
        parts = stripped.split(",")
        parsed = False
        if len(parts) >= 2:
            raw_type = parts[0].strip().lower()
            if raw_type in SURGE_TO_CLASH:
                clash_type = SURGE_TO_CLASH[raw_type]
                value = parts[1].strip()
                clash_rule = "{},{}".format(clash_type, value)
                if is_rule_line(clash_rule):
                    rules.add(clash_rule)
                    parsed = True
        if not parsed:
            fb = fallback_parse_line(stripped)
            if fb is not None and is_rule_line(fb):
                rules.add(fb)
            else:
                unrecognized += 1
    return rules, unrecognized


def parse_sgmodule_content(text):
    """Parse Surge module (.sgmodule/.plugin), [Rule] section, with fallback."""
    rules = set()
    total_meaningful = 0
    unrecognized = 0
    in_rule_section = False
    for line in text.splitlines():
        stripped = line.strip()
        if stripped.startswith("[") and stripped.endswith("]"):
            section_name = stripped[1:-1].lower()
            in_rule_section = (section_name == "rule")
            continue
        if not in_rule_section:
            continue
        if not stripped or stripped.startswith("#") or stripped.startswith("//") or stripped.startswith(";"):
            continue
        if stripped.startswith("/*") or stripped.startswith("*/"):
            continue
        total_meaningful += 1
        parts = stripped.split(",")
        parsed = False
        if len(parts) >= 2:
            raw_type = parts[0].strip().lower()
            if raw_type in SURGE_TO_CLASH:
                clash_type = SURGE_TO_CLASH[raw_type]
                value = parts[1].strip()
                clash_rule = "{},{}".format(clash_type, value)
                if is_rule_line(clash_rule):
                    rules.add(clash_rule)
                    parsed = True
        if not parsed:
            fb = fallback_parse_line(stripped)
            if fb is not None and is_rule_line(fb):
                rules.add(fb)
            else:
                unrecognized += 1
    return rules, unrecognized


def parse_quantumultx_content(text):
    """Parse Quantumult X format (TYPE,value,policy), with fallback.

    Also handles pre-converted Clash-format rules (TYPE,value) that may
    appear mixed in with QX-format rules, including those with a 3rd
    column (policy) that should be ignored.
    """
    rules = set()
    total_meaningful = 0
    unrecognized = 0
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        total_meaningful += 1
        parts = stripped.split(",")
        parsed = False
        if len(parts) >= 2:
            qx_type = parts[0].strip()
            if qx_type in QUANTUMULTX_TO_CLASH:
                clash_type = QUANTUMULTX_TO_CLASH[qx_type]
                value = parts[1].strip()
                clash_rule = "{},{}".format(clash_type, value)
                if is_rule_line(clash_rule):
                    rules.add(clash_rule)
                    parsed = True
            # Also try as a pre-converted Clash rule (e.g. DOMAIN-SUFFIX,domain,policy)
            if not parsed:
                # Try with first 2 parts (TYPE,value)
                clash_rule = "{},{}".format(parts[0].strip(), parts[1].strip())
                if is_rule_line(clash_rule):
                    rules.add(clash_rule)
                    parsed = True
        if not parsed:
            fb = fallback_parse_line(stripped)
            if fb is not None and is_rule_line(fb):
                rules.add(fb)
            else:
                unrecognized += 1
    return rules, unrecognized


def parse_loyalsoldier_content(text):
    """Parse Loyalsoldier format ('+.domain' -> DOMAIN-SUFFIX), with fallback."""
    rules = set()
    total_meaningful = 0
    unrecognized = 0
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
                total_meaningful += 1
                parsed = False
                if entry.startswith("+."):
                    domain = entry[2:]
                    rule = "DOMAIN-SUFFIX,{}".format(domain)
                    if is_rule_line(rule):
                        rules.add(rule)
                        parsed = True
                elif entry.startswith("*."):
                    # Domain wildcard: *.domain -> DOMAIN-SUFFIX,domain
                    domain = entry[2:]
                    rule = "DOMAIN-SUFFIX,{}".format(domain)
                    if is_rule_line(rule):
                        rules.add(rule)
                        parsed = True
                elif is_rule_line(entry):
                    rules.add(entry)
                    parsed = True
                if not parsed:
                    fb = fallback_parse_line(entry)
                    if fb is not None and is_rule_line(fb):
                        rules.add(fb)
                    else:
                        unrecognized += 1
            elif stripped.startswith("#") or stripped == "":
                continue
            else:
                break
    return rules, unrecognized


def parse_plain_text(text):
    """Parse plain text lines as DOMAIN-SUFFIX rules, with fallback."""
    rules = set()
    total_meaningful = 0
    unrecognized = 0
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        total_meaningful += 1
        rule = "DOMAIN-SUFFIX,{}".format(stripped)
        if is_rule_line(rule):
            rules.add(rule)
        else:
            fb = fallback_parse_line(stripped)
            if fb is not None and is_rule_line(fb):
                rules.add(fb)
            else:
                unrecognized += 1
    return rules, unrecognized


def parse_plain_cidr(text):
    """Parse plain CIDR lines (one IP-CIDR per line), with fallback."""
    rules = set()
    total_meaningful = 0
    unrecognized = 0
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        total_meaningful += 1
        if "/" in stripped:
            rule = "IP-CIDR,{}".format(stripped)
            if is_rule_line(rule):
                rules.add(rule)
            else:
                fb = fallback_parse_line(stripped)
                if fb is not None and is_rule_line(fb):
                    rules.add(fb)
                else:
                    unrecognized += 1
        else:
            fb = fallback_parse_line(stripped)
            if fb is not None and is_rule_line(fb):
                rules.add(fb)
            else:
                unrecognized += 1
    return rules, unrecognized


# ---------------------------------------------------------------------------
# Parser dispatch map
# ---------------------------------------------------------------------------

PARSER_MAP = {
    "list": parse_list_content,
    "yaml": parse_yaml_content,
    "surge": parse_surge_content,
    "sgmodule": parse_sgmodule_content,
    "quantumultx": parse_quantumultx_content,
    "loyalsoldier": parse_loyalsoldier_content,
    "plaintext": parse_plain_text,
    "plaincidr": parse_plain_cidr,
    "barelist": parse_bare_domain_list,
}


# ---------------------------------------------------------------------------
# Display name helpers (always show filename, disambiguate collisions)
# ---------------------------------------------------------------------------

# Map (repo, filename) -> count, populated before download phase
_REPO_FILENAME_COUNTS = {}


def _get_url_meta(url):
    """Parse a URL and return (repo, filename).

    Returns:
        (repo, filename) tuple. 'repo' is 'owner/repo' for github URLs,
        or the hostname for non-github URLs.
    """
    parts = url.split("/")
    filename = parts[-1] if parts[-1] else parts[-2]
    if "raw.githubusercontent.com" in url and len(parts) >= 5:
        repo = "{}/{}".format(parts[3], parts[4])
    elif "github.com" in url and len(parts) >= 5:
        repo = "{}/{}".format(parts[3], parts[4])
    else:
        repo = parts[2] if len(parts) > 2 else url
    return repo, filename


def _build_repo_filename_counts(tasks):
    """Pre-compute filename collision map from the task list.

    Args:
        tasks: list of (list_name, url, parser_type, headers)
    """
    counts = {}
    for _, url, _, _ in tasks:
        repo, filename = _get_url_meta(url)
        key = (repo, filename)
        counts[key] = counts.get(key, 0) + 1
    _REPO_FILENAME_COUNTS.clear()
    _REPO_FILENAME_COUNTS.update(counts)


def _display_name(url):
    """Return just the filename for a URL, with repo disambiguation if needed.

    If the same filename appears from multiple repos, appends ' (owner/repo)'.
    """
    repo, filename = _get_url_meta(url)
    # Check if this filename appears from multiple repos
    other_repos = set()
    for (r, fn), count in _REPO_FILENAME_COUNTS.items():
        if fn == filename and r != repo:
            other_repos.add(r)
    if other_repos:
        return "{} ({})".format(filename, repo)
    return filename


# ---------------------------------------------------------------------------
# Download + parse
# ---------------------------------------------------------------------------

def download_and_extract(url, parser_type, headers=None):
    """Download a single data source and parse rules.

    Args:
        url: Source URL to download.
        parser_type: Key into PARSER_MAP.
        headers: Optional custom headers (uses DEFAULT_HEADERS if None).

    Returns:
        set of rule strings.
    """
    if headers is None:
        headers = DEFAULT_HEADERS
    try:
        r = requests.get(url=url, headers=headers, timeout=120)
        r.raise_for_status()
        text = r.text
        parser = PARSER_MAP.get(parser_type, parse_list_content)
        rules, unrecognized = parser(text)
        if unrecognized > 0:
            print("  [OK] {} ({:,} bytes, {:,} rules, {:,} unrecognized)".format(
                _display_name(url), len(text), len(rules), unrecognized))
        else:
            print("  [OK] {} ({:,} bytes, {:,} rules)".format(
                _display_name(url), len(text), len(rules)))
        return rules
    except Exception as e:
        print("  [FAIL] {} - {}".format(_display_name(url), e))
        return set()
