"""
Generate all Clash rule lists in Clash/filter/auto/ with deduplication.

Aggregates rules from 200+ data sources across 36+ rule lists.
Downloads are performed concurrently using ThreadPoolExecutor.

AUTHOR: jshir700
REPO: https://github.com/jshir700/config
"""

from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone, timedelta
import os
import sys

# Ensure common.py is importable (same directory)
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from common import (
    RULE_TYPES, LOON_HEADERS, DEFAULT_HEADERS,
    download_and_extract, write_rule_list, count_rules_by_type,
    remove_subsumed_rules,
)

# ---------------------------------------------------------------------------
# Output directory
# ---------------------------------------------------------------------------
OUTPUT_DIR = "Clash/filter/auto"


# ---------------------------------------------------------------------------
# Rule list definitions
#
# Each entry: "ListName": (reference_line, [(url, parser_type, headers?), ...])
#   parser_type: "list", "yaml", "surge", "sgmodule", "quantumultx",
#                 "loyalsoldier", "plaintext", "plaincidr"
#   headers: None (use DEFAULT_HEADERS) or a dict for custom headers
# ---------------------------------------------------------------------------

RULE_LISTS = {}

# ---------------------------------------------------------------------------
# BanAD (Ad blocking / Reject list)
# ---------------------------------------------------------------------------
RULE_LISTS["Reject"] = (
    "# REFERENCE: https://github.com/ACL4SSR/ACL4SSR, "
    "https://github.com/NobyDa/Script, "
    "https://github.com/limbopro/Adblock4limbo, "
    "https://github.com/blackmatrix7/ios_rule_script, "
    "https://github.com/scomper/surge-list, "
    "https://github.com/sve1r/Rules-For-Quantumult-X, "
    "https://github.com/yjqiang/surge_scripts, "
    "https://github.com/Loyalsoldier/clash-rules, "
    "https://github.com/zqzess/rule_for_quantumultX",
    [
        ("https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/"
         "Clash/BanProgramAD.list", "list", None),
        ("https://raw.githubusercontent.com/NobyDa/Script/master/"
         "Surge/AdRule.list", "list", None),
        ("https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/"
         "Clash/BanProgramAD.list", "list", None),
        ("https://raw.githubusercontent.com/limbopro/Adblock4limbo/"
         "refs/heads/main/Adblock4limbo_surge.list", "surge", None),
        ("https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/"
         "Clash/BanEasyList.list", "list", None),
        ("https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/"
         "Clash/BanEasyListChina.list", "list", None),
        ("https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/"
         "refs/heads/master/rule/Clash/Advertising/Advertising.list", "list", None),
        ("https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/"
         "refs/heads/master/rule/Clash/ZhihuAds/ZhihuAds.list", "list", None),
        ("https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/"
         "Clash/BanEasyPrivacy.list", "list", None),
        ("https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/"
         "refs/heads/master/rule/Clash/EasyPrivacy/EasyPrivacy.list", "list", None),
        ("https://raw.githubusercontent.com/scomper/surge-list/"
         "master/reject.list", "list", None),
        ("https://raw.githubusercontent.com/scomper/surge-list/"
         "master/adblock.list", "list", None),
        ("https://raw.githubusercontent.com/sve1r/Rules-For-Quantumult-X/"
         "develop/Rules/Advertising/AdReject.list", "surge", None),
        ("https://raw.githubusercontent.com/sve1r/Rules-For-Quantumult-X/"
         "develop/Rules/Advertising/Hijacking.list", "surge", None),
        ("https://raw.githubusercontent.com/yjqiang/surge_scripts/"
         "main/modules/hupu/hupu.sgmodule", "sgmodule", None),
        ("https://raw.githubusercontent.com/Loyalsoldier/clash-rules/"
         "release/reject.txt", "loyalsoldier", None),
        ("https://raw.githubusercontent.com/zqzess/rule_for_quantumultX/"
         "master/QuantumultX/rules/AdBlock.list", "surge", None),
    ]
)

# ---------------------------------------------------------------------------
# Binance
# ---------------------------------------------------------------------------
RULE_LISTS["Binance"] = (
    "# REFERENCE: https://github.com/blackmatrix7/ios_rule_script, "
    "https://github.com/ACL4SSR/ACL4SSR, "
    "https://github.com/StricklandF/Filter",
    [
        ("https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/"
         "refs/heads/master/rule/Clash/Binance/Binance.list", "list", None),
        ("https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/"
         "Clash/Ruleset/Binance.list", "list", None),
        ("https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/"
         "Clash/Providers/Ruleset/Binance.yaml", "yaml", None),
        ("https://raw.githubusercontent.com/StricklandF/Filter/"
         "main/Binance.list", "surge", None),
    ]
)

# ---------------------------------------------------------------------------
# Scholar
# ---------------------------------------------------------------------------
RULE_LISTS["Scholar"] = (
    "# REFERENCE: https://github.com/ACL4SSR/ACL4SSR, "
    "https://github.com/LM-Firefly/Rules, "
    "https://github.com/dler-io/Rules, "
    "https://github.com/ke1ewang/Profiles, "
    "https://github.com/blackmatrix7/ios_rule_script",
    [
        ("https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/"
         "Clash/Ruleset/Scholar.list", "list", None),
        ("https://raw.githubusercontent.com/LM-Firefly/Rules/master/"
         "PROXY/Scholar.list", "list", None),
        ("https://raw.githubusercontent.com/dler-io/Rules/main/"
         "Clash/Provider/Scholar.yaml", "yaml", None),
        ("https://raw.githubusercontent.com/LM-Firefly/Rules/master/"
         "Clash-RuleSet-Classical/PROXY/Scholar.yaml", "yaml", None),
        ("https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/"
         "Clash/Providers/Ruleset/Scholar.yaml", "yaml", None),
        ("https://raw.githubusercontent.com/ke1ewang/Profiles/"
         "refs/heads/main/Surge/Ruleset/Extra/Scholar.list", "list", None),
        ("https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/"
         "refs/heads/master/rule/Clash/Scholar/Scholar.list", "list", None),
    ]
)

# ---------------------------------------------------------------------------
# Speedtest
# ---------------------------------------------------------------------------
RULE_LISTS["Speedtest"] = (
    "# REFERENCE: https://kelee.one, "
    "https://github.com/blackmatrix7/ios_rule_script, "
    "https://github.com/GeQ1an/Rules, "
    "https://github.com/dler-io/Rules",
    [
        ("https://kelee.one/Tool/Clash/Rule/SpeedtestChina.yaml",
         "yaml", LOON_HEADERS),
        ("https://kelee.one/Tool/Clash/Rule/SpeedtestInternational.yaml",
         "yaml", LOON_HEADERS),
        ("https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/"
         "refs/heads/master/rule/Clash/Speedtest/Speedtest.list", "list", None),
        ("https://raw.githubusercontent.com/GeQ1an/Rules/master/"
         "QuantumultX/Filter/Speedtest.list", "quantumultx", None),
        ("https://raw.githubusercontent.com/dler-io/Rules/main/"
         "Clash/Provider/Speedtest.yaml", "yaml", None),
    ]
)

RULE_LISTS["SteamCN"] = (
    "# REFERENCE: https://github.com/blackmatrix7/ios_rule_script, "
    "https://github.com/ACL4SSR/ACL4SSR",
    [
        ("https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/"
         "refs/heads/master/rule/Clash/SteamCN/SteamCN.list", "list", None),
        ("https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/"
         "Clash/Ruleset/SteamCN.list", "list", None),
        ("https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/"
         "Clash/Providers/Ruleset/SteamCN.yaml", "yaml", None),
    ]
)

RULE_LISTS["NetEaseMusic"] = (
    "# REFERENCE: https://github.com/blackmatrix7/ios_rule_script, "
    "https://github.com/ACL4SSR/ACL4SSR, https://github.com/LM-Firefly/Rules",
    [
        ("https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/"
         "refs/heads/master/rule/Clash/NetEaseMusic/NetEaseMusic.list", "list", None),
        ("https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/refs/heads/master/"
         "Clash/Ruleset/NetEaseMusic.list", "list", None),
        ("https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/"
         "Clash/Providers/Ruleset/NetEaseMusic.yaml", "yaml", None),
        ("https://raw.githubusercontent.com/LM-Firefly/Rules/master/"
         "Domestic-Services/NeteaseMusic.list", "list", None),
    ]
)

RULE_LISTS["115"] = (
    "# REFERENCE: https://github.com/blackmatrix7/ios_rule_script, "
    "https://github.com/LM-Firefly/Rules",
    [
        ("https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/"
         "refs/heads/master/rule/Clash/115/115.list", "list", None),
        ("https://raw.githubusercontent.com/LM-Firefly/Rules/master/"
         "Domestic-Services/115.list", "list", None),
    ]
)

RULE_LISTS["Bilibili"] = (
    "# REFERENCE: https://github.com/blackmatrix7/ios_rule_script, "
    "https://github.com/LM-Firefly/Rules, https://github.com/ACL4SSR/ACL4SSR",
    [
        ("https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/"
         "refs/heads/master/rule/Clash/BiliBili/BiliBili.list", "list", None),
        ("https://raw.githubusercontent.com/LM-Firefly/Rules/master/"
         "Domestic-Services/BiliBili.list", "list", None),
        ("https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/"
         "Clash/Ruleset/Bilibili.list", "list", None),
        ("https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/"
         "Clash/Providers/Ruleset/Bilibili.yaml", "yaml", None),
    ]
)

RULE_LISTS["AppleUpdate"] = (
    "# REFERENCE: https://github.com/blackmatrix7/ios_rule_script",
    [
        ("https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/"
         "refs/heads/master/rule/Loon/SystemOTA/SystemOTA.list", "list", None),
        ("https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/"
         "master/source/rule/SystemOTA/SystemOTA.list", "list", None),
    ]
)

RULE_LISTS["Douyu"] = (
    "# REFERENCE: https://github.com/blackmatrix7/ios_rule_script, "
    "https://github.com/ACL4SSR/ACL4SSR, https://github.com/LM-Firefly/Rules",
    [
        ("https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/"
         "master/rule/Loon/Douyu/Douyu.list", "list", None),
        ("https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/"
         "Clash/Ruleset/Douyu.list", "list", None),
        ("https://raw.githubusercontent.com/LM-Firefly/Rules/master/"
         "Domestic-Services/DouYu.list", "list", None),
        ("https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/"
         "Clash/Providers/Ruleset/Douyu.yaml", "yaml", None),
    ]
)

RULE_LISTS["DouYin"] = (
    "# REFERENCE: https://github.com/blackmatrix7/ios_rule_script, "
    "https://github.com/dler-io/Rules",
    [
        ("https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/"
         "master/rule/Loon/DouYin/DouYin.list", "list", None),
        ("https://raw.githubusercontent.com/dler-io/Rules/main/"
         "Clash/Provider/Douyin.yaml", "yaml", None),
    ]
)

RULE_LISTS["Baidu"] = (
    "# REFERENCE: https://github.com/blackmatrix7/ios_rule_script, "
    "https://github.com/ACL4SSR/ACL4SSR, https://github.com/LM-Firefly/Rules",
    [
        ("https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/"
         "master/rule/Loon/Baidu/Baidu.list", "list", None),
        ("https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/"
         "Clash/Ruleset/Baidu.list", "list", None),
        ("https://raw.githubusercontent.com/LM-Firefly/Rules/master/"
         "Domestic-Services/BaiDu.list", "list", None),
    ]
)

RULE_LISTS["WeChat"] = (
    "# REFERENCE: https://github.com/blackmatrix7/ios_rule_script, "
    "https://github.com/ACL4SSR/ACL4SSR",
    [
        ("https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/"
         "master/rule/Loon/WeChat/WeChat.list", "list", None),
        ("https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/"
         "Clash/Ruleset/Wechat.list", "list", None),
        ("https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/"
         "Clash/Providers/Ruleset/Wechat.yaml", "yaml", None),
    ]
)

RULE_LISTS["Weibo"] = (
    "# REFERENCE: https://github.com/blackmatrix7/ios_rule_script",
    [
        ("https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/"
         "master/rule/Loon/Weibo/Weibo.list", "list", None),
        ("https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/"
         "master/source/rule/Weibo/Weibo.list", "list", None),
    ]
)

RULE_LISTS["XPTV"] = (
    "# REFERENCE: https://github.com/fangkuia/XPTV",
    [
        ("https://raw.githubusercontent.com/fangkuia/XPTV/main/X/xptv.plugin",
         "sgmodule", None),
    ]
)

RULE_LISTS["ChinaMedia"] = (
    "# REFERENCE: https://github.com/blackmatrix7/ios_rule_script, "
    "https://github.com/LM-Firefly/Rules, https://github.com/ACL4SSR/ACL4SSR, "
    "https://github.com/sve1r/Rules-For-Quantumult-X, "
    "https://github.com/zqzess/rule_for_quantumultX",
    [
        ("https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/"
         "refs/heads/master/rule/Clash/ChinaMedia/ChinaMedia.list", "list", None),
        ("https://raw.githubusercontent.com/LM-Firefly/Rules/master/"
         "Domestic-Services/BiliBili.list", "list", None),
        ("https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/"
         "Clash/Ruleset/CCTV.list", "list", None),
        ("https://raw.githubusercontent.com/LM-Firefly/Rules/master/"
         "Domestic-Services/CCTV.list", "list", None),
        ("https://raw.githubusercontent.com/sve1r/Rules-For-Quantumult-X/"
         "develop/Rules/Media/DomesticMedia.list", "surge", None),
        ("https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/"
         "Clash/Ruleset/Bilibili.list", "list", None),
        ("https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/"
         "Clash/Providers/Ruleset/Bilibili.yaml", "yaml", None),
        ("https://raw.githubusercontent.com/zqzess/rule_for_quantumultX/"
         "master/QuantumultX/rules/CMedia.list", "quantumultx", None),
        ("https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/refs/heads/master/"
         "Clash/ChinaMedia.list", "list", None),
    ]
)

# NOTE: China.list is defined separately below because it needs
# special exclusion logic (must exclude rules from all other auto lists).

RULE_LISTS["Microsoft"] = (
    "# REFERENCE: https://github.com/blackmatrix7/ios_rule_script, "
    "https://github.com/ACL4SSR/ACL4SSR, https://github.com/sve1r/Rules-For-Quantumult-X, "
    "https://github.com/dler-io/Rules, https://github.com/zqzess/rule_for_quantumultX",
    [
        ("https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/"
         "refs/heads/master/rule/Clash/Microsoft/Microsoft.list", "list", None),
        ("https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/"
         "Clash/Ruleset/OneDrive.list", "list", None),
        ("https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/"
         "Clash/OneDrive.list", "list", None),
        ("https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/"
         "Clash/Ruleset/Microsoft.list", "list", None),
        ("https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/"
         "Clash/Microsoft.list", "list", None),
        ("https://raw.githubusercontent.com/sve1r/Rules-For-Quantumult-X/"
         "develop/Rules/Services/Microsoft.list", "surge", None),
        ("https://raw.githubusercontent.com/dler-io/Rules/main/"
         "Clash/Provider/Microsoft.yaml", "yaml", None),
        ("https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/"
         "Clash/Providers/Ruleset/Microsoft.yaml", "yaml", None),
        ("https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/"
         "Clash/Providers/Ruleset/OneDrive.yaml", "yaml", None),
        ("https://raw.githubusercontent.com/zqzess/rule_for_quantumultX/"
         "master/QuantumultX/rules/Microsoft.list", "quantumultx", None),
    ]
)

RULE_LISTS["Download"] = (
    "# REFERENCE: https://github.com/blackmatrix7/ios_rule_script, "
    "https://github.com/ACL4SSR/ACL4SSR, https://github.com/LM-Firefly/Rules",
    [
        ("https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/"
         "refs/heads/master/rule/Clash/Download/Download.list", "list", None),
        ("https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/"
         "Clash/Download.list", "list", None),
        ("https://raw.githubusercontent.com/LM-Firefly/Rules/master/"
         "Special/Download.list", "list", None),
        ("https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/"
         "Clash/Ruleset/Download.list", "list", None),
        ("https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/"
         "Clash/Providers/Ruleset/Download.yaml", "yaml", None),
    ]
)

RULE_LISTS["GoogleFCM"] = (
    "# REFERENCE: https://github.com/blackmatrix7/ios_rule_script, "
    "https://github.com/dler-io/Rules, https://github.com/ACL4SSR/ACL4SSR",
    [
        ("https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/"
         "refs/heads/master/rule/Clash/GoogleFCM/GoogleFCM.list", "list", None),
        ("https://raw.githubusercontent.com/dler-io/Rules/main/"
         "Clash/Provider/Google%20FCM.yaml", "yaml", None),
        ("https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/"
         "Clash/Ruleset/GoogleFCM.list", "list", None),
        ("https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/"
         "Clash/Providers/Ruleset/GoogleFCM.yaml", "yaml", None),
    ]
)

RULE_LISTS["Instagram"] = (
    "# REFERENCE: https://github.com/blackmatrix7/ios_rule_script, "
    "https://github.com/ACL4SSR/ACL4SSR",
    [
        ("https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/"
         "refs/heads/master/rule/Clash/Instagram/Instagram.list", "list", None),
        ("https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/"
         "Clash/Ruleset/Instagram.list", "list", None),
        ("https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/"
         "Clash/Providers/Ruleset/Instagram.yaml", "yaml", None),
    ]
)

RULE_LISTS["Google"] = (
    "# REFERENCE: https://github.com/blackmatrix7/ios_rule_script, "
    "https://github.com/Loyalsoldier/surge-rules, https://github.com/Loyalsoldier/clash-rules, "
    "https://github.com/sve1r/Rules-For-Quantumult-X, https://github.com/LM-Firefly/Rules, "
    "https://github.com/ACL4SSR/ACL4SSR",
    [
        ("https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/"
         "refs/heads/master/rule/Clash/Google/Google.list", "list", None),
        ("https://raw.githubusercontent.com/Loyalsoldier/surge-rules/"
         "release/ruleset/google.txt", "list", None),
        ("https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/"
         "master/source/rule/Google/Google.list", "list", None),
        ("https://raw.githubusercontent.com/sve1r/Rules-For-Quantumult-X/"
         "develop/Rules/Services/Google.list", "surge", None),
        ("https://raw.githubusercontent.com/LM-Firefly/Rules/master/"
         "PROXY/Google.list", "list", None),
        ("https://raw.githubusercontent.com/Loyalsoldier/clash-rules/"
         "release/google.txt", "loyalsoldier", None),
        ("https://raw.githubusercontent.com/LM-Firefly/Rules/master/"
         "Clash-RuleSet-Classical/PROXY/Google.yaml", "yaml", None),
        ("https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/"
         "Clash/Ruleset/Google.list", "list", None),
        ("https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/"
         "Clash/Providers/Ruleset/Google.yaml", "yaml", None),
    ]
)

RULE_LISTS["YouTube"] = (
    "# REFERENCE: https://github.com/blackmatrix7/ios_rule_script, "
    "https://github.com/ACL4SSR/ACL4SSR, https://github.com/GeQ1an/Rules, "
    "https://github.com/LM-Firefly/Rules",
    [
        ("https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/"
         "refs/heads/master/rule/Clash/YouTube/YouTube.list", "list", None),
        ("https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/"
         "Clash/Ruleset/YouTube.list", "list", None),
        ("https://raw.githubusercontent.com/GeQ1an/Rules/master/"
         "QuantumultX/Filter/Optional/YouTube.list", "quantumultx", None),
        ("https://raw.githubusercontent.com/LM-Firefly/Rules/master/"
         "Global-Services/YouTube.list", "list", None),
        ("https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/"
         "Clash/Providers/Ruleset/YouTube.yaml", "yaml", None),
        ("https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/"
         "refs/heads/master/rule/Clash/YouTube/YouTube.list", "list", None),
        ("https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/"
         "refs/heads/master/rule/Loon/YouTubeMusic/YouTubeMusic.list", "list", None),
        ("https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/"
         "Clash/Ruleset/YouTubeMusic.list", "list", None),
        ("https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/"
         "Clash/Providers/Ruleset/YouTubeMusic.yaml", "yaml", None),
    ]
)

RULE_LISTS["Netflix"] = (
    "# REFERENCE: https://github.com/blackmatrix7/ios_rule_script, "
    "https://github.com/ACL4SSR/ACL4SSR, https://github.com/GeQ1an/Rules, "
    "https://github.com/LM-Firefly/Rules, https://github.com/QiuSimons/Netflix_IP, "
    "https://github.com/zqzess/rule_for_quantumultX",
    [
        ("https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/"
         "refs/heads/master/rule/Clash/Netflix/Netflix.list", "list", None),
        ("https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/"
         "Clash/Ruleset/Netflix.list", "list", None),
        ("https://raw.githubusercontent.com/GeQ1an/Rules/master/"
         "QuantumultX/Filter/Optional/Netflix.list", "quantumultx", None),
        ("https://raw.githubusercontent.com/LM-Firefly/Rules/master/"
         "Global-Services/Netflix.list", "list", None),
        ("https://raw.githubusercontent.com/QiuSimons/Netflix_IP/"
         "master/getflix.txt", "plaincidr", None),
        ("https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/"
         "Clash/Ruleset/NetflixIP.list", "list", None),
        ("https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/"
         "Clash/Providers/Ruleset/Netflix.yaml", "yaml", None),
        ("https://raw.githubusercontent.com/zqzess/rule_for_quantumultX/"
         "master/QuantumultX/rules/Netflix.list", "quantumultx", None),
        ("https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/"
         "Clash/Providers/Ruleset/NetflixIP.yaml", "yaml", None),
    ]
)

RULE_LISTS["Bahamut"] = (
    "# REFERENCE: https://github.com/blackmatrix7/ios_rule_script, "
    "https://github.com/LM-Firefly/Rules, https://github.com/ACL4SSR/ACL4SSR",
    [
        ("https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/"
         "refs/heads/master/rule/Clash/Bahamut/Bahamut.list", "list", None),
        ("https://raw.githubusercontent.com/LM-Firefly/Rules/master/"
         "Global-Services/Bahamut.list", "list", None),
        ("https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/"
         "Clash/Ruleset/Bahamut.list", "list", None),
        ("https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/"
         "Clash/Providers/Ruleset/Bahamut.yaml", "yaml", None),
    ]
)

RULE_LISTS["Telegram"] = (
    "# REFERENCE: https://github.com/blackmatrix7/ios_rule_script, "
    "https://github.com/ACL4SSR/ACL4SSR, https://github.com/Hackl0us/SS-Rule-Snippet, "
    "https://github.com/Loyalsoldier/surge-rules, https://github.com/GeQ1an/Rules, "
    "https://github.com/sve1r/Rules-For-Quantumult-X, https://github.com/LM-Firefly/Rules, "
    "https://github.com/Loyalsoldier/clash-rules, https://core.telegram.org, "
    "https://github.com/dler-io/Rules",
    [
        ("https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/"
         "refs/heads/master/rule/Clash/Telegram/Telegram.list", "list", None),
        ("https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/"
         "Clash/Ruleset/Telegram.list", "list", None),
        ("https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/"
         "Clash/Telegram.list", "list", None),
        ("https://raw.githubusercontent.com/Hackl0us/SS-Rule-Snippet/"
         "master/Rulesets/Surge/App/social/Telegram.list", "list", None),
        ("https://raw.githubusercontent.com/Loyalsoldier/surge-rules/"
         "release/ruleset/telegramcidr.txt", "surge", None),
        ("https://raw.githubusercontent.com/GeQ1an/Rules/master/"
         "QuantumultX/Filter/Optional/Telegram.list", "quantumultx", None),
        ("https://raw.githubusercontent.com/sve1r/Rules-For-Quantumult-X/"
         "develop/Rules/Services/SNS/Telegram.list", "surge", None),
        ("https://raw.githubusercontent.com/LM-Firefly/Rules/master/"
         "PROXY/Telegram.list", "list", None),
        ("https://raw.githubusercontent.com/Loyalsoldier/clash-rules/"
         "release/telegramcidr.txt", "loyalsoldier", None),
        ("https://core.telegram.org/resources/cidr.txt", "plaincidr", None),
        ("https://raw.githubusercontent.com/dler-io/Rules/main/"
         "Clash/Provider/Telegram.yaml", "yaml", None),
        ("https://raw.githubusercontent.com/LM-Firefly/Rules/master/"
         "Clash-RuleSet-Classical/PROXY/Telegram.yaml", "yaml", None),
        ("https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/"
         "Clash/Providers/Ruleset/Telegram.yaml", "yaml", None),
    ]
)

RULE_LISTS["AI"] = (
    "# REFERENCE: https://github.com/blackmatrix7/ios_rule_script, "
    "https://github.com/ACL4SSR/ACL4SSR",
    [
        ("https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/"
         "refs/heads/master/rule/Clash/OpenAI/OpenAI.list", "list", None),
        ("https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/"
         "Clash/Providers/Ruleset/OpenAi.yaml", "yaml", None),
        ("https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/"
         "Clash/Ruleset/OpenAi.list", "list", None),
        ("https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/"
         "Clash/Ruleset/AI.list", "list", None),
    ]
)

RULE_LISTS["LinkedIn"] = (
    "# REFERENCE: https://github.com/blackmatrix7/ios_rule_script",
    [
        ("https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/"
         "refs/heads/master/rule/Clash/LinkedIn/LinkedIn.list", "list", None),
    ]
)

RULE_LISTS["Apple"] = (
    "# REFERENCE: https://github.com/blackmatrix7/ios_rule_script, "
    "https://github.com/Loyalsoldier/surge-rules, https://github.com/ACL4SSR/ACL4SSR, "
    "https://github.com/GeQ1an/Rules, https://github.com/sve1r/Rules-For-Quantumult-X, "
    "https://github.com/Hackl0us/SS-Rule-Snippet, https://github.com/Loyalsoldier/clash-rules, "
    "https://github.com/dler-io/Rules, https://github.com/LM-Firefly/Rules, "
    "https://github.com/zqzess/rule_for_quantumultX",
    [
        ("https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/"
         "refs/heads/master/rule/Clash/Apple/Apple.list", "list", None),
        ("https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/"
         "master/source/rule/AppStore/AppStore.list", "list", None),
        ("https://raw.githubusercontent.com/Loyalsoldier/surge-rules/"
         "release/ruleset/icloud.txt", "list", None),
        ("https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/"
         "master/source/rule/TestFlight/TestFlight.list", "list", None),
        ("https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/"
         "Clash/Ruleset/AppleNews.list", "list", None),
        ("https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/"
         "Clash/Ruleset/AppleTV.list", "list", None),
        ("https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/"
         "Clash/Ruleset/Apple.list", "list", None),
        ("https://raw.githubusercontent.com/Loyalsoldier/surge-rules/"
         "release/ruleset/apple.txt", "list", None),
        ("https://raw.githubusercontent.com/GeQ1an/Rules/master/"
         "QuantumultX/Filter/Apple.list", "quantumultx", None),
        ("https://raw.githubusercontent.com/sve1r/Rules-For-Quantumult-X/"
         "develop/Rules/Services/Apple.list", "surge", None),
        ("https://raw.githubusercontent.com/Hackl0us/SS-Rule-Snippet/"
         "master/Rulesets/Surge/Basic/Apple-proxy.list", "list", None),
        ("https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/"
         "master/source/rule/AppleBlock/AppleBlock.list", "list", None),
        ("https://raw.githubusercontent.com/Loyalsoldier/clash-rules/"
         "release/apple.txt", "loyalsoldier", None),
        ("https://raw.githubusercontent.com/Loyalsoldier/clash-rules/"
         "release/icloud.txt", "loyalsoldier", None),
        ("https://raw.githubusercontent.com/dler-io/Rules/main/"
         "Clash/Provider/Apple.yaml", "yaml", None),
        ("https://raw.githubusercontent.com/LM-Firefly/Rules/master/"
         "Apple/AppleFirmware.list", "list", None),
        ("https://raw.githubusercontent.com/LM-Firefly/Rules/master/"
         "Apple/AppleHardware.list", "list", None),
        ("https://raw.githubusercontent.com/LM-Firefly/Rules/master/"
         "Apple/AppleMedia.list", "list", None),
        ("https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/"
         "Clash/Providers/Ruleset/Apple.yaml", "yaml", None),
        ("https://raw.githubusercontent.com/zqzess/rule_for_quantumultX/"
         "master/QuantumultX/rules/Apple.list", "quantumultx", None),
        ("https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/"
         "Clash/Providers/Ruleset/AppleNews.yaml", "yaml", None),
        ("https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/"
         "Clash/Providers/Ruleset/AppleTV.yaml", "yaml", None),
    ]
)

RULE_LISTS["Game"] = (
    "# REFERENCE: https://github.com/blackmatrix7/ios_rule_script, "
    "https://github.com/sve1r/Rules-For-Quantumult-X, https://github.com/LM-Firefly/Rules, "
    "https://github.com/ACL4SSR/ACL4SSR, https://github.com/dler-io/Rules",
    [
        # Epic
        ("https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/"
         "refs/heads/master/rule/Clash/Epic/Epic.list", "list", None),
        ("https://raw.githubusercontent.com/sve1r/Rules-For-Quantumult-X/"
         "develop/Rules/Games/Epic.list", "surge", None),
        ("https://raw.githubusercontent.com/LM-Firefly/Rules/master/"
         "Game/Epicgames.list", "list", None),
        ("https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/"
         "Clash/Ruleset/Epic.list", "list", None),
        ("https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/"
         "Clash/Providers/Ruleset/Epic.yaml", "yaml", None),
        # Origin
        ("https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/"
         "refs/heads/master/rule/Clash/Origin/Origin.list", "list", None),
        ("https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/"
         "Clash/Providers/Ruleset/Origin.yaml", "yaml", None),
        ("https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/"
         "Clash/Ruleset/Origin.list", "list", None),
        # Sony
        ("https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/"
         "refs/heads/master/rule/Clash/Sony/Sony.list", "list", None),
        ("https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/"
         "Clash/Ruleset/Sony.list", "list", None),
        ("https://raw.githubusercontent.com/LM-Firefly/Rules/master/"
         "Global-Services/Sony.list", "list", None),
        ("https://raw.githubusercontent.com/LM-Firefly/Rules/master/"
         "PROXY/Sony.list", "list", None),
        ("https://raw.githubusercontent.com/LM-Firefly/Rules/master/"
         "Clash-RuleSet-Classical/PROXY/Sony.yaml", "yaml", None),
        ("https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/"
         "Clash/Providers/Ruleset/Sony.yaml", "yaml", None),
        # Steam
        ("https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/"
         "refs/heads/master/rule/Clash/Steam/Steam.list", "list", None),
        ("https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/"
         "Clash/Ruleset/Steam.list", "list", None),
        ("https://raw.githubusercontent.com/LM-Firefly/Rules/master/"
         "Game/Steam.list", "list", None),
        ("https://raw.githubusercontent.com/dler-io/Rules/main/"
         "Clash/Provider/Steam.yaml", "yaml", None),
        ("https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/"
         "Clash/Providers/Ruleset/Steam.yaml", "yaml", None),
        # Nintendo
        ("https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/"
         "refs/heads/master/rule/Clash/Nintendo/Nintendo.list", "list", None),
        ("https://raw.githubusercontent.com/LM-Firefly/Rules/master/"
         "Game/Nintendo.list", "list", None),
        ("https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/"
         "Clash/Providers/Ruleset/Nintendo.yaml", "yaml", None),
        ("https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/"
         "Clash/Ruleset/Nintendo.list", "list", None),
        # Blizzard
        ("https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/"
         "master/rule/Clash/Blizzard/Blizzard.list", "list", None),
        ("https://raw.githubusercontent.com/LM-Firefly/Rules/master/"
         "Game/Blizzard.list", "list", None),
        ("https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/"
         "Clash/Ruleset/Blizzard.list", "list", None),
        ("https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/"
         "Clash/Providers/Ruleset/Blizzard.yaml", "yaml", None),
    ]
)

RULE_LISTS["PayPal"] = (
    "# REFERENCE: https://github.com/blackmatrix7/ios_rule_script, "
    "https://github.com/GeQ1an/Rules, https://github.com/sve1r/Rules-For-Quantumult-X, "
    "https://github.com/LM-Firefly/Rules, https://github.com/dler-io/Rules",
    [
        ("https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/"
         "refs/heads/master/rule/Clash/PayPal/PayPal.list", "list", None),
        ("https://raw.githubusercontent.com/GeQ1an/Rules/master/"
         "QuantumultX/Filter/Optional/PayPal.list", "quantumultx", None),
        ("https://raw.githubusercontent.com/sve1r/Rules-For-Quantumult-X/"
         "develop/Rules/Services/Paypal.list", "surge", None),
        ("https://raw.githubusercontent.com/LM-Firefly/Rules/master/"
         "PROXY/PayPal.list", "list", None),
        ("https://raw.githubusercontent.com/dler-io/Rules/main/"
         "Clash/Provider/PayPal.yaml", "yaml", None),
        ("https://raw.githubusercontent.com/LM-Firefly/Rules/master/"
         "Clash-RuleSet-Classical/PROXY/PayPal.yaml", "yaml", None),
    ]
)

RULE_LISTS["HBO"] = (
    "# REFERENCE: https://github.com/blackmatrix7/ios_rule_script, "
    "https://github.com/LM-Firefly/Rules, https://github.com/ACL4SSR/ACL4SSR",
    [
        ("https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/"
         "master/rule/Loon/HBO/HBO.list", "list", None),
        ("https://raw.githubusercontent.com/LM-Firefly/Rules/master/"
         "Global-Services/HBO.list", "list", None),
        ("https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/"
         "Clash/Ruleset/HBO.list", "list", None),
        ("https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/"
         "Clash/Providers/Ruleset/HBO.yaml", "yaml", None),
    ]
)

RULE_LISTS["TikTok"] = (
    "# REFERENCE: https://github.com/blackmatrix7/ios_rule_script, "
    "https://github.com/ACL4SSR/ACL4SSR, https://github.com/LM-Firefly/Rules, "
    "https://github.com/Semporia/Quantumult-X",
    [
        ("https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/"
         "master/rule/Loon/TikTok/TikTok.list", "list", None),
        ("https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/"
         "Clash/Ruleset/TikTok.list", "list", None),
        ("https://raw.githubusercontent.com/LM-Firefly/Rules/master/"
         "Global-Services/TikTok.list", "list", None),
        ("https://raw.githubusercontent.com/Semporia/Quantumult-X/"
         "master/Filter/TikTok.list", "list", None),
        ("https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/"
         "Clash/Providers/Ruleset/TikTok.yaml", "yaml", None),
    ]
)

RULE_LISTS["Twitch"] = (
    "# REFERENCE: https://github.com/blackmatrix7/ios_rule_script, "
    "https://github.com/LM-Firefly/Rules, https://github.com/ACL4SSR/ACL4SSR",
    [
        ("https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/"
         "master/rule/Loon/Twitch/Twitch.list", "list", None),
        ("https://raw.githubusercontent.com/LM-Firefly/Rules/master/"
         "PROXY/Twitch.list", "list", None),
        ("https://raw.githubusercontent.com/LM-Firefly/Rules/master/"
         "Clash-RuleSet-Classical/PROXY/Twitch.yaml", "yaml", None),
        ("https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/"
         "Clash/Ruleset/Twitch.list", "list", None),
        ("https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/"
         "Clash/Providers/Ruleset/Twitch.yaml", "yaml", None),
    ]
)

RULE_LISTS["Disney"] = (
    "# REFERENCE: https://github.com/blackmatrix7/ios_rule_script, "
    "https://github.com/LM-Firefly/Rules",
    [
        ("https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/"
         "master/rule/Loon/Disney/Disney.list", "list", None),
        ("https://raw.githubusercontent.com/LM-Firefly/Rules/master/"
         "Global-Services/Disney.list", "list", None),
    ]
)

RULE_LISTS["Whatsapp"] = (
    "# REFERENCE: https://github.com/blackmatrix7/ios_rule_script, "
    "https://github.com/ACL4SSR/ACL4SSR, https://github.com/Hackl0us/SS-Rule-Snippet",
    [
        ("https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/"
         "master/rule/Loon/Whatsapp/Whatsapp.list", "list", None),
        ("https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/"
         "Clash/Ruleset/Whatsapp.list", "list", None),
        ("https://raw.githubusercontent.com/Hackl0us/SS-Rule-Snippet/"
         "master/Rulesets/Surge/App/social/WhatsApp.list", "list", None),
        ("https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/"
         "Clash/Providers/Ruleset/Whatsapp.yaml", "yaml", None),
    ]
)

RULE_LISTS["Facebook"] = (
    "# REFERENCE: https://github.com/blackmatrix7/ios_rule_script, "
    "https://github.com/sve1r/Rules-For-Quantumult-X, https://github.com/LM-Firefly/Rules, "
    "https://github.com/ACL4SSR/ACL4SSR, https://github.com/tkzc11/QX-Rules",
    [
        ("https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/"
         "master/rule/Loon/Facebook/Facebook.list", "list", None),
        ("https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/"
         "master/source/rule/Facebook/Facebook.list", "list", None),
        ("https://raw.githubusercontent.com/sve1r/Rules-For-Quantumult-X/"
         "develop/Rules/Services/SNS/Facebook.list", "surge", None),
        ("https://raw.githubusercontent.com/LM-Firefly/Rules/master/"
         "PROXY/Facebook.list", "list", None),
        ("https://raw.githubusercontent.com/LM-Firefly/Rules/master/"
         "Clash-RuleSet-Classical/PROXY/Facebook.yaml", "yaml", None),
        ("https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/"
         "Clash/Ruleset/Facebook.list", "list", None),
        ("https://raw.githubusercontent.com/tkzc11/QX-Rules/main/"
         "Meta.list", "list", None),
        ("https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/"
         "Clash/Providers/Ruleset/Facebook.yaml", "yaml", None),
    ]
)

RULE_LISTS["Twitter"] = (
    "# REFERENCE: https://github.com/blackmatrix7/ios_rule_script, "
    "https://github.com/ACL4SSR/ACL4SSR, https://github.com/sve1r/Rules-For-Quantumult-X, "
    "https://github.com/LM-Firefly/Rules",
    [
        ("https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/"
         "master/rule/Loon/Twitter/Twitter.list", "list", None),
        ("https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/"
         "master/source/rule/Twitter/Twitter.list", "list", None),
        ("https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/"
         "Clash/Ruleset/Twitter.list", "list", None),
        ("https://raw.githubusercontent.com/sve1r/Rules-For-Quantumult-X/"
         "develop/Rules/Services/SNS/Twitter.list", "surge", None),
        ("https://raw.githubusercontent.com/LM-Firefly/Rules/master/"
         "PROXY/Twitter.list", "list", None),
        ("https://raw.githubusercontent.com/LM-Firefly/Rules/master/"
         "Clash-RuleSet-Classical/PROXY/Twitter.yaml", "yaml", None),
        ("https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/"
         "Clash/Providers/Ruleset/Twitter.yaml", "yaml", None),
    ]
)

RULE_LISTS["GitHub"] = (
    "# REFERENCE: https://github.com/blackmatrix7/ios_rule_script, "
    "https://github.com/ACL4SSR/ACL4SSR, https://github.com/LM-Firefly/Rules",
    [
        ("https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/"
         "master/rule/Loon/GitHub/GitHub.list", "list", None),
        ("https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/"
         "Clash/Ruleset/Github.list", "list", None),
        ("https://raw.githubusercontent.com/LM-Firefly/Rules/master/"
         "PROXY/Github.list", "list", None),
        ("https://raw.githubusercontent.com/LM-Firefly/Rules/master/"
         "Clash-RuleSet-Classical/PROXY/Github.yaml", "yaml", None),
        ("https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/"
         "Clash/Providers/Ruleset/Github.yaml", "yaml", None),
    ]
)

RULE_LISTS["Discord"] = (
    "# REFERENCE: https://github.com/blackmatrix7/ios_rule_script, "
    "https://github.com/ACL4SSR/ACL4SSR, https://github.com/LM-Firefly/Rules",
    [
        ("https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/"
         "master/rule/Loon/Discord/Discord.list", "list", None),
        ("https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/"
         "Clash/Ruleset/Discord.list", "list", None),
        ("https://raw.githubusercontent.com/LM-Firefly/Rules/master/"
         "PROXY/Discord.list", "list", None),
        ("https://raw.githubusercontent.com/LM-Firefly/Rules/master/"
         "Clash-RuleSet-Classical/PROXY/Discord.yaml", "yaml", None),
        ("https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/"
         "Clash/Providers/Ruleset/Discord.yaml", "yaml", None),
    ]
)

RULE_LISTS["GlobalMedia"] = (
    "# REFERENCE: https://github.com/blackmatrix7/ios_rule_script, "
    "https://github.com/ACL4SSR/ACL4SSR, https://github.com/GeQ1an/Rules, "
    "https://github.com/LM-Firefly/Rules, https://github.com/sve1r/Rules-For-Quantumult-X, "
    "https://github.com/zqzess/rule_for_quantumultX",
    [
        ("https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/"
         "refs/heads/master/rule/Clash/GlobalMedia/GlobalMedia.yaml", "yaml", None),
        ("https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/"
         "refs/heads/master/rule/Clash/GlobalMedia/GlobalMedia_Domain.yaml", "yaml", None),
        ("https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/"
         "Clash/Ruleset/YouTube.list", "list", None),
        ("https://raw.githubusercontent.com/GeQ1an/Rules/master/"
         "QuantumultX/Filter/Optional/YouTube.list", "quantumultx", None),
        ("https://raw.githubusercontent.com/LM-Firefly/Rules/master/"
         "Global-Services/YouTube.list", "list", None),
        ("https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/"
         "Clash/Ruleset/YouTubeMusic.list", "list", None),
        ("https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/"
         "Clash/ProxyMedia.list", "list", None),
        ("https://raw.githubusercontent.com/sve1r/Rules-For-Quantumult-X/"
         "develop/Rules/Media/ForeignMedia.list", "surge", None),
        ("https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/"
         "Clash/Providers/Ruleset/YouTube.yaml", "yaml", None),
        ("https://raw.githubusercontent.com/zqzess/rule_for_quantumultX/"
         "master/QuantumultX/rules/GMedia.list", "quantumultx", None),
        ("https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/"
         "Clash/Providers/Ruleset/YouTubeMusic.yaml", "yaml", None),
    ]
)

RULE_LISTS["Global"] = (
    "# REFERENCE: https://github.com/blackmatrix7/ios_rule_script, "
    "https://github.com/sve1r/Rules-For-Quantumult-X, https://github.com/ACL4SSR/ACL4SSR, "
    "https://github.com/Hackl0us/SS-Rule-Snippet, https://github.com/Loyalsoldier/surge-rules, "
    "https://github.com/GeQ1an/Rules, https://github.com/Loyalsoldier/clash-rules, "
    "https://github.com/dler-io/Rules",
    [
        ("https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/"
         "refs/heads/master/rule/Clash/Global/Global.yaml", "yaml", None),
        ("https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/"
         "refs/heads/master/rule/Clash/Global/Global_Domain.yaml", "yaml", None),
        ("https://raw.githubusercontent.com/sve1r/Rules-For-Quantumult-X/"
         "develop/Rules/Region/Global.list", "surge", None),
        ("https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/"
         "master/source/rule/BlackList/BlackList.list", "list", None),
        ("https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/"
         "Clash/ProxyGFWlist.list", "list", None),
        ("https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/"
         "Clash/ProxyLite.list", "list", None),
        ("https://raw.githubusercontent.com/Hackl0us/SS-Rule-Snippet/"
         "master/Rulesets/Surge/Basic/foreign.list", "list", None),
        ("https://raw.githubusercontent.com/Hackl0us/SS-Rule-Snippet/"
         "master/Rulesets/Surge/Basic/Apple-proxy.list", "list", None),
        ("https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/"
         "master/source/rule/Proxy/Proxy.list", "list", None),
        ("https://raw.githubusercontent.com/Loyalsoldier/surge-rules/"
         "release/ruleset/greatfire.txt", "list", None),
        ("https://raw.githubusercontent.com/Loyalsoldier/surge-rules/"
         "release/ruleset/gfw.txt", "list", None),
        ("https://raw.githubusercontent.com/GeQ1an/Rules/master/"
         "QuantumultX/Filter/Outside.list", "quantumultx", None),
        ("https://raw.githubusercontent.com/Loyalsoldier/clash-rules/"
         "release/gfw.txt", "loyalsoldier", None),
        ("https://raw.githubusercontent.com/Loyalsoldier/clash-rules/"
         "release/greatfire.txt", "loyalsoldier", None),
        ("https://raw.githubusercontent.com/Loyalsoldier/clash-rules/"
         "release/proxy.txt", "loyalsoldier", None),
        ("https://raw.githubusercontent.com/dler-io/Rules/main/"
         "Clash/Provider/Proxy.yaml", "yaml", None),
    ]
)


# ---------------------------------------------------------------------------
# China.list (special: must exclude rules from ALL other auto lists)
# ---------------------------------------------------------------------------
CHINA_SOURCES = (
    "# REFERENCE: https://github.com/blackmatrix7/ios_rule_script, "
    "https://github.com/ACL4SSR/ACL4SSR",
    [
        ("https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/"
         "refs/heads/master/rule/Clash/ChinaMax/ChinaMax.yaml", "yaml", None),
        ("https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/"
         "refs/heads/master/rule/Clash/ChinaMax/ChinaMax_Domain.yaml", "yaml", None),
        ("https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/"
         "refs/heads/master/rule/Clash/ChinaMax/ChinaMax_IP.yaml", "yaml", None),
        ("https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/"
         "Clash/ChinaCompanyIp.list", "list", None),
        ("https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/"
         "Clash/ChinaDomain.list", "list", None),
    ]
)


# ---------------------------------------------------------------------------
# Main generation
# ---------------------------------------------------------------------------

def download_all_sources():
    """Download all sources concurrently using ThreadPoolExecutor.

    Returns:
        dict mapping list_name -> set of rules.
    """
    all_rules = {name: set() for name in RULE_LISTS}
    tasks = []  # (list_name, url, parser_type, headers)

    for list_name, (_, sources) in RULE_LISTS.items():
        for url, parser_type, headers in sources:
            tasks.append((list_name, url, parser_type, headers))

    total_tasks = len(tasks)
    print("=" * 60)
    print("Downloading {} sources across {} rule lists...".format(
        total_tasks, len(RULE_LISTS)))
    print("=" * 60)

    with ThreadPoolExecutor(max_workers=20) as executor:
        future_to_task = {
            executor.submit(download_and_extract, url, parser_type, headers): (list_name, url)
            for list_name, url, parser_type, headers in tasks
        }

        completed = 0
        for future in as_completed(future_to_task):
            list_name, url = future_to_task[future]
            try:
                rules = future.result()
                all_rules[list_name].update(rules)
            except Exception as e:
                print("  [EXCEPTION] {} - {}".format(url.split("/")[-1], e))
            completed += 1
            if completed % 20 == 0 or completed == total_tasks:
                print("Progress: {}/{} sources processed".format(completed, total_tasks))

    return all_rules


def generate_all():
    """Generate all rule list files."""
    print("\nStarting generation at {}\n".format(
        datetime.now(timezone(timedelta(hours=8))).strftime("%Y-%m-%d %H:%M:%S")))

    # Step 1: Download all sources concurrently
    all_rules = download_all_sources()

    # Step 2: Generate each list
    print("\n" + "=" * 60)
    print("Generating rule list files...")
    print("=" * 60)

    grand_total = 0

    for list_name in sorted(RULE_LISTS.keys()):
        ref_line, _ = RULE_LISTS[list_name]
        rules = sorted(all_rules[list_name])
        output_path = os.path.join(OUTPUT_DIR, "{}.list".format(list_name))
        total, type_counts = write_rule_list(output_path, list_name, rules, ref_line)
        grand_total += total
        type_summary = ", ".join(
            "{}:{}".format(t, c) for t, c in type_counts.items()
        )
        print("{:20s} -> {:>8,} rules  [{}]".format(list_name, total, type_summary))

    # Step 3: Generate China.list with exclusion
    print("\n" + "-" * 40)
    print("Generating China.list (excluding all other auto list rules)...")

    # Collect all rules from every OTHER auto list for exclusion
    exclude_set = set()
    for list_name, rules in all_rules.items():
        if list_name != "China":
            exclude_set.update(rules)

    print("Exclusion set size: {:,} rules from {} other lists".format(
        len(exclude_set), len(RULE_LISTS) - 1))

    # Download China sources
    china_rules = set()
    china_ref, china_sources = CHINA_SOURCES
    print("\nDownloading China sources...")
    for url, parser_type, headers in china_sources:
        rules = download_and_extract(url, parser_type, headers)
        china_rules.update(rules)

    # Apply exclusion (exact match + subsumption)
    before = len(china_rules)
    china_rules = remove_subsumed_rules(china_rules, exclude_set)
    after = len(china_rules)
    print("China.list: {} rules after excluding {} overlapped rules".format(after, before - after))

    # Write China.list
    output_path = os.path.join(OUTPUT_DIR, "China.list")
    total, type_counts = write_rule_list(output_path, "China", sorted(china_rules), china_ref)
    type_summary = ", ".join(
        "{}:{}".format(t, c) for t, c in type_counts.items()
    )
    print("{:20s} -> {:>8,} rules  [{}]".format("China", total, type_summary))

    grand_total += total

    # Summary
    print("\n" + "=" * 60)
    print("Generation complete! {} lists, {:,.0f} total rules".format(
        len(RULE_LISTS) + 1, grand_total))
    print("=" * 60)


if __name__ == "__main__":
    generate_all()
