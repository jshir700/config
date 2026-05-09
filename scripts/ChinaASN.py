'''
生成 Clash 格式的 ChinaASN.list 规则文件
从 bgp.he.net 抓取中国 ASN 数据，输出为 Clash 规则格式

作者: jshir700
仓库: https://github.com/jshir700/config
参考: https://github.com/missuo/ASN-China
'''
import requests
from lxml import etree
from datetime import datetime, timezone, timedelta
import os

def generate_clash_asn():
    url = "https://bgp.he.net/country/CN"
    headers = {
        "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/107.0.0.0 Safari/537.36"
    }
    
    r = requests.get(url=url, headers=headers).text
    tree = etree.HTML(r)
    asns = tree.xpath('//*[@id="asns"]/tbody/tr')
    
    # 提取 ASN 编号
    asn_numbers = []
    for asn in asns:
        asn_number = asn.xpath('td[1]/a')[0].text.replace('AS', '')
        asn_numbers.append(asn_number)
    
    # 去重并保持顺序
    seen = set()
    unique_asns = []
    for num in asn_numbers:
        if num not in seen:
            seen.add(num)
            unique_asns.append(num)
    
    total = len(unique_asns)
    # 使用北京时间 (UTC+8)
    beijing_tz = timezone(timedelta(hours=8))
    beijing_time = datetime.now(beijing_tz).strftime("%Y-%m-%d %H:%M:%S")
    
    # 确保输出目录存在
    output_dir = "Clash/filter"
    os.makedirs(output_dir, exist_ok=True)
    output_path = os.path.join(output_dir, "ChinaASN.list")
    
    with open(output_path, "w") as f:
        f.write("# NAME: ChinaASN\n")
        f.write("# AUTHOR: jshir700\n")
        f.write("# REPO: https://github.com/jshir700/config\n")
        f.write("# REFERENCE: https://github.com/missuo/ASN-China\n")
        f.write("# UPDATED: {}\n".format(beijing_time))
        f.write("# IP-ASN: 1\n")
        f.write("# TOTAL: {}\n".format(total))
        for asn_num in unique_asns:
            f.write("IP-ASN,{},no-resolve\n".format(asn_num))
    
    print("已生成 {}，共 {} 条 ASN 条目".format(output_path, total))

generate_clash_asn()
