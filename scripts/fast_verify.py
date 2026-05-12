"""
Fast URL verification - tests accessibility and writes to file.
"""

from concurrent.futures import ThreadPoolExecutor, as_completed
import requests
import json

DEFAULT_HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0 Safari/537.36",
    "Accept": "text/plain, text/html, */*",
}

URLS = [
    "https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/Clash/Ruleset/DiDi.list",
    "https://raw.githubusercontent.com/LM-Firefly/Rules/master/Domestic-Services/DiDi.list",
    "https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/Clash/Ruleset/Meitu.list",
    "https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/Clash/Ruleset/PDD.list",
    "https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/Clash/Ruleset/Sina.list",
    "https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/source/rule/Weibo/Weibo.list",
    "https://raw.githubusercontent.com/LM-Firefly/Rules/master/Domestic-Services/Sina.list",
    "https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/Clash/Ruleset/Baidu.list",
    "https://raw.githubusercontent.com/LM-Firefly/Rules/master/Domestic-Services/BaiDu.list",
    "https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/Clash/Ruleset/360.list",
    "https://raw.githubusercontent.com/LM-Firefly/Rules/master/Domestic-Services/360.list",
    "https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/Clash/Ruleset/4399.list",
    "https://raw.githubusercontent.com/LM-Firefly/Rules/master/Domestic-Services/4399.list",
    "https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/Clash/Ruleset/Vip.list",
    "https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/Clash/Ruleset/MI.list",
    "https://raw.githubusercontent.com/LM-Firefly/Rules/master/Domestic-Services/Xiaomi.list",
    "https://raw.githubusercontent.com/LM-Firefly/Rules/master/Domestic-Services/BiliBili.list",
    "https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/source/rule/ByteDance/ByteDance.list",
    "https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/Clash/Ruleset/ByteDance.list",
    "https://raw.githubusercontent.com/LM-Firefly/Rules/master/Domestic-Services/ByteDance.list",
    "https://raw.githubusercontent.com/Hackl0us/SS-Rule-Snippet/master/Rulesets/Surge/Basic/CN.list",
    "https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/source/rule/China/China.list",
    "https://raw.githubusercontent.com/GeQ1an/Rules/master/QuantumultX/Filter/Mainland.list",
    "https://raw.githubusercontent.com/sve1r/Rules-For-Quantumult-X/develop/Rules/Region/China.list",
    "https://raw.githubusercontent.com/Loyalsoldier/surge-rules/release/ruleset/direct.txt",
    "https://raw.githubusercontent.com/Loyalsoldier/surge-rules/release/ruleset/cncidr.txt",
    "https://raw.githubusercontent.com/Hackl0us/GeoIP2-CN/release/CN-ip-cidr.txt",
    "https://raw.githubusercontent.com/sve1r/Rules-For-Quantumult-X/develop/Rules/Region/ChinaIP.list",
    "https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/Clash/Ruleset/CCTV.list",
    "https://raw.githubusercontent.com/LM-Firefly/Rules/master/Domestic-Services/CCTV.list",
    "https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/Clash/Ruleset/Xunlei.list",
    "https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/Clash/Ruleset/HuaWei.list",
    "https://raw.githubusercontent.com/LM-Firefly/Rules/master/Domestic-Services/HuaWei.list",
    "https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/Clash/Ruleset/Tencent.list",
    "https://raw.githubusercontent.com/LM-Firefly/Rules/master/Domestic-Services/Tencent.list",
    "https://raw.githubusercontent.com/sve1r/Rules-For-Quantumult-X/develop/Rules/Media/DomesticMedia.list",
    "https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/Clash/Ruleset/NetEase.list",
    "https://raw.githubusercontent.com/LM-Firefly/Rules/master/Domestic-Services/Netease.list",
    "https://raw.githubusercontent.com/Mazetsz/ACL4SSR/master/Clash/NetEaseCloudMusic.list",
    "https://raw.githubusercontent.com/LM-Firefly/Rules/master/Domestic-Services/NeteaseMusic.list",
    "https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/Clash/Ruleset/Youku.list",
    "https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/Clash/Ruleset/TencentVideo.list",
    "https://raw.githubusercontent.com/sve1r/Rules-For-Quantumult-X/develop/Rules/Media/Domestic/iQiyi.list",
    "https://raw.githubusercontent.com/LM-Firefly/Rules/master/Domestic-Services/iQIYI.list",
    "https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/Clash/Ruleset/Douyu.list",
    "https://raw.githubusercontent.com/LM-Firefly/Rules/master/Domestic-Services/DouYu.list",
    "https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/Clash/Ruleset/Ximalaya.list",
    "https://raw.githubusercontent.com/LM-Firefly/Rules/master/Domestic-Services/XiMaLaYa.list",
    "https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/Clash/Ruleset/Alibaba.list",
    "https://raw.githubusercontent.com/LM-Firefly/Rules/master/Domestic-Services/Alibaba.list",
    "https://raw.githubusercontent.com/LM-Firefly/Rules/master/Domestic-Services/115.list",
    "https://raw.githubusercontent.com/LM-Firefly/Rules/master/Domestic-Services/12306.list",
    "https://raw.githubusercontent.com/LM-Firefly/Rules/master/Domestic-Services/17173.list",
    "https://raw.githubusercontent.com/LM-Firefly/Rules/master/Domestic-Services/178.list",
    "https://raw.githubusercontent.com/LM-Firefly/Rules/master/Domestic-Services/17zuoye.list",
    "https://raw.githubusercontent.com/LM-Firefly/Rules/master/Domestic-Services/36kr.list",
    "https://raw.githubusercontent.com/LM-Firefly/Rules/master/Domestic-Services/51Job.list",
    "https://raw.githubusercontent.com/LM-Firefly/Rules/master/Domestic-Services/56.list",
    "https://raw.githubusercontent.com/LM-Firefly/Rules/master/Domestic-Services/58TongCheng.list",
    "https://raw.githubusercontent.com/LM-Firefly/Rules/master/Domestic-Services/ABC.list",
    "https://raw.githubusercontent.com/LM-Firefly/Rules/master/Domestic-Services/Agora.list",
    "https://raw.githubusercontent.com/LM-Firefly/Rules/master/Domestic-Services/AliPay.list",
    "https://raw.githubusercontent.com/LM-Firefly/Rules/master/Domestic-Services/AnTianKeJi.list",
    "https://raw.githubusercontent.com/LM-Firefly/Rules/master/Domestic-Services/Anjuke.list",
    "https://raw.githubusercontent.com/LM-Firefly/Rules/master/Domestic-Services/BOC.list",
    "https://raw.githubusercontent.com/LM-Firefly/Rules/master/Domestic-Services/BOCOM.list",
    "https://raw.githubusercontent.com/LM-Firefly/Rules/master/Domestic-Services/BaiFenDian.list",
    "https://raw.githubusercontent.com/LM-Firefly/Rules/master/Domestic-Services/BaoFengYingYin.list",
    "https://raw.githubusercontent.com/LM-Firefly/Rules/master/Domestic-Services/BianFeng.list",
    "https://raw.githubusercontent.com/LM-Firefly/Rules/master/Domestic-Services/Bootcss.list",
    "https://raw.githubusercontent.com/LM-Firefly/Rules/master/Domestic-Services/CAS.list",
    "https://raw.githubusercontent.com/LM-Firefly/Rules/master/Domestic-Services/CCB.list",
    "https://raw.githubusercontent.com/LM-Firefly/Rules/master/Domestic-Services/CEB.list",
    "https://raw.githubusercontent.com/LM-Firefly/Rules/master/Domestic-Services/CGB.list",
    "https://raw.githubusercontent.com/LM-Firefly/Rules/master/Domestic-Services/CIBN.list",
    "https://raw.githubusercontent.com/LM-Firefly/Rules/master/Domestic-Services/CKJR.list",
    "https://raw.githubusercontent.com/LM-Firefly/Rules/master/Domestic-Services/CNKI.list",
    "https://raw.githubusercontent.com/LM-Firefly/Rules/master/Domestic-Services/CNNIC.list",
    "https://raw.githubusercontent.com/LM-Firefly/Rules/master/Domestic-Services/CSDN.list",
    "https://raw.githubusercontent.com/LM-Firefly/Rules/master/Domestic-Services/AcFun.list",
    "https://raw.githubusercontent.com/LM-Firefly/Rules/master/Domestic-Services/CaiNiao.list",
    "https://raw.githubusercontent.com/LM-Firefly/Rules/master/Domestic-Services/CaiXinChuanMei.list",
    "https://raw.githubusercontent.com/LM-Firefly/Rules/master/Domestic-Services/Camera360.list",
    "https://raw.githubusercontent.com/LM-Firefly/Rules/master/Domestic-Services/ChinaMobile.list",
    "https://raw.githubusercontent.com/LM-Firefly/Rules/master/Domestic-Services/ChinaNews.list",
    "https://raw.githubusercontent.com/LM-Firefly/Rules/master/Domestic-Services/ChinaTelecom.list",
    "https://raw.githubusercontent.com/LM-Firefly/Rules/master/Domestic-Services/ChinaUnicom.list",
    "https://raw.githubusercontent.com/LM-Firefly/Rules/master/Domestic-Services/ChuangKeTie.list",
    "https://raw.githubusercontent.com/LM-Firefly/Rules/master/Domestic-Services/ChunYou.list",
    "https://raw.githubusercontent.com/LM-Firefly/Rules/master/Domestic-Services/DaMai.list",
    "https://raw.githubusercontent.com/LM-Firefly/Rules/master/Domestic-Services/DanDanZan.list",
    "https://raw.githubusercontent.com/LM-Firefly/Rules/master/Domestic-Services/Dandanplay.list",
    "https://raw.githubusercontent.com/LM-Firefly/Rules/master/Domestic-Services/DangDang.list",
    "https://raw.githubusercontent.com/LM-Firefly/Rules/master/Domestic-Services/Dedao.list",
    "https://raw.githubusercontent.com/LM-Firefly/Rules/master/Domestic-Services/Deepin.list",
    "https://raw.githubusercontent.com/LM-Firefly/Rules/master/Domestic-Services/DiSiFanShi.list",
    "https://raw.githubusercontent.com/LM-Firefly/Rules/master/Domestic-Services/DianCeWangKe.list",
    "https://raw.githubusercontent.com/LM-Firefly/Rules/master/Domestic-Services/DingTalk.list",
    "https://raw.githubusercontent.com/LM-Firefly/Rules/master/Domestic-Services/DingXiangYuan.list",
    "https://raw.githubusercontent.com/LM-Firefly/Rules/master/Domestic-Services/Domob.list",
    "https://raw.githubusercontent.com/LM-Firefly/Rules/master/Domestic-Services/DouBan.list",
    "https://raw.githubusercontent.com/LM-Firefly/Rules/master/Domestic-Services/EastMoney.list",
    "https://raw.githubusercontent.com/LM-Firefly/Rules/master/Domestic-Services/Eleme.list",
    "https://raw.githubusercontent.com/LM-Firefly/Rules/master/Domestic-Services/FanFou.list",
    "https://raw.githubusercontent.com/LM-Firefly/Rules/master/Domestic-Services/FeiZhu.list",
    "https://raw.githubusercontent.com/LM-Firefly/Rules/master/Domestic-Services/FengHuangWang.list",
    "https://raw.githubusercontent.com/LM-Firefly/Rules/master/Domestic-Services/FengXiaWangLuo.list",
    "https://raw.githubusercontent.com/LM-Firefly/Rules/master/Domestic-Services/Fiio.list",
    "https://raw.githubusercontent.com/LM-Firefly/Rules/master/Domestic-Services/Funshion.list",
    "https://raw.githubusercontent.com/LM-Firefly/Rules/master/Domestic-Services/6JianFang.list",
    "https://raw.githubusercontent.com/LM-Firefly/Rules/master/Domestic-Services/GaoDe.list",
    "https://raw.githubusercontent.com/LM-Firefly/Rules/master/Domestic-Services/GuiGuDongLi.list",
    "https://raw.githubusercontent.com/LM-Firefly/Rules/master/Domestic-Services/HaiNanHangKong.list",
    "https://raw.githubusercontent.com/LM-Firefly/Rules/master/Domestic-Services/HanYi.list",
    "https://raw.githubusercontent.com/LM-Firefly/Rules/master/Domestic-Services/HeMa.list",
    "https://raw.githubusercontent.com/LM-Firefly/Rules/master/Domestic-Services/HibyMusic.list",
    "https://raw.githubusercontent.com/LM-Firefly/Rules/master/Domestic-Services/HuYa.list",
    "https://raw.githubusercontent.com/LM-Firefly/Rules/master/Domestic-Services/HuaShuTV.list",
    "https://raw.githubusercontent.com/LM-Firefly/Rules/master/Domestic-Services/HunanTV.list",
    "https://raw.githubusercontent.com/LM-Firefly/Rules/master/Domestic-Services/Hupu.list",
    "https://raw.githubusercontent.com/LM-Firefly/Rules/master/Domestic-Services/ICBC.list",
    "https://raw.githubusercontent.com/LM-Firefly/Rules/master/Domestic-Services/JiGuangTuiSong.list",
    "https://raw.githubusercontent.com/LM-Firefly/Rules/master/Domestic-Services/JianGuoYun.list",
    "https://raw.githubusercontent.com/LM-Firefly/Rules/master/Domestic-Services/JianShu.list",
    "https://raw.githubusercontent.com/LM-Firefly/Rules/master/Domestic-Services/JinJiangWenXue.list",
    "https://raw.githubusercontent.com/LM-Firefly/Rules/master/Domestic-Services/JingDong.list",
    "https://raw.githubusercontent.com/LM-Firefly/Rules/master/Domestic-Services/JueJin.list",
    "https://raw.githubusercontent.com/LM-Firefly/Rules/master/Domestic-Services/Keep.list",
    "https://raw.githubusercontent.com/LM-Firefly/Rules/master/Domestic-Services/KingSmith.list",
    "https://raw.githubusercontent.com/LM-Firefly/Rules/master/Domestic-Services/Kingsoft.list",
    "https://raw.githubusercontent.com/LM-Firefly/Rules/master/Domestic-Services/KouDaiShiShang.list",
    "https://raw.githubusercontent.com/LM-Firefly/Rules/master/Domestic-Services/Ku6.list",
    "https://raw.githubusercontent.com/LM-Firefly/Rules/master/Domestic-Services/KuKeMusic.list",
    "https://raw.githubusercontent.com/LM-Firefly/Rules/master/Domestic-Services/KuaiDi100.list",
    "https://raw.githubusercontent.com/LM-Firefly/Rules/master/Domestic-Services/KuaiShou.list",
    "https://raw.githubusercontent.com/LM-Firefly/Rules/master/Domestic-Services/KuangShi.list",
    "https://raw.githubusercontent.com/LM-Firefly/Rules/master/Domestic-Services/Kugou%26Kuwo.list",
    "https://raw.githubusercontent.com/LM-Firefly/Rules/master/Domestic-Services/LanZouYun.list",
    "https://raw.githubusercontent.com/LM-Firefly/Rules/master/Domestic-Services/LeJu.list",
    "https://raw.githubusercontent.com/LM-Firefly/Rules/master/Domestic-Services/LeTV.list",
    "https://raw.githubusercontent.com/LM-Firefly/Rules/master/Domestic-Services/Lenovo.list",
    "https://raw.githubusercontent.com/LM-Firefly/Rules/master/Domestic-Services/LuDaShi.list",
    "https://raw.githubusercontent.com/LM-Firefly/Rules/master/Domestic-Services/LvMiLianChuang.list",
    "https://raw.githubusercontent.com/LM-Firefly/Rules/master/Domestic-Services/Maocloud.list",
    "https://raw.githubusercontent.com/LM-Firefly/Rules/master/Domestic-Services/MeiTuan.list",
    "https://raw.githubusercontent.com/LM-Firefly/Rules/master/Domestic-Services/MeiZu.list",
    "https://raw.githubusercontent.com/LM-Firefly/Rules/master/Domestic-Services/MiWu.list",
    "https://raw.githubusercontent.com/LM-Firefly/Rules/master/Domestic-Services/Migu.list",
    "https://raw.githubusercontent.com/LM-Firefly/Rules/master/Domestic-Services/MingLueZhaoHui.list",
    "https://raw.githubusercontent.com/LM-Firefly/Rules/master/Domestic-Services/Mogujie.list",
    "https://raw.githubusercontent.com/LM-Firefly/Rules/master/Domestic-Services/Mojitianqi.list",
    "https://raw.githubusercontent.com/LM-Firefly/Rules/master/Domestic-Services/NGAA.list",
    "https://raw.githubusercontent.com/LM-Firefly/Rules/master/Domestic-Services/OPPO.list",
    "https://raw.githubusercontent.com/LM-Firefly/Rules/master/Domestic-Services/OnePlus.list",
    "https://raw.githubusercontent.com/LM-Firefly/Rules/master/Domestic-Services/OuPeng.list",
    "https://raw.githubusercontent.com/LM-Firefly/Rules/master/Domestic-Services/PPTV.list",
    "https://raw.githubusercontent.com/LM-Firefly/Rules/master/Domestic-Services/PSBC.list",
    "https://raw.githubusercontent.com/LM-Firefly/Rules/master/Domestic-Services/PingAn.list",
    "https://raw.githubusercontent.com/LM-Firefly/Rules/master/Domestic-Services/QiNiuYun.list",
    "https://raw.githubusercontent.com/LM-Firefly/Rules/master/Domestic-Services/Qihoo360.list",
    "https://raw.githubusercontent.com/LM-Firefly/Rules/master/Domestic-Services/QingCloud.list",
    "https://raw.githubusercontent.com/LM-Firefly/Rules/master/Domestic-Services/RuanMei.list",
    "https://raw.githubusercontent.com/LM-Firefly/Rules/master/Domestic-Services/SF-Express.list",
    "https://raw.githubusercontent.com/LM-Firefly/Rules/master/Domestic-Services/SMZDM.list",
    "https://raw.githubusercontent.com/LM-Firefly/Rules/master/Domestic-Services/ShangHaiJuXiao.list",
    "https://raw.githubusercontent.com/LM-Firefly/Rules/master/Domestic-Services/Shanling.list",
    "https://raw.githubusercontent.com/LM-Firefly/Rules/master/Domestic-Services/ShenMa.list",
    "https://raw.githubusercontent.com/LM-Firefly/Rules/master/Domestic-Services/ShiNongZhiKe.list",
    "https://raw.githubusercontent.com/LM-Firefly/Rules/master/Domestic-Services/Sohu.list",
    "https://raw.githubusercontent.com/LM-Firefly/Rules/master/Domestic-Services/SouFang.list",
    "https://raw.githubusercontent.com/LM-Firefly/Rules/master/Domestic-Services/SuNing.list",
    "https://raw.githubusercontent.com/LM-Firefly/Rules/master/Domestic-Services/SuiShiChuanMei.list",
    "https://raw.githubusercontent.com/LM-Firefly/Rules/master/Domestic-Services/TCL.list",
    "https://raw.githubusercontent.com/LM-Firefly/Rules/master/Domestic-Services/TaiKang.list",
    "https://raw.githubusercontent.com/LM-Firefly/Rules/master/Domestic-Services/TaiheMusic.list",
    "https://raw.githubusercontent.com/LM-Firefly/Rules/master/Domestic-Services/Teambition.list",
    "https://raw.githubusercontent.com/LM-Firefly/Rules/master/Domestic-Services/TianTianKanKan.list",
    "https://raw.githubusercontent.com/LM-Firefly/Rules/master/Domestic-Services/TianWeiChengXin.list",
    "https://raw.githubusercontent.com/LM-Firefly/Rules/master/Domestic-Services/TianYaForum.list",
    "https://raw.githubusercontent.com/LM-Firefly/Rules/master/Domestic-Services/TigerFintech.list",
    "https://raw.githubusercontent.com/LM-Firefly/Rules/master/Domestic-Services/TongCheng.list",
    "https://raw.githubusercontent.com/LM-Firefly/Rules/master/Domestic-Services/U17.list",
    "https://raw.githubusercontent.com/LM-Firefly/Rules/master/Domestic-Services/UC.list",
    "https://raw.githubusercontent.com/LM-Firefly/Rules/master/Domestic-Services/UCloud.list",
    "https://raw.githubusercontent.com/LM-Firefly/Rules/master/Domestic-Services/UPYun.list",
    "https://raw.githubusercontent.com/LM-Firefly/Rules/master/Domestic-Services/UnionPay.list",
    "https://raw.githubusercontent.com/LM-Firefly/Rules/master/Domestic-Services/Vancl.list",
    "https://raw.githubusercontent.com/LM-Firefly/Rules/master/Domestic-Services/Vivo.list",
    "https://raw.githubusercontent.com/LM-Firefly/Rules/master/Domestic-Services/WanMeiShiJie.list",
    "https://raw.githubusercontent.com/LM-Firefly/Rules/master/Domestic-Services/WangSuKeJi.list",
    "https://raw.githubusercontent.com/LM-Firefly/Rules/master/Domestic-Services/WangXinKeJi.list",
    "https://raw.githubusercontent.com/LM-Firefly/Rules/master/Domestic-Services/WenJuanXing.list",
    "https://raw.githubusercontent.com/LM-Firefly/Rules/master/Domestic-Services/WiFiMaster.list",
    "https://raw.githubusercontent.com/LM-Firefly/Rules/master/Domestic-Services/XiamiMusic.list",
    "https://raw.githubusercontent.com/LM-Firefly/Rules/master/Domestic-Services/XianYu.list",
    "https://raw.githubusercontent.com/LM-Firefly/Rules/master/Domestic-Services/XiaoGouKeJi.list",
    "https://raw.githubusercontent.com/LM-Firefly/Rules/master/Domestic-Services/XiaoYuanKeJi.list",
    "https://raw.githubusercontent.com/LM-Firefly/Rules/master/Domestic-Services/XieCheng.list",
    "https://raw.githubusercontent.com/LM-Firefly/Rules/master/Domestic-Services/XueErSi.list",
    "https://raw.githubusercontent.com/LM-Firefly/Rules/master/Domestic-Services/XueQiu.list",
    "https://raw.githubusercontent.com/LM-Firefly/Rules/master/Domestic-Services/YYeTs.list",
    "https://raw.githubusercontent.com/LM-Firefly/Rules/master/Domestic-Services/YiChe.list",
    "https://raw.githubusercontent.com/LM-Firefly/Rules/master/Domestic-Services/YiXiaKeJi.list",
    "https://raw.githubusercontent.com/LM-Firefly/Rules/master/Domestic-Services/YiZhiBo.list",
    "https://raw.githubusercontent.com/LM-Firefly/Rules/master/Domestic-Services/YouMengChuangXiang.list",
    "https://raw.githubusercontent.com/LM-Firefly/Rules/master/Domestic-Services/YouZan.list",
    "https://raw.githubusercontent.com/LM-Firefly/Rules/master/Domestic-Services/Youku%26Tudou.list",
    "https://raw.githubusercontent.com/LM-Firefly/Rules/master/Domestic-Services/YuanFuDao.list",
    "https://raw.githubusercontent.com/LM-Firefly/Rules/master/Domestic-Services/YunFanJiaSu.list",
    "https://raw.githubusercontent.com/LM-Firefly/Rules/master/Domestic-Services/ZDNS.list",
    "https://raw.githubusercontent.com/LM-Firefly/Rules/master/Domestic-Services/ZhangYue.list",
    "https://raw.githubusercontent.com/LM-Firefly/Rules/master/Domestic-Services/ZhiYunZhong.list",
    "https://raw.githubusercontent.com/LM-Firefly/Rules/master/Domestic-Services/ZhongGuoShiHua.list",
    "https://raw.githubusercontent.com/LM-Firefly/Rules/master/Domestic-Services/ZhongWeiShiJi.list",
    "https://raw.githubusercontent.com/LM-Firefly/Rules/master/Domestic-Services/ZhongYuanYiShang.list",
    "https://raw.githubusercontent.com/LM-Firefly/Rules/master/Domestic-Services/ZhuanZhuan.list",
    "https://raw.githubusercontent.com/LM-Firefly/Rules/master/Domestic-Services/hpplay.list",
    "https://raw.githubusercontent.com/LM-Firefly/Rules/master/Domestic-Services/iFlytek.list",
    "https://raw.githubusercontent.com/LM-Firefly/Rules/master/Domestic-Services/ifanr.list",
    "https://raw.githubusercontent.com/LM-Firefly/Rules/master/Domestic-Services/CMB.list",
    "https://raw.githubusercontent.com/LM-Firefly/Rules/master/Domestic-Services/BaiShanYunKeJi.list",
    "https://raw.githubusercontent.com/LM-Firefly/Rules/master/Domestic-Services/DiLianWangLuo.list",
    "https://raw.githubusercontent.com/LM-Firefly/Rules/master/Domestic-Services/WeiZhiYunDong.list",
    "https://raw.githubusercontent.com/LM-Firefly/Rules/master/Domestic-Services/8btc.list",
    "https://raw.githubusercontent.com/misakaio/chnroutes2/master/chnroutes.txt",
    "https://raw.githubusercontent.com/LM-Firefly/Rules/master/Domestic-Services/ChengTongWangPan.list",
    "https://raw.githubusercontent.com/Loyalsoldier/clash-rules/release/cncidr.txt",
    "https://raw.githubusercontent.com/LM-Firefly/Rules/master/Domestic-Services/DuoWan.list",
    "https://raw.githubusercontent.com/LM-Firefly/Rules/master/Domestic-Services/WanKaHuanJu.list",
    "https://raw.githubusercontent.com/LM-Firefly/Rules/master/Domestic-Services/ZhiYinManKe.list",
    "https://raw.githubusercontent.com/LM-Firefly/Rules/master/Domestic-Services/ShiJiChaoXing.list",
    "https://raw.githubusercontent.com/gaoyifan/china-operator-ip/ip-lists/cernet.txt",
    "https://raw.githubusercontent.com/gaoyifan/china-operator-ip/ip-lists/cernet6.txt",
    "https://raw.githubusercontent.com/gaoyifan/china-operator-ip/ip-lists/china.txt",
    "https://raw.githubusercontent.com/gaoyifan/china-operator-ip/ip-lists/china6.txt",
    "https://raw.githubusercontent.com/gaoyifan/china-operator-ip/ip-lists/chinanet6.txt",
    "https://raw.githubusercontent.com/gaoyifan/china-operator-ip/ip-lists/chinanet.txt",
    "https://raw.githubusercontent.com/gaoyifan/china-operator-ip/ip-lists/cmcc.txt",
    "https://raw.githubusercontent.com/gaoyifan/china-operator-ip/ip-lists/cmcc6.txt",
    "https://raw.githubusercontent.com/gaoyifan/china-operator-ip/ip-lists/cstnet.txt",
    "https://raw.githubusercontent.com/gaoyifan/china-operator-ip/ip-lists/cstnet6.txt",
    "https://raw.githubusercontent.com/gaoyifan/china-operator-ip/ip-lists/drpeng.txt",
    "https://raw.githubusercontent.com/gaoyifan/china-operator-ip/ip-lists/drpeng6.txt",
    "https://raw.githubusercontent.com/gaoyifan/china-operator-ip/ip-lists/unicom.txt",
    "https://raw.githubusercontent.com/gaoyifan/china-operator-ip/ip-lists/unicom6.txt",
    "https://raw.githubusercontent.com/LM-Firefly/Rules/master/Domestic-Services/WoLai.list",
    "https://raw.githubusercontent.com/dler-io/Rules/main/Clash/Provider/Domestic%20IPs.yaml",
    "https://raw.githubusercontent.com/dler-io/Rules/main/Clash/Provider/Domestic.yaml",
    "https://raw.githubusercontent.com/dler-io/Rules/main/Clash/Provider/Douyin.yaml",
    "https://raw.githubusercontent.com/LM-Firefly/Rules/master/Special/Government-CN.list",
    "https://raw.githubusercontent.com/LM-Firefly/Rules/master/Special/XunLei.list",
    "https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/Clash/Ruleset/Bilibili.list",
    "https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/Clash/Ruleset/Iflytek.list",
    "https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/Clash/Ruleset/Iqiyi.list",
    "https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/Clash/Ruleset/Kingsoft.list",
    "https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/Clash/Ruleset/Kuaishou.list",
    "https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/Clash/Ruleset/LeTV.list",
    "https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/Clash/Ruleset/MOO.list",
    "https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/Clash/Ruleset/Marketing.list",
    "https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/Clash/Ruleset/NetEaseMusic.list",
    "https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/Clash/Ruleset/PPTVPPLive.list",
    "https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/Clash/Ruleset/TapTap.list",
    "https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/Clash/Ruleset/Wechat.list",
    "https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/Clash/Ruleset/YYeTs.list",
    "https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/Clash/Providers/Ruleset/Bilibili.yaml",
    "https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/Clash/Providers/Ruleset/NetEaseMusic.yaml",
    "https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/Clash/Providers/Ruleset/Wechat.yaml",
    "https://raw.githubusercontent.com/LM-Firefly/Rules/master/Domestic-Services/ZhongXingTongXun.list",
    "https://raw.githubusercontent.com/LM-Firefly/Rules/master/Domestic-Services/Geely.list",
    "https://raw.githubusercontent.com/LM-Firefly/Rules/master/Domestic-Services/FangZhengDianZi.list",
    "https://raw.githubusercontent.com/LM-Firefly/Rules/master/Domestic-Services/BeStore.list",
    "https://raw.githubusercontent.com/zqzess/rule_for_quantumultX/master/QuantumultX/rules/CMedia.list",
    "https://raw.githubusercontent.com/zqzess/rule_for_quantumultX/master/QuantumultX/rules/Mainland.list",
    "https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/Clash/Providers/Ruleset/Alibaba.yaml",
    "https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/Clash/Providers/Ruleset/ByteDance.yaml",
    "https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/Clash/Providers/Ruleset/Douyu.yaml",
    "https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/Clash/Providers/Ruleset/HuaWei.yaml",
    "https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/Clash/Providers/Ruleset/Iflytek.yaml",
    "https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/Clash/Providers/Ruleset/Iqiyi.yaml",
    "https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/Clash/Providers/Ruleset/Kingsoft.yaml",
    "https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/Clash/Providers/Ruleset/Kuaishou.yaml",
    "https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/Clash/Providers/Ruleset/Marketing.yaml",
    "https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/Clash/Providers/Ruleset/Meitu.yaml",
    "https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/Clash/Providers/Ruleset/NetEase.yaml",
    "https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/Clash/Providers/Ruleset/PPTVPPLive.yaml",
    "https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/Clash/Providers/Ruleset/TapTap.yaml",
    "https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/Clash/Providers/Ruleset/Tencent.yaml",
    "https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/Clash/Providers/Ruleset/TencentVideo.yaml",
    "https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/Clash/Providers/Ruleset/Xunlei.yaml",
    "https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/Clash/Providers/Ruleset/YYeTs.yaml",
    "https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/Clash/Providers/Ruleset/Youku.yaml",
    "https://raw.githubusercontent.com/imDazui/Tvlist-awesome-m3u-m3u8/master/m3u/%E5%9B%BD%E5%86%85%E7%94%B5%E8%A7%86%E5%8F%B02023.m3u8",
    "https://raw.githubusercontent.com/imDazui/Tvlist-awesome-m3u-m3u8/master/m3u/%E8%BD%AE%E6%92%AD_%E5%8D%8E%E6%95%B0.%E9%BB%91%E8%8E%93.NewTV.SiTV.CIBN.m3u",
    "https://raw.githubusercontent.com/imDazui/Tvlist-awesome-m3u-m3u8/master/m3u/%E9%87%8D%E5%BA%86%E5%B9%BF%E7%94%B5cqccn.m3u",
    "https://raw.githubusercontent.com/LM-Firefly/Rules/master/Domestic-Services/BesTV.list",
    "https://raw.githubusercontent.com/LM-Firefly/Rules/master/Domestic-Services/CETV.list",
    "https://raw.githubusercontent.com/LM-Firefly/Rules/master/Domestic-Services/SMG.list",
    "https://ruleset.isagood.day/alibaba.conf",
    "https://ruleset.isagood.day/bilibili.conf",
    "https://raw.githubusercontent.com/missuo/ASN-China/main/IP.China.list",
]

def infer_parser(url):
    u = url.lower()
    if u.endswith(".m3u8") or u.endswith(".m3u"):
        return None
    if "ruleset.isagood.day" in u:
        return "surge"
    if u.endswith(".yaml"):
        return "yaml"
    if u.endswith(".module"):
        return "sgmodule"
    if u.endswith(".conf"):
        return "surge"
    if u.endswith(".list"):
        return "list"
    if u.endswith(".txt"):
        if "gaoyifan" in u or "misakaio" in u:
            return "plaincidr"
        if "loyalsoldier" in u:
            return "loyalsoldier"
        if "hackl0us" in u:
            return "plaincidr"
        return "loyalsoldier"
    return None

def check(url):
    pt = infer_parser(url)
    if pt is None:
        return (url, False, None, "SKIP")
    try:
        r = requests.head(url, headers=DEFAULT_HEADERS, timeout=10, allow_redirects=True)
        if r.status_code == 200:
            return (url, True, pt, 200)
        r = requests.get(url, headers=DEFAULT_HEADERS, timeout=15, stream=True)
        if r.status_code == 200:
            return (url, True, pt, 200)
        return (url, False, pt, r.status_code)
    except Exception as e:
        return (url, False, pt, type(e).__name__)

def main():
    ok = []
    fail = []
    with ThreadPoolExecutor(max_workers=30) as ex:
        futs = {ex.submit(check, u): u for u in URLS}
        for f in as_completed(futs):
            url, accessible, ptype, status = f.result()
            fn = url.rstrip("/").split("/")[-1]
            if accessible:
                ok.append((url, ptype))
                print(f"  OK  {status} | {fn}")
            else:
                fail.append((url, status))
                print(f"  FAIL {status} | {fn}")

    print(f"\n=== RESULTS: {len(ok)} accessible, {len(fail)} inaccessible ===")
    
    # Write accessible URLs to file
    with open("scripts/accessible_urls.py", "w") as f:
        f.write("ACCESSIBLE_URLS = [\n")
        for url, pt in ok:
            f.write(f'    ("{url}", "{pt}", None),\n')
        f.write("]\n")
    
    print(f"\nWritten {len(ok)} accessible URLs to scripts/accessible_urls.py")
    
    if fail:
        print(f"\nInaccessible ({len(fail)}):")
        for url, reason in fail:
            print(f"  {reason} | {url}")

main()
