#-*- coding: utf-8 -*-
import requests
from lxml import etree
import re
import json
import threading,Queue
import multiprocessing
import traceback
import time,datetime
import MySQLdb as db
import sys,os
reload(sys)
sys.setdefaultencoding('utf-8')


headers = {
    "User-Agent": "Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/45.0.2454.101 Safari/537.36"
}

#log日志
def loggs(strs):
    path = '\\'.join(sys.argv[0].split('\\')[:-1])
    logfile = path+'\\'+'ipproxy_logs.log'
    with open(logfile,'ab') as f:
        time = str(datetime.datetime.now())[:-7]
        t = os.linesep
        s = time+' : '+str(strs)
        print s
        f.write(s+t)

#获取一张网页
def getHtml(url,num_retrive=3):
    res = requests.get(url,headers=headers,verify=False,timeout=10)
    code = res.status_code
    if 400<=code<500 and num_retrive>0:
        getHtml(url,num_retrive-1) #下载失败重试3次
    meta = re.findall('meta.*?charset=[\"\'](.*?)[\"\']',res.text) #自动匹配网页编码方式
    if len(meta)>0:
        res.encoding = meta[0]
    else:
        meta = re.findall('charset=(.*?)"',res.text)
        if len(meta)>0:
            res.encoding = meta[0]
    s = res.text if code==200 else None
    return s

#国内高级匿名,不限协议,800
#66ip提取器http
def fetch_66ip():
    url = 'http://www.66ip.cn/nmtq.php?getnum=800&isp=0&anonymoustype=3&start=&ports=&export=&ipaddress=&area=0&proxytype=0&api=66ip'
    html = getHtml(url)
    p = re.compile('\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}:\d{2,5}')
    text = p.findall(html)
    ips = []
    for t in text:
        s = t.split(':')
        one = {}
        one['ip'] = s[0]
        one['port'] = s[1]
        one['protocol'] = 'http'
        ips.append(one)
    return ips

#66免费代理网
def fetch_66minafei():
    ips = []
    for i in range(1,2):
        url = 'http://www.66ip.cn/%d.html'%i
        html = getHtml(url)
        tree = etree.HTML(html)
        trs = tree.xpath('//*[@id="main"]/div/div[1]/table/tr')[1:]
        for tr in trs:
            one = {}
            one['ip'] = tr.xpath('td[1]/text()')[0].strip()
            one['port'] = tr.xpath('td[2]/text()')[0].strip()
            one['position'] = tr.xpath('td[3]/text()')[0].strip()
            ips.append(one)
    return ips
    

#库伯伯HTTP代理,3秒，匿名,传参：页数
def fetch_coobobo(page=10):
    url_mo = 'http://www.coobobo.com/free-http-proxy/'
    ips = []
    for p in range(1,page+1):
        url = url_mo+str(p)
        html = etree.HTML(getHtml(url))
        table = html.xpath('//tr')[1:]
        for tr in table:
            hid = tr.xpath(u'contains(string(td[3]),"匿名")')
            if hid:
                speeds = float(re.findall('\d\.\d',tr.xpath('string(td[5])').strip())[0]) #响应速度
                if speeds < 3.0: ###选择代理ip的响应时间
                    one = {}
                    try:
                        t1 = tr.xpath('string(td[1])').strip()
                        t2 = re.findall('\d+',t1)
                        if len(t2) == 4:
                            ip = '.'.join(t2)
                        else:
                            ip = False
                    except Exception:
                        ip = False
                    if not ip:
                        continue
                    one['ip'] = ip #代理IP地址
                    one['port'] = tr.xpath('td[2]/text()')[0] #端口
                    one['speed'] = speeds
                    one['position'] = re.sub('\r|\t|\n| ','',tr.xpath('td[4]/text()')[0].strip()) #地理位置
                    ips.append(one)
    return ips

#快代理，HTTP，高匿，参数：页. --- (未知异常，弃用)
def fetch_kuaidaili(page=2):
    url_mo = 'http://www.kuaidaili.com/free/inha/'
    ips = []
    for p in range(1,page+1):
        url = url_mo+str(p)+'/'
        html = etree.HTML(getHtml(url)) #获取网页
        table = html.xpath('//tr') #提取网页中的所有tr标签
        for tr in table[1:]:
            hid = tr.xpath('td[3]/text()')[0] #匿名度
            if '高匿名' in hid:
                types = tr.xpath('td[4]/text()')[0].lower() #类型
                try:
                    speed = float(re.findall('\d+',tr.xpath('td[6]/text()')[0])[0]) #速度
                except Exception:
                    speed = 100.0
                if speed < 3.0:
                    one = {}
                    one['ip'] = tr.xpath('td[1]/text()')[0] #ip地址
                    one['port'] = tr.xpath('td[2]/text()')[0] #端口
                    one['protocol'] = 'https' if 'https' in types else 'http'
                    one['position'] = tr.xpath('string(td[5])').strip()
                    one['speed'] = speed
                    ips.append(one)
        time.sleep(1) #休眠1秒防止被ban
    return ips

#年少
def fetch_nianshao(page=10):
    urls = []
    for i in range(1,page+1):
        url_http = 'http://www.nianshao.me/?stype=1&page=%d'%i
        url_https = 'http://www.nianshao.me/?stype=2&page=%d'%i
        urls.append(url_http)
        urls.append(url_https)
    ips = []
    for url in urls:
        html = etree.HTML(getHtml(url))
        table = html.xpath('//tr')
        for tr in table[1:]:
            one = {}
            one['ip'] = tr.xpath('td[1]/text()')[0] #ip
            one['port'] = tr.xpath('td[2]/text()')[0] #端口
            one['protocol'] = 'https' if 'https' in tr.xpath('td[5]/text()')[0].lower() else 'http' #类型
            one['position'] = tr.xpath('string(td[3])').strip()
            ips.append(one)
    return ips

#西刺代理
def fetch_xici(page=1):
    ips = []
    for p in range(1,page+1): #翻页
        url = 'http://www.xicidaili.com/nn/%s'%str(p)
        tree = etree.HTML(getHtml(url)) #向函数中传入页数得到原始网页,通过etree对网页进行结构化以方便解析
        table = tree.xpath('//*[@id="ip_list"]/tr') #使用xpath解析得到网页中的table表
        for tr in table[1:]:
            types = tr.xpath('td[6]/text()')[0].lower() #类型
            types = 'https' if 'https' in types else 'http'
            connectTime = float(tr.xpath('td[7]/div/@title')[0][:-1])
            if connectTime < 3.0: #提取小于3秒的连接
                one = {}
                one['ip'] = tr.xpath('td[2]/text()')[0]
                one['port'] = tr.xpath('td[3]/text()')[0]
                one['position'] = tr.xpath('string(td[4])').strip()
                one['speed'] = connectTime
                one['protocol'] = types
                ips.append(one)
    return ips

#proxy360
def fetch_proxy360():
    url = 'http://www.proxy360.cn/default.aspx'
    tree = etree.HTML(getHtml(url))
    divs = tree.xpath('//div[@id="ctl00_ContentPlaceHolder1_upProjectList"]/div[@class="proxylistitem"]')
    ips = []
    for div in divs:
        one = {}
        one['ip'] = div.xpath('string(div[1]/span[1])').strip() #IP地址
        one['port'] = div.xpath('string(div[1]/span[2])').strip() #端口
        one['position'] = div.xpath('string(div[1]/span[4])').strip() #地区
        one['speed'] = "%.3f"%float(re.sub('\r|\t|\n| ','',div.xpath('string(div[2]/div/@title)'))) #速度
        ips.append(one)
    return ips

#us-proxy
def fetch_us_proxy():
    url = 'https://www.us-proxy.org/'
    tree = etree.HTML(getHtml(url))
    trs = tree.xpath('//*[@id="proxylisttable"]//tr')[1:-1]
    ips = []
    for tr in trs:
        one = {}
        one['ip'] = tr.xpath('td[1]/text()')[0].strip()
        one['port'] = tr.xpath('td[2]/text()')[0].strip()
        one['position'] = tr.xpath('td[4]/text()')[0].strip()
        one['protocol'] = 'https' if tr.xpath('contains(td[7],"yes")') else 'http'
        ips.append(one)
    return ips

#ip海
def fetch_iphai():
    url = 'http://www.iphai.com/free/ng'
    tree = etree.HTML(getHtml(url))
    trs = tree.xpath('/html/body/div[2]/div[2]/table/tr')[1:]
    ips = []
    for tr in trs:
        one = {}
        one['ip'] = tr.xpath('string(td[1])').strip()
        one['port'] = tr.xpath('string(td[2])').strip()
        one['protocol'] = 'https' if 'https' in tr.xpath('string(td[4])').strip().lower() else 'http' #对于支持双协议的http,https，保守一点，只选择http
        one['position'] = tr.xpath('string(td[5])').strip()
        one['speed'] = re.findall('\d+\.\d*',tr.xpath('string(td[6])').strip())[0]
        ips.append(one)
    return ips

#360代理ip
def fetch_swei360():
    urls = []
    for i in range(1,8):
        url_china = 'http://www.swei360.com/free/?stype=1&page=%d'%i
        url_others = 'http://www.swei360.com/free/?stype=3&page=%d'%i
        urls.append(url_china)
        urls.append(url_others)
    ips = []
    tasks = []
    def function(url):
        tree = etree.HTML(getHtml(url))
        trs = tree.xpath('//*[@id="list"]/table/tbody/tr')
        for tr in trs:
            one = {}
            one['ip'] = tr.xpath('td[1]/text()')[0]
            one['port'] = tr.xpath('td[2]/text()')[0]
            one['protocol'] = tr.xpath('td[4]/text()')[0]
            one['position'] = tr.xpath('td[5]/text()')[0]
            one['speed'] = float(re.findall('\d+\.*\d*',tr.xpath('string(td[6])').strip())[0])
            ips.append(one)
    for url in urls:
        t = threading.Thread(target=function,args=(url,))
        t.setDaemon(True)
        tasks.append(t)
    for t in tasks:
        t.start()
    for t in tasks:
        t.join()
    return ips


#流年
def fetch_89ip():
    url = 'http://www.89ip.cn/tiqv.php?sxb=&tqsl=10000&ports=&ktip=&xl=on&submit=%CC%E1++%C8%A1'
    html = getHtml(url)
    matches = re.findall('\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}:\d+',html)
    ips = []
    for m in matches:
        t = m.split(':')
        one = {}
        one['ip'] = t[0]
        one['port'] = t[1]
        ips.append(one)
    return ips

#云代理
def fetch_ip3366():
    urls = ['http://www.ip3366.net/?page=%d'%i for i in range(1,8)]
    ips = []
    for url in urls:
        tree = etree.HTML(getHtml(url))
        trs = tree.xpath('//*[@id="list"]/table/tbody/tr')
        for tr in trs:
            if tr.xpath(u'contains(string(td[3]),"高匿")'):
                one = {}
                one['ip'] = tr.xpath('td[1]/text()')[0]
                one['port'] = tr.xpath('td[2]/text()')[0]
                one['protocol'] = tr.xpath('td[4]/text()')[0]
                one['position'] = tr.xpath('string(td[6])').strip()
                one['speed'] = float(re.findall('\d+\.*\d*',tr.xpath('td[7]/text()')[0])[0])
                ips.append(one)
    return ips

#迷惘免费IP
def fetch_wy96():
    urls = ['http://daili.wy96.com/page%d.asp'%i for i in range(1,11)]
    ips = []
    for url in urls[:1]:
        tree = etree.HTML(getHtml(url))
        trs = tree.xpath('//*[@id="list"]/table/tbody/tr')
        for tr in trs:
            if tr.xpath(u'contains(string(td[3]),"高匿")'):
                one = {}
                one['ip'] = tr.xpath('td[1]/text()')[0]
                one['port'] = tr.xpath('td[2]/text()')[0]
                one['protocol'] = tr.xpath('td[4]/text()')[0]
                one['position'] = tr.xpath('td[5]/text()')[0].strip()
                one['speed'] = float(tr.xpath('td[6]/text()')[0][:-1])
                ips.append(one)
    return ips


#敲代码
def fetch_qiaodm():
    from lxml.cssselect import CSSSelector as css
    url = 'http://ip.qiaodm.com/free/index.html'
    tree = etree.HTML(getHtml(url))
    trs = tree.xpath('//*[@id="main_container"]/div[1]/table/tbody/tr')[2:]
    ips = []
    #传入一个etree的element对象,返回一个IP地址
    def matchIp(tr):
        ip = ""
        td = tr.getchildren()[0].getchildren()
        for t in td:
            tp = t.attrib.get('style')
            tp = tp if tp else ''
            if not "none" in tp:
                text = t.text
                text = text if text else ''
                ip += text
        # if re.match('\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}',tr): #判断IP是否合法
        #     ip = False
        return ip
    for tr in trs:
        ip = matchIp(tr)
        if ip:
            if tr.xpath(u'contains(string(td[4]),"高匿")'):
                one = {}
                one['ip'] = ip
                one['port'] = tr.xpath('td[2]/text()')[0]
                types = tr.xpath('string(td[3])').strip().lower()
                one['protocol'] = 'https' if 'https' in types else 'http'
                one['position'] = tr.xpath('string(td[5])').replace(' ','').strip()
                one['speed'] = float(tr.xpath('string(td[6])').replace(' ','').strip()[:-1])
                ips.append(one)
    return ips



#全网代理IP
def fetch_goubanjia():
    urls = ['http://www.goubanjia.com/index%d.shtml'%i for i in range(1,11)]
    ips = []
    for url in urls:
        tree = etree.HTML(getHtml(url))
        trs = tree.xpath('//*[@id="list"]/table/tbody/tr')
        def matchIp(tr):
            ip = ''
            td = tr.getchildren()[0].getchildren()
            for t in td[:-1]:
                tp = t.attrib.get('style')
                tp = tp if tp else ''
                if not 'none' in tp:
                    text = t.text
                    text = text if text else ''
                    ip += text
            return ip
        for tr in trs:
            try:
                ip = matchIp(tr)
                if ip:
                    if tr.xpath(u'contains(string(td[2]),"匿")'):
                        one = {}
                        one['ip'] = ip
                        one['port'] = tr.getchildren()[0].getchildren()[-1].text
                        types = tr.xpath('string(td[3])').strip().lower()
                        one['protocol'] = 'https' if 'https' in types else 'http'
                        one['position'] = ''.join(tr.xpath('string(td[4]/a/text())')).replace(' ','')
                        speed = re.findall('\d+\.*\d*',tr.xpath('td[6]/text()')[0].strip())
                        one['speed'] = float(speed[0]) if len(speed)>0 else 0
                        ips.append(one)
            except Exception,e:
                continue

    return ips

#每日代理IP，ip181
def fetch_ip181():
    urls = ['http://www.ip181.com/daili/%d.html'%i for i in range(1,11)]
    ips = []
    for url in urls:
        try:
            tree = etree.HTML(getHtml(url))
            trs = tree.xpath('/html/body/div[2]/div/div[2]/div/div[3]/table/tbody/tr')[1:]
            for tr in trs:
                if tr.xpath(u'contains(string(td[3]),"高匿")'):
                    one = {}
                    one['ip'] = tr.xpath('string(td[1])').strip()
                    one['port'] = tr.xpath('string(td[2])').strip()
                    one['protocol'] = 'https' if 'https' in tr.xpath('string(td[4])').strip().lower() else 'http'
                    one['speed'] = float(re.findall('\d+\.*\d*',tr.xpath('string(td[5])'))[0])
                    one['position'] = tr.xpath('string(td[6])').strip()
                    ips.append(one) 
        except Exception,e:
            loggs('Error at fetch_ip181 with %s'%(str(e)))

    return ips

#瑶瑶代理
def fetch_httpsdaili():
    urls = ['http://www.httpsdaili.com/free.asp?page=1']
    ips = []
    for url in urls:
        tree = etree.HTML(getHtml(url))
        trs = tree.xpath('//*[@id="list"]/table/tbody/tr')
        for tr in trs:
            one = {}
            one['ip'] = tr.xpath('string(td[1])').strip()
            one['port'] = tr.xpath('string(td[2])').strip()
            one['protocol'] = 'https' if 'https' in tr.xpath('string(td[4])').strip().lower() else 'http'
            one['position'] = tr.xpath('string(td[5])').strip()
            one['speed'] = float(re.findall('\d+\.*\d*',tr.xpath('string(td[6])'))[0])
            ips.append(one)
    return ips

#风云代理
def fetch_fengyunip():
    url = 'http://www.fengyunip.com/free/index.html'
    tree = etree.HTML(getHtml(url))
    trs = tree.xpath('//*[@id="nav_btn01"]/div[5]/table/tbody/tr')
    ips = []
    def matchIp(tr):
        ip = ''
        td = tr.getchildren()[0].getchildren()
        for t in td:
            tp = t.attrib.get('style')
            tp = tp if tp else ''
            if not 'none' in tp:
                text = t.text
                text = text if text else ''
                ip += text
        return ip
    for tr in trs:
        ip = matchIp(tr)
        if ip:
            one = {}
            one['ip'] = ip
            one['port'] = tr.xpath('string(td[2])').strip()
            types = tr.xpath('string(td[4])').strip().lower()
            one['protocol'] = 'https' if 'https' in types else 'http'
            one['speed'] = float(re.findall('\d+\.*\d*',tr.xpath('string(td[5])'))[0])
            one['position'] = re.sub('\r|\n|\t| ','',tr.xpath('string(td[6])'))
            ips.append(one)
    return ips


#开心代理
def fetch_kxdaili():
    urls = ['http://www.kxdaili.com/dailiip/1/%d.html#ip'%i for i in range(1,11)]
    ips = []
    for url in urls:
        tree = etree.HTML(getHtml(url))
        trs = tree.xpath('//*[@id="nav_btn01"]/div[6]/table/tbody/tr')
        for tr in trs:
            one = {}
            one['ip'] = tr.xpath('string(td[1])').strip()
            one['port'] = tr.xpath('string(td[2])').strip()
            types = tr.xpath('string(td[4])').strip().lower()
            one['protocol'] = 'https' if 'https' in types else 'http'
            one['speed'] = float(re.findall('\d+\.*\d*',tr.xpath('string(td[5])'))[0])
            one['position'] = tr.xpath('string(td[6])').strip()
            ips.append(one)
    return ips

#讯代理
def fetch_xdaili():
    url = 'http://www.xdaili.cn/ipagent//freeip/getFreeIps?page=1&rows=10'
    headers = {
        "Referer":"http://www.xdaili.cn/freeproxy",
        "User-Agent":"Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/45.0.2454.101 Safari/537.36"
    }
    ips = []
    res = requests.get(url,headers=headers).text
    jd = json.loads(res)
    getips = jd['RESULT']['rows']
    for g in getips:
        one = {}
        one['ip'] = g.get('ip')
        one['port'] = g.get('port')
        one['protocol'] = 'https' if 'https' in g.get('type').lower() else 'http'
        one['position'] = g.get('position')
        one['speed'] = g.get('responsetime')
        ips.append(one)
    return ips

#急速代理IP
def fetch_superfastip():
    url = 'http://superfastip.com/welcome/getapi'
    res = getHtml(url)
    jd = json.loads(res)['data']
    ips = []
    for j in jd:
        if u'高匿' in j[4]:
            one = {}
            one['ip'] = j[1]
            one['port'] = j[2]
            one['position'] = j[3]
            one['protocol'] = 'https' if 'https' in j[5].lower() else 'http'
            one['speed'] = j[6]
            ips.append(one)
    return ips

#提取数据库中有用的IP
def getFromMysql():
    con = db.connect('localhost','root','123456','spidertools',charset='utf8') #连接数据库
    cur = con.cursor() #获取游标
    cur.execute('select ip,port from proxyippool') #查询所有IP
    ips = cur.fetchall() #获取所有查询结果
    cur.close() #关闭游标
    con.close() #关闭连接
    sqlip = []
    for ip in ips:
        one = {}
        one['ip'] = ip[0]
        one['port'] = ip[1]
        sqlip.append(one)
    loggs(u'提取,%d'%len(sqlip))
    return sqlip

#定义一个线程类
class ProxyConnectionText(threading.Thread):
    def __init__(self,ipd,q):
        threading.Thread.__init__(self)
        self.url1 = 'http://hotel.qunar.com/'
        self.url2 = 'https://www.baidu.com/'
        
        self.ipd = ipd
        self.protocol = ipd.get('protocol','http').lower()
        self.ip = self.protocol+'://'+ipd.get('ip')+':'+ipd.get('port')
        self.q = q

    def run(self):
        url = self.url2 if 'https' in self.protocol else self.url1
        try:
            res = requests.get(url,headers=headers,proxies={self.protocol:self.ip},timeout=5)
            if res.status_code == 200:
                self.q.put(self.ipd)
        except Exception:
            pass

#测试代理ip是否可用
def testIp(ip_list):
    q = Queue.Queue()
    usefullIp = []
    iplists = [ip_list[i:i+400] for i in range(0,len(ip_list),400)]
    for ips in iplists:
        tasks = []
        for ipd in ips:
            t = ProxyConnectionText(ipd,q)
            t.setDaemon(True)
            tasks.append(t)
        for t in tasks:
            t.start()
        for t in tasks:
            t.join()
    while not q.empty():
        usefullIp.append(q.get())
    s =  traceback.extract_stack()
    loggs(u'检测: 传入%d,返回%d'%(len(ip_list),len(usefullIp)))
    return usefullIp


#保存到数据库
def saveToMysql(iplist):
    con = db.connect('localhost','root','123456','spidertools',charset='utf8')
    cur = con.cursor()
    ok = 0
    for ipd in iplist:
        ip = ipd.get('ip')
        port = ipd.get('port')
        protocol = ipd.get('protocol','http').lower()
        speed = float(ipd.get('speed',0))
        position = ipd.get('position')
        score = 1
        ip_data = (protocol,ip,port,speed,position,score)
        sql = "insert into proxyippool(protocol,ip,port,speed,position,score) values('%s','%s','%s','%.3f','%s','%d')"%ip_data
        try:
            cur.execute(sql)
            ok += 1
        except Exception,e:
            loggs('error at(%s) with %s'%(sql,str(e)))
    con.commit()
    cur.close()
    con.close()
    loggs(u'入库,%d'%ok)


#对数据库中的IP进行加分或者减分
def changeIpScore(iplist,aord):
    con = db.connect('localhost','root','123456','spidertools',charset='utf8')
    cur = con.cursor()
    score = "+1" if aord else "-1"
    for ipd in iplist:
        try:
            ip = ipd.get('ip')
        except Exception,e:
            continue
        port = ipd.get('port')
        ip_data = 'update proxyippool set score=score%s where ip="%s" and port="%s"'%(score,ip,port)
        if not aord: #如果减分，则将失败次数+1
            ip_score_ded = 'update proxyippool set failtimes=failtimes+1 where ip="%s" and port="%s"'%(ip,port)
            try:
                cur.execute(ip_score_ded)
            except Exception,e:
                loggs('error at(%s) with %s'%(ip_data,str(e)))
        try:
            cur.execute(ip_data)
        except Exception,e:
            loggs('error at(%s) with %s'%(ip_data,str(e)))
    con.commit()
    cur.close()
    con.close()
    sco = u'加分' if aord else u'减分'
    loggs("%s: %d"%(sco,len(iplist)))

#删除数据库中失败次数>=3的IP
def deleteIpFromMysql():
    con = db.connect('localhost','root','123456','spidertools',charset='utf8')
    cur = con.cursor()
    sql = 'delete from proxyippool where failtimes>=3'
    cur.execute(sql)
    p = cur.rowcount
    loggs(u'删除: %d'%int(p))
    con.commit()
    cur.close()
    con.close()

#传入一个IP对象列表，返回一个IP字典
def list2dict(iplist):
    ips = {}
    for a in iplist: #去重
        one = {}
        ip = a.get('ip')
        one[ip] = a
        ips.update(one)
    return ips

#传入一个IP字典，返回一个IP对象列表
def dict2list(ipdict):
    iptest = []
    for k,v in ipdict.iteritems(): #去重还原
        iptest.append(v)
    return iptest


#传入一个对象列表，针对ip及port去重后返回一个对象列表
def drop_dups(iplist):
    iptest = dict2list(list2dict(iplist))
    loggs(u'去重:传入%d,返回%d'%(len(iplist),len(iptest)))
    return iptest

#加分减分管理
def scoreMangement(mysql_old_ip,mysql_ok_ip_dict):
    if len(mysql_old_ip)>0:
        scoreAdd = [] #需要加分的IP列表
        scoreDed = [] #需要减分的IP列表
        for oldip in mysql_old_ip: #根据测试结果判断从数据库中读取的IP哪些需要加分，哪些需要减分
            oldip_name = oldip.get('ip')
            if oldip_name in mysql_ok_ip_dict:
                scoreAdd.append(oldip)
            else:
                scoreDed.append(oldip)
        if len(scoreAdd)>0:
            changeIpScore(scoreAdd,1) #加分
        if len(scoreDed)>0:
            changeIpScore(scoreDed,0) #减分

#比对爬取的IP与数据库中的IP，爬取的IP有可能与原数据库中的重复，如果重复则丢弃
#传入（爬取的IP列表，读取库中的IP列表）,返回无重复可插入的IP列表
def crawl_ip_not_in_mysql(crawl_ip,mysql_old_ip_dict):
    ips = []
    if mysql_old_ip_dict != {}:
        crawl_insert_ip = [] #爬取的可以插入的IP
        for newip in crawl_ip: #如果新爬取的IP不与之前的数据库中ip重复，则可以插入
            newip_name = newip.get('ip')
            if not newip_name in mysql_old_ip_dict:
                crawl_insert_ip.append(newip)
        ips = crawl_insert_ip
    else:
        ips = crawl_ip
    loggs(u'校对: 传入%d,返回%d'%(len(crawl_ip),len(ips)))
    return ips

#将json以更优雅的方式显示
def printf(jd):
    print json.dumps(jd,sort_keys=True,indent=4,separators=(',',': '),encoding='utf8',ensure_ascii=False)

#传入一个字符串形式的函数名，返回该函数的调用接口
def function(f):
    return getattr(sys.modules[__name__],f)

def main():
    functions = [
        "fetch_66ip",
        "fetch_66minafei",
        "fetch_coobobo",
        "fetch_kuaidaili",
        "fetch_nianshao",
        "fetch_xici",
        "fetch_proxy360",
        "fetch_us_proxy",
        "fetch_iphai",
        "fetch_swei360",
        "fetch_89ip",
        "fetch_ip3366",
        "fetch_wy96",
        "fetch_qiaodm",
        "fetch_goubanjia",
        "fetch_ip181",
        "fetch_httpsdaili",
        "fetch_fengyunip",
        "fetch_kxdaili",
        "fetch_xdaili",
        "fetch_superfastip"
        ]
    loggs(u'开始运行')
    allIp = []
    for func in functions:
        try:
            data = function(func)()
            loggs(u"%s,%d"%(func,len(data)))
            allIp.extend(data)
        except Exception,e:
            loggs('Error at %s with %s'%(func,str(e)))
    iptest = drop_dups(allIp) #将从网上抓取到的IP进行去重操作
    crawl_ip = testIp(iptest) #测试抓取到的IP是否可用
    mysql_old_ip = getFromMysql() #从数据库中读取ip
    mysql_ok_ip = testIp(mysql_old_ip) #测试IP
    mysql_ok_ip_dict = list2dict(mysql_ok_ip) #将列表转为对象
    mysql_old_ip_dict = list2dict(mysql_old_ip) #将列表转为对象

    scoreMangement(mysql_old_ip,mysql_ok_ip_dict) #处理加分减分
    crawl_insert_ip = crawl_ip_not_in_mysql(crawl_ip,mysql_old_ip_dict) #查重,返回不与数据库重复的IP
    saveToMysql(crawl_insert_ip) #插入数据库
    deleteIpFromMysql() #删除分数低的IP
    loggs(u'运行结束')
    # printf(useip)

#用来做测试的地方
def test():
    path = '\\'.join(sys.argv[0].split('\\')[:-1])
    print path


if __name__ == '__main__':
    main()
    # test()

