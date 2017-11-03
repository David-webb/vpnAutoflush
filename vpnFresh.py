#!/usr/bin/env python
# -*- coding:utf-8 -*-
__author__ = 'Tengwei'

import requests
import time
import uuid
import re
import codecs
import os
import sys
import chardet 

class vpnFresh():
    """
        vpn来源：http://www.kuaichaxun.com/LCIP.txt
    """
    def __init__(self, username, pwd, hostRootpwd=""):
        self.hostRootPwd = hostRootpwd
        self.username = username
        self.pwd = pwd
        self.serviceType = {
            "PPTP": "org.freedesktop.NetworkManager.pptp",
            "L2TP": "org.freedesktop.NetworkManager.l2tp",
        }
        self.srcUrl = "http://www.kuaichaxun.com/LCIP.txt"
        self.VpnConfpath = "/etc/NetworkManager/system-connections/"
        self.locfolder = sys.path[0]

    def getVpns(self, write2file=False, filepath="vpn.txt"):
        """ 爬取VPN的ip主页（"http://www.kuaichaxun.com/LCIP.txt"）信息 """
        res = requests.get(self.srcUrl)
        # print res.content
        tmptext = res.content
        filepath = os.path.join(self.locfolder, filepath)
        if write2file:
            with open(filepath, 'w')as wr:
                wr.write(tmptext)
        return tmptext
        pass

    def is_chinese(self, uchar):
        """判断一个unicode是否是汉字"""
        if uchar >= u'\u4e00' and uchar<=u'\u9fa5':
            return True
        else:
            return False

    def is_strContainChinese(self, tmpstr):
        """ 检测字符串中是否包含中文: 被测字符串一定要是Unicode编码"""
        zhPattern = re.compile(u"[\u4e00-\u9fa5]+")
        match = zhPattern.search(tmpstr)
        if match:
            return True
        else:
            return False

        pass

    def readVpnPagefile2list(self, filepath="vpn.txt"):
        filepath = os.path.join(self.locfolder, filepath)
        with open(filepath, 'r')as rd:
            page = rd.read()
        encoding = "utf-8"
        if page.startswith(codecs.BOM_UTF8):            # 增加这个判断是为了去掉BOM头（\xef\xbb\xbf）
            encoding = "utf-8-sig"
        with codecs.open(filepath, 'r', encoding=encoding )as rd:
            lines = rd.readlines()
        return lines
        pass

    def prejudge(self, tmpstr):
        if tmpstr == "\r\n" or tmpstr == "" or "----" in tmpstr:
            # print tmpstr
            return True
        else:
            return False

    def ParseVpn2list(self):
        """ 从VPN主页中提取处VPN并转换成列表 """
        vpnpagelist = self.readVpnPagefile2list()

        finalAnslist = []   # 保存最终结果的list
        tmpAnslist = []     # 临时使用的list
        tmpstr = ""

        for line in vpnpagelist:
            line = line.strip()
	    """
	    try:

            	line = line.decode('utf-8')
	    except Exception as e:
		print line.decode('ascii')
		print chardet.detect(line)
		print e
	    """
            if self.prejudge(line):                     # 如果当前行是空行， 或者是分割符号"---", 直接跳过
                continue
            elif self.is_strContainChinese(line):       # 如果当前行包含中文，则在说明区，累积到tmpstr
                if len(tmpAnslist) > 0:                 # 累积ip列表不空，说明ip列表区刚结束
                    finalAnslist.append(tmpAnslist)
                    tmpAnslist = []
                tmpstr += line.encode('utf-8')
            else:                                       # 如果当前行不包含中文，进入ip区
                if tmpstr != "":                        # 累积字符串不空，表示说明区刚结束
                    finalAnslist.append(tmpstr)
                    tmpstr = ""
                tmpAnslist.append(line.encode('utf-8'))
        if tmpstr != "":
            finalAnslist.append(tmpstr)
        if tmpAnslist != []:
            finalAnslist.append(tmpAnslist)

        return finalAnslist
        pass

    def mergeList(self, indexStart, indexEnd, finalVpnList):
        s = indexStart
        tmplist = []
        while(s < indexEnd):
            if isinstance(finalVpnList[s], list):
                tmplist.extend(finalVpnList[s])
            s += 1
        return tmplist

    def fullVpnIpDict(self):
        """ 将VPN主页中解析得到的说明和ip列表结构化 """
        finalAnsDict = {
            "PPTP_L2TP": [],
            "IPSEC": [],
            "PPTP": [],
            "HongKong": [],
            "TaiWan": [],
            "Japan": [],
            "Korea": [],
            "ShangHai": [],
            "England": [],
        }
        finalVpnList = self.ParseVpn2list()

        for index, item in enumerate(finalVpnList):
            if isinstance(item, str):
                if "IPSEC" in item:
                    finalAnsDict["IPSEC"] = index
                elif "PPTP" in item and "L2TP" in item:
                    finalAnsDict["PPTP_L2TP"] = index
                elif "PPTP" in item:
                    finalAnsDict["PPTP"] = index
                elif "韩国" in item:
                    finalAnsDict["Korea"] = index
                elif "香港" in item:
                    finalAnsDict["HongKong"] = index
                elif "日本" in item:
                    finalAnsDict["Japan"] = index
                elif "英国" in item:
                    finalAnsDict["England"] = index
                elif "上海" in item:
                    finalAnsDict["ShangHai"] = index
                elif "台湾" in item:
                    finalAnsDict["TaiWan"] = index

        sortlist = sorted(finalAnsDict.iteritems(), key=lambda asd: asd[1], reverse=False)
        for index, item in enumerate(sortlist):
            c = index
            if item != sortlist[-1]:
                endindex = sortlist[c+1][1]
            else:
                endindex = len(finalVpnList)
            finalAnsDict[item[0]] = self.mergeList(item[1], endindex, finalVpnList)
        return finalAnsDict

    def gettimeStamp(self):
        return int(time.time())

    def getUUID(self):
        """
            1.Unix/Linux环境中大都有一个名为uuidgen的小工具，运行即可生成一个UUID到标准输出
            读取文件/proc/sys/kernel/random/uuid即得UUID，例如：
                    cat /proc/sys/kernel/random/uuid
            2. 这里使用的是Python自带的uuid模块，其中的uuid1()是基于mac，时间戳和随机数
        """
        # return uuid.uuid1()
        filepath = os.path.join(self.locfolder, "tmpuuid.txt")
        cmd = "cat /proc/sys/kernel/random/uuid > %s" % filepath
        os.system(cmd)
        with open(filepath, 'r')as rd:
            uuidStr = rd.read()
        return uuidStr.strip('\n')
        pass


    def getVpnMoudle(self, serviceType="PPTP"):
        """ 这是ubnutu下Network Manager VPN配置文件的模板(/etc/NetworkManager/system-connections/) """
        if serviceType == "PPTP":
            filename = "VPN_moudle"
        else:
            filename = "VPN_moudle_L2TP"
        filePath = os.path.join(self.locfolder, filename)
        with open(filePath, 'r') as rd:
            moudleText = rd.read()
        return moudleText.strip()
        pass

    def makeVpnConf(self, VpnName, uuid, timestamp, ip, serviceType="PPTP", shareKey="666888"):
        """ 创建VPN账号文件VPNx 保存到路径 /etc/NetworkManager/system-connections/下"""
        saveType = serviceType
        serviceType = self.serviceType[serviceType]         # 这里需要进行参数有效性验证！！！
        moudle_text = self.getVpnMoudle(saveType)
        if saveType == "PPTP":
            return moudle_text % (VpnName, uuid, timestamp, serviceType, ip, self.username, self.pwd)
        else:
            return moudle_text % (VpnName, uuid, timestamp, serviceType, ip, shareKey, self.username, ip, self.pwd)


    def delOldVpnfiles(self):
        filepath = os.path.join(self.VpnConfpath, "VPN*")
        cmd = "echo '%s' | sudo rm %s" % (self.hostRootPwd, filepath)
        try:
            os.system(cmd)
        except:
            print "没有VPN旧文件..."

    def flushNetWorkManage(self):
        """ 在系统中添加VPN账号文件后，还要修改文件的权限（为600）并重启NM才能看见新建的VPN """
        Vpnsfilepath = os.path.join(self.VpnConfpath, "VPN*")
        # 将所有新添加的VPN文件权限改为600,这步一定不能少，否则GNome中最终将看不见添加的账号
        cmd_chmod_600_VPNs = "echo '%s' | sudo chmod 600 %s" % (self.hostRootPwd, Vpnsfilepath)
        # print cmd_chmod_600_VPNs
        # 重启Network-Manager
        cmd_restart_NM = "echo '%s' | sudo service network-manager restart" % self.hostRootPwd
        os.system(cmd_chmod_600_VPNs)
        os.system(cmd_restart_NM)

    def createConfFiles(self, tmpdict, confList):
        """ confList = ["PPTP_L2TP", "VPN_%S", "PPTP"] """
        for index, item in enumerate(tmpdict[confList[0]]):
            filename = confList[1] % (index+1)
            filepath = os.path.join(self.VpnConfpath, filename)
            fileContent = self.makeVpnConf(filename, self.getUUID(), self.gettimeStamp(), item, confList[2])
            with open(filepath, 'w') as wr:
                wr.write(fileContent)
        pass
    def goFresh(self):
        """ 主程序 """
        # 获取新文件
        self.getVpns(True, os.path.join(self.locfolder, 'vpn.txt'))
        # 删除所有旧文件
        self.delOldVpnfiles()
        # 创建所有的PPTP协议的VPN账号（使用"PPTP_L2TP"下的IP）
        tmpdict = self.fullVpnIpDict()
        self.createConfFiles(tmpdict,  ["PPTP_L2TP", "VPN_%s", "PPTP"])
        self.createConfFiles(tmpdict,  ["PPTP_L2TP", "VPN_L2TP_%s", "L2TP"])
        self.flushNetWorkManage()
        pass


    def goFresh_20171021(self):
        """主程序"""
        # 获取新文件
        self.getVpns(True, os.path.join(self.locfolder, 'vpn.txt'))
        # 删除所有旧文件
        self.delOldVpnfiles()
        # 创建所有的PPTP协议的VPN账号（使用"PPTP_L2TP"下的IP）
        # tmpdict = self.fullVpnIpDict()
        tmplist = self.readVpnPagefile2list()[4:]
        tmplist = [i.split('\t')[1] for i in tmplist]
        tmpdict = {"PPTP_L2TP": tmplist}
        self.createConfFiles(tmpdict,  ["PPTP_L2TP", "VPN_L2TP_%s", "L2TP"])
        self.flushNetWorkManage()
        pass

    def timestamp2time(self, timeStamp):
        timeStamp = timeStamp
        timeArray = time.localtime(timeStamp)
        otherStyleTime = time.strftime("%Y-%m-%d %H:%M:%S", timeArray)
        return otherStyleTime


if __name__ == '__main__':
    vpn_username = sys.argv[1]
    vpn_pwd = sys.argv[2]
    vpn_host_pwd = sys.argv[3]
    # print vpn_username, vpn_pwd, vpn_host_pwd
    tmpobj = vpnFresh(vpn_username, vpn_pwd, vpn_host_pwd)
    # tmpobj.goFresh()
    tmpobj.goFresh_20171021()
    pass
