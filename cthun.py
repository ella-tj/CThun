# -*- coding: utf-8 -*-
# @File  : main.py
# @Date  : 2019/9/3
# @Desc  :
# @license : Copyright(C), funnywolf 
# @Author: funnywolf
# @Contact : github.com/FunnyWolf
import datetime
import json
import os
import sys
import time
from itertools import groupby

from gevent.pool import Pool
from ipaddr import summarize_address_range, IPv4Network, IPv4Address

from lib.config import logger, work_path, ipportservicelogfilename, finishlogfile
from portscan.RE_DATA import TOP_1000_PORTS_WITH_ORDER


def group_numbers(lst):
    templist = []
    fun = lambda x: x[1] - x[0]
    for k, g in groupby(enumerate(lst), fun):
        l1 = [j for i, j in g]
        if len(l1) > 1:
            scop = str(min(l1)) + '-' + str(max(l1))
        else:
            scop = l1[0]
        templist.append(scop)
    return templist


def get_ipaddresses(raw_lines):
    ipaddress_list = []
    for line in raw_lines:
        if '-' in line:
            try:
                startip = line.split("-")[0]
                endip = line.split("-")[1]
                ipnetwork_list = summarize_address_range(IPv4Address(startip), IPv4Address(endip))
                for ipnetwork in ipnetwork_list:
                    for ip in ipnetwork:
                        if ip.compressed not in ipaddress_list:
                            ipaddress_list.append(ip.compressed)
            except Exception as E:
                print(E)
        else:
            try:
                ipnetwork = IPv4Network(line)
                for ip in ipnetwork:
                    if ip.compressed not in ipaddress_list:
                        ipaddress_list.append(ip.compressed)
            except Exception as E:
                print(E)

    return ipaddress_list


def get_one_result(raw_line, proto):
    try:
        proto_default_port = {'ftp': 21, 'ssh': 22, 'rdp': 3389, 'smb': 445, 'mysql': 3306, 'mssql': 1433,
                              'redis': 6379, 'mongodb': 27017, 'memcached': 11211,
                              'postgresql': 5432, 'vnc': 5901, "http": 80, "ssl/http": 443, "https": 443}
        if len(raw_line.split(":")) < 2:
            # 没有填写端口,使用默认端口
            port = proto_default_port.get(proto)
        else:
            port = int(raw_line.split(":")[1])
        line = raw_line.split(":")[0]
    except Exception as E:
        print(E)
        return []
    result = []
    ipaddress_list = []
    if '-' in line:
        try:
            startip = line.split("-")[0]
            endip = line.split("-")[1]
            ipnetwork_list = summarize_address_range(IPv4Address(startip), IPv4Address(endip))
            for ipnetwork in ipnetwork_list:
                for ip in ipnetwork:
                    if ip.compressed not in ipaddress_list:
                        ipaddress_list.append(ip.compressed)
        except Exception as E:
            print(E)
    else:
        try:
            ipnetwork = IPv4Network(line)
            for ip in ipnetwork:
                if ip.compressed not in ipaddress_list:
                    ipaddress_list.append(ip.compressed)
        except Exception as E:
            # 输入可能是网址
            ipaddress_list.append(line)
            print(E)

    for ip in ipaddress_list:
        result.append({"ipaddress": ip, "port": port, "service": proto})
    return result


def write_finish_flag():
    logfilepath = os.path.join(os.path.dirname(os.path.realpath(sys.argv[0])), finishlogfile)
    with open(logfilepath, 'wb+') as f:
        f.write(datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S'))


if __name__ == '__main__':
    # 获取时间戳
    logger.info("----------------- Progrem Start ---------------------")
    try:
        paramsfile = "param.json"
        paramsfilepath = os.path.join(work_path, paramsfile)
        with open(paramsfilepath) as f:
            params = json.load(f)
    except Exception as E:
        logger.error("Can not find {0}".format(paramsfile))
        sys.exit(1)

    # 处理debug标签
    debug_flag = params.get("debug")
    if debug_flag is True:
        fullname = "debug.log"
        sys.stderr = open(fullname, "w+")
    else:
        sys.stderr = None

    # 处理最大连接数
    max_socket_count = params.get("maxsocket")
    if max_socket_count <= 100:
        max_socket_count = 100
    elif max_socket_count >= 1000:
        top_ports_count = 1000

    # 处理socket超时时间
    timeout = params.get("sockettimeout")

    if timeout <= 0.1:
        timeout = 0.1
    elif timeout >= 3:
        timeout = 3

    # 公共变量
    pool = Pool(max_socket_count)
    portScan_result_list = []

    # 加载历史记录
    load_from_history = params.get("loadfromhistory")
    if load_from_history is True:
        # 读取文件中保存的ip地址,端口,服务
        filepath = os.path.join(work_path, ipportservicelogfilename)
        try:
            with open(filepath, "rb") as f:
                file_lines = f.readlines()
                for line in file_lines:
                    ip = line.strip().split(",")[0]
                    port = line.strip().split(",")[1]
                    proto = line.strip().split(",")[2]
                    try:
                        one_record = {"ipaddress": ip, "port": port, "service": proto}
                        if one_record not in portScan_result_list:
                            portScan_result_list.append({"ipaddress": ip, "port": port, "service": proto})
                    except Exception as E:
                        pass
        except Exception as E:
            pass

    # 端口扫描参数
    if params.get("portscan"):
        portscan = params.get("portscan").get("run")
        if portscan is True:
            ip_list = []
            try:
                raw_ips = params.get("portscan").get("ipaddress")
                if raw_ips == [] or raw_ips is None:
                    ip_list = []
                else:
                    ip_list = get_ipaddresses(raw_ips)
            except Exception as E:
                pass
            if len(ip_list) <= 0:
                logger.warn("Can not get portscan ipaddress from param.json.")
                portscan = False

        if portscan:
            showports = ""
            top_ports_count = params.get("portscan").get("topports")
            if top_ports_count <= 0:
                top_ports_count = 0
            elif top_ports_count >= 1000:
                top_ports_count = 1000

            port_list = []
            ports_str = params.get("portscan").get("ports")

            if params.get("portscan").get("ports") == [] or params.get("portscan").get("ports") is None:
                ports_str = []
            else:
                ports_str = params.get("portscan").get("ports")

            for one in ports_str:
                try:
                    if isinstance(one, int):
                        if one not in port_list and (0 < one <= 65535):
                            port_list.append(one)
                    elif len(one.split("-")) == 2:
                        start_port = int(one.split("-")[0])
                        end_port = int(one.split("-")[1])
                        for i in range(start_port, end_port + 1):
                            if i not in port_list and (0 < i <= 65535):
                                port_list.append(i)
                    else:
                        i = int(one)
                        if i not in port_list and (0 < i <= 65535):
                            port_list.append(i)
                except Exception as E:
                    pass

            top_port_list = TOP_1000_PORTS_WITH_ORDER[0:top_ports_count]
            for i in port_list:
                if i not in top_port_list:
                    top_port_list.append(i)
            if len(top_port_list) <= 0:
                logger.warn("Can not get portscan ports param.json.")
                portscan = False
            else:
                showports = group_numbers(top_port_list)

        if portscan:
            # 处理retry参数
            retry = params.get("portscan").get("retry")
            if retry <= 1:
                retry = 1
            elif retry >= 3:
                retry = 3

            if timeout <= 0.1:
                timeout = 0.1
            elif timeout >= 3:
                timeout = 3

            logger.info("----------------- PortScan Start --------------------")
            logger.info(
                "IP list: {}\tIP count: {}\tSocketTimeout: {}\tMaxsocket: {}\tPorts: {}".format(raw_ips,
                                                                                                len(ip_list),
                                                                                                timeout,
                                                                                                max_socket_count,
                                                                                                showports))
            t1 = time.time()

            from portscan.portScan import GeventScanner

            geventScanner = GeventScanner(max_socket_count=max_socket_count, timeout=timeout, retry=retry)
            portScan_result_list = geventScanner.aysnc_main(ip_list, top_port_list, pool)
            t2 = time.time()
            logger.info("PortScan finish,time use : {}s".format(t2 - t1))
            logger.info("----------------- PortScan Finish --------------------")

    # netbios扫描
    if params.get("netbiosscan"):
        netbios_scan = params.get("netbiosscan").get("run")
        if netbios_scan is True:

            ip_list = []
            try:
                raw_ips = params.get("netbiosscan").get("ipaddress")
                if raw_ips == [] or raw_ips is None:
                    ip_list = []
                else:
                    ip_list = get_ipaddresses(raw_ips)
            except Exception as E:
                pass

            if len(ip_list) <= 0:
                logger.warn("Can not get ipaddress from param.json.")
                netbios_scan = False
            else:
                logger.info("----------------- Netbios Scan Start ----------------------")
                logger.info(
                    "IP list: {}\tIP count: {}\tSocketTimeout: {}\tMaxsocket: {}".format(raw_ips,
                                                                                         len(ip_list),
                                                                                         timeout,
                                                                                         max_socket_count,
                                                                                         ))
                t3 = time.time()

                from netbios.netbios import netbios_interface

                netbios_interface(ip_list, timeout, pool)
                t4 = time.time()
                logger.info("Netbios Scan finish,time use : {} s".format(t4 - t3))
                logger.info("----------------- Netbios Scan Finish ---------------------")

    # http扫描
    if params.get("httpscan"):
        http_scan = params.get("httpscan").get("run")
        if http_scan is True:

            raw_lines = params.get("httpscan").get("http")
            if raw_lines == [] or raw_lines is None:
                lines = []
            else:
                lines = params.get("httpscan").get("http")
            for line in lines:
                manly_input_result = get_one_result(line.strip(), "http")
                portScan_result_list.extend(manly_input_result)

            raw_lines = params.get("httpscan").get("https")
            if raw_lines == [] or raw_lines is None:
                lines = []
            else:
                lines = params.get("httpscan").get("https")
            for line in lines:
                manly_input_result = get_one_result(line.strip(), "https")
                portScan_result_list.extend(manly_input_result)

            raw_lines = params.get("httpscan").get("flagurl")
            if raw_lines == [] or raw_lines is None:
                flagurl = []
            else:
                flagurl = params.get("httpscan").get("flagurl")

            logger.info("----------------- HttpCheck Start ----------------------")
            t3 = time.time()

            from httpcheck.httpCheck import http_interface

            http_interface(portScan_result_list, timeout, pool, flagurl)
            t4 = time.time()
            logger.info("HttpCheck finish,time use : {}s".format(t4 - t3))
            logger.info("----------------- HttpCheck Finish ---------------------")

    # 暴力破解
    if params.get("bruteforce"):
        bruteforce = params.get("bruteforce").get("run")
        if bruteforce is True:

            defaultdict = params.get("bruteforce").get("defaultdict")

            if params.get("bruteforce").get("users") == [] or params.get("bruteforce").get("users") is None:
                users = []
            else:
                users = params.get("bruteforce").get("users")

            if params.get("bruteforce").get("passwords") == [] or params.get("bruteforce").get("passwords") is None:
                passwords = []
            else:
                passwords = params.get("bruteforce").get("passwords")

            if params.get("bruteforce").get("hashes") == [] or params.get("bruteforce").get("hashes") is None:
                hashes = []
            else:
                hashes = params.get("bruteforce").get("hashes")

            if params.get("bruteforce").get("sshkeys") == [] or params.get("bruteforce").get("sshkeys") is None:
                sshkeys = []
            else:
                sshkeys = []
                sshkeysstr = params.get("bruteforce").get("sshkeys")
                for onekey in sshkeysstr:
                    sshkeys.append(os.path.join(work_path, onekey))

            proto_list = []
            proto_list_all = ['ftp', 'ssh', 'rdp', 'smb', 'mysql', 'mssql', 'redis', 'mongodb', 'memcached', 'vnc']

            for proto in proto_list_all:
                raw_lines = params.get("bruteforce").get(proto)
                if raw_lines == [] or raw_lines is None:
                    pass
                else:
                    proto_list.append(proto)  # 加入到列表,端口扫描结果也使用
                    for line in raw_lines:
                        manly_input_result = get_one_result(line.strip(), proto)
                        portScan_result_list.extend(manly_input_result)

            if len(proto_list) > 0:
                t2 = time.time()
                logger.info("----------------- BruteForce Start -------------------")
                logger.info("Protocols: {}\tDefaultdict: {}".format(proto_list, defaultdict))

                from bruteforce.bruteForce import bruteforce_interface

                bruteforce_interface(
                    portScan_result_list=portScan_result_list,
                    timeout=timeout,
                    proto_list=proto_list,
                    pool=pool,
                    default_dict=defaultdict,
                    users=users,
                    passwords=passwords,
                    hashes=hashes,
                    ssh_keys=sshkeys,
                )
                t3 = time.time()
                logger.info("BruteForce finish,time use : {} s".format(t3 - t2))
                logger.info("----------------- BruteForce Finish --------------------")

    if params.get("vulscan"):
        vulscan = params.get("vulscan").get("run")
        if vulscan is True:
            proto_list = []
            proto_list_all = ["smb", "http", "https"]
            for proto in proto_list_all:
                raw_lines = params.get("vulscan").get(proto)
                if raw_lines == [] or raw_lines is None:
                    pass
                else:
                    proto_list.append(proto)  # 加入到列表,端口扫描结果也使用
                    for line in raw_lines:
                        manly_input_result = get_one_result(line.strip(), proto)
                        portScan_result_list.extend(manly_input_result)

            if len(proto_list) > 0:
                logger.info("----------------- VulScan Start ---------------------")
                t3 = time.time()
                from vulscan.vulScan import vulscan_interface

                vulscan_interface(portScan_result_list=portScan_result_list, timeout=timeout, pool=pool)
                t4 = time.time()
                logger.info("Vulscan Scan finish,time use : {}s".format(t4 - t3))
                logger.info("----------------- VulScan Finish --------------------")

    logger.info("----------------- Progrem Finish -----------------------\n\n")

    # 写入结束标志
    try:
        write_finish_flag()
    except Exception as e:
        print(e)
        pass
