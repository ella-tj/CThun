# -*- coding: utf-8 -*-
# @File  : main.py
# @Date  : 2019/9/3
# @Desc  :
# @license : Copyright(C), funnywolf 
# @Author: funnywolf
# @Contact : github.com/FunnyWolf
import argparse
import datetime
import os
import sys
import time
from itertools import groupby

from gevent.pool import Pool
from ipaddr import summarize_address_range, IPv4Network, IPv4Address

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
                              'postgresql': 5432, 'vnc': 5901}
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
            print(E)
    # service = one_portscan_result.get("service").lower()
    # ipaddress = one_portscan_result.get("ipaddress")
    # port = one_portscan_result.get("port")
    # 读取mysql.txt,redis.txt中的ip地址
    for ip in ipaddress_list:
        result.append({"ipaddress": ip, "port": port, "service": proto})
    return result


def write_finish_flag(start_timestamp):
    logfilename = "{}-finish.log".format(start_timestamp)
    logfilepath = os.path.join(os.path.dirname(os.path.realpath(sys.argv[0])), logfilename)

    with open(logfilepath, 'wb+') as f:
        f.write(datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S'))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(
        description="This script can scan port&service like nmap and bruteforce like hydra."
                    "result will store in result.log in same folder."
                    "progrem has default user/password dict inside,"
                    "you can add extra users in user.txt and extra password in password.ext in same folder"
                    "(one line one word)")
    parser.add_argument('-ips', metavar='ipaddress',
                        help="Scan ipaddresses(e.g. '192.172.1.1,192.172.1.1/24,192.172.1.1-192.172.1.10')",
                        required=False)
    parser.add_argument('-ipf', metavar='ip.txt',
                        help="File store ipaddress,one ip one line,you can use 192.172.1.1\n192.172.1.1/24\n192.172.1.1-192.172.1.10\n(do not use ,)",
                        required=False)
    parser.add_argument('-p', '--ports',
                        default=[],
                        metavar='N,N',
                        type=lambda s: [i for i in s.split(",")],
                        help="Port(s) to scan(e.g. '22,80,1-65535').",
                        )
    parser.add_argument('-tp', '--topports',
                        metavar='N',
                        help='The N most commonly used ports(e.g. 100).',
                        default=0,
                        type=int)
    parser.add_argument('-t', '--sockettimeout',
                        metavar='N',
                        help='Socket Timeout(second),default is 0.5',
                        default=0.5,
                        type=float)
    parser.add_argument('-ms', '--maxsocket',
                        metavar='N',
                        help='Max sockets(100-1000),default is 300',
                        default=300,
                        type=int)
    parser.add_argument('-rt', '--retry',
                        metavar='N',
                        help='Retry count if connet port timeout(1-3),default is 2',
                        default=2,
                        type=int)
    parser.add_argument('-hs', '--http_scan', default=False,
                        nargs='?',
                        metavar="true",
                        type=bool,
                        help="Advance scan http(s) services,get title,status code and website techs",
                        )
    parser.add_argument('-hs-url', '--http_scan_urls',
                        default=[],
                        metavar='STR,STR',
                        type=lambda s: [i for i in s.split(",")],
                        help="Check whether website respond 200 on input url,you can input like '/admin/login.jsp,/js/ijustcheck.js'",
                        )
    parser.add_argument('-bf', '--bruteforce',
                        default=[],
                        metavar='STR,STR',
                        type=lambda s: [i for i in s.split(",")],
                        help="Bruteforce Protocols after portscan.(e.g. 'all,ftp,ssh,rdp,vnc,smb,mysql,mssql,postgresql,redis,mongodb,memcached')",
                        )
    parser.add_argument('-nd', '--no_default_dict', default=False,
                        nargs='?',
                        metavar="true",
                        type=bool,
                        help="do not use default user/password dict,only user.txt,password.txt",
                        )
    parser.add_argument('-sshkeys', '--sshkeys',
                        default=[],
                        metavar='STR,STR',
                        type=lambda s: [i for i in s.split(",")],
                        help="rsa private key filepath(for ssh bruteforce,you can input like 'id_rsa_1,id_rsa_2', use users in user.txt)",
                        )
    parser.add_argument('-nbs', '--netbios_scan', default=False,
                        nargs='?',
                        metavar="true",
                        type=bool,
                        help="Run netbios scan on input ipadddresses",
                        )
    parser.add_argument('-vs', '--vulscan', default=False,
                        nargs='?',
                        metavar="true",
                        type=bool,
                        help="VulScan",
                        )
    parser.add_argument('-debug', '--debug', default=False,
                        nargs='?',
                        metavar="true",
                        type=bool,
                        help="Get error log in debug.log",
                        )

    args = parser.parse_args()
    # 处理ip输入
    ips = args.ips
    ipf = args.ipf
    raw_lines = []

    if ips is not None:
        try:
            input_lines = ips.split(",")
            raw_lines.extend(input_lines)
        except Exception as E:
            print(E)
    if ipf is not None:
        try:
            with open(ipf, "rb") as f:
                file_lines = f.readlines()
                for line in file_lines:
                    raw_lines.append(line.strip())
        except Exception as E:
            print(E)

    ip_list = get_ipaddresses(raw_lines)

    if len(ip_list) <= 0:
        print("[!] Can not get ipaddress for -ips or -ipf.")
        print("[!] port/http/netbios scan will pass.")
    # 处理端口输入
    top_ports_count = args.topports
    if top_ports_count <= 0:
        top_ports_count = 0
    elif top_ports_count >= 1000:
        top_ports_count = 1000

    retry = args.retry
    if retry <= 1:
        top_ports_count = 1
    elif retry >= 3:
        retry = 3

    port_list = []
    ports_str = args.ports
    for one in ports_str:
        try:
            if len(one.split("-")) == 2:
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
        print("[!] Can not get ports from -p and -tp.")
        print("[!] port/http scan will pass.")
    # 最大连接数
    max_socket_count = args.maxsocket

    if max_socket_count <= 100:
        max_socket_count = 100
    elif max_socket_count >= 1000:
        top_ports_count = 1000
    timeout = args.sockettimeout
    print("[!] Progrem Start ! All infomation will write to xxx-result.log,finish time will write to xxx-finish.log"
          " You can run this progrem on blackground next time. HAPPY HACKING!")
    showports = group_numbers(top_port_list)

    debug_flag = args.debug
    if debug_flag is not False:
        debug_flag = True

    if debug_flag is True:
        fullname = "debug.log"
        sys.stderr = open(fullname, "w+")
    else:
        sys.stderr = None
    # 动态加载,获取时间
    start_timestamp = datetime.datetime.now().strftime('%Y%m%d-%H%M%S')
    from lib.config import logger

    logger.info("----------------- Progrem Start ---------------------")
    logger.info(datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S'))

    # 端口扫描
    # 端口扫描
    # 端口扫描
    # 输入了有效的ip列表及端口号
    if len(ip_list) > 0 and top_port_list > 0:
        logger.info("----------------- PortScan Start --------------------")
        logger.info("\nIP list: {}\nIP count: {}\nSocketTimeout: {}\nMaxsocket: {}\nPorts: {}".format(raw_lines,
                                                                                                      len(ip_list),
                                                                                                      timeout,
                                                                                                      max_socket_count,
                                                                                                      showports))

        t1 = time.time()
        pool = Pool(max_socket_count)
        from portscan.portScan import GeventScanner

        geventScanner = GeventScanner(max_socket_count=max_socket_count, timeout=timeout, retry=retry)
        portScan_result_list = geventScanner.aysnc_main(ip_list, top_port_list, pool)
        t2 = time.time()
        logger.info("PortScan finish,time use : {}s".format(t2 - t1))
        logger.info("----------------- PortScan Finish --------------------")
    else:
        pool = Pool(max_socket_count)
        portScan_result_list = []

    # web扫描
    # web扫描
    # web扫描
    http_scan = args.http_scan
    if http_scan is not False:
        from httpcheck.httpCheck import http_interface

        http_scan_urls = args.http_scan_urls
        filename = "http.txt"
        try:
            with open(filename, "rb") as f:
                file_lines = f.readlines()
                for line in file_lines:
                    manly_input_result = get_one_result(line.strip(), "http")
                    portScan_result_list.extend(manly_input_result)
        except Exception as E:
            pass

        filename = "https.txt"
        try:
            with open(filename, "rb") as f:
                file_lines = f.readlines()
                for line in file_lines:
                    manly_input_result = get_one_result(line.strip(), "http")
                    portScan_result_list.extend(manly_input_result)
        except Exception as E:
            pass

        logger.info("----------------- HttpCheck Start ----------------------")
        t3 = time.time()
        http_interface(portScan_result_list, timeout, pool, http_scan_urls)
        t4 = time.time()
        logger.info("HttpCheck finish,time use : {}s".format(t4 - t3))
        logger.info("----------------- HttpCheck Finish ---------------------")

    # 暴力破解
    # 暴力破解
    # 暴力破解
    bf = args.bruteforce
    if len(bf) > 0:
        no_default_dict = args.no_default_dict
        if no_default_dict is not False:
            no_default_dict = True

        proto_list_all = ['ftp', 'ssh', 'rdp', 'smb', 'mysql', 'mssql', 'redis', 'mongodb', 'memcached',
                          'postgresql', 'vnc']
        proto_list = []
        for proto in bf:
            if proto.lower() == "all":
                proto_list = proto_list_all
                break
            elif proto.lower() in proto_list_all:
                proto_list.append(proto.lower())

        if len(proto_list) > 0:
            from bruteforce.bruteForce import bruteforce_interface

            for prote in proto_list:
                filename = "{}.txt".format(prote)
                try:
                    with open(filename, "rb") as f:
                        file_lines = f.readlines()
                        for line in file_lines:
                            manly_input_result = get_one_result(line.strip(), prote)
                            portScan_result_list.extend(manly_input_result)
                except Exception as E:
                    pass

            sshkeys = args.sshkeys
            t2 = time.time()
            logger.info("----------------- BruteForce Start -------------------")
            logger.info("Protocols: {}\nNo_default_dict: {}".format(proto_list, no_default_dict))
            bruteforce_interface(portScan_result_list, timeout, no_default_dict, proto_list, pool, sshkeys)
            t3 = time.time()
            logger.info("BruteForce finish,time use : {}s".format(t3 - t2))
            logger.info("----------------- BruteForce Finish --------------------")

    # netbios扫描
    # netbios扫描
    # netbios扫描
    netbios_scan = args.netbios_scan
    if netbios_scan is not False:
        from netbios.netbios import netbios_scan

        logger.info("----------------- Netbios Scan Start ----------------------")
        t3 = time.time()
        netbios_scan(ip_list, timeout)
        t4 = time.time()
        logger.info("Netbios Scan finish,time use : {}s".format(t4 - t3))
        logger.info("----------------- Netbios Scan Finish ---------------------")

    vulscan = args.vulscan
    if vulscan is not False:
        from vulscan.vulScan import vulscan_interface

        logger.info("----------------- Vul Scan Start ----------------------")
        t3 = time.time()
        proto_list = ["smb"]
        for prote in proto_list:
            filename = "{}.txt".format(prote)
            try:
                with open(filename, "rb") as f:
                    file_lines = f.readlines()
                    for line in file_lines:
                        manly_input_result = get_one_result(line.strip(), prote)
                        portScan_result_list.extend(manly_input_result)
            except Exception as E:
                pass
        vulscan_interface(portScan_result_list, timeout, pool)
        t4 = time.time()
        logger.info("Netbios Scan finish,time use : {}s".format(t4 - t3))
        logger.info("----------------- Vul Scan Finish ---------------------")

    logger.info("----------------- Progrem Finish -----------------------\n\n")
    # 写入结束标志
    try:
        write_finish_flag(start_timestamp)
    except Exception as e:
        pass
