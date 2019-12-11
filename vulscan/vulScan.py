# -*- coding: utf-8 -*-
# @File  : vulscan.py
# @Date  : 2019/12/11
# @Desc  :
# @license : Copyright(C), funnywolf 
# @Author: funnywolf
# @Contact : github.com/FunnyWolf

import gevent

from vulscan.ms17010 import ms17010scan


def vulscan_interface(portScan_result_list, timeout, pool):
    pool = pool
    tasks = []
    for one_portscan_result in portScan_result_list:
        service = one_portscan_result.get("service").lower()
        ipaddress = one_portscan_result.get("ipaddress")
        port = one_portscan_result.get("port")
        # 快的扫描
        if ("microsoft-ds" in service or "smb" in service):
            task = pool.spawn(ms17010scan, ipaddress, port)
            tasks.append(task)
    gevent.joinall(tasks)
