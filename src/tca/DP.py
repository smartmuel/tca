from __init__ import *
from typing import Dict
import re

def Port_Error(dps: Dict[], user: str, password: str, legit_only: bool = False):
    for i in DPs:  # For all DPs that the DF is in contact with
        with CM.ssh(host=i, user=user, password=password) as ssh:
            com = ssh.Command("system inf-stats")
            for j in DTCT["DP_Ports"]:  # For the ports the configured at Data_For_TCT.json
                if (not re.search(rf"{j}\s+[0-9]+\s+0\s+0\s+[0-9]+\s+0\s+0", com, re.IGNORECASE)) and re.search(
                        rf"^{j}\s+", com, re.IGNORECASE):
                    return f'{i}:\n{com}'

        else:
            if Legit_Only:
                com = telnet.Command("system internal dpe-statistics total all", True)
                if (not re.search(rf"DPE Counters\s+: Forwards\s+=\s+[0-9]+\s+Discards\s+=\s+0", com,
                                  re.IGNORECASE)) and (
                        not re.search(
                            rf"HW-Accelerator Counters\s+: Forwards\s+=\s+[0-9]+\s+Discards\s+=\s+0", com,
                            re.IGNORECASE)) and (
                        not re.search(rf"Total Counters\s+: Forwards\s+=\s+[0-9]+\s+Discards\s+=\s+0", com,
                                      re.IGNORECASE)):
                    return f'{i}:\n{com}'



def No_BDOS_Attack():
    for i in list(DPs):
        telnet = Telnet(i)
        com = telnet.Command("system internal security bdos attacks", True)
        if len(com.split("\n")) > 4:
            return f'{i}:\n{com}'



def BDOS_Attacks():
    for i in list(DPs):
        telnet = Telnet(i)
        com = telnet.Command("system internal security bdos attacks", True)
        if len(com.split("\n")) < 5:
            return f'{i}:\n{com}'



def Support_File_Extract():
    with CM.Chrome() as driver:
        for i in DTCT.DP_Info.keys():
            driver.Click('//*[@data-debug-id="VISIONSETTINGS_ICON"]')
            driver.Click(f"gwt-debug-DevicesTree_Node_{i}")
            driver.ClickIf('//*[@title="Click to lock the device"]', delay=3)
            driver.Click("gwt-debug-DeviceControlBar_Operations")
            while not driver.Wait("gwt-debug-DeviceControlBar_Operations_getFileFromDevice_Support", delay=10):
                driver.Click("gwt-debug-DeviceControlBar_Operations")
            driver.Click("gwt-debug-DeviceControlBar_Operations_getFileFromDevice_Support")
            if not file_check():
                return "File not downloaded after the default time"