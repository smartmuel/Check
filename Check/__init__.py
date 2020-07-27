from TCT import *
import pytest, allure

class DP(object):
    """
    DP Tests
    """

    @staticmethod
    def Port_Error(Legit_Only=False):
        for i in DTCT.DP_Info.values():  # For all DPs that the DF is in contact with
            telnet = Telnet(i)
            com = telnet.Command("system inf-stats")
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

    @staticmethod
    def No_BDOS_Attack():
        for i in list(DTCT.DP_Info.values()):
            telnet = Telnet(i)
            com = telnet.Command("system internal security bdos attacks", True)
            if len(com.split("\n")) > 4:
                return f'{i}:\n{com}'

    @staticmethod
    def BDOS_Attacks():
        for i in list(DTCT.DP_Info.values()):
            telnet = Telnet(i)
            com = telnet.Command("system internal security bdos attacks", True)
            if len(com.split("\n")) < 5:
                return f'{i}:\n{com}'

    @staticmethod
    def Support_File_Extract():
        with CM.Chrome() as driver:
            for i in DTCT.DP_Info.keys():
                driver.Click(f"gwt-debug-DevicesTree_Node_{i}")
                driver.ClickIf('//*[@title="Click to lock the device"]', delay=3)
                driver.Click("gwt-debug-DeviceControlBar_Operations")
                while not driver.Wait("gwt-debug-DeviceControlBar_Operations_getFileFromDevice_Support", delay=10):
                    driver.Click("gwt-debug-DeviceControlBar_Operations")
                driver.Click("gwt-debug-DeviceControlBar_Operations_getFileFromDevice_Support")
                if not file_check():
                    return "File not downloaded after the default time"

class DF(object):
    """
    DF Tests
    """

    @staticmethod
    def BGP_Established():
        api = Vision_API()
        response = api.Get(f'https://{DTCT["Vision_IP"]}/mgmt/device/df/config/BgpPeers',True)
        for i in response["BgpPeers"]:
            if i["state"] != "ESTABLISHED":
                return i

    @staticmethod
    def BGP_Announcements():
        api = Vision_API()
        response1 = api.Get(f'https://{DTCT["Vision_IP"]}/mgmt/device/df/config/BgpPeers')
        response2 = api.Get(f'https://{DTCT["Vision_IP"]}/mgmt/device/df/config/Announcements', True)
        if len(response1["BgpPeers"]) * (len(Syslog.start) + DTCT["OngoingProtections"]) > len(
                response2["Announcements"]):
            """peers = dict()
            for i in response1["BgpPeers"]:
                try:
                    if i["state"] == "ESTABLISHED":
                        peers[i["localIp"]].add(i["ip"])
                except KeyError:
                    peers[i["localIp"]] = (i["ip"])
            for i in response2["Announcements"]:
                if i["status"] == "SUCCESS":"""
            return "Number of announcements is less then expected"

    @staticmethod
    def Support_File_Extract():
        with CM.Chrome() as driver:
            driver.DF_Configuration()
            driver.Click("#gwt-debug-Configuration")
            driver.Click("gwt-debug-TopicsNode_dfc-vision-support-content")
            if not driver.Wait("gwt-debug-TopicsNode_dfc-vision-support-content", delay=3):
                driver.Click("gwt-debug-Configuration")
            driver.Click("gwt-debug-TopicsNode_dfc-vision-support-content")
            while not driver.Wait(
                    "#dfc-vision-support > div > div > div:nth-child(1) > div > div > div:nth-child(1) > button"):
                driver.Click("gwt-debug-TopicsNode_dfc-vision-support-content")
            driver.Click(
                "#dfc-vision-support > div > div > div:nth-child(1) > div > div > div:nth-child(1) > button")
            driver.Click(
                "body > div.ReactModalPortal > div > div > div > div:nth-child(4) > div:nth-child(1) > div > div:nth-child(1) > button")
            if file_check(extract=False):
                return "File not downloaded after the default time"

class Vision(object):
    """
    Vision Tests
    """

    @staticmethod
    def Graph_Comparison_BP(Legit_Only=False, driver=None):
        driver_flag = True

        def delete():
            for file in os.listdir(os.getcwd()):
                if file.endswith(".zip") or file.endswith(".crdownload") or file.endswith(".csv"):
                    os.remove(file)
            try:
                rmtree("Test_Report")
            except:pass
        try:
            if not driver:
                driver = Driver()
            else:
                driver_flag = False
            driver.Click('//*[@data-debug-id="ANALYTICS_AMS_ICON"]')
            driver.Click('//*[@data-debug-id="AMS_REPORTS_ICON"]')
            if driver.Wait(f'//*[@data-debug-id="vrm-forensics-views-list-item-expand_{DTCT["Fill_Name"]}"]'):
                driver.Click(f'//*[@data-debug-id="vrm-forensics-views-list-item-expand_{DTCT["Fill_Name"]}"]')
            else:
                driver.Click(
                    "#main-content > div.vrm-reports-container > div.reports-main-content > div.reports-list-placeholder > div > div.vrm-report-list-title-wrapper > button")
                driver.Fill(
                    "#main-content > div.vrm-reports-container > div.reports-main-content > div.report-preview > div > div > div > div.wizard-form-content > div.wizard-form-content--header.not-valid > div > div.form-content-header--content > div > div.wizard-form-content-header--input-wrapper > div.new-filter-wrapper > input",
                    DTCT["Fill_Name"])
                driver.Click('//*[@data-debug-id="template_"]')
                time.sleep(1)
                driver.Click('//*[@data-debug-id="template_DefenseFlow Analytics Dashboard"]')
                driver.Click('#visionAppRoot > div > div > div.footer > button:nth-child(2)')
                driver.Click(
                    '#main-content > div.vrm-reports-container > div.reports-main-content > div.report-preview > div > div > div > div.wizard-form-content > div.wizard-form-content--main > div > div:nth-child(1) > div.tab-header.collapsed-header.with-error')
                driver.Click(
                    '#main-content > div.vrm-reports-container > div.reports-main-content > div.report-preview > div > div > div > div.wizard-form-content > div.wizard-form-content--main > div > div:nth-child(1) > div.tab-body.expanded > div > div > div.device-filter-search-bar-container > div > label')
                driver.Click(
                    '#main-content > div.vrm-reports-container > div.reports-main-content > div.report-preview > div > div > div > div.wizard-form-content > div.wizard-form-content--main > div > div:nth-child(5) > div.tab-header.collapsed-header')
                driver.Click('#csv')
                driver.Click(
                    '#main-content > div.vrm-reports-container > div.reports-main-content > div.report-preview > div > div > div > div.wizard-form-footer > div > button.form-button.form-submit')
                driver.Click(f'//*[@data-debug-id="vrm-forensics-views-list-item-expand_{DTCT["Fill_Name"]}"]')
            driver.Click(
                "#main-content > div.vrm-reports-container > div.reports-main-content > div.reports-list-placeholder > div > ul > li > div.vrm-reports-item-expaneded-details > div > div.vrm-reports-item-expaneded-details-header > div > button")
            driver.Displayed("div > div > div > div > div.loading-dots--dot-yellow")
            driver.Click(
                "#main-content > div.vrm-reports-container > div.reports-main-content > div.reports-list-placeholder > div > ul > li > div.vrm-reports-item-expaneded-details > div > div.reports-logs > div > div > ul > li:nth-child(1) > li > a")
            driver.Click(
                "#main-content > div.vrm-reports-container > div.reports-main-content > div.report-preview > div > div > header > button")
            driver.Click(f'//*[@data-debug-id="vrm-forensics-delete-item-button_{DTCT["Fill_Name"]}"]')
            driver.Click(
                '#main-content > div.vrm-reports-container > div.reports-main-content > div.reports-list-placeholder > div > ul > li > div.vrm-reports-item-main-details.selected > div.vrm-reports-list-item-actions-container > div.vrm-forensics-delete-item-wrapper > div > div.vrm-forensics-delete-item-confirm')
            if not file_check():
                return "File not downloaded after the default time"

            # Turning the csv files to dataframes
            with open("Traffic_Bandwidth.csv", "r") as csv:
                TB = read_csv(csv).astype("float64")
            with open("Traffic_Rate.csv", "r") as csv:
                TR = read_csv(csv).astype("float64")

            if not os.path.isdir("Test_Report"):
                BP.CSV_Export()
            with open(os.path.join(cwd, "Test_Report", "Test_Report.csv"), "r") as file:
                data = file.readlines()
            # index list for slicing the Test_Report later
            index = []
            # indicators where to slice
            strings = ["6.1.2.3. Frames/s", "6.1.2.4. Megabits/s", "6.1.3. [interface=2]", "6.1.3.3. Frames/s",
                       "6.1.3.4. Megabits/s", "6.2. "]
            for k in strings:
                for i, j in enumerate(data):
                    if k in j:
                        if "Frames/s" in j:
                            index.append(i + 2)
                        else:
                            index.append(i)
                        if "Megabits/s" in j:
                            index.append(i + 2)
                        break
            # TR - Trafic Rate , TB - Trafic Bandwidth
            int1_TR = read_csv(StringIO("".join(data[index[0]:index[1]]))).replace(to_replace=r',', value='',
                                                                                   regex=True).astype(
                "float64")
            int1_TB = read_csv(StringIO("".join(data[index[2]:index[3]]))).replace(to_replace=r',', value='',
                                                                                   regex=True).astype(
                "float64")
            # int2_TR = read_csv(StringIO("".join(data[index[4]:index[5]]))).replace(to_replace=r',', value='',
            #                                                                            regex=True).astype(
            #   "float64")
            # int2_TB = read_csv(StringIO("".join(data[index[6]:index[7]]))).replace(to_replace=r',', value='',
            #                                                                            regex=True).astype(
            #   "float64")
            if Legit_Only:
                Frames = TR[TR['inbound'] > TR['inbound'].max() * 0.5]['inbound'].mean() / \
                         int1_TR[int1_TR['ethTxFrameRate'] > int1_TR['ethTxFrameRate'].max() * 0.5][
                             'ethTxFrameRate'].mean() > 0.95
                BW = TB[TB['inbound'] > TB['inbound'].max() * 0.5]['inbound'].mean() / 1000 / \
                     int1_TB[int1_TB['ethTxFrameDataRate'] > int1_TB['ethTxFrameDataRate'].max() * 0.5][
                         'ethTxFrameDataRate'].mean() > 0.91
                if not Frames and BW:
                    return "Fail"
        finally:
            delete()
            if driver_flag:
                driver.Close()

class FD(object):
    """
    FD Tests
    """

    @staticmethod
    def No_Detection():
        response = requests.get(f'http://{DTCT["FD_IP"]}:10007/blackhole',
                                auth=(DTCT["FD_Username"], DTCT["FD_Password"]))
        if len(response.json()["values"]) != 0:
            return f'Number of Blackholes: {len(response.json()["values"])}\n\n{response.json()["values"]}'

    @staticmethod
    def Detection_Syslog_DF():
            response = requests.get(f'http://{DTCT["FD_IP"]}:10007/blackhole',
                                    auth=(DTCT["FD_Username"], DTCT["FD_Password"]))
            if len(response.json()["values"]) != len(Syslog.start):
                return f'Number of Attack Start Captured: {len(Syslog.start)}\n\n{Syslog.start}\n\nNumber of Blackholes: {len(response.json()["values"])}\n\n{response.json()["values"]}'

class BSN(object):
    """
    BSN Tests
    """
    pass

class Other(object):
        """
        Other Tests
        """
        @staticmethod
        def Check_Components_Version():
            api = Vision_API()
            DP_Version = [api.Get(f"https://10.170.19.115/mgmt/device/df/config/MitigationDevices/{i}")["version"] for i
                          in DTCT.DP_Info.keys()]
            DF_Version = api.Get("https://10.170.19.115/mgmt/device/df/config?prop=Version", True)["Version"]
            ssh = SSH(DTCT["Vision_IP"], DTCT["Vision_Username"], DTCT["Vision_Password"])
            match = re.search(r'\d+\.\d+\.\d+', ssh.command("system vertion", True)[1])
            Vision_Version = match.group(0)

        @staticmethod
        def Ping_All_Components(Fail_Time=5):
            Components_List = Vision_API.DF_IP() if DTCT.DF_HA else [Vision_API.DF_IP()[0]]
            Components_List += [i for i in DTCT.DP_Info.values()]
            Components_List.append(DTCT["Vision_IP"])
            match = re.search(r'\d+\.\d+\.\d+\.\d+', DTCT["MSSP_Dash_URL"])
            Components_List.append(match.group(0))
            No_Ping = ""
            for i in Components_List:
                for _ in range(Fail_Time):
                    if ping(i):
                        break
                else:
                    No_Ping = f'{No_Ping}\n{i}'
            if No_Ping:
                return f'No Ping:{No_Ping}'