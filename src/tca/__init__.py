import logging
import paramiko
import requests
import asyncio
import aiohttp
import sys
import telnetlib
from io import StringIO
from os import getcwd, chdir, popen
from threading import Thread
from time import sleep
from typing import Any, Dict, List
from socketserver import BaseRequestHandler
from urllib3.exceptions import MaxRetryError

from bps_restpy.bps_restpy_v1.bpsRest import BPS
from selenium import webdriver
from selenium.common.exceptions import TimeoutException, WebDriverException, ElementNotInteractableException, \
    InvalidElementStateException, NoSuchElementException, StaleElementReferenceException
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.common.by import By
from selenium.webdriver.common.keys import Keys
from selenium.webdriver.support import expected_conditions
from selenium.webdriver.support.ui import WebDriverWait


# class for context manager tools like: cd( change directory ), ping, etc..
class Tools:
    # current working directory
    cwd = getcwd()

    # exception flag
    exc = False

    # context manager for changing directory
    class cd:
        def __init__(self, path: str):
            """

            :param path: The path of the directory to change to.
            """
            chdir(path)

        def __enter__(self):
            return self

        def __exit__(self, exc_type, value, traceback):
            chdir(Tools.cwd)

    # context manager for turning prints into string
    class to_string:
        def __init__(self):
            self.old_stdout = sys.stdout
            sys.stdout = self.mystdout = StringIO()

        def __enter__(self):
            return self.mystdout

        def __exit__(self, exc_type, value, traceback):
            sys.stdout = self.old_stdout

    # the IP that can connect to the specified destination, 8.8.8.8 is the default
    @staticmethod
    def get_ip_address(destination: str = "8.8.8.8") -> Any:
        """
        :param destination: The destination ip to reach from the machine
        :return: The ip address that can connect to the specified destination
        """
        import socket
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect((destination, 80))
        return s.getsockname()[0]

    # ping command, returns True/False
    @staticmethod
    def ping(host: str, timeout: int = 1, tries: int = 2) -> bool:
        """
        :param host: can be ip or host name
        :param timeout: timeout in seconds, 1 is the minimum
        :param tries: number of ping re-tries
        :return: True/False
        """
        from platform import system
        flag = False
        try:
            assert timeout >= 1 and tries >= 1

        except AssertionError:
            timeout, tries = 1, 2
            print(
                "timeout and tries should be more or equal to 1, revert to defaults timeout, tries = 1, 2")

        command = f'ping -n 1 -w {timeout * 1000} {host}' if system().lower() == 'windows' else \
            f'ping -c 1 -W {timeout} {host}'
        for i in range(tries):
            response = popen(command).read().lower()
            if 'unreachable' not in response and "100%" not in response:
                flag = True
                break
        if Tools.exc and (not flag):
            raise Exc.NoPingError
        return flag


# exceptions
class Exc:
    class NoPingError(Exception):
        pass

    class SSHError(Exception):
        pass

    class TelnetError(Exception):
        pass


# class that contain all the automation functions with Chrome.
class Chrome:
    """
    Chrome Automation.
    """

    def __init__(self, url: str = ""):
        """

        :param url: The URL
        """
        # Opening Chrome Driver
        options = Options()
        options.add_experimental_option("prefs", {
            "download.default_directory": rf"{Tools.cwd}",
            "download.prompt_for_download": False,
            "download.directory_upgrade": True,
            "safebrowsing.enabled": True
        })
        options.add_argument('--ignore-certificate-errors')

        try:
            self.driver = webdriver.Chrome(options=options)
        except WebDriverException:
            import chromedriver_autoinstaller
            chromedriver_autoinstaller.install()
            self.driver = webdriver.Chrome(options=options)
        self.url(url)

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()

    def url(self, url: str):
        # if the url string don't have '://' in it the next line would add 'https://'
        # and if the url string is empty the default page is google.com
        url = f"{('://' not in url) * 'https://'}{url}{(not url) * 'www.google.com'}"

        Tools.ping(url)
        try:
            self.driver.get(url)
            self.driver.fullscreen_window()
        except WebDriverException:
            print("ERR_CONNECTION_TIMED_OUT")
            self.close()

    def close(self):
        try:
            self.driver.close()
            self.driver.quit()
        except MaxRetryError:
            pass

    def wait(self, elem: str, delay: int = 10, elem_type: str = By.XPATH) -> bool:
        """

        :param elem: The copied element, the element should be in the type that is selected
        :param delay: The delay
        :param elem_type: The default type is Xpath
        :return: True if the element is existing
        """

        elem = elem.strip()
        flag = True
        try:
            WebDriverWait(self.driver, delay).until(expected_conditions.presence_of_element_located((elem_type, elem)))
        except TimeoutException:
            print("Wait False", elem)
            flag = False
        return flag

    def click(self, elem: str, elem_type: str = By.XPATH, tries: int = 3, delay: int = 3) -> bool:
        """

        :param elem: The copied Xpath element
        :param elem_type: The default type is Xpath
        :param tries: tries to click
        :param delay: The delay for the wait function
        :return: True if click succeeded
        """

        flag = True
        if self.wait(elem=elem, delay=delay):
            elem = elem.strip()
            for i in range(tries):
                try:
                    self.driver.find_element(elem_type, elem).click()
                    break
                except (ElementNotInteractableException, InvalidElementStateException, StaleElementReferenceException,
                        NoSuchElementException):
                    pass
            else:
                flag = False
        else:
            flag = False
        return flag

    def fill(self, elem: str, text: str, elem_type: str = By.XPATH, enter: bool = False,
             tries: int = 3, delay: int = 5) -> bool:
        """

        :param elem: The copied Xpath element
        :param text:
        :param elem_type: The default type is Xpath
        :param enter:
        :param tries:
        :param delay:
        :return:
        """

        flag = True
        if self.wait(elem=elem, delay=delay):
            for i in range(tries):
                try:
                    my_elem = self.driver.find_element(elem_type, elem)
                    my_elem.click()
                    my_elem.clear()
                    my_elem.send_keys(text)
                    if enter:
                        my_elem.send_keys(Keys.ENTER)
                    break
                except (ElementNotInteractableException, InvalidElementStateException, StaleElementReferenceException,
                        NoSuchElementException):
                    flag = False
            else:
                flag = False
        else:
            flag = False
        return flag


# class for ssh
class SSH:
    def __init__(self, host: str, user: str, password: str, port: int = 22, pingf: bool = True):
        """

        :param host: host to ssh
        :param user: username for the ssh
        :param password: password for the ssh
        :param port: ssh port
        :param pingf: flag to ping
        """
        self.host, self.user, self.password, self.port = host, user, password, port
        if Tools.ping(self.host) if pingf else True:
            self.ssh_connect()
        else:
            print("invalid host or no ping to host")

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()

    def ssh_connect(self):
        self.ssh = paramiko.SSHClient()
        self.ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        try:
            self.ssh.connect(hostname=self.host, port=self.port, username=self.user, password=self.password)
            self.channel = self.ssh.invoke_shell()
        except (OSError, TimeoutError, AttributeError, paramiko.ssh_exception.NoValidConnectionsError,
                paramiko.ssh_exception.SSHException):
            self.close()
            if Tools.exc:
                raise Exc.SSHError
        except paramiko.ssh_exception.AuthenticationException:
            self.close()
            print("Username or Password is incorrect")
            if Tools.exc:
                raise Exc.SSHError

    def command(self, command: str, command_sleep: int = 2, recv_buffer: int = 99999999, tries: int = 3) -> Any:
        """

        :param command: the command
        :param command_sleep: the to execute the command
        :param recv_buffer: the recv command buffer
        :param tries: the number of times to try to send the command
        :return: returns the output of the command - not working all the time
        """
        for i in range(tries):
            try:
                # Clearing output.
                sleep(command_sleep / 6)
                if self.channel.recv_ready():
                    self.channel.recv(recv_buffer)
                self.channel.send(f'{command}\n'.encode('ascii'))
                sleep(command_sleep)
                if self.channel.recv_ready():
                    return self.channel.recv(recv_buffer).decode("utf-8", 'replace').replace("???", "").split("\n")[1:-1]
            except (OSError, TimeoutError, AttributeError, paramiko.ssh_exception.NoValidConnectionsError,
                    paramiko.ssh_exception.SSHException):
                self.ssh_connect()
        else:
            print("ssh_command failed")

    def close(self):
        self.ssh.close()


# class for telnet
class Telnet:
    def __init__(self, host: str, user: str, password: str, ask_user: str = "User:", ask_pass: str = "Password:",
                 cli_sign: str = "#", pingf: bool = True):
        """

        :param host: host to telnet
        :param user: username for the telnet
        :param password: password for the telnet
        :param ask_user: Read until a given byte string of the username statement
        :param ask_pass: Read until a given byte string of the password statement
        :param cli_sign: Read until a given byte string of the cli sign
        :param pingf: flag to ping
        """
        self.host, self.user, self.password = host, user, password
        self.ask_user, self.ask_pass, self.cli_sign = ask_user, ask_pass, cli_sign
        self.tn: telnetlib.Telnet
        if Tools.ping(self.host) if pingf else True:
            self.tel_connect()
        else:
            print("invalid host or no ping to host")

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()

    def tel_connect(self):
        try:
            self.tn = telnetlib.Telnet()
            self.tn.open(self.host)
            self.tn.read_until(self.ask_user.encode('ascii'))
            self.tn.write(f"{self.user}\n".encode('ascii'))
            self.tn.read_until(self.ask_pass.encode('ascii'))
            self.tn.write(f"{self.password}\n".encode('ascii'))
            self.tn.read_until(self.cli_sign.encode('ascii'), 60)
            self.command(" ")
        except (TimeoutError, EOFError):
            self.close()
            if Tools.exc:
                raise Exc.TelnetError

    def command(self, command: str) -> Any:
        """

        :param command: the command
        :return: returns the output of the command
        """

        try:
            self.tn.write(command.encode('ascii') + b"\n")
            output = self.tn.read_until(b"#", 60)
            return output.decode('utf-8', 'replace').replace("???", "").split("\n")
        except AttributeError:
            self.tn.write(command.encode('ascii') + b"\n")
            output = self.tn.read_until(b"#", 60)
            return output.decode('utf-8', 'replace').replace("???", "").split("\n")
        except EOFError:
            self.close()
            if Tools.exc:
                raise Exc.TelnetError

    def close(self):
        self.tn.close()
    # data class for Telnet


# class for Syslog Server
class Syslog:
    """
    Class for Syslog Server
    """

    class SyslogUDPHandler(BaseRequestHandler):
        def handle(self):
            logging.info(str(bytes.decode(self.request[0].strip())))

    def __init__(self, name: str = "syslog.log", ip: str = Tools.get_ip_address(), port: int = 514):
        """

        :param name: Syslog log file name
        :param ip: The IP address to listen to, the default ip would be the ip that can connect to 8.8.8.8
        :param port: The listening port
        """
        from socketserver import UDPServer
        self.name, self.ip, self.port = name, ip, port
        self.server = UDPServer((self.ip, self.port), Syslog.SyslogUDPHandler)
        t1 = Thread(target=self.Server)
        t1.start()

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()

    # Setting the Syslog server
    def Server(self):
        try:
            logging.basicConfig(level=logging.INFO, format='%(asctime)s.%(msecs)03d %(levelname)s:\t%(message)s',
                                datefmt='%Y-%m-%d %H:%M:%S', filename=self.name,
                                filemode='a')
            self.server.serve_forever(poll_interval=0.5)
        except (IOError, SystemExit):
            raise
        except KeyboardInterrupt:
            print("Crtl+C Pressed. Shutting down.")

    # Closing the Server and clearing logging handler
    def close(self):
        # shutting down the server
        self.server.shutdown()
        # clearing logging handler
        for handler in logging.root.handlers:
            logging.root.removeHandler(handler)


# class for Breaking Point
class BP:
    """
    Class for Breaking Point
    """

    test_id = ""

    def __init__(self, test: str, ip: str, user: str, password: str, slot: int = 0, ports: Any = None):
        """

        :param test: Test name
        :param ip: BP IP
        :param user: BP username
        :param password: BP password
        :param slot: Slot number of the ports to reserve
        :param ports: Ports to reserve as list, example: [1,2]
        """
        self.ip, self.user, self.password = ip, user, password
        self.bps = BPS(self.ip, self.user, self.password)
        if slot:
            self.reserve(slot, ports)
        if test:
            self.start(test)

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.stop()

    @staticmethod
    def LoginDecorator(func):
        def inner(self):
            self.bps.login()
            func(self)
            self.bps.logout()

        return inner

    def reserve(self, slot: int, ports: List[int]):
        self.bps.reservePorts(slot=slot,
                              portList=ports,
                              group=1, force=True)

    @LoginDecorator
    def start(self, test: str):
        """

        :param test: Test name
        :return: None
        """

        # showing current port reservation state
        with Tools.to_string() as output:
            self.bps.portsState()
        if self.user in output.getvalue():
            self.test_id = self.bps.runTest(modelname=test, group=1)
        else:
            print("No Reserved Ports")

    @LoginDecorator
    def stop(self, csv: bool = False):
        """

        :param csv: Export csv report
        :return: None
        """

        with Tools.to_string() as output:
            self.bps.runningTestInfo()
        if output.getvalue():

            # stopping test
            self.bps.stopTest(testid=self.test_id)

            # exporting csv report of the test
            if csv:
                self.csv(self.test_id)
        else:
            print("No Running Tests")

    def csv(self, test_id: Any):
        self.bps.exportTestReport(test_id, "Test_Report.csv", "Test_Report")

    def login(self):
        self.bps.login()

    def logout(self):
        self.bps.logout()


# class for Vision API
class API:
    """
    Login/Logout/Get/Post/Put/Delete from Vision with REST API
    """

    def __init__(self, vision: str, user: str, password: str, ping_timeout: int = 1):
        """

        :param vision: Vision IP
        :param user: Username
        :param password: Password
        :param ping_timeout: ping timeout in seconds
        """
        self.vision, self.user, self.password = vision, user, password
        self.ping_timeout, self.flag = ping_timeout, False
        if Tools.ping(vision, ping_timeout) if ping_timeout else True:
            self.login()
        else:
            print("invalid host or no ping to host")

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()

    def login(self):
        # if self.cookie:
        #     url = f"https://{self.vision}/mgmt/system/user/logout"
        #     self.response = requests.post(url, verify=False, cookies=self.cookie)
        #     if self.response.status_code != 200:
        #         self.flag = False
        if not self.flag:
            url = f"https://{self.vision}/mgmt/system/user/login"
            fill_json = {"username": self.user, "password": self.password}
            self.response = requests.post(url, verify=False, data=None, json=fill_json)
            self.cookie = self.response.cookies
            self.flag = False if "jsessionid" not in self.response.text else True

    def url(self, url: str) -> str:
        if "://" not in url:
            if "/mgmt" in url:
                url = f"https://{self.vision}{url}"
            else:
                url = f"https://{self.vision}/mgmt/device/df{url}"
        return url

    def get(self, url: str) -> Any:
        url = self.url(url)
        self.response = requests.get(url, verify=False, data=None, cookies=self.cookie)
        return self.response.json()

    def post(self, url: str, json: Dict[str, Any]) -> Any:
        url = self.url(url)
        self.response = requests.post(url, verify=False, data=None, json=json, cookies=self.cookie)
        return self.response.json()

    def put(self, url: str, json: Dict[str, Any]) -> Any:
        url = self.url(url)
        self.response = requests.put(url, verify=False, data=None, json=json, cookies=self.cookie)
        return self.response.json()

    def delete(self, url: str) -> Any:
        url = self.url(url)
        self.response = requests.delete(url, verify=False, data=None, cookies=self.cookie)
        return self.response.json()

    def a_get(self, urls):
        results = []
        headers = {'Cookie': "; ".join([f"{x}={y}" for x, y in self.cookie.items()])}

        def get_tasks(session):
            tasks = []
            for url in urls:
                url = self.url(url)
                tasks.append(asyncio.create_task(session.get(url, headers=headers, ssl=False)))
            return tasks

        async def get_responses():
            async with aiohttp.ClientSession() as session:
                tasks = get_tasks(session)
                responses = await asyncio.gather(*tasks)
                for response in responses:
                    results.append(await response.json())

        asyncio.run(get_responses())
        return results

    def close(self):
        url = f"https://{self.vision}/mgmt/system/user/logout"
        self.response = requests.post(url, verify=False, cookies=self.cookie)
