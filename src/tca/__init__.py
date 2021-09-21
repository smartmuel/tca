import logging
import paramiko
import requests
from inspect import getframeinfo, stack
from os import getcwd, chdir, popen
from subprocess import check_call
from sys import exc_info, executable
from threading import Thread
from time import sleep
from typing import Any, Dict, List
from socketserver import BaseRequestHandler

from bps_restpy.bps_restpy_v1.bpsRest import BPS
from selenium import webdriver
from selenium.common.exceptions import TimeoutException, WebDriverException
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.common.by import By
from selenium.webdriver.common.keys import Keys
from selenium.webdriver.support import expected_conditions
from selenium.webdriver.support.ui import WebDriverWait

try:
    from dataclasses import dataclass, field
except ModuleNotFoundError:
    check_call([executable, "-m", "pip", "install", "dataclasses"])
    from dataclasses import dataclass, field


# class for context manager tools like: cd( change directory ), ping, etc..
class Tools(object):
    # current working directory
    cwd = getcwd()

    # exception flag
    exc = True

    # context manager for changing directory
    class cd(object):
        def __init__(self, path: str):
            """

            :param path: The path of the directory to change to.
            """
            chdir(path)

        def __enter__(self):
            return self

        def __exit__(self, exc_type, value, traceback):
            chdir(Tools.cwd)

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
            Tools.debug(
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

    # printing line and a message
    @staticmethod
    def debug(*args):
        caller = getframeinfo(stack()[-1][0])
        print(f"{caller.lineno} - {args}")


# exceptions
class Exc:
    class NoPingError(Exception):
        pass

    class SSHError(Exception):
        pass

    class TelnetError(Exception):
        pass


# Context Managers Class For All The Functions That Need To Be Closed.
class CM(object):
    # Chrome Context Manager
    class chrome(object):
        def __init__(self, url: str = ""):
            """

            :param url: The URL
            """
            self.driver = Chrome(url=url)

        def __enter__(self):
            return self.driver

        def __exit__(self, exc_type, value, traceback):
            self.driver.close()
            del self.driver

    # SSH Context Manager
    class ssh(object):
        def __init__(self, host: str, user: str, password: str, shell: bool = False, shell_key: bytes = b"dfcshell\n",
                     port: int = 22, pingf: bool = True):
            """

            :param host: host to ssh
            :param user: username for the ssh
            :param password: password for the ssh
            :param pingf: flag to ping
            """
            self.host, self.user, self.password = host, user, password
            self.shell, self.shell_key, self.port, self.pingf = shell, shell_key, port, pingf

        def __enter__(self):
            self.ssh = SSH(host=self.host, user=self.user, password=self.password, shell=self.shell,
                           shell_key=self.shell_key, port=self.port,
                           pingf=self.pingf)
            return self.ssh

        def __exit__(self, exc_type, value, traceback):
            self.ssh.close()
            del self.ssh

    # Telnet Context Manager
    class telnet(object):
        def __init__(self, host: str, user: str, password: str, ask_user: bytes = b"User:",
                     ask_pass: bytes = b"Password:", cli_sign: bytes = b"#", pingf: bool = True):
            """

            :param host: host to telnet
            :param user: username for the telnet
            :param password: password for the telnet
            :param pingf: flag to ping
            :param ask_user: Read until a given byte string of the username statement
            :param ask_pass: Read until a given byte string of the password statement
            :param cli_sign: Read until a given byte string of the cli sign
            """
            self.telnet = Telnet(host=host, user=user, password=password, ask_user=ask_user,
                                 ask_pass=ask_pass, cli_sign=cli_sign, pingf=pingf)

        def __enter__(self):
            return self.telnet

        def __exit__(self, exc_type, value, traceback):
            self.telnet.close()
            del self.telnet

    # Syslog server Context Manager
    class syslog(object):
        def __init__(self, name: str = "syslog", ip: str = Tools.get_ip_address()):
            """

            :param name: Syslog log file name
            :param ip: The IP address to listen to, the default ip would be the ip that can connect to 8.8.8.8
            """
            self.syslog = Syslog(name=name, ip=ip)

        def __enter__(self):
            return self.syslog

        def __exit__(self, exc_type, value, traceback):
            self.syslog.close()
            del self.syslog

    # context manager for Vision API
    class api(object):
        def __init__(self, vision: str, user: str, password: str):
            """

            :param vision: Vision IP
            :param user: Username
            :param password: Password
            """
            self.api = API(vision=vision, user=user, password=password)

        def __enter__(self):
            return self.api

        def __exit__(self, exc_type, value, traceback):
            self.api.close()
            del self.api

    # context manager for Breaking Point
    class bp(object):
        def __init__(self, test: str, ip: str, user: str, password: str, slot: int = 0, ports: List[int] = []):
            """

            :param test: Test name
            :param ip: BP IP
            :param user: BP username
            :param password: BP password
            :param slot: Slot number of the ports to reserve
            :param ports: Ports to reserve as list, example: [1,2]
            :return: None
            """
            BP.start(test=test, ip=ip, user=user, password=password, slot=slot, ports=ports)
            self.ip, self.user, self.password = ip, user, password

        def __enter__(self):
            return self

        def __exit__(self, exc_type, value, traceback):
            BP.stop(ip=self.ip, user=self.user, password=self.password)


# class that contain all the automation functions with Chrome.
class Chrome(object):
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

    def __call__(self):
        return self.driver

    def url(self, url: str):
        # if the url string don't have '://' in it the next line would add 'https://'
        # and if the url string is empty the default page is google.com
        url = f"{('://' not in url) * 'https://'}{url}{(not url) * 'www.google.com'}"
        self.driver.get(url)
        self.driver.fullscreen_window()

    def close(self):
        try:
            self.driver.close()
            self.driver.quit()
        except:
            Tools.debug("Unexpected error:", exc_info()[0], exc_info()[1])

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
            Tools.debug("Wait False", elem)
            flag = False
        return flag

    def click(self, elem: str, tries: int = 3, delay: int = 3) -> bool:
        """

        :param elem: The copied Xpath element
        :param tries: tries to click
        :param delay: The delay for the wait function
        :return: True if click succeeded
        """

        flag = True
        if self.wait(elem=elem, delay=delay):
            elem = elem.strip()
            for i in range(tries):
                try:
                    self.driver.find_element_by_xpath(elem).click()
                    break
                except:
                    Tools.debug(f"Failed to Click_{str(i)}", elem, "Unexpected error:", exc_info()[0], exc_info()[1])
            else:
                flag = False
        else:
            flag = False
        return flag

    def fill(self, elem: str, text: str, enter: bool = False, tries: int = 3, delay: int = 5) -> bool:
        """

        :param elem: The copied Xpath element
        :param text:
        :param enter:
        :param tries:
        :param delay:
        :return:
        """

        flag = True
        if self.wait(elem=elem, delay=delay):
            for i in range(tries):
                try:
                    my_elem = self.driver.find_element_by_xpath(elem)
                    my_elem.click()
                    my_elem.clear()
                    my_elem.send_keys(text)
                    if enter:
                        my_elem.send_keys(Keys.ENTER)
                    break
                except:
                    Tools.debug("Unexpected error:", exc_info()[0], exc_info()[1])
                    flag = False
            else:
                flag = False
        else:
            flag = False
        return flag


# data class for SSH
@dataclass
class SSH:
    """
    host: host to ssh
    user: username for the ssh
    password: password for the ssh
    shell: flag for using invoke shell
    shell_key: the command to invoke a shell script
    port: ssh port
    pingf: flag to ping
    """
    host: str
    user: str
    password: str
    shell: bool = False
    shell_key: bytes = b"dfcshell\n"
    port: int = 22
    pingf: bool = True
    channel: Any = field(init=False, repr=False)
    ssh: Any = field(init=False, repr=False)

    def __post_init__(self):
        if Tools.ping(self.host) if self.pingf else True:
            self.ssh_connect()
        else:
            Tools.debug("invalid host or no ping to host")

    def ssh_connect(self):
        self.ssh = paramiko.SSHClient()
        self.ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        try:
            self.ssh.connect(hostname=self.host, port=self.port, username=self.user, password=self.password)
        except (TimeoutError, paramiko.ssh_exception.NoValidConnectionsError):
            self.close()
            if Tools.exc:
                raise Exc.SSHError
        except paramiko.ssh_exception.AuthenticationException:
            self.close()
            Tools.debug("Username or Password is incorrect")
            if Tools.exc:
                raise Exc.SSHError
        if self.shell:
            self.channel = self.ssh.invoke_shell()
            self.channel.send(self.shell_key)

    def command(self, command: str, command_sleep: int = 2, recv_buffer: int = 99999999, tries: int = 3,
                line: int = -1) -> Any:
        """

        :param command: the command
        :param command_sleep: the to execute the command
        :param recv_buffer: the recv command buffer
        :param tries: the number of times to try to send the command
        :param line:
        :return: returns the output of the command - not working all the time
        """
        for i in range(tries):
            try:
                if self.shell:
                    # Clearing output.
                    sleep(command_sleep / 6)
                    if self.channel.recv_ready():
                        self.channel.recv(recv_buffer)
                    self.channel.send(f'{command}\n'.encode('ascii'))
                    sleep(command_sleep)
                    if self.channel.recv_ready():
                        return self.channel.recv(recv_buffer).decode("utf-8").split("\n")[1:-1]
                else:
                    stdin, stdout, stderr = self.ssh.exec_command(command)
                    return stdout.readlines(line)
            except (OSError,paramiko.ssh_exception.SSHException,paramiko.ssh_exception.NoValidConnectionsError):
                Tools.debug("Unexpected error:", exc_info()[0], exc_info()[1])
                self.ssh_connect()
        else:
            Tools.debug("ssh_command failed")

    def close(self):
        self.ssh.close()


# data class for Telnet
@dataclass
class Telnet:
    """
    host: host to telnet
    user: username for the telnet
    password: password for the telnet
    ask_user: Read until a given byte string of the username statement
    ask_pass: Read until a given byte string of the password statement
    cli_sign: Read until a given byte string of the cli sign
    pingf: flag to ping
    """
    host: str
    user: str
    password: str
    ask_user: bytes = b"User:"
    ask_pass: bytes = b"Password:"
    cli_sign: bytes = b"#"
    pingf: bool = True
    tn: Any = field(init=False, repr=False)

    def __post_init__(self):
        if Tools.ping(self.host) if self.pingf else True:
            self.tel_connect()
        else:
            Tools.debug("invalid host or no ping to host")

    def tel_connect(self):
        try:
            import telnetlib
            self.tn = telnetlib.Telnet()
            self.tn.open(self.host)
            self.tn.read_until(self.ask_user)
            self.tn.write(self.user.encode('ascii') + b"\n")
            self.tn.read_until(self.ask_pass)
            self.tn.write(self.password.encode('ascii') + b"\n")
            self.tn.read_until(self.cli_sign, 60)
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
            return output.decode('utf-8', 'replace').replace("�", "").split("\n")
        except AttributeError:
            self.tn.write(command.encode('ascii') + b"\n")
            output = self.tn.read_until(b"#", 60)
            return output.decode('utf-8', 'replace').replace("�", "").split("\n")
        except EOFError:
            self.close()
            if Tools.exc:
                raise Exc.TelnetError

    def close(self):
        try:
            self.tn.close()
        except:
            Tools.debug("Unexpected error:", exc_info()[0], exc_info()[1])
            pass  # silenced


# class for Syslog Server
class Syslog(object):
    """
    Class for Syslog Server
    """

    class SyslogUDPHandler(BaseRequestHandler):
        def handle(self):
            # socket = self.request[1]
            self.data = str(bytes.decode(self.request[0].strip()))
            # Tools.debug("%s : " % self.client_address[0], self.data)
            logging.info(self.data)

    def __init__(self, name: str = "syslog", ip: str = Tools.get_ip_address()):
        """

        :param name: Syslog log file name
        :param ip: The IP address to listen to, the default ip would be the ip that can connect to 8.8.8.8
        """
        self.name, self.ip = name, ip
        t1 = Thread(target=self.Server)
        t1.start()

    # Setting the Syslog server
    def Server(self):
        from socketserver import UDPServer
        try:
            logging.basicConfig(level=logging.INFO, format='%(asctime)s.%(msecs)03d %(levelname)s:\t%(message)s',
                                datefmt='%Y-%m-%d %H:%M:%S', filename=self.name,
                                filemode='a')
            self.server = UDPServer((self.ip, 514), Syslog.SyslogUDPHandler)
            self.server.serve_forever(poll_interval=0.5)
        except (IOError, SystemExit):
            raise
        except KeyboardInterrupt:
            Tools.debug("Crtl+C Pressed. Shutting down.")

    # Closing the Server
    def close(self):
        try:
            self.server.shutdown()
        except:
            Tools.debug("Unexpected error:", exc_info()[0], exc_info()[1])


# class for Breaking Point
class BP(object):
    """
    Class for Breaking Point
    """

    test_id = ""

    @staticmethod
    def start(test: str, ip: str, user: str, password: str, slot: int = 0, ports: List[int] = []):
        """

        :param test: Test name
        :param ip: BP IP
        :param user: BP username
        :param password: BP password
        :param slot: Slot number of the ports to reserve
        :param ports: Ports to reserve as list, example: [1,2]
        :return: None
        """
        bps = BPS(ip, user, password)
        # login
        bps.login()
        if slot:
            bps.reservePorts(slot=slot,
                             portList=ports,
                             group=1, force=True)
        # showing current port reservation state
        bps.portsState()
        BP.test_id = bps.runTest(modelname=test, group=1)
        bps.logout()

    @staticmethod
    def stop(ip: str, user: str, password: str, csv: bool = False):
        """

        :param ip: BP IP
        :param user: BP username
        :param password: BP password
        :param csv: Export csv report
        :return: None
        """

        bps = BPS(ip, user, password)
        # login
        bps.login()
        try:
            # stopping test
            bps.stopTest(testid=BP.test_id)
            # logging out
            if csv:
                bps.exportTestReport(BP.test_id, "Test_Report.csv", "Test_Report")
        except:
            Tools.debug("Unexpected error:", exc_info()[0], exc_info()[1])
        finally:
            try:
                bps.logout()
            except:
                Tools.debug("Unexpected error:", exc_info()[0], exc_info()[1])
                pass  # Silenced


# class for Vision API
class API(object):
    """
    Login/Logout/Get from Vision with REST API
    """

    def __init__(self, vision: str, user: str, password: str):
        """

        :param vision: Vision IP
        :param user: Username
        :param password: Password
        """
        self.vision = vision
        url = f"https://{self.vision}/mgmt/system/user/login"
        fill_json = {"username": user, "password": password}
        response = requests.post(url, verify=False, data=None, json=fill_json)
        self.cookie = response.cookies
        self.flag = False if "jsessionid" not in response.text else True

    def get(self, url: str) -> Any:
        if "://" not in url:
            url = f"https://{self.vision}/mgmt/device/df{url}"
        response = requests.get(url, verify=False, data=None, cookies=self.cookie)
        return response.json()

    def post(self, url: str, json: Dict[str, Any]) -> Any:
        if "://" not in url:
            url = f"https://{self.vision}/mgmt/device/df{url}"
        response = requests.post(url, verify=False, data=None, json=json, cookies=self.cookie)
        return response.json()

    def put(self, url: str, json: Dict[str, Any]) -> Any:
        if "://" not in url:
            url = f"https://{self.vision}/mgmt/device/df{url}"
        response = requests.put(url, verify=False, data=None, json=json, cookies=self.cookie)
        return response.json()

    def delete(self, url: str) -> Any:
        if "://" not in url:
            url = f"https://{self.vision}/mgmt/device/df{url}"
        response = requests.delete(url, verify=False, data=None, cookies=self.cookie)
        return response.json()

    def close(self):
        url = f"https://{self.vision}/mgmt/system/user/logout"
        requests.post(url, verify=False, cookies=self.cookie)


"""class Script(object):

    @staticmethod
    def DP_upgrade():"""
