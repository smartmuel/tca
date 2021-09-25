from tca import *
import pytest

Tools.exc = True
user, password = "radware", "radware1"
TEL_ENABLED = ["10.174.30.101", user, password]
NO_PING = ["172.16.255.254", user, password]
TEL_DISABLED = ["google.com", user, password]
TEL_WRONG_LOGIN = ["10.174.30.101", "wrong", "login"]


class TestTelnet():
    def test_telnet_enabled_no_ping(self):
        try:
            tel = Telnet(NO_PING[0], NO_PING[1], NO_PING[2])
            tel.close()
            raise
        except Exc.NoPingError:
            pass

    def test_telnet_enabled_no_ping_cm(self):
        try:
            with CM.telnet(NO_PING[0], NO_PING[1], NO_PING[2]) as tel:
                pass
            raise
        except Exc.NoPingError:
            pass

    def test_telnet_enabled_ping(self):
        tel = Telnet(TEL_ENABLED[0],TEL_ENABLED[1],TEL_ENABLED[2])
        tel.close()

    def test_telnet_enabled_ping_cm(self):
        with CM.telnet(TEL_ENABLED[0],TEL_ENABLED[1],TEL_ENABLED[2]) as tel:
            pass

    def test_telnet_disabled(self):
        try:
            tel = Telnet(TEL_DISABLED[0],TEL_DISABLED[1],TEL_DISABLED[2])
            tel.close()
            raise
        except Exc.TelnetError:
            pass

    def test_telnet_disabled_cm(self):
        try:
            with Telnet(TEL_DISABLED[0],TEL_DISABLED[1],TEL_DISABLED[2]) as tel:
                pass
            raise
        except Exc.TelnetError:
            pass

    def test_telnet_wrong_login(self):
        try:
            tel = Telnet(TEL_WRONG_LOGIN[0],TEL_WRONG_LOGIN[1],TEL_WRONG_LOGIN[2])
            tel.command(" ")
            tel.close()
            raise
        except Exc.TelnetError:
            pass

    def test_telnet_wrong_login_cm(self):
        try:
            with Telnet(TEL_WRONG_LOGIN[0],TEL_WRONG_LOGIN[1],TEL_WRONG_LOGIN[2]) as tel:
                tel.command(" ")
            raise
        except Exc.TelnetError:
            pass

    def test_telnet_command(self):
        tel = Telnet(TEL_ENABLED[0], TEL_ENABLED[1], TEL_ENABLED[2])
        tel.command(" ")
        tel.close()

    def test_telnet_command_cm(self):
        with CM.telnet(TEL_ENABLED[0],TEL_ENABLED[1],TEL_ENABLED[2]) as tel:
            tel.command(" ")