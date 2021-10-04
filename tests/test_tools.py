from tca import *

Tools.exc = True
PING = "10.170.19.111"
NO_PING = "172.16.255.254"


class TestTools:
    def test_ping(self):
        Tools.ping(host=PING)

    def test_no_ping(self):
        try:
            Tools.ping(host=NO_PING)
        except Exc.NoPingError:
            pass

    def test_cd(self):
        with Tools.cd("/".join(getcwd().replace("\\", "/").split("/")[:-2])):
            assert Tools.cwd != getcwd()

    def test_to_string(self):
        with Tools.to_string() as output:
            print("hi")
        assert "hi\n" in output.getvalue()
