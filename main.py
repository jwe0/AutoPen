import socket, requests
from bs4 import BeautifulSoup
class HTTPAttacks:
    def __init__(self, target) -> None:
        self.target = target

    def PortScan(self, ports):
        openp = []
        for port in ports:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(5)
            con = s.connect_ex((self.target, port))
            if con == 0:
                openp.append(str(port))

        return openp
    
    def CheckCommonFiles(self):
        paths = []
        exten = [".txt", ".php", ".xml", ".html"]
        files = ["robots", "sitemap", "license"]

        for file in files:
            for ext in exten:
                content = ""
                r = requests.get(f"http://{self.target}/{file}{ext}")
                if r.status_code == 200:
                    if file == "robots" or file == "license":
                        content = r.text
                    paths.append((f"/{file}{ext}", content))

        return paths
    
    def CheckLoginPortals(self):
        paths = []
        panls = ["wp-login", "wp-admin", "login", "admin"]
        exten = [".php", ".xml", ".html"]

        for panel in panls:
            for ext in exten:
                r = requests.get(f"http://{self.target}/{panel}{ext}")
                if r.status_code == 200:
                    paths.append(f"/{panel}{ext}")

        return paths
    
    def CheckPageTitle(self):
        r = requests.get(f"http://{self.target}")
        if "<title>" in r.text:
            return r.text.split("<title>")[1].split("</title>")[0]
        return "No title found"
    

class SSHAttacks:
    def __init__(self, target) -> None:
        self.target = target

class FTPAttacks:
    def __init__(self, target) -> None:
        self.target = target

class TELNETAttacks:
    def __init__(self, target) -> None:
        self.target = target

class Modules:
    def __init__(self, target) -> None:
        self.target = target
        self.HTTPattack = HTTPAttacks(target)
        self.SSHattack = SSHAttacks(target)
        self.FTPattack = FTPAttacks(target)
        self.TELNETattack = TELNETAttacks(target)

    

    def IsHTTP(self):
        print("[#] Checking for web server...\n")
        ports = [80, 8000, 8080, 443]
        openp = self.attack.PortScan(ports)

        if openp:
            title = self.HTTPattack.CheckPageTitle()
            message = ""
            for port in openp:
                message += f"[{str(openp.index(port) + 1)}]\t » http://{self.target}:{port}/\n"
            print("[+] Web server detected {}\n{}".format(title, message))

            files = self.HTTPattack.CheckCommonFiles()

            if files:
                message = ""
                progres = 0
                for file in files:
                    progres += 1
                    message += f"[{str(progres)}]\t » {file[0]}\n"
                    if file[1]:
                        lines = []
                        tlines = file[1].split("\n")
                        for line in tlines:
                            if line:
                                lines.append(line)
                        lines = ", ".join(lines)
                        message += f"\t\t » {lines}\n"
                print("[+] Common files found\n{}".format(message))

            logins = self.HTTPattack.CheckLoginPortals()

            if logins:
                message = ""
                for login in logins:
                    message += f"[{str(logins.index(login) + 1)}]\t » {login}\n"
                print("[+] Login portals found\n{}".format(message))

        else:
            print("[-] Web server not detected")



    def IsSSH(self):
        print("[#] Checking for SSH server...\n")
        ports = [22]
        openp = self.SSHattack.PortScan(ports)

        if openp:
            print("[+] SSH server detected")
        else:
            print("[-] SSH server not detected")


    def IsFTP(self):
        print("[#] Checking for FTP server...\n")
        ports = [21]
        openp = self.FTPattack.PortScan(ports)

        if openp:
            print("[+] FTP server detected")
        else:
            print("[-] FTP server not detected")
    def IsTELNET(self):
        print("[#] Checking for TELNET server...\n")
        ports = [23]
        openp = self.TELNETattack.PortScan(ports)

        if openp:
            print("[+] TELNET server detected")
        else:
            print("[-] TELNET server not detected")

if __name__ == "__main__":
    target = input("Target: ")
    mod = Modules(target)
    mod.IsHTTP()