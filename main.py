import socket, requests, paramiko, urllib.parse
from ftplib import FTP
from bs4 import BeautifulSoup

class GeneralModules:
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

    def Banner(self, port):
        s = socket.socket()
        s.settimeout(5)
        s.connect((self.target, port))
        banner = s.recv(1024).decode().strip()
        s.close()

        return banner
    
    def FindCVE_NVD_NIST(self, search):
        vulns = []
        dist = "https://nvd.nist.gov/vuln/search/results?form_type=Basic&results_type=overview&query={}&search_type=all&isCpeNameSearch=false".format(urllib.parse.quote(search))
        r = requests.get(dist)
        soup = BeautifulSoup(r.text, 'html.parser')
        for a in soup.find_all('a', href=True):
            vulns.append(a['href'] if "detail" in a['href'] else None)
        exploits = [vuln for vuln in vulns if vuln is not None]

        return exploits

class HTTPAttacks:
    def __init__(self, target) -> None:
        self.target = target

    
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

    def CheckBanner(self):
        s = socket.socket()
        s.settimeout(5)
        s.connect((self.target, 22))
        banner = s.recv(1024).decode().strip()
        s.close()

        return banner 
    
    def CheckAlgorithm(self):
        transport = paramiko.Transport((self.target, 22))
        transport.start_client()

        hex = transport.get_security_options().kex
        ciphers = transport.get_security_options().ciphers
        transport.close()

        return (hex, ciphers)

class FTPAttacks:
    def __init__(self, target) -> None:
        self.target = target

    def CheckAnonymousLogin(self):
        try:
            files = []
            with FTP(self.target) as ftp:
                ftp.login("anonymous", "anonymous")
                for file in ftp.nlst():
                    files.append(file)
                return (True, files)
        except Exception as e:
            print(e)
            return (False, files)
        
    def CheckBanner(self):
        s = socket.socket()
        s.settimeout(5)
        s.connect((self.target, 21))
        banner = s.recv(1024).decode().strip()
        s.close()

        return banner
        
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
        self.Modules = GeneralModules(target)

    

    def IsHTTP(self):
        print("[#] Checking for web server...\n")
        ports = [80, 8000, 8080, 443]
        openp = self.Modules.PortScan(ports)

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
        openp = self.Modules.PortScan(ports)

        if openp:
            banner = self.Modules.Banner(22)
            print("[+] SSH server detected {}".format(banner))

            algorithms = self.SSHattack.CheckAlgorithm()
            progress = 0
            if algorithms[0]:
                progress += 1
                message = ""
                for algorithm in algorithms:
                    name = "Algorithms" if progress == 1 else "Hexs"
                    message += f"[{str(algorithms.index(algorithm) + 1)}]\t » {name}\n"
                    progress += 1
                    for cipher in algorithm:
                        message += f"\t\t » {cipher}\n"
                print("[+] Algorithms found\n{}".format(message))

            exploits = self.Modules.FindCVE_NVD_NIST(banner)

            if exploits:
                message = ""
                for exploit in exploits:
                    message += f"[{str(exploits.index(exploit) + 1)}]\t » {exploit}\n"
                print("[+] Exploits found {}\n{}".format(len(exploits), message))

        else:
            print("[-] SSH server not detected")


    def IsFTP(self):
        print("[#] Checking for FTP server...\n")
        ports = [21]
        openp = self.Modules.PortScan(ports)

        if openp:
            banner = self.Modules.Banner(21)
            print("[+] FTP server detected {}".format(banner))
            anonlogon = self.FTPattack.CheckAnonymousLogin()

            if anonlogon[0]:
                message = ""
                for file in anonlogon[1]:
                    message += f"[{str(anonlogon[1].index(file) + 1)}]\t » {file}\n"
                print("[+] Anonymous login possible\n{}".format(message))

            exploits = self.Modules.FindCVE_NVD_NIST(banner)

            if exploits:
                message = ""
                for exploit in exploits:
                    message += f"[{str(exploits.index(exploit) + 1)}]\t » {exploit}\n"
                print("[+] Exploits found {}\n{}".format(len(exploits), message))

        else:
            print("[-] FTP server not detected")
    def IsTELNET(self):
        print("[#] Checking for TELNET server...\n")
        ports = [23]
        openp = self.Modules.PortScan(ports)

        if openp:
            print("[+] TELNET server detected")
        else:
            print("[-] TELNET server not detected")

if __name__ == "__main__":
    target = input("Target: ")
    print("[#] Scanning... (This may take a while)\n")
    mod = Modules(target)
    # mod.IsHTTP()
    mod.IsSSH()
    # mod.IsFTP()
    # mod.IsTELNET()