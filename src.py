import random
from unicodedata import name
import requests
import math
import subprocess
import time
import base64
import json
from datetime import date, datetime
import urllib
import hashlib
from colorama import Fore
from pystyle import Colors, Colorate
from json import dumps
from json import loads, dumps, load
import secrets
import sys
import os   

hwid = str(str(subprocess.check_output('wmic csproduct get uuid')).strip().replace(r"\r", "").split(r"\n")[1].strip())
r =requests.get("https://pastebin.com/uSf8hHrt")

os.system('cls')

def printSlow(text):
    for char in text:
        print(char, end="")
        sys.stdout.flush()
        time.sleep(.1)

def Main_Program():
    if hwid in r.text:
        printSlow("Load Hwid ...")
        time.sleep(1.5)
        os.system('cls')
    else:
        print("Error! HWID Not I Database!")
        print("HWID: " + hwid)
        os.system('pause >NUL')

Main_Program()

with open('config.json') as settings:
    config = load(settings)

invite = config.get("invite")
name = config.get("name")

os.system('cls')

class Settings:
    capmonster = "2656770342505d0a10b6096bc2bd02f2"
    onlinesimru = "UBkP4e9zK174hdu-Pn7Bmy8n-rag577S4-WxBf16J8-6ts9689DC27FXxw"
    # random select proxy
    proxy = open("proxies.txt","r").read().split("\n")

    def get_proxy(self):
        proxies = {
    "https":"http://"+random.choice(self.proxy),
    "http":"http://"+random.choice(self.proxy)
            }
        return proxies
    # random select proxy
    proxy = open("proxies.txt","r").read().split("\n")

    def get_proxy(self):
        if open("proxies.txt","r").read() == '':
                proxies = {
                    "https":"http://127.0.0.1",
                    "http":"http://127.0.0.1"
                }
        else:
            proxies = {
        "https":"http://"+random.choice(self.proxy),
        "http":"http://"+random.choice(self.proxy)
                }
            return proxies

headers = {
    "Host": "hcaptcha.com",
    "Connection": "keep-alive",
    "sec-ch-ua": 'Chromium";v="92", " Not A;Brand";v="99", "Google Chrome";v="92',
    "Accept": "application/json",
    "sec-ch-ua-mobile": "?0",
    "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/92.0.4515.131 Safari/537.36",
    "Content-type": "application/json; charset=utf-8",
    "Origin": "https://newassets.hcaptcha.com",
    "Sec-Fetch-Site": "same-site",
    "Sec-Fetch-Mode": "cors",
    "Sec-Fetch-Dest": "empty",
    "Referer": "https://newassets.hcaptcha.com/",
    "Accept-Language": "en-US,en;q=0.9"

}

def N_Data(req) -> str:
        try:
            """
            this part takes the req value inside the getsiteconfig and converts it into our hash, we need this for the final step.
            (thanks to h0nde for this function btw, you can find the original code for this at the top of the file.)
            """
            x = "0123456789/:abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"

            req = req.split(".")

            req = {
                "header": json.loads(
                    base64.b64decode(
                        req[0] +
                        "=======").decode("utf-8")),
                "payload": json.loads(
                    base64.b64decode(
                        req[1] +
                        "=======").decode("utf-8")),
                "raw": {
                    "header": req[0],
                    "payload": req[1],
                    "signature": req[2]}}

            def a(r):
                for t in range(len(r) - 1, -1, -1):
                    if r[t] < len(x) - 1:
                        r[t] += 1
                        return True
                    r[t] = 0
                return False

            def i(r):
                t = ""
                for n in range(len(r)):
                    t += x[r[n]]
                return t

            def o(r, e):
                n = e
                hashed = hashlib.sha1(e.encode())
                o = hashed.hexdigest()
                t = hashed.digest()
                e = None
                n = -1
                o = []
                for n in range(n + 1, 8 * len(t)):
                    e = t[math.floor(n / 8)] >> n % 8 & 1
                    o.append(e)
                a = o[:r]

                def index2(x, y):
                    if y in x:
                        return x.index(y)
                    return -1
                return 0 == a[0] and index2(a, 1) >= r - 1 or -1 == index2(a, 1)

            def get():
                for e in range(25):
                    n = [0 for i in range(e)]
                    while a(n):
                        u = req["payload"]["d"] + "::" + i(n)
                        if o(req["payload"]["s"], u):
                            return i(n)

            result = get()
            hsl = ":".join([
                "1",
                str(req["payload"]["s"]),
                datetime.now().isoformat()[:19]
                .replace("T", "")
                .replace("-", "")
                .replace(":", ""),
                req["payload"]["d"],
                "",
                result
            ])
            return hsl
        except Exception as e:
            print(e)
            return False

def REQ_Data(host, sitekey,proxy):
        try:
            r = requests.get(f"https://hcaptcha.com/checksiteconfig?host={host}&sitekey={sitekey}&sc=1&swa=1", headers=headers,proxies={"https://": f"http://{proxy}"},timeout=4)
            if r.json()["pass"]:
                return r.json()["c"]
            else:
                return False
        except :
            return False

def Get_Captcha(host, sitekey, n, req,proxy):
        try:
            json = {
                "sitekey": sitekey,
                "v": "b1129b9",
                "host": host,
                "n": n,
                'motiondata': '{"st":1628923867722,"mm":[[203,16,1628923874730],[155,42,1628923874753],[137,53,1628923874770],[122,62,1628923874793],[120,62,1628923875020],[107,62,1628923875042],[100,61,1628923875058],[93,60,1628923875074],[89,59,1628923875090],[88,59,1628923875106],[87,59,1628923875131],[87,59,1628923875155],[84,56,1628923875171],[76,51,1628923875187],[70,47,1628923875203],[65,44,1628923875219],[63,42,1628923875235],[62,41,1628923875251],[61,41,1628923875307],[58,39,1628923875324],[54,38,1628923875340],[49,36,1628923875363],[44,36,1628923875380],[41,35,1628923875396],[40,35,1628923875412],[38,35,1628923875428],[38,35,1628923875444],[37,35,1628923875460],[37,35,1628923875476],[37,35,1628923875492]],"mm-mp":13.05084745762712,"md":[[37,35,1628923875529]],"md-mp":0,"mu":[[37,35,1628923875586]],"mu-mp":0,"v":1,"topLevel":{"st":1628923867123,"sc":{"availWidth":1680,"availHeight":932,"width":1680,"height":1050,"colorDepth":30,"pixelDepth":30,"availLeft":0,"availTop":23},"nv":{"vendorSub":"","productSub":"20030107","vendor":"Google Inc.","maxTouchPoints":0,"userActivation":{},"doNotTrack":null,"geolocation":{},"connection":{},"webkitTemporaryStorage":{},"webkitPersistentStorage":{},"hardwareConcurrency":12,"cookieEnabled":true,"appCodeName":"Mozilla","appName":"Netscape","appVersion":"5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/92.0.4515.131 Safari/537.36","platform":"MacIntel","product":"Gecko","userAgent":"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/92.0.4515.131 Safari/537.36","language":"en-US","languages":["en-US","en"],"onLine":true,"webdriver":false,"serial":{},"scheduling":{},"xr":{},"mediaCapabilities":{},"permissions":{},"locks":{},"usb":{},"mediaSession":{},"clipboard":{},"credentials":{},"keyboard":{},"mediaDevices":{},"storage":{},"serviceWorker":{},"wakeLock":{},"deviceMemory":8,"hid":{},"presentation":{},"userAgentData":{},"bluetooth":{},"managed":{},"plugins":["internal-pdf-viewer","mhjfbmdgcfjbbpaeojofohoefgiehjai","internal-nacl-plugin"]},"dr":"https://discord.com/","inv":false,"exec":false,"wn":[[1463,731,2,1628923867124],[733,731,2,1628923871704]],"wn-mp":4580,"xy":[[0,0,1,1628923867125]],"xy-mp":0,"mm":[[1108,233,1628923867644],[1110,230,1628923867660],[1125,212,1628923867678],[1140,195,1628923867694],[1158,173,1628923867711],[1179,152,1628923867727],[1199,133,1628923867744],[1221,114,1628923867768],[1257,90,1628923867795],[1272,82,1628923867811],[1287,76,1628923867827],[1299,71,1628923867844],[1309,68,1628923867861],[1315,66,1628923867877],[1326,64,1628923867894],[1331,62,1628923867911],[1336,60,1628923867927],[1339,58,1628923867944],[1343,56,1628923867961],[1345,54,1628923867978],[1347,53,1628923867994],[1348,52,1628923868011],[1350,51,1628923868028],[1354,49,1628923868045],[1366,44,1628923868077],[1374,41,1628923868094],[1388,36,1628923868110],[1399,31,1628923868127],[1413,25,1628923868144],[1424,18,1628923868161],[1436,10,1628923868178],[1445,3,1628923868195],[995,502,1628923871369],[722,324,1628923874673],[625,356,1628923874689],[523,397,1628923874705],[457,425,1628923874721]],"mm-mp":164.7674418604651},"session":[],"widgetList":["0a1l5c3yudk4"],"widgetId":"0a1l5c3yudk4","href":"https://discord.com/register","prev":{"escaped":false,"passed":false,"expiredChallenge":false,"expiredResponse":false}}',
                "hl": "en",
                "c": dumps(req)
            }

            data = urllib.parse.urlencode(json)
            headers = {
                "Host": "hcaptcha.com",
                "Connection": "keep-alive",
                "sec-ch-ua": 'Chromium";v="92", " Not A;Brand";v="99", "Google Chrome";v="92',
                "Accept": "application/json",
                "sec-ch-ua-mobile": "?0",
                "Content-length": str(len(data)),
                "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/92.0.4515.131 Safari/537.36",
                "Content-type": "application/x-www-form-urlencoded",
                "Origin": "https://newassets.hcaptcha.com",
                "Sec-Fetch-Site": "same-site",
                "Sec-Fetch-Mode": "cors",
                "Sec-Fetch-Dest": "empty",
                "Referer": "https://newassets.hcaptcha.com/",
                "Accept-Language": "en-US,en;q=0.9"

            }

            cookies = {"hc_accessibility": "wAHi1MOKSosBLK6HVeeBzfbaQknsYZOOkIB/s3TXYK3NzxiIzJ3HzV6uQOMlyTSI1GIVz9AazrmLIgl7NAufVofFaQDhnTL9CNyhqVwlaibJmi6mQrr377HrCaTI7VCWxo1kniMjJDOEz4X29+NH5awd4jH6hPyKIOZhNjWuMrNSKu6ZFLuRSgOiy4c+0idoOSRYiOiX9HK8KkQaHk8EfkR05vRrjPBkaNVKqg1RcpcfREQ06gIS9YzkItTt+2z/aHHZU1rAdJTyJ8oijsq2Mis23zqp9EWQ52H4oWEstionkOct9Z8NgybESmrdNsowi3NXNOoVwWoU4ZEwGCbjG8eO+2HnSP1vPKUi6tT7Z39E2eCMAJJDn9dyenkOuFRcOMmFiMIIIFsTUniyM7EhvSWxWDFvI+4zbx/+TP5pQClZJcLbXinpw1SMk3GVT3S6EG2n/DyLQ0/p3+/CJYbr7sVjdeRLQBGyCMvaOPy+dvaRH+mszz58EoV35sq9835SPRD17jNym9E=UCa12gEu9VIPScd9"}
            r = requests.post(f"https://hcaptcha.com/getcaptcha?s={sitekey}",cookies=cookies, data=data, headers=headers, timeout=4,proxies={"https://": f"http://{proxy}"})   

            return r.json()
        except Exception as e:
            print(e)
            return False

def bypass(sitekey, host,proxy):
    try :
        req = REQ_Data(sitekey=sitekey, host=host,proxy=proxy)
        req["type"] = "hsl"
        n = N_Data(req["req"])
        res = Get_Captcha(sitekey=sitekey, host=host,proxy=proxy,n=n, req=req)
        if "generated_pass_UUID" in res:
            captcha = res["generated_pass_UUID"]
            return captcha
        else:
            return False
    except : return False


class Main:
    def __init__(self):

        # init Logger
        self.Logger = Logger()

        self.Faker = FDiscord()

        self.Solver = Solver(Settings.capmonster)

        # introduces the banner
        # print(banner) i dont we need banner

        self.Settings = Settings()

        self.reg()

    def reg(self):

        email = self.Faker._get_fake_email()+"@aemfiat.business"

        print(Colorate.Horizontal(Colors.rainbow,f'''Email : {email}'''))

        # the password that is going to be needed in the final phone number verifiy
        password = secrets.token_hex(10)

        print(Colorate.Horizontal(Colors.rainbow,f'''Password : {password}'''))

        # Reciving cookies

        header1 = {
            "Host": "discord.com",
            "Connection": "keep-alive",
            "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/92.0.4515.131 Safari/537.36",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9",
            "Sec-Fetch-Site": "none",
            "Sec-Fetch-Mode": "navigate",
            "Sec-Fetch-User": "?1",
            "Sec-Fetch-Dest": "document",
            "sec-ch-ua": '"Chromium";v="92", " Not A;Brand";v="99", "Google Chrome";v="92"',
            "sec-ch-ua-mobile": "?0",
            "Upgrade-Insecure-Requests": "1",
            "Accept-Encoding": "gzip, deflate, br",
            "Accept-Language": "en-us,en;q=0.9",
        }

        getcookie = requests.get("https://discord.com/register").headers['set-cookie']
        sep = getcookie.split(";")
        sx = sep[0]
        sx2 = sx.split("=")
        dfc = sx2[1]
        split = sep[6]
        split2 = split.split(",")
        split3 = split2[1]
        split4 = split3.split("=")
        sdc = split4[1]

        # Get Fingerprint

        header2 = {
            "Host": "discord.com",
            "Connection": "keep-alive",
            "sec-ch-ua": '"Chromium";v="92", " Not A;Brand";v="99", "Microsoft Edge";v="92"',
            "X-Super-Properties": "eyJvcyI6Ik1hYyBPUyBYIiwiYnJvd3NlciI6IkNocm9tZSIsImRldmljZSI6IiIsInN5c3RlbV9sb2NhbGUiOiJlbi1VUyIsImJyb3dzZXJfdXNlcl9hZ2VudCI6Ik1vemlsbGEvNS4wIChNYWNpbnRvc2g7IEludGVsIE1hYyBPUyBYIDEwXzE1XzcpIEFwcGxlV2ViS2l0LzUzNy4zNiAoS0hUTUwsIGxpa2UgR2Vja28pIENocm9tZS85Mi4wLjQ1MTUuMTMxIFNhZmFyaS81MzcuMzYiLCJicm93c2VyX3ZlcnNpb24iOiI5Mi4wLjQ1MTUuMTMxIiwib3NfdmVyc2lvbiI6IjEwLjE1LjciLCJyZWZlcnJlciI6IiIsInJlZmVycmluZ19kb21haW4iOiIiLCJyZWZlcnJlcl9jdXJyZW50IjoiIiwicmVmZXJyaW5nX2RvbWFpbl9jdXJyZW50IjoiIiwicmVsZWFzZV9jaGFubmVsIjoic3RhYmxlIiwiY2xpZW50X2J1aWxkX251bWJlciI6OTI3OTIsImNsaWVudF9ldmVudF9zb3VyY2UiOm51bGx9",
            "X-Context-Properties": "eyJsb2NhdGlvbiI6IlJlZ2lzdGVyIn0=",
            "Accept-Language": "en-US",
            "sec-ch-ua-mobile": "?0",
            "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/92.0.4515.131 Safari/537.36",
            "Authorization": "undefined",
            "Accept": "*/*",
            "Sec-Fetch-Site": "same-origin",
            "Sec-Fetch-Mode": "cors",
            "Sec-Fetch-Dest": "empty",
            "Referer": "https://discord.com/register",
            "Accept-Encoding": "gzip, deflate, br"
        }

        fingerprintres = requests.get("https://discord.com/api/v9/experiments", timeout=10)

        while True:
            if fingerprintres.text != "":
                fingerprint = fingerprintres.json()['fingerprint']
                break
            else:
                return True

        param = {
            "username": self.Faker._get_fake_username(),
            "email": email,
            "date_of_birth":"1978-06-09",
            "password": password,
            "fingerprint": fingerprint,
            "gift_code_sku_id":"null",
            "invite": invite,
            "consent": "true",
            "captcha_key":  self.Solver.get_captcha_key(False)
        }

        headers = {
            "accept" : "*/*",
            "accept-encoding" : "gzip, deflate, br",
            "accept-language" : "zh-CN,zh;q=0.9,en;q=0.8",
            "content-length":"4797",
            "content-type":"application-json",
            "cookie":f"__dcfduid={dfc}; __sdcfduid={sdc}; _gcl_au=1.1.33345081.1647643031; _ga=GA1.2.291092015.1647643031; _gid=GA1.2.222777380.1647643031; OptanonConsent=isIABGlobal=false&datestamp=Fri+Mar+18+2022+18%3A53%3A43+GMT-0400+(%E5%8C%97%E7%BE%8E%E4%B8%9C%E9%83%A8%E5%A4%8F%E4%BB%A4%E6%97%B6%E9%97%B4)&version=6.17.0&hosts=&landingPath=https%3A%2F%2Fdiscord.com%2F&groups=C0001%3A1%2CC0002%3A1%2CC0003%3A1; __cf_bm=.fksdoBlzBs1zuhiY0rYFqFhDkstwwQJultZ756_yrw-1647645226-0-AaluVZQHZhOL5X4GXWxqEIC5Rp3/gkhKORy7WXjZpp5N/a4ovPxRX6KUxD/zpjZ/YFHBokF82hLwBtxtwetYhp/TSrGowLS7sC4nnLNy2WWMpZSA7Fv1tMISsR6qBZdPvg==; locale=en-US",
            "origin":"https://discord.com",
            "referer":"https://discord.com/register",
            "sec-ch-ua" : "Not A;Brand\";v=\"99\", \"Chromium\";v=\"99\", \"Google Chrome\";v=\"99",
            "sec-ch-ua-mobile":"?0",
            "sec-ch-ua-platform":"macOS",
            "sec-fetch-dest":"empty",
            "sec-fetch-mode":"cors",
            "sec-fetch-site":"same-origin",
            "user-agent":"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/99.0.4844.74 Safari/537.36",
            "x-discord-locale": "en-US",
            "x-fingerprint": fingerprint,
            "x-super-properties": "eyJvcyI6Ik1hYyBPUyBYIiwiYnJvd3NlciI6IkNocm9tZSIsImRldmljZSI6IiIsInN5c3RlbV9sb2NhbGUiOiJ6aC1DTiIsImJyb3dzZXJfdXNlcl9hZ2VudCI6Ik1vemlsbGEvNS4wIChNYWNpbnRvc2g7IEludGVsIE1hYyBPUyBYIDEwXzE1XzcpIEFwcGxlV2ViS2l0LzUzNy4zNiAoS0hUTUwsIGxpa2UgR2Vja28pIENocm9tZS85OS4wLjQ4NDQuNzQgU2FmYXJpLzUzNy4zNiIsImJyb3dzZXJfdmVyc2lvbiI6Ijk5LjAuNDg0NC43NCIsIm9zX3ZlcnNpb24iOiIxMC4xNS43IiwicmVmZXJyZXIiOiIiLCJyZWZlcnJpbmdfZG9tYWluIjoiIiwicmVmZXJyZXJfY3VycmVudCI6IiIsInJlZmVycmluZ19kb21haW5fY3VycmVudCI6IiIsInJlbGVhc2VfY2hhbm5lbCI6InN0YWJsZSIsImNsaWVudF9idWlsZF9udW1iZXIiOjExOTc2MSwiY2xpZW50X2V2ZW50X3NvdXJjZSI6bnVsbH0=",
        }

        resp = requests.post("https://discord.com/api/v9/auth/register",json=param,headers=headers,proxies=self.Settings.get_proxy())

        token = None

        try:
            token = resp.json()['token']
        except Exception as e:
            self.Logger.error(__name__,"Reat Limite - "+resp.text)
            sys.exit(0)

        print(Colorate.Horizontal(Colors.rainbow,"Token : " + str(token)))
        with open('token.txt', 'a') as f:
          f.write(str(token) + '\n')

  #      self.Logger.info(__name__, "Verifing without proxy")
  #      core.PhoneNumberVerifier.Verify(Settings.onlinesimru,Settings.capmonster,token,password).verify_phone_number()
  #      self.Logger.info(__name__,"finished verifying token phone number")

class Verify:
    def __init__(self, ptoken, stoken, dtoken, dpwd):

        self.ptoken = ptoken

        self.stoken = stoken

        self.dtoken = dtoken

        self.Solver = Solver(stoken)

        self.Logger = Logger()

        self.dpwd = dpwd

    def verify_phone_number(self):
        try:
            result = requests.get(
                f"https://onlinesim.ru/api/getNum.php?apikey={self.ptoken}&service=discord&number=true&country=7"
            ).json()
        except Exception as e:
            self.Logger.error(
                __name__,
                "problem while registering a phone number task - " + str(e))

        # phone number
        number = result.get("number")

        # TODO BAN DETECTOR post without catpcha



        tzid = result.get("tzid")

        self.Logger.info(
            __name__, "succesfully registered phone number verfication task")

        json = {
            "captcha_key": self.Solver.get_captcha_key(True),
            "change_phone_reason": "user_action_required",
            "phone": number,
        }

        headers = {
            "accept":
            "*/*",
            "accept-encoding":
            "gzip, deflate, br",
            "accept-language":
            "it",
            "authorization":
            self.dtoken,
            "content-type":
            "application/json",
            "origin":
            "https://discord.com",
            "referer":
            "https://discord.com/channels/@me",
            "sec-ch-ua":
            'Google Chrome";v="93", " Not;A Brand";v="99", "Chromium";v="93',
            "sec-ch-ua-mobile":
            "?0",
            "sec-ch-ua-platform":
            "Windows",
            "sec-fetch-dest":
            "empty",
            "sec-fetch-mode":
            "cors",
            "sec-fetch-site":
            "same-origin",
            "user-agent":
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/93.0.4577.82 Safari/537.36",
            "x-debug-options":
            "bugReporterEnabled",
            "x-super-properties":
            "eyJvcyI6IldpbmRvd3MiLCJicm93c2VyIjoiQ2hyb21lIiwiZGV2aWNlIjoiIiwic3lzdGVtX2xvY2FsZSI6ImVuLVVTIiwiYnJvd3Nlcl91c2VyX2FnZW50IjoiTW96aWxsYS81LjAgKFdpbmRvd3MgTlQgMTAuMDsgV2luNjQ7IHg2NCkgQXBwbGVXZWJLaXQvNTM3LjM2IChLSFRNTCwgbGlrZSBHZWNrbykgQ2hyb21lLzkzLjAuNDU3Ny44MiBTYWZhcmkvNTM3LjM2IiwiYnJvd3Nlcl92ZXJzaW9uIjoiOTMuMC40NTc3LjgyIiwib3NfdmVyc2lvbiI6IjEwIiwicmVmZXJyZXIiOiJodHRwczovL2Rpc2NvcmQuY29tL2xvZ2luIiwicmVmZXJyaW5nX2RvbWFpbiI6ImRpc2NvcmQuY29tIiwicmVmZXJyZXJfY3VycmVudCI6IiIsInJlZmVycmluZ19kb21haW5fY3VycmVudCI6IiIsInJlbGVhc2VfY2hhbm5lbCI6InN0YWJsZSIsImNsaWVudF9idWlsZF9udW1iZXIiOjk3NjYyLCJjbGllbnRfZXZlbnRfc291cmNlIjpudWxsfQ==",
        }
        try:
            with requests.post("https://discord.com/api/v9/users/@me/phone",
                               json=json,
                               headers=headers) as response:
                pass  #expects no response
        except Exception as e:
            self.Logger.error(
                __name__,
                "problem while initing phone number verficiation request - " +
                str(e))

        self.Logger.info(__name__, "requested phone number verify")

        uncaught_sms_times = 0

        while True:
            if uncaught_sms_times >= 45:
                self.Logger.warn(__name__, "PHONE NUMBER BANNED")
                self.verify_phone_number()
                break
            with requests.get(
                    f"https://onlinesim.ru/api/getState.php?apikey={self.ptoken}&tzid={tzid}"
            ) as response:
                if response.json()[1].get("msg")  != None:
                    code = response.json().get("msg")
                    break
                else:
                    time.sleep(1)
                    uncaught_sms_times = uncaught_sms_times + 1

        self.Logger.info(__name__, "got sms")
        json = {
            "code": code,
            "phone": number,
        }
        headers = {
            "accept":
            "*/*",
            "accept-language":
            "it",
            "authorization":
            self.dtoken,
            "content-type":
            "application/json",
            "origin":
            "https://discord.com",
            "referer":
            "https://discord.com/channels/@me",
            "sec-ch-ua":
            'Google Chrome";v="93", " Not;A Brand";v="99", "Chromium";v="93',
            "sec-ch-ua-mobile":
            "?0",
            "sec-ch-ua-platform":
            "Windows",
            "sec-fetch-dest":
            "empty",
            "sec-fetch-mode":
            "cors",
            "sec-fetch-site":
            "same-origin",
            "user-agent":
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/93.0.4577.82 Safari/537.36",
            "x-debug-options":
            "bugReporterEnabled",
            "x-super-properties":
            "eyJvcyI6IldpbmRvd3MiLCJicm93c2VyIjoiQ2hyb21lIiwiZGV2aWNlIjoiIiwic3lzdGVtX2xvY2FsZSI6ImVuLVVTIiwiYnJvd3Nlcl91c2VyX2FnZW50IjoiTW96aWxsYS81LjAgKFdpbmRvd3MgTlQgMTAuMDsgV2luNjQ7IHg2NCkgQXBwbGVXZWJLaXQvNTM3LjM2IChLSFRNTCwgbGlrZSBHZWNrbykgQ2hyb21lLzkzLjAuNDU3Ny44MiBTYWZhcmkvNTM3LjM2IiwiYnJvd3Nlcl92ZXJzaW9uIjoiOTMuMC40NTc3LjgyIiwib3NfdmVyc2lvbiI6IjEwIiwicmVmZXJyZXIiOiJodHRwczovL2Rpc2NvcmQuY29tL2xvZ2luIiwicmVmZXJyaW5nX2RvbWFpbiI6ImRpc2NvcmQuY29tIiwicmVmZXJyZXJfY3VycmVudCI6IiIsInJlZmVycmluZ19kb21haW5fY3VycmVudCI6IiIsInJlbGVhc2VfY2hhbm5lbCI6InN0YWJsZSIsImNsaWVudF9idWlsZF9udW1iZXIiOjk3NjYyLCJjbGllbnRfZXZlbnRfc291cmNlIjpudWxsfQ==",
        }

        with requests.post(
                "https://discord.com/api/v9/phone-verifications/verify",
                json=json,
                headers=headers) as response:
            final_token = response.json()['token']

        json = {
            "phone_token": final_token,
            "password": self.dpwd,
            "change_phone_reason": "user_action_required",
        }

        self.Logger.info(__name__, "requested change")

        headers = {
            "accept":
            "*/*",
            "accept-language":
            "it",
            "authorization":
            self.dtoken,
            "content-type":
            "application/json",
            "origin":
            "https://discord.com",
            "referer":
            "https://discord.com/channels/@me",
            "sec-ch-ua":
            'Google Chrome";v="93", " Not;A Brand";v="99", "Chromium";v="93',
            "sec-ch-ua-mobile":
            "?0",
            "sec-ch-ua-platform":
            "Windows",
            "sec-fetch-dest":
            "empty",
            "sec-fetch-mode":
            "cors",
            "sec-fetch-site":
            "same-origin",
            "user-agent":
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/93.0.4577.82 Safari/537.36",
            "x-debug-options":
            "bugReporterEnabled",
            "x-super-properties":
            "eyJvcyI6IldpbmRvd3MiLCJicm93c2VyIjoiQ2hyb21lIiwiZGV2aWNlIjoiIiwic3lzdGVtX2xvY2FsZSI6ImVuLVVTIiwiYnJvd3Nlcl91c2VyX2FnZW50IjoiTW96aWxsYS81LjAgKFdpbmRvd3MgTlQgMTAuMDsgV2luNjQ7IHg2NCkgQXBwbGVXZWJLaXQvNTM3LjM2IChLSFRNTCwgbGlrZSBHZWNrbykgQ2hyb21lLzkzLjAuNDU3Ny44MiBTYWZhcmkvNTM3LjM2IiwiYnJvd3Nlcl92ZXJzaW9uIjoiOTMuMC40NTc3LjgyIiwib3NfdmVyc2lvbiI6IjEwIiwicmVmZXJyZXIiOiJodHRwczovL2Rpc2NvcmQuY29tL2xvZ2luIiwicmVmZXJyaW5nX2RvbWFpbiI6ImRpc2NvcmQuY29tIiwicmVmZXJyZXJfY3VycmVudCI6IiIsInJlZmVycmluZ19kb21haW5fY3VycmVudCI6IiIsInJlbGVhc2VfY2hhbm5lbCI6InN0YWJsZSIsImNsaWVudF9idWlsZF9udW1iZXIiOjk3NjYyLCJjbGllbnRfZXZlbnRfc291cmNlIjpudWxsfQ==",
        }

        with requests.post("https://discord.com/api/v9/users/@me/phone",
                           json=json,
                           headers=headers) as response:
            pass

class Solver:
    def __init__(self, token):

        # inits the capmonster token
        self.token = token

        # prepares logger
        self.Logger = Logger()

    def get_captcha_key(self,isPhone):
        if isPhone == True:
            token = "f5561ba9-8f1e-40ca-9b5b-a0b3f719ef34"
        else:
            token = "4c672d35-0701-42b2-88c3-78380b0db560"
        json = {
            "clientKey" : self.token,
            "task" : {
                "type" : "HCaptchaTaskProxyless",
                "websiteURL" : "https://discord.com/",
                "websiteKey" : token,
                "minScore" : 0.3
            }
        }
        with requests.post("https://api.capmonster.cloud/createTask", json=json) as response:
            task_id = response.json().get("taskId")

        json = {
            "clientKey" : self.token,
            "taskId" : task_id
        }

        # keep on looping until getting the token, time efficient.
        while True:
            with requests.get("https://api.capmonster.cloud/getTaskResult", json = json) as response:
                 if "processing" in response.text:
                     pass
                 else:
                    try:
                        return response.json()["solution"]["gRecaptchaResponse"]
                    except Exception:
                        print("YOU NEED https://capmonster.cloud api key and with CREDIT INSIDE, YOU NEED TO PAY!")
                    break

class FDiscord:

    def __init__(self):
        self.random_username = [
            name,
            name,
        ]

        self.random_email = [
            secrets.token_hex(10)
        ]

    def _get_fake_username(self):
        return random.choice(self.random_username)
    def _get_fake_email(self):
        # TODO
        return random.choice(self.random_email)

class Logger:
    def info(self,name,msg):
        date_time = datetime.fromtimestamp(time.time())
        print(f"[{name} {date_time.strftime('%H:%M:%S')} {Fore.GREEN}INFO{Fore.RESET}] {msg}")

    def warn(self,name,msg):
        date_time = datetime.fromtimestamp(time.time())
        print(f"[{name} {date_time.strftime('%H:%M:%S')} {Fore.YELLOW}WARNING{Fore.RESET}] {msg}")

    def error(self,name,msg):
        date_time = datetime.fromtimestamp(time.time())
        print(f"[{name} {date_time.strftime('%H:%M:%S')} {Fore.RED}ERROR{Fore.RESET}] {msg}")

if __name__ == "__main__":
    Main()