import requests
import json
import sys
import random
import string
import os
import time
from colorama import init, Fore
import queue
import turkce_isimler
import threading
import base64
from requests.packages.urllib3.exceptions import InsecureRequestWarning
init()
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)


proxies_q = queue.Queue()
predefinedNames = []


def random_nick(_file):
    conf = open(_file, 'r', encoding='utf-8')
    _lines = conf.readlines()
    return random.choice(_lines).lstrip().rsplit()


def debug(text, conf):
    if conf['debug']:
        print("[DEBUG] "+str(text))


def read_configurations():
    try:
        conf = json.loads(
            open('config/config.json', 'r', encoding='utf-8').read())
        print("Configuration loaded! Starting workers!")
        return conf
    except:
        print("Failed to load config.json")
        sys.exit(1)


def array_to_queue(arr, q):
    for i in arr:
        q.put(i)
    return q


def getGenericHeader():
    return {
        'Host': 'getinboxes.com',
        'Accept': '*/*',
        'Accept-Language': 'en-US',
        'Content-Type': 'application/json',
        'DNT': '1',
        'Connection': 'keep-alive'
    }


def getInfo():
    id = random.randint(1, 7)
    if id == 1:
        return ("Windows", "Chrome", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/69.0.3497.100 Safari/537.36", "69.0.3497.100", "10")
    elif id == 2:
        return ("Windows", "Chrome", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/64.0.3282.140 Safari/537.36 Edge/18.17763", "18.17763", "10")
    elif id == 3:
        return ("Windows", "Edge", "Mozilla/5.0 (Windows NT 5.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/60.0.3112.90 Safari/537.36", "60.0.3112.90", "XP")
    elif id == 4:
        return ("Windows", "Chrome", "Mozilla/5.0 (Windows NT 6.3; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/60.0.3112.113 Safari/537.36", "60.0.3112.113", "8.1")
    elif id == 5:
        return ("Windows", "Internet Explorer", "Mozilla/5.0 (Windows NT 10.0; WOW64; Trident/7.0; .NET4.0C; .NET4.0E; .NET CLR 2.0.50727; .NET CLR 3.0.30729; .NET CLR 3.5.30729; rv:11.0) like Gecko", "11.0", "7")
    elif id == 6:
        return ("Windows", "Firefox", "Mozilla/5.0 (Windows NT 6.1; WOW64; rv:54.0) Gecko/20100101 Firefox/54.0", "54.0", "7")
    elif id == 7:
        return ("Windows", "Firefox", "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:66.0) Gecko/20100101 Firefox/66.0", "66.0", "10")


def get_headers():
    return {
        'Host': 'discordapp.com',
        'Accept': '*/*',
        'Accept-Language': 'en-US',
        'Content-Type': 'application/json',
        'Referer': 'https://discordapp.com/register',
        'Origin': 'https://discordapp.com',
        'DNT': '1',
        'Connection': 'keep-alive'
    }


def getSuperProp(os, browser, useragent, browser_version, os_version, client_build):
    return {
        "os": os,
        "browser": browser,
        "device": "",
        "browser_user_agent": useragent,
        "browser_version": browser_version,
        "os_version": os_version,
        "referrer": "",
        "referring_domain": "",
        "referrer_current": "",
        "referring_domain_current": "",
        "release_channel": "stable",
        "client_build_number": client_build,
        "client_event_source": None
    }


sys.path.append("././.")


def get_random_string(length):
    letters = string.ascii_letters
    result_str = ''.join(random.choice(letters) for i in range(length))
    return result_str


def generateUUID():
    alphabet = "abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
    uuidlength = 32
    uuid = ""
    for i in range(uuidlength):
        uuid = uuid + alphabet[random.randrange(len(alphabet))]
    return uuid


def sunucuya_sok(token, davet_kodlari):
    for davet_linki in davet_kodlari:
        param = {
            "user-agent": "Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) discord/0.0.301 Chrome/56.0.2924.87 Discord/1.6.15 Safari/537.36",
            "authority": "discordapp.com",
            "method": "POST",
            "path": f"/api/v6/invite/{davet_linki}",
            "scheme": "https",
            "accept": "*/*",
            "accept-encoding": "gzip, deflate",
            "accept-language": "en-US",
            "authorization": token,
            "content-length": "0",
            "origin": "https://discordapp.com",
            "referer": "http://discordapp.com/channels/@me"
        }
        source = requests.post(
            f"https://discordapp.com/api/v6/invite/{davet_linki}", headers=param)


def get_info(token):
    r = requests.get("https://discord.com/api/v8/users/@me",
                     headers={"Authorization": f"{token}"}, verify=False)
    return r.json()


def register(email, username, password, proxy, conf):
    headers = get_headers()
    genericHeaders = getGenericHeader()
    os, browser, headers['user-agent'], browserver, osvers = getInfo()
    genericHeaders['user-agent'] = headers['user-agent']
    s = requests.Session()

    if proxy != None:
        proxies = {
            'http': 'http://' + proxy,
            'https': 'https://' + proxy
        }
        s.proxies.update(proxies)

    fingerprint_json = s.get("https://discordapp.com/api/v6/experiments",
                             timeout=conf['timeout'], headers=headers, verify=False).text
    fingerprint = json.loads(fingerprint_json)["fingerprint"]
    debug("Finger print: " + fingerprint, conf)
    xsuperprop = base64.b64encode(json.dumps(getSuperProp(
        os, browser, headers['user-agent'], browserver, osvers, 36127), separators=",:").encode()).decode()
    debug("X-Super-Properties: " + xsuperprop, conf)
    time.sleep(conf['sleepdelay'])
    headers['X-Super-Properties'] = xsuperprop
    headers['X-Fingerprint'] = fingerprint

    payload = {
        'fingerprint': fingerprint,
        'email': email,
        'username': username,
        'password': password,
        'invite': None,
        'captcha_key': None,
        'consent': True,
        "date_of_birth": "1997-04-24",
        'gift_code_sku_id': None
    }
    uuid = generateUUID()

    #print("first registration post "+email+":"+username+":"+password, conf)
    messages = f'{Fore.LIGHTRED_EX}--------------------{Fore.RESET}\nMail: {email}\nUsername: {username}\nPassword: {password}\n{Fore.LIGHTRED_EX}--------------------{Fore.RESET}'
    print(messages)
    response = s.post('https://discordapp.com/api/v6/auth/register',
                      json=payload, headers=headers, timeout=conf['timeout'], verify=False)
    time.sleep(conf['sleepdelay'])
    captchaRequired = False
    if 'captcha-required' in response.text:
        print("Captcha is required to verify user.")
        captchaRequired = True
    if 'You are being rate limited.' in response.text:
        print("You are being rate limited.")
        return False
    if 'Email is already registered.' in response.text:
        print("Already registered")
        return False
    if 'Please update Discord to continue.' in response.text:
        print("Please update Discord to continue.")
        return False
    if 'response-already-used-error' in response.text:
        print("Captcha response already used once. Returning.")
        return False

    if captchaRequired:
        if conf['skip_if_captcha']:
            return False
        ss = requests.Session()
        time.sleep(conf['sleepdelay'])
        debug("fetching captcha", conf)
        API_KEY = conf["captchakey"]
        site_key = conf["sitekey"]
        discord_url_s = 'https://discordapp.com/api/v6/auth/register'
        captcha_id = ss.get("http://2captcha.com/in.php?key={}&method=userrecaptcha&googlekey={}&pageurl={}".format(
            API_KEY, site_key, discord_url_s)).text.split('|')[1]
        recaptcha_answer = ss.get(
            "http://2captcha.com/res.php?key={}&action=get&id={}".format(API_KEY, captcha_id)).text
        #print(f"{Fore.CYAN}Captcha Çözülüyor...")
        while 'CAPCHA_NOT_READY' in recaptcha_answer:
            time.sleep(5)
            recaptcha_answer = ss.get(
                "http://2captcha.com/res.php?key={}&action=get&id={}".format(API_KEY, captcha_id)).text
        recaptcha_answer = recaptcha_answer.split('|')[1]
        debug("Result: "+recaptcha_answer, conf)
        payload['captcha_key'] = recaptcha_answer
        debug("sending payload: "+str(payload), conf)
        time.sleep(conf['sleepdelay'])
        response = s.post('https://discordapp.com/api/v6/auth/register',
                          json=payload, headers=headers, timeout=conf['timeout'], verify=False)
        debug(response.json(), conf)
        token = response.json()['token']
        file = open('token_gen.txt', 'a')
        file.writelines(token + '\n')
        file.close()
        try:
            _info = get_info(token)
            _id = _info['id']
            _discriminator = _info['discriminator']

            file2 = open('accounts.txt', 'a')
            _datam = f"\nMail: {email}\nUsername: {username}\nDiscriminator: {_discriminator}\nID: {_id}\nPassword: {password}\nToken: {token}\n\n\n"
            file2.writelines(_datam)
            file2.close()
        except:
            pass

        print(f'{Fore.CYAN}Account Generated\n{Fore.LIGHTRED_EX}--------------------{Fore.RESET}\n{Fore.CYAN}Mail: {Fore.LIGHTGREEN_EX}{email}\n{Fore.CYAN}Username: {Fore.LIGHTGREEN_EX}{username}#{_discriminator}\n{Fore.CYAN}Token: {Fore.LIGHTGREEN_EX}{token}\n{Fore.LIGHTRED_EX}--------------------{Fore.RESET}')

        davet_kodlari = conf["invite_codes"]
        davet_kodlari = davet_kodlari.split(',')
        sunucuya_sok(token, davet_kodlari)
        return True

    if 'unauthorize' in response.text:
        debug('unauthorized', conf)
        return False


def worker(conf):
    debug("worker started", conf)
    proxy = None
    if conf['use_proxies']:
        proxies_used_file = conf['usedproxies']
        try:
            proxies_used = open(proxies_used_file).read()
        except:
            proxies_used = ''

        proxy = proxies_q.get()
        proxies_q.task_done()

        while proxies_used.count(proxy) > 2 and not proxies_q.empty():
            proxy = proxies_q.get()
            proxies_q.task_done()
        open(proxies_used_file, 'a').write(proxy+'\n')
    if conf["username"] == 'random':
        username = turkce_isimler.rastgele_isim_al()
    elif conf["username"] == "file":
        _file = conf["usernames"]
        username = random_nick(_file)[0]
    else:
        # Aynı kullanıcı adı ile çok sayıda hesaplar açılırsa taglar biter o yüzden bu kodu yanına ekleyin kullanıcı adının yanında random karakterler oluşturmak için[ {get_random_string(3)} ]
        username = f'{conf["username"]}'
    password = f'{conf["password"]}'
    email = f'{get_random_string(7)}@gmail.com'
    try:
        if not register(email, username, password, proxy, conf):
            print("Fail")
            worker(conf)
        else:
            print("Successfully made a account.")
            open(proxies_used_file, 'a').write(proxy+'\n')
            worker(conf)
    except:
        worker(conf)
        pass


def runIt(conf):
    tx = []
    debug("Starting "+str(conf['nb_threads'])+" threads", conf)
    for i in range(conf['nb_threads']):
        mT = threading.Thread(target=worker, args=(conf, ))
        mT.daemon = True
        mT.start()
        tx.append(mT)
    for t in tx:
        t.join(75)


def main():
    global proxies_q
    global predefinedNames

    conf = read_configurations()

    proxies = [x.rstrip() for x in open(conf['proxy_file'], 'r').readlines()]
    proxies_q = array_to_queue(proxies, proxies_q)

    debug("Starting "+str(conf['nb_threads'])+" threads", conf)

    while 1:
        runIt(conf)


main()
