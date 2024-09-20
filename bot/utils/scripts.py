import json
import os
import glob
import time
import random
import shutil
import pathlib
from multiprocessing import Queue
from contextlib import contextmanager

from better_proxy import Proxy

from seleniumwire import webdriver
from selenium.webdriver.chrome.service import Service as ChromeService
from selenium.webdriver.chrome.options import Options as ChromeOptions
from webdriver_manager.chrome import ChromeDriverManager
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.webdriver.common.by import By

from bot.config import settings
from bot.utils import logger


def get_session_names() -> list[str]:
    session_names = [os.path.splitext(os.path.basename(file))[0] for file in glob.glob("sessions/*.session")]

    return session_names


def get_proxies() -> list[Proxy]:
    if settings.USE_PROXY_FROM_FILE:
        with open(file="bot/config/proxies.txt", encoding="utf-8-sig") as file:
            proxies = [Proxy.from_str(proxy=row.strip()).as_url for row in file]
    else:
        proxies = []

    return proxies


def escape_html(text: str) -> str:
    text = str(text)
    return text.replace('<', '\\<').replace('>', '\\>')


web_options = ChromeOptions
web_service = ChromeService
web_manager = ChromeDriverManager
web_driver = webdriver.Chrome

if not pathlib.Path("webdriver").exists() or len(list(pathlib.Path("webdriver").iterdir())) == 0:
    logger.info("Downloading webdriver. It may take some time...")
    pathlib.Path("webdriver").mkdir(parents=True, exist_ok=True)
    webdriver_path = pathlib.Path(web_manager().install())
    shutil.move(webdriver_path, f"webdriver/{webdriver_path.name}")
    logger.info("Webdriver downloaded successfully")

webdriver_path = next(pathlib.Path("webdriver").iterdir()).as_posix()

device_metrics = {"width": 375, "height": 812, "pixelRatio": 3.0}
user_agent = "Mozilla/5.0 (Linux; Android 13; RMX3630 Build/TP1A.220905.001; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/125.0.6422.165 Mobile Safari/537.36"

mobile_emulation = {
    "deviceMetrics": device_metrics,
    "userAgent": user_agent,
}

options = web_options()

options.add_experimental_option("mobileEmulation", mobile_emulation)

options.add_argument("--headless")
options.add_argument("--log-level=3")
if os.name == 'posix':
    options.add_argument('--no-sandbox')
    options.add_argument('--disable-dev-shm-usage')
session_queue = Queue()
driver = None


# Other way
def login_in_browser(auth_url: str, proxy: str):
    global driver

    proxy_options = {
        'proxy': {
            'http': proxy,
            'https': proxy,
        },
        'timeout': 30
    } if proxy else None

    if driver is None:
        driver = web_driver(service=web_service(webdriver_path), options=options, seleniumwire_options=proxy_options)

    driver.get(auth_url)

    try:
        WebDriverWait(driver, 10).until(
            EC.presence_of_element_located((By.XPATH, '//*[@id="root"]/div[2]/div/div[2]/div/div[1]/img'))
        )
    except Exception as e:
        logger.error(f"Error waiting for the element: {e}")
        return None

    response_text = '{}'
    signature = ''
    for request in driver.requests:
        if request.url == "https://api.sograph.xyz/api/login/web2":
            response_text = request.response.body.decode('utf-8')
            response_json = json.loads(response_text)
            signature = response_json.get('data', {}).get('signature', {})
            session_queue.put(1)

    if len(get_session_names()) == session_queue.qsize():
        logger.info("All sessions are closed. Quitting driver...")
        driver.quit()
        driver = None
        while session_queue.qsize() > 0:
            session_queue.get()

    return signature
