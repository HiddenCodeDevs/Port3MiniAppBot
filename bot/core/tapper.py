import hashlib
import json
import asyncio
from time import time
from random import randint

import aiohttp
from aiocfscrape import CloudflareScraper
from aiohttp_proxy import ProxyConnector
from better_proxy import Proxy
from pyrogram import Client
from pyrogram.errors import Unauthorized, UserDeactivated, AuthKeyUnregistered, FloodWait
from pyrogram.raw.functions.messages import RequestWebView

from bot.config import settings
from bot.utils import logger
from bot.utils.scripts import escape_html, login_in_browser
from bot.exceptions import InvalidSession
from .headers import headers
from time import time


class Tapper:
    def __init__(self, tg_client: Client, lock: asyncio.Lock):
        self.session_name = tg_client.name
        self.tg_client = tg_client
        self.user_id = 0
        self.lock = lock
        self.auth_token = None

    async def get_auth_url(self, proxy: str | None) -> str:
        if proxy:
            proxy = Proxy.from_str(proxy)
            proxy_dict = dict(
                scheme=proxy.protocol,
                hostname=proxy.host,
                port=proxy.port,
                username=proxy.login,
                password=proxy.password
            )
        else:
            proxy_dict = None

        self.tg_client.proxy = proxy_dict

        try:
            with_tg = True

            if not self.tg_client.is_connected:
                with_tg = False
                try:
                    await self.tg_client.connect()
                    start_command_found = False

                    async for message in self.tg_client.get_chat_history('Port3miniapp_bot'):
                        if (message.text and message.text.startswith('/start')) or (
                                message.caption and message.caption.startswith('/start')):
                            start_command_found = True
                            break

                    if not start_command_found:
                        REF_ID = 'kESn89' or settings.REF_ID
                        await self.tg_client.send_message("Port3miniapp_bot", f"/start {REF_ID}")
                except (Unauthorized, UserDeactivated, AuthKeyUnregistered):
                    raise InvalidSession(self.session_name)

            while True:
                try:
                    peer = await self.tg_client.resolve_peer('Port3miniapp_bot')
                    break
                except FloodWait as fl:
                    fls = fl.value

                    logger.warning(f"{self.session_name} | FloodWait {fl}")
                    logger.info(f"{self.session_name} | Sleep {fls}s")

                    await asyncio.sleep(fls + 3)

            web_view = await self.tg_client.invoke(RequestWebView(
                peer=peer,
                bot=peer,
                platform='android',
                from_bot_menu=False,
                url='https://mini.port3.io/'
            ))

            auth_url = web_view.url.replace('tgWebAppVersion=6.7', 'tgWebAppVersion=7.8')

            self.user_id = (await self.tg_client.get_me()).id

            if with_tg is False:
                await self.tg_client.disconnect()

            return auth_url

        except InvalidSession as error:
            raise error

        except Exception as error:
            logger.error(f"{self.session_name} | Unknown error during Authorization: {escape_html(error)}")
            await asyncio.sleep(delay=3)

    async def login(self, auth_url: str, proxy: str):
        response_text = ''
        try:
            async with self.lock:
                signature = login_in_browser(auth_url, proxy=proxy)

            return signature
        except Exception as error:
            logger.error(f"{self.session_name} | Unknown error while Login: {escape_html(error)} | "
                         f"Response text: {escape_html(response_text)}...")
            await asyncio.sleep(delay=3)

            return None

    async def generate_headers(self):
        try:
            current_time = str(int(time()))
            api_key = '96B27124E4684CC10646CC9D21D3BA4D'
            just_secret_str = '_oF0M1-K3AJ0iPAqiBs3w4uiJ2iKXR9GFcxFi_Vy78A='

            sign_input = f"{api_key}{just_secret_str}{current_time}"
            SIGN = hashlib.sha256(sign_input.encode()).hexdigest()

            new_headers = {
                "address": f"telegram_{self.user_id}",
                "Apikey": api_key,
                "Sign": SIGN,
                "Signature": self.auth_token,
                "Time": current_time,
            }

            return new_headers

        except Exception as e:
            logger.error(f'{self.session_name} | Error generate headers - {e}')

    async def make_click(self, http_client: aiohttp.ClientSession, clicks):
        try:
            payload = {"number": clicks}
            new_headers = await self.generate_headers()
            response = await http_client.post(url='https://api.sograph.xyz/api/mining/tap/click', json=payload,
                                              headers=new_headers)
            if response.status in [200, 201]:
                return True
            return False

        except Exception as e:
            logger.error(f'{self.session_name} | Error making click - {e}')

    async def get_info(self, http_client: aiohttp.ClientSession):
        try:
            new_headers = await self.generate_headers()
            response = await http_client.get(url='https://api.sograph.xyz/api/mining/tap/userinfo?', headers=new_headers)
            resp_json = await response.json()
            balance = resp_json.get('data').get('gems', 0)
            get_gems_per_click = resp_json.get('data').get('click_gems', 1)
            everyday_clicks = resp_json.get('data').get('daily_number', 0)
            today_clicked = resp_json.get('data').get('daily_use_number', 0)

            new_headers = await self.generate_headers()
            response_lvl_info = await http_client.get(url='https://api.sograph.xyz/api/user/info?', headers=new_headers)
            resp_json_lvl = await response_lvl_info.json()
            identity = resp_json_lvl.get('data', {}).get('identity')

            return balance, get_gems_per_click, everyday_clicks, today_clicked, identity

        except Exception as e:
            logger.error(f'{self.session_name} | Error getting info - {e}')

    async def buy_lvl(self, http_client: aiohttp.ClientSession):
        try:
            identities_with_price = {
                "resident": 0,
                "space_traveler": 500,
                "knight": 1000,
                "skywalker": 5000,
                "grand_master": 20000,
            }

            balance, gems, everyday, today, my_identity = await self.get_info(http_client)

            identity_order = ["resident", "space_traveler", "knight", "skywalker", "grand_master"]

            current_index = identity_order.index(my_identity)

            while True:
                if current_index < len(identity_order) - 1:
                    next_identity = identity_order[current_index + 1]
                    next_price = identities_with_price[next_identity]

                    if balance >= next_price:
                        balance -= next_price
                        payload = {"identity": next_identity}
                        new_headers = await self.generate_headers()
                        response = await http_client.post(url='https://api.sograph.xyz/api/user/identity/claim',
                                                          json=payload,
                                                          headers=new_headers)
                        if response.status in [200, 201]:
                            logger.success(f'{self.session_name} | Reached new lvl - {next_identity}')
                    else:
                        logger.info(f'{self.session_name} | Not enough to update lvl')
                        return False
                else:
                    logger.info(f'{self.session_name} | You reached max lvl')
                    return False

        except Exception as e:
            logger.error(f'{self.session_name} | Error buy_lvl - {e}')

    async def check_proxy(self, http_client: aiohttp.ClientSession, proxy: Proxy) -> None:
        try:
            response = await http_client.get(url='https://httpbin.org/ip', timeout=aiohttp.ClientTimeout(5))
            ip = (await response.json()).get('origin')
            logger.info(f"{self.session_name} | Proxy IP: {ip}")
        except Exception as error:
            logger.error(f"{self.session_name} | Proxy: {proxy} | Error: {escape_html(error)}")

    async def run(self, proxy: str | None) -> None:
        proxy_conn = ProxyConnector().from_url(proxy) if proxy else None

        http_client = CloudflareScraper(headers=headers, connector=proxy_conn)

        if proxy:
            await self.check_proxy(http_client=http_client, proxy=proxy)


        while True:
            try:
                auth_url = await self.get_auth_url(proxy=proxy)

                if not auth_url:
                    return

                if http_client.closed:
                    if proxy_conn:
                        if not proxy_conn.closed:
                            proxy_conn.close()

                    proxy_conn = ProxyConnector().from_url(proxy) if proxy else None
                    http_client = aiohttp.ClientSession(headers=headers, connector=proxy_conn)

                signature = await self.login(auth_url=auth_url, proxy=proxy)
                if signature:
                    logger.success(f"{self.session_name} | Logged in")
                    self.auth_token = signature

                balance, gems_per_click, day_limit, current_clicks, identity = await self.get_info(http_client)
                logger.info(f'{self.session_name} | Balance: {balance} | Gems per click - {gems_per_click} | '
                            f'Day limit - {day_limit} | Current clicked of day limit - {current_clicks} | '
                            f'Current level - {identity}')
                if current_clicks < day_limit:
                    clicks_to_do = day_limit-current_clicks
                    logger.info(f'{self.session_name} | Trying to click')
                    status = await self.make_click(http_client, clicks_to_do)
                    if status:
                        logger.success(f'{self.session_name} | Successfully clicked {clicks_to_do} times, got '
                                       f'{clicks_to_do*gems_per_click} gems')

                logger.info(f'{self.session_name} | Trying to upgrade lvl')
                status = await self.buy_lvl(http_client)
                if status:
                    logger.success(f'{self.session_name} | Successfully upgraded lvl')

                logger.info(f'{self.session_name} | Going sleep 1h')

                await asyncio.sleep(3600)

            except InvalidSession as error:
                raise error

            except Exception as error:
                logger.error(f"{self.session_name} | Unknown error: {escape_html(error)}")
                await asyncio.sleep(delay=3)


async def run_tapper(tg_client: Client, proxy: str | None, lock: asyncio.Lock):
    try:
        await Tapper(tg_client=tg_client, lock=lock).run(proxy=proxy)
    except InvalidSession:
        logger.error(f"{tg_client.name} | Invalid Session")
