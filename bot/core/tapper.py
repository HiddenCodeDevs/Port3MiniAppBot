import asyncio
import hashlib
import random
from time import time
from urllib.parse import unquote, quote

import aiohttp
import json
from aiocfscrape import CloudflareScraper
from aiohttp_proxy import ProxyConnector
from better_proxy import Proxy
from pyrogram import Client
from pyrogram.errors import Unauthorized, UserDeactivated, AuthKeyUnregistered, FloodWait
from pyrogram.raw.functions.messages import RequestWebView
from .agents import generate_random_user_agent
from bot.config import settings

from bot.utils import logger
from bot.exceptions import InvalidSession
from .headers import headers


class Tapper:
    def __init__(self, tg_client: Client):
        self.session_name = tg_client.name
        self.tg_client = tg_client
        self.user_id = 0
        self.username = None
        self.first_name = None
        self.last_name = None
        self.fullname = None
        self.auth_token = ''

        self.session_ug_dict = self.load_user_agents() or []

        headers['User-Agent'] = self.check_user_agent()

    async def generate_random_user_agent(self):
        return generate_random_user_agent(device_type='android', browser_type='chrome')

    def save_user_agent(self):
        user_agents_file_name = "user_agents.json"

        if not any(session['session_name'] == self.session_name for session in self.session_ug_dict):
            user_agent_str = generate_random_user_agent()

            self.session_ug_dict.append({
                'session_name': self.session_name,
                'user_agent': user_agent_str})

            with open(user_agents_file_name, 'w') as user_agents:
                json.dump(self.session_ug_dict, user_agents, indent=4)

            logger.success(f"<light-yellow>{self.session_name}</light-yellow> | User agent saved successfully")

            return user_agent_str

    def load_user_agents(self):
        user_agents_file_name = "user_agents.json"

        try:
            with open(user_agents_file_name, 'r') as user_agents:
                session_data = json.load(user_agents)
                if isinstance(session_data, list):
                    return session_data

        except FileNotFoundError:
            logger.warning("User agents file not found, creating...")

        except json.JSONDecodeError:
            logger.warning("User agents file is empty or corrupted.")

        return []

    def check_user_agent(self):
        load = next(
            (session['user_agent'] for session in self.session_ug_dict if session['session_name'] == self.session_name),
            None)

        if load is None:
            return self.save_user_agent()

        return load

    def info(self, message):
        from bot.utils import info
        info(f"<light-yellow>{self.session_name}</light-yellow> | {message}")

    def debug(self, message):
        from bot.utils import debug
        debug(f"<light-yellow>{self.session_name}</light-yellow> | {message}")

    def warning(self, message):
        from bot.utils import warning
        warning(f"<light-yellow>{self.session_name}</light-yellow> | {message}")

    def error(self, message):
        from bot.utils import error
        error(f"<light-yellow>{self.session_name}</light-yellow> | {message}")

    def critical(self, message):
        from bot.utils import critical
        critical(f"<light-yellow>{self.session_name}</light-yellow> | {message}")

    def success(self, message):
        from bot.utils import success
        success(f"<light-yellow>{self.session_name}</light-yellow> | {message}")

    async def get_tg_web_data(self, proxy: str | None) -> str:
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
                        if (message.text and message.text.startswith('/start')) or (message.caption and message.caption.startswith('/start')):
                            start_command_found = True
                            break

                    if not start_command_found:
                        if settings.REF_ID == '':
                            await self.tg_client.send_message("Port3miniapp_bot", "/start kESn89")
                        else:
                            await self.tg_client.send_message("Port3miniapp_bot", f"/start {settings.REF_ID}")
                except (Unauthorized, UserDeactivated, AuthKeyUnregistered):
                    raise InvalidSession(self.session_name)

            while True:
                try:
                    peer = await self.tg_client.resolve_peer('Port3miniapp_bot')
                    break
                except FloodWait as fl:
                    fls = fl.value

                    logger.warning(f"<light-yellow>{self.session_name}</light-yellow> | FloodWait {fl}")
                    logger.info(f"<light-yellow>{self.session_name}</light-yellow> | Sleep {fls}s")

                    await asyncio.sleep(fls + 3)

            web_view = await self.tg_client.invoke(RequestWebView(
                peer=peer,
                bot=peer,
                platform='android',
                from_bot_menu=False,
                url='https://mini.port3.io/'
            ))

            auth_url = web_view.url
            tg_web_data = unquote(
                    string=auth_url.split('tgWebAppData=', maxsplit=1)[1].split('&tgWebAppVersion', maxsplit=1)[0])

            try:
                information = await self.tg_client.get_me()
                self.user_id = information.id
                self.first_name = information.first_name or ''
                self.last_name = information.last_name or ''
                self.username = information.username or ''
            except Exception as e:
                print(e)

            if with_tg is False:
                await self.tg_client.disconnect()

            return tg_web_data

        except InvalidSession as error:
            raise error

        except Exception as error:
            logger.error(f"<light-yellow>{self.session_name}</light-yellow> | Unknown error during Authorization: {error}")
            await asyncio.sleep(delay=3)

    async def login(self, http_client: aiohttp.ClientSession, initdata):
        try:
            payload = {
                'platform': 'telegram',
                'token': initdata,
                'type': 'telegram_app'
            }
            new_headers = await self.generate_headers()
            response = await http_client.post(url='https://api.sograph.xyz/api/login/web2', json=payload,
                                              headers=new_headers, ssl=False)
            resp_json = await response.json()
            signature = resp_json.get('data', {}).get('signature', {})

            return signature

        except Exception as error:
            logger.error(f"<light-yellow>{self.session_name}</light-yellow> | Unknown error while login try: {error} ")

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
            logger.error(f'<light-yellow>{self.session_name}</light-yellow> | Error generate headers - {e}')

    async def make_click(self, http_client: aiohttp.ClientSession, clicks):
        try:
            payload = {"number": clicks}
            new_headers = await self.generate_headers()
            response = await http_client.post(url='https://api.sograph.xyz/api/mining/tap/click', json=payload,
                                              headers=new_headers, ssl=False)
            if response.status in [200, 201]:
                return True
            return False

        except Exception as e:
            logger.error(f'<light-yellow>{self.session_name}</light-yellow> | Error making click - {e}')

    async def get_info(self, http_client: aiohttp.ClientSession):
        try:
            new_headers = await self.generate_headers()
            response = await http_client.get(url='https://api.sograph.xyz/api/mining/tap/userinfo?', headers=new_headers, ssl=False)
            resp_json = await response.json()
            balance = resp_json.get('data').get('gems', 0)
            get_gems_per_click = resp_json.get('data').get('click_gems', 1)
            everyday_clicks = resp_json.get('data').get('daily_number', 0)
            today_clicked = resp_json.get('data').get('daily_use_number', 0)

            new_headers = await self.generate_headers()
            response_lvl_info = await http_client.get(url='https://api.sograph.xyz/api/user/info?', headers=new_headers, ssl=False)
            resp_json_lvl = await response_lvl_info.json()
            identity = resp_json_lvl.get('data', {}).get('identity')

            return balance, get_gems_per_click, everyday_clicks, today_clicked, identity

        except Exception as e:
            logger.error(f'<light-yellow>{self.session_name}</light-yellow> | Error getting info - {e}')

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
                                                          headers=new_headers, ssl=False)
                        if response.status in [200, 201]:
                            logger.success(f'<light-yellow>{self.session_name}</light-yellow> | Reached new lvl - {next_identity}')

                        current_index += 1
                    else:
                        logger.info(f'<light-yellow>{self.session_name}</light-yellow> | Not enough to update lvl')
                        return False
                else:
                    logger.info(f'<light-yellow>{self.session_name}</light-yellow> | You reached max lvl')
                    return False

        except Exception as e:
            logger.error(f'<light-yellow>{self.session_name}</light-yellow> | Error buy_lvl - {e}')

    async def check_proxy(self, http_client: aiohttp.ClientSession, proxy: Proxy) -> None:
        try:
            response = await http_client.get(url='https://httpbin.org/ip', timeout=aiohttp.ClientTimeout(5))
            ip = (await response.json()).get('origin')
            logger.info(f"<light-yellow>{self.session_name}</light-yellow> | Proxy IP: {ip}")
        except Exception as error:
            logger.error(f"<light-yellow>{self.session_name}</light-yellow> | Proxy: {proxy} | Error: {error}")

    async def run(self, proxy: str | None) -> None:
        proxy_conn = ProxyConnector().from_url(proxy) if proxy else None

        http_client = CloudflareScraper(headers=headers, connector=proxy_conn)

        if proxy:
            await self.check_proxy(http_client=http_client, proxy=proxy)

        tg_web_data = await self.get_tg_web_data(proxy=proxy)

        while True:
            try:

                signature = await self.login(http_client=http_client, initdata=tg_web_data)
                if not signature:
                    continue

                self.auth_token = signature

                balance, gems_per_click, day_limit, current_clicks, identity = await self.get_info(http_client)
                logger.info(f'<light-yellow>{self.session_name}</light-yellow> | Balance: {balance} | Gems per click - '
                            f'{gems_per_click} | '
                            f'Day limit - {day_limit} | Current clicked of day limit - {current_clicks} | '
                            f'Current level - {identity}')

                if current_clicks < day_limit:
                    clicks_to_do = day_limit - current_clicks
                    logger.info(f'<light-yellow>{self.session_name}</light-yellow> | Trying to click')
                    status = await self.make_click(http_client, clicks_to_do)
                    if status:
                        logger.success(f'<light-yellow>{self.session_name}</light-yellow> | Successfully clicked '
                                       f'{clicks_to_do} times, got '
                                       f'{clicks_to_do * gems_per_click} gems')

                logger.info(f'<light-yellow>{self.session_name}</light-yellow> | Trying to upgrade lvl')
                status = await self.buy_lvl(http_client)
                if status:
                    logger.success(f'<light-yellow>{self.session_name}</light-yellow> | Successfully upgraded lvl')

                logger.info(f"<light-yellow>{self.session_name}</light-yellow> | Going sleep 1 hour")

                await asyncio.sleep(3600)

            except InvalidSession as error:
                raise error

            except Exception as error:
                logger.error(f"<light-yellow>{self.session_name}</light-yellow> | Unknown error: {error}")
                await asyncio.sleep(delay=3)


async def run_tapper(tg_client: Client, proxy: str | None):
    try:
        await Tapper(tg_client=tg_client).run(proxy=proxy)
    except InvalidSession:
        logger.error(f"{tg_client.name} | Invalid Session")
