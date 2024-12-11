import asyncio

import aiohttp
from eth_account import Account
from loguru import logger
from tenacity import retry
from web3.auto import w3

from utils import append_file
from utils import get_proxy
from utils import loader

Account.enable_unaudited_hdwallet_features()


def log_retry_error(retry_state):
    logger.error(retry_state.outcome.exception())


class Checker:
    def __init__(self,
                 client: aiohttp.ClientSession,
                 account_data: str,
                 account_address: str):
        self.client: aiohttp.ClientSession = client
        self.account_data: str = account_data
        self.account_address: str = account_address

    @retry(after=log_retry_error)
    async def _get_balances(self) -> list:
        response_text: None = None
        total_balances: list = []

        try:
            r: aiohttp.ClientResponse = await self.client.post(
                url=f'https://asia-east2-kip-genesis-nft-4c1d8.cloudfunctions.net/getAllocations',
                proxy=get_proxy(),
                json={
                    'data': {
                        'walletAddress': self.account_address
                    }
                }
            )

            response_text: str = await r.text()
            response_json: dict = await r.json(content_type=None)

            for current_balance in response_json['result']['allocations'].values():
                if not current_balance['points']:
                    continue

                if float(list(current_balance['points'].values())[0]['available']) <= 0:
                    continue

                total_balances.append({
                    'name': list(current_balance['points'].values())[0]['name'],
                    'total_amount': float(list(current_balance['points'].values())[0]['amount']),
                    'claimed': float(list(current_balance['points'].values())[0]['claimed']),
                    'available': float(list(current_balance['points'].values())[0]['available'])
                })

            return total_balances

        except Exception as error:
            raise Exception(
                f'{self.account_address} | Unexpected Error When Checking Eligible: {error}'
                + (f', response: {response_text}' if response_text else '')
            ) from error

    @retry(after=log_retry_error)
    async def _check_eligible(self) -> bool:
        response_text: None = None

        try:
            r: aiohttp.ClientResponse = await self.client.post(
                url=f'https://asia-east2-kip-genesis-nft-4c1d8.cloudfunctions.net/getEligibility',
                proxy=get_proxy(),
                json={
                    'data': {
                        'walletAddress': self.account_address
                    }
                }
            )

            response_text: str = await r.text()
            response_json: dict = await r.json(content_type=None)

            return True if response_json['result']['eligibility'] else False

        except Exception as error:
            raise Exception(
                f'{self.account_address} | Unexpected Error When Checking Eligible: {error}'
                + (f', response: {response_text}' if response_text else '')
            ) from error

    async def balance_checker(self) -> None:
        tokens_data: list = await self._get_balances()

        if not tokens_data:
            logger.error(f'{self.account_address} | Not Eligible')
            return

        for balance in tokens_data:
            logger.success(
                f'{self.account_data} | {self.account_address} | Name: {balance["name"]} | Available: {balance["available"]} | ({balance["total_amount"]}/{balance["claimed"]})',
            )

            async with asyncio.Lock():
                await append_file(
                    file_path='result/with_balances.txt',
                    file_content=f'{self.account_data} | {self.account_address} | Name: {balance["name"]} | Available: {balance["available"]} | ({balance["total_amount"]}/{balance["claimed"]})\n'
                )

    async def eligible_checker(self) -> None:
        is_eligible: bool = await self._check_eligible()

        if not is_eligible:
            logger.error(f'{self.account_address} | Not Eligible')
            return

        logger.success(
            f'{self.account_data} | {self.account_address} | Eligible',
        )

        async with asyncio.Lock():
            await append_file(
                file_path='result/eligible.txt',
                file_content=f'{self.account_data} | {self.account_address}\n'
            )


async def check_account(
        client: aiohttp.ClientSession,
        account_data: str
) -> None:
    async with loader.semaphore:
        account_address: None = None

        try:
            account_address: str = Account.from_key(private_key=account_data).address

        except Exception:
            pass

        if not account_address:
            try:
                account_address: str = Account.from_mnemonic(mnemonic=account_data).address

            except Exception:
                pass

        if not account_address:
            try:
                account_address: str = w3.to_checksum_address(value=account_data)

            except Exception:
                pass

        if not account_address:
            logger.error(f'{account_data} | Not Mnemonic and not PKey')
            return

        checker: Checker = Checker(
            client=client,
            account_data=account_data,
            account_address=account_address
        )


        return await checker.balance_checker() if loader.parse_method == 2 else await checker.eligible_checker()
