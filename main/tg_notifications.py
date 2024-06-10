import requests

from parser_logs.settings import bot_token, chat_id


def send_telegram_message(message):
    requests.post(
        f'https://api.telegram.org/bot{bot_token}/sendMessage?chat_id={chat_id}&text={message}')
