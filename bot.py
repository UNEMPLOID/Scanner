import logging
import os
import shodan
import sublist3r
import requests
import json
import whois
import dns.resolver
from datetime import datetime
from telegram import Update, InlineKeyboardButton, InlineKeyboardMarkup, ParseMode
from telegram.ext import Updater, CommandHandler, CallbackQueryHandler, MessageHandler, Filters, CallbackContext
from telegram.error import BadRequest

# Replace placeholders with your actual API keys, bot token, and other details
SHODAN_API_KEY = 'YaLNvFBVpaTrMkW829nATM3xRTvMaVsH'
TELEGRAM_BOT_TOKEN = '7289883891:AAE-zMR_5Ln0GMknhgSeYZrmUGd0UsMt5qA'
OWNER_ID = 5460343986
OWNER_USERNAME = '@moon_god_khonsu'
LOG_GROUP_ID = -1002233757002  # Replace with your log group ID
REQUIRED_GROUP = '@fakaoanl'
REQUIRED_CHANNELS = ['@found_us', '@hacking_Mathod']

# Enable logging
logging.basicConfig(format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
                    level=logging.INFO)
logger = logging.getLogger(__name__)

# Create Shodan API instance
shodan_api = shodan.Shodan(SHODAN_API_KEY)

# Global data storage for user searches
user_searches = {}
user_limits = {}

# Helper functions
def check_subscription(user_id):
    return user_id in user_limits and user_limits[user_id] > 0

def check_joined_group_and_channels(user_id):
    # This function should interact with the Telegram API to verify group and channel membership
    return True  # Replace with actual logic

def add_premium_user(user_id, search_limit):
    user_limits[user_id] = search_limit

def scan_website(url):
    result = {
        'whois': '',
        'ip_geo': '',
        'real_ip': '',
        'ssl_info': '',
        'dns_records': '',
        'http_headers': {},
        'web_technologies': {},
        'subdomains': ''
    }

    # WHOIS Info
    try:
        whois_info = whois.whois(url)
        result['whois'] = whois_info.text
    except Exception as e:
        result['whois'] = f"Error fetching WHOIS info: {str(e)}"

    # IP Geolocation
    try:
        ip_info = requests.get(f'https://ipinfo.io/{url}/json').json()
        result['ip_geo'] = ip_info
    except Exception as e:
        result['ip_geo'] = f"Error fetching IP geolocation: {str(e)}"

    # SSL Certificate Info
    try:
        ssl_info = requests.get(f'https://api.ssllabs.com/api/v3/analyze?host={url}').json()
        result['ssl_info'] = ssl_info
    except Exception as e:
        result['ssl_info'] = f"Error fetching SSL info: {str(e)}"

    # DNS Records
    try:
        dns_info = dns.resolver.resolve(url, 'A')
        result['dns_records'] = [str(record) for record in dns_info]
    except Exception as e:
        result['dns_records'] = f"Error fetching DNS records: {str(e)}"

    # HTTP Headers
    try:
        headers_info = requests.head(f'http://{url}').headers
        result['http_headers'] = dict(headers_info)
    except Exception as e:
        result['http_headers'] = f"Error fetching HTTP headers: {str(e)}"

    # Web Technologies
    try:
        web_technologies_info = shodan_api.search(url)
        result['web_technologies'] = web_technologies_info['matches'][0]['data']
    except Exception as e:
        result['web_technologies'] = f"Error fetching web technologies: {str(e)}"

    # Subdomains
    try:
        subdomains = sublist3r.main(url, 40, savefile=False, ports=None, silent=True, verbose=False, enable_bruteforce=False, engines=None)
        result['subdomains'] = subdomains
    except Exception as e:
        result['subdomains'] = f"Error fetching subdomains: {str(e)}"

    return result

# Command handlers
def start(update: Update, context: CallbackContext):
    user_id = update.message.from_user.id
    username = update.message.from_user.username
    logger.info(f"User {user_id} (@{username}) initiated the bot.")
    
    # Log the user start event
    context.bot.send_message(chat_id=LOG_GROUP_ID, text=f"User {user_id} (@{username}) started the bot.")

    keyboard = [
        [InlineKeyboardButton("Join Group", url="https://t.me/fakaoanl")],
        [InlineKeyboardButton("Join Channel 1", url="https://t.me/found_us")],
        [InlineKeyboardButton("Join Channel 2", url="https://t.me/hacking_Mathod")],
        [InlineKeyboardButton("Check Joined", callback_data="check_joined")]
    ]

    reply_markup = InlineKeyboardMarkup(keyboard)

    update.message.reply_text(
        "Welcome to the Subdomain Scanner Bot!\n\n"
        "Please join our required group and channels, then click 'Check Joined' to proceed.",
        reply_markup=reply_markup
    )

def button(update: Update, context: CallbackContext):
    query = update.callback_query
    user_id = query.from_user.id
    username = query.from_user.username

    if query.data == "check_joined":
        logger.info(f"User {user_id} (@{username}) pressed 'Check Joined'.")
        if check_joined_group_and_channels(user_id):
            query.edit_message_text(text="You have joined all required channels and groups. You can now use the bot.")
            # Show the scan button
            keyboard = [
                [InlineKeyboardButton("Start Scan", callback_data="start_scan")]
            ]
            reply_markup = InlineKeyboardMarkup(keyboard)
            query.message.reply_text("You can now start scanning websites.", reply_markup=reply_markup)
        else:
            query.edit_message_text(text="Please join all required channels and groups before using the bot.")
    elif query.data == "start_scan":
        query.message.reply_text("Please enter the URL you want to scan.")

def scan(update: Update, context: CallbackContext):
    user_id = update.message.from_user.id
    username = update.message.from_user.username
    logger.info(f"User {user_id} (@{username}) requested a scan.")

    if not check_joined_group_and_channels(user_id):
        update.message.reply_text("Please join all required channels and groups before using the bot.")
        return

    if not check_subscription(user_id):
        update.message.reply_text("You have reached your search limit. Please contact the bot owner to buy more searches.")
        return

    url = update.message.text.strip()
    if not url:
        update.message.reply_text("Please provide a valid URL to scan.")
        return

    # Check for falconsec.net domain
    if 'falconsec.net' in url:
        update.message.reply_text("Data for falconsec.net cannot be provided.")
        return

    update.message.reply_text("Scanning... This might take a few minutes.")
    result = scan_website(url)

    # If the scanned site is a .gov domain, forward the data to the owner
    if url.endswith('.gov'):
        context.bot.send_message(chat_id=OWNER_ID, text=f"User {user_id} (@{username}) scanned a .gov site: {url}\nData: {json.dumps(result, indent=2)}")

    user_limits[user_id] -= 1

    result_message = f"Web scanner:\n\n"
    result_message += f"WHOIS Info:\n{result['whois']}\n\n"
    result_message += f"IP Geolocation:\n{json.dumps(result['ip_geo'], indent=2)}\n\n"
    result_message += f"Real IP Address:\n{result['real_ip']}\n\n"
    result_message += f"SSL Certificate:\n{json.dumps(result['ssl_info'], indent=2)}\n\n"
    result_message += f"DNS Records:\n{result['dns_records']}\n\n"
    result_message += f"HTTP Headers:\n{json.dumps(result['http_headers'], indent=2)}\n\n"
    result_message += f"Web Technologies:\n{json.dumps(result['web_technologies'], indent=2)}\n\n"
    result_message += f"Subdomains:\n{result['subdomains']}\n\n"
    result_message += f"Join us - @fakaoanl"

    try:
        if len(result_message) > 4096:
            for i in range(0, len(result_message), 4096):
                update.message.reply_text(result_message[i:i+4096], parse_mode=ParseMode.MARKDOWN)
        else:
            update.message.reply_text(result_message, parse_mode=ParseMode.MARKDOWN)
    except BadRequest as e:
        update.message.reply_text(f"An error occurred while sending the message: {str(e)}")

    # Log the scan event
    context.bot.send_message(chat_id=LOG_GROUP_ID, text=f"User {user_id} (@{username}) scanned site: {url}\nResult: {json.dumps(result, indent=2)}")

def help_command(update: Update, context: CallbackContext):
    user_id = update.message.from_user.id
    if user_id == OWNER_ID:
        update.message.reply_text(
            "/premium - Add premium users\n"
            "/broadcast - Broadcast a message to all users\n"
            "/statistics - View bot statistics\n"
            "/help - Show this help message"
        )
    else:
        update.message.reply_text("You do not have permission to use this command.")

def main():
    updater = Updater(TELEGRAM_BOT_TOKEN, use_context=True)

    dp = updater.dispatcher

    dp.add_handler(CommandHandler("start", start))
    dp.add_handler(CallbackQueryHandler(button))
    dp.add_handler(MessageHandler(Filters.text & ~Filters.command, scan))
    dp.add_handler(CommandHandler("help", help_command))

    updater.start_polling()

    updater.idle()

if __name__ == '__main__':
    main()
