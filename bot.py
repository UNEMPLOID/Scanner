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
    return user_limits.get(user_id, 0) > 0

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
        if 'error' in ip_info:
            result['ip_geo'] = f"Error fetching IP geolocation: {ip_info['error']['message']}"
        else:
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
    logger.info(f"User {update.message.from_user.id} initiated the bot.")
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

    if query.data == "check_joined":
        logger.info(f"User {user_id} pressed 'Check Joined'.")
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
    logger.info(f"User {user_id} requested a scan.")

    if not check_joined_group_and_channels(user_id):
        update.message.reply_text("Please join all required channels and groups before using the bot.")
        return

    if user_id not in user_limits:
        user_limits[user_id] = 2  # Give 2 free scans

    if not check_subscription(user_id):
        update.message.reply_text("You have reached your search limit. Please contact the bot owner to buy more searches.")
        return

    url = update.message.text.strip()
    if not url:
        update.message.reply_text("Please provide a valid URL to scan.")
        return

    update.message.reply_text("Scanning... This might take a few minutes.")
    result = scan_website(url)

    user_limits[user_id] -= 1

    result_messages = []
    result_messages.append(f"Web scanner:\n\n")
    result_messages.append(f"WHOIS Info:\n```\n{result['whois']}\n```\n\n")
    result_messages.append(f"IP Geolocation:\n```\n{json.dumps(result['ip_geo'], indent=2)}\n```\n\n")
    result_messages.append(f"Real IP Address:\n```\n{result['real_ip']}\n```\n\n")
    result_messages.append(f"SSL Certificate:\n```\n{json.dumps(result['ssl_info'], indent=2)}\n```\n\n")
    result_messages.append(f"DNS Records:\n```\n{result['dns_records']}\n```\n\n")
    result_messages.append(f"HTTP Headers:\n```\n{json.dumps(result['http_headers'], indent=2)}\n```\n\n")
    result_messages.append(f"Web Technologies:\n```\n{json.dumps(result['web_technologies'], indent=2)}\n```\n\n")
    result_messages.append(f"Subdomains:\n```\n{result['subdomains']}\n```\n\n")
    result_messages.append(f"Join us - @fakaoanl")

    try:
        for msg in result_messages:
            if len(msg) > 4096:
                for i in range(0, len(msg), 4096):
                    update.message.reply_text(msg[i:i+4096], parse_mode=ParseMode.MARKDOWN)
            else:
                update.message.reply_text(msg, parse_mode=ParseMode.MARKDOWN)
    except BadRequest as e:
        update.message.reply_text(f"An error occurred while sending the message: {str(e)}")

def stats(update: Update, context: CallbackContext):
    user_id = update.message.from_user.id

    if user_id != OWNER_ID:
        update.message.reply_text("You are not authorized to use this command.")
        return

    num_users = len(user_searches)
    num_groups = len(user_limits)
    update.message.reply_text(f"Bot Stats:\n\nUsers: {num_users}\nGroups: {num_groups}")

def broadcast(update: Update, context: CallbackContext):
    user_id = update.message.from_user.id

    if user_id != OWNER_ID:
        update.message.reply_text("You are not authorized to use this command.")
        return

    if not context.args:
        update.message.reply_text("Please provide a message to broadcast.")
        return

    message = ' '.join(context.args)
    for chat_id in user_limits:
        try:
            context.bot.send_message(chat_id=chat_id, text=message)
        except Exception as e:
            logger.error(f"Error sending message to {chat_id}: {str(e)}")
            update.message.reply_text(f"An error occurred while sending the message to {chat_id}: {str(e)}")

    update.message.reply_text("Broadcast sent.")

def premium(update: Update, context: CallbackContext):
    user_id = update.message.from_user.id

    if user_id != OWNER_ID:
        update.message.reply_text("You are not authorized to use this command.")
        return

    if len(context.args) != 2:
        update.message.reply_text("Usage: /premium <user_id> <search_limit>")
        return

    target_user_id = int(context.args[0])
    search_limit = int(context.args[1])

    add_premium_user(target_user_id, search_limit)
    update.message.reply_text(f"User {target_user_id} has been given a limit of {search_limit} searches.")

def error_handler(update: Update, context: CallbackContext):
    logger.error(msg="Exception while handling an update:", exc_info=context.error)
    update.message.reply_text("An error occurred. Please try again later.")

def main():
    os.system("pip install -r requirements.txt")

    updater = Updater(TELEGRAM_BOT_TOKEN, use_context=True)
    dispatcher = updater.dispatcher

    dispatcher.add_handler(CommandHandler("start", start))
    dispatcher.add_handler(CallbackQueryHandler(button))
    dispatcher.add_handler(MessageHandler(Filters.text & Filters.chat_type.groups & Filters.regex('^/start$'), start))
    dispatcher.add_handler(MessageHandler(Filters.text & Filters.chat_type.private, scan))
    dispatcher.add_handler(CommandHandler("stats", stats))
    dispatcher.add_handler(CommandHandler("broadcast", broadcast))
    dispatcher.add_handler(CommandHandler("premium", premium))
    dispatcher.add_error_handler(error_handler)

    updater.start_polling()
    updater.idle()

if __name__ == '__main__':
    main()
      
