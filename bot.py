import logging
import os
import shodan
import sublist3r
import requests
import json
import whois
import dns.resolver
import socket
from datetime import datetime
from telegram import Update, InlineKeyboardButton, InlineKeyboardMarkup, ParseMode
from telegram.ext import Updater, CommandHandler, CallbackQueryHandler, MessageHandler, Filters, CallbackContext
from telegram.error import BadRequest
from telegram.utils.helpers import escape_markdown

# Replace placeholders with your actual API keys, bot token, and other details
SHODAN_API_KEY = 'YaLNvFBVpaTrMkW829nATM3xRTvMaVsH'
TELEGRAM_BOT_TOKEN = '7289883891:AAE-zMR_5Ln0GMknhgSeYZrmUGd0UsMt5qA'
OWNER_ID = 5460343986
OWNER_USERNAME = '@moon_god_khonsu'
REQUIRED_GROUP = '@fakaoanl'
REQUIRED_CHANNELS = ['@found_us', '@hacking_Mathod']
LOGGER_GROUP_ID = -1002233757002  # Replace with your logger group ID

# Enable logging
logging.basicConfig(format='%(asctime)s - %(name)s - %(levelname)s - %(message)s', level=logging.INFO)
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

def strip_protocol(url):
    if url.startswith("http://"):
        return url[7:]
    elif url.startswith("https://"):
        return url[8:]
    return url

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

    try:
        whois_info = whois.whois(url)
        result['whois'] = whois_info.text if isinstance(whois_info, str) else whois_info.to_json()
    except Exception as e:
        result['whois'] = f"Error fetching WHOIS info: {str(e)}"

    try:
        ip_address = socket.gethostbyname(strip_protocol(url))
        ip_info = requests.get(f'https://ipinfo.io/{ip_address}/json').json()
        result['ip_geo'] = json.dumps(ip_info, indent=2)
        result['real_ip'] = ip_address
    except Exception as e:
        result['ip_geo'] = f"Error fetching IP geolocation: {str(e)}"

    try:
        ssl_info = requests.get(f'https://api.ssllabs.com/api/v3/analyze?host={strip_protocol(url)}').json()
        result['ssl_info'] = json.dumps(ssl_info, indent=2)
    except Exception as e:
        result['ssl_info'] = f"Error fetching SSL info: {str(e)}"

    try:
        dns_info = dns.resolver.resolve(strip_protocol(url), 'A')
        result['dns_records'] = [str(record) for record in dns_info]
    except Exception as e:
        result['dns_records'] = f"Error fetching DNS records: {str(e)}"

    try:
        headers_info = requests.head(f'http://{strip_protocol(url)}').headers
        result['http_headers'] = dict(headers_info)
    except Exception as e:
        result['http_headers'] = f"Error fetching HTTP headers: {str(e)}"

    try:
        web_technologies_info = shodan_api.search(url)
        result['web_technologies'] = json.dumps(web_technologies_info['matches'][0]['data'], indent=2)
    except Exception as e:
        result['web_technologies'] = f"Error fetching web technologies: {str(e)}"

    try:
        subdomains = sublist3r.main(url, 40, savefile=False, ports=None, silent=True, verbose=False, enable_bruteforce=False, engines=None)
        result['subdomains'] = subdomains if isinstance(subdomains, str) else "\n".join(subdomains)
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
        user_limits[user_id] = 1  # Give 1 free scan

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

    # Log to logger group
    try:
        context.bot.send_message(chat_id=LOGGER_GROUP_ID, text=f"User {user_id} scanned URL: {url}")
    except Exception as e:
        logger.error(f"Error logging to logger group: {str(e)}")

    result_messages = []
    result_messages.append(f"*Web scanner:*\n\n")
    result_messages.append(f"*WHOIS Info:*\n`{escape_markdown(result['whois'], version=2)}`\n\n")
    result_messages.append(f"*IP Geolocation:*\n`{escape_markdown(result['ip_geo'], version=2)}`\n\n")
    result_messages.append(f"*Real IP Address:*\n`{escape_markdown(result['real_ip'], version=2)}`\n\n")
    result_messages.append(f"*SSL Certificate:*\n`{escape_markdown(result['ssl_info'], version=2)}`\n\n")
    result_messages.append(f"*DNS Records:*\n`{escape_markdown(str(result['dns_records']), version=2)}`\n\n")
    result_messages.append(f"*HTTP Headers:*\n`{escape_markdown(json.dumps(result['http_headers'], indent=2), version=2)}`\n\n")
    result_messages.append(f"*Web Technologies:*\n`{escape_markdown(result['web_technologies'], version=2)}`\n\n")
    result_messages.append(f"*Subdomains:*\n`{escape_markdown(result['subdomains'], version=2)}`")

    # Telegram message character limit is 4096, split the messages if too long
    MAX_MESSAGE_LENGTH = 4096
    for message in result_messages:
        for i in range(0, len(message), MAX_MESSAGE_LENGTH):
            update.message.reply_text(message[i:i+MAX_MESSAGE_LENGTH], parse_mode=ParseMode.MARKDOWN_V2)

def stats(update: Update, context: CallbackContext):
    user_id = update.message.from_user.id
    if user_id != OWNER_ID:
        update.message.reply_text("You are not authorized to use this command.")
        return

    total_users = len(user_searches)
    total_scans = sum(len(scans) for scans in user_searches.values())

    update.message.reply_text(f"Total Users: {total_users}\nTotal Scans: {total_scans}")

def broadcast(update: Update, context: CallbackContext):
    user_id = update.message.from_user.id
    if user_id != OWNER_ID:
        update.message.reply_text("You are not authorized to use this command.")
        return

    message = update.message.text[len('/broadcast '):].strip()
    if not message:
        update.message.reply_text("Please provide a message to broadcast.")
        return

    for user_id in user_searches.keys():
        try:
            context.bot.send_message(chat_id=user_id, text=message)
        except Exception as e:
            logger.error(f"Error sending message to {user_id}: {str(e)}")

def premium(update: Update, context: CallbackContext):
    user_id = update.message.from_user.id
    if user_id != OWNER_ID:
        update.message.reply_text("You are not authorized to use this command.")
        return

    args = update.message.text.split()
    if len(args) != 3:
        update.message.reply_text("Usage: /premium <user_id> <search_limit>")
        return

    target_user_id = int(args[1])
    search_limit = int(args[2])
    add_premium_user(target_user_id, search_limit)

    update.message.reply_text(f"Granted {search_limit} searches to user {target_user_id}.")

def error_handler(update: Update, context: CallbackContext):
    logger.error(f"Update {update} caused error {context.error}")

# Main function
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
