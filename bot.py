import os
import json
import socket
import ssl
import subprocess
import whois
import requests
import dns.resolver
import builtwith
import shodan
import threading
from telegram import Update, InlineKeyboardButton, InlineKeyboardMarkup
from telegram.ext import Updater, CommandHandler, CallbackQueryHandler, MessageHandler, Filters, CallbackContext
from telegram.error import NetworkError, Unauthorized

# Replace placeholders with your actual API keys, bot token, and other details
SHODAN_API_KEY = 'YaLNvFBVpaTrMkW829nATM3xRTvMaVsH'
TELEGRAM_BOT_TOKEN = '7289883891:AAFIMGy9T9-V8iklbHc3Gl3jPE30ogMIBdY'
OWNER_ID = 5460343986
OWNER_USERNAME = '@moon_god_khonsu'

REQUIRED_GROUP = '@fakaoanl'
REQUIRED_CHANNELS = ['@found_us', '@hacking_Mathod']

# Setup Shodan API
shodan_api = shodan.Shodan(SHODAN_API_KEY)

# User data
user_data = {}

# Load user data
if os.path.exists('user_data.json'):
    with open('user_data.json', 'r') as f:
        user_data = json.load(f)

def save_user_data():
    with open('user_data.json', 'w') as f:
        json.dump(user_data, f)

def install_dependencies():
    # Install required tools if they are not available
    dependencies = ['sublist3r']
    for dep in dependencies:
        try:
            subprocess.run(['which', dep], check=True, stdout=subprocess.PIPE)
        except subprocess.CalledProcessError:
            subprocess.run(['pip', 'install', dep], check=True)

def start(update: Update, context: CallbackContext):
    user_id = update.message.from_user.id
    user_name = update.message.from_user.username

    if user_id not in user_data:
        user_data[user_id] = {
            'free_searches': 5,
            'premium_searches': 0,
            'is_banned': False,
            'scan_history': []
        }
        save_user_data()

    # Check if user is banned
    if user_data[user_id]['is_banned']:
        update.message.reply_text("You are banned from using this bot.")
        return

    # Check if user is part of required group and channels
    if not check_subscription(user_id, context.bot):
        keyboard = [
            [InlineKeyboardButton("Join Group", url=f"https://t.me/{REQUIRED_GROUP}")],
            *[InlineKeyboardButton(f"Join Channel {i+1}", url=f"https://t.me/{channel}") for i, channel in enumerate(REQUIRED_CHANNELS)],
            [InlineKeyboardButton("Check Joined", callback_data='check_joined')]
        ]
        reply_markup = InlineKeyboardMarkup(keyboard)
        update.message.reply_text(
            "Please join all required channels and groups before using the bot.",
            reply_markup=reply_markup
        )
        return

    # Show welcome message and the scan button
    keyboard = [
        [InlineKeyboardButton("Start Scan", callback_data='start_scan')]
    ]
    reply_markup = InlineKeyboardMarkup(keyboard)
    update.message.reply_text(
        f"Welcome {user_name}! Click 'Start Scan' to begin scanning a website.",
        reply_markup=reply_markup
    )

def check_subscription(user_id: int, bot):
    chat_member = bot.get_chat_member(REQUIRED_GROUP, user_id)
    if chat_member.status not in ['member', 'administrator', 'creator']:
        return False

    for channel in REQUIRED_CHANNELS:
        try:
            chat_member = bot.get_chat_member(channel, user_id)
            if chat_member.status not in ['member', 'administrator', 'creator']:
                return False
        except Exception:
            return False

    return True

def button(update: Update, context: CallbackContext):
    query = update.callback_query
    query.answer()
    
    if query.data == 'start_scan':
        query.edit_message_text("Please enter the URL you want to scan.")
        context.bot_data['waiting_for_url'] = query.message.chat_id

    if query.data == 'check_joined':
        user_id = query.from_user.id
        if check_subscription(user_id, context.bot):
            keyboard = [
                [InlineKeyboardButton("Start Scan", callback_data='start_scan')]
            ]
            reply_markup = InlineKeyboardMarkup(keyboard)
            query.edit_message_text(
                "Thank you for joining! Click 'Start Scan' to begin scanning a website.",
                reply_markup=reply_markup
            )
        else:
            query.edit_message_text(
                "Please join all required channels and groups before using the bot.\n"
                f"Group: {REQUIRED_GROUP}\n"
                f"Channels: {', '.join(REQUIRED_CHANNELS)}"
            )

def handle_message(update: Update, context: CallbackContext):
    user_id = update.message.from_user.id
    chat_id = update.message.chat_id

    # Check if user is banned
    if user_data[user_id]['is_banned']:
        update.message.reply_text("You are banned from using this bot.")
        return

    # Ensure user has joined required group and channels
    if not check_subscription(user_id, context.bot):
        update.message.reply_text("Please join all required channels and groups before using the bot.")
        return

    # Check if user has reached the search limit
    if user_data[user_id]['free_searches'] <= 0 and user_data[user_id]['premium_searches'] <= 0:
        keyboard = [
            [InlineKeyboardButton("Contact Owner", url=f"https://t.me/{OWNER_USERNAME}")]
        ]
        reply_markup = InlineKeyboardMarkup(keyboard)
        update.message.reply_text("You have reached the search limit. Please contact the owner to buy more searches.", reply_markup=reply_markup)
        return

    if chat_id in context.bot_data and context.bot_data['waiting_for_url'] == chat_id:
        url = update.message.text

        if not url.startswith(('http://', 'https://')):
            update.message.reply_text("Invalid URL. Please provide a URL starting with http:// or https://")
            return

        # Decrease search count
        if user_data[user_id]['premium_searches'] > 0:
            user_data[user_id]['premium_searches'] -= 1
        else:
            user_data[user_id]['free_searches'] -= 1
        save_user_data()

        # Start scanning process
        update.message.reply_text("Scanning... This might take a few minutes.")
        scan_data = scan_url(url)

        # Record scan history
        user_data[user_id]['scan_history'].append(url)
        save_user_data()

        # Send scan results
        update.message.reply_text(scan_data)
        context.bot_data['waiting_for_url'] = None

def scan_url(url):
    result = ["Web scanner:\nScanning... This might take a few minutes.\n"]

    # WHOIS Info
    try:
        whois_info = whois.whois(url)
        result.append("WHOIS Info:")
        result.append(json.dumps(whois_info, indent=4))
    except Exception as e:
        result.append(f"Error fetching WHOIS info: {e}")

    # IP Geolocation
    try:
        ip = socket.gethostbyname(url)
        geo_info = requests.get(f'http://ip-api.com/json/{ip}').json()
        result.append("IP Geolocation:")
        result.append(json.dumps(geo_info, indent=4))
    except Exception as e:
        result.append(f"Error fetching IP geolocation: {e}")

    # Real IP Address
    try:
        shodan_info = shodan_api.host(ip)
        result.append("Real IP Address:")
        result.append(shodan_info['ip_str'])
    except Exception as e:
        result.append(f"Error fetching real IP: {e}")

    # SSL Certificate
    try:
        conn = ssl.create_default_context().wrap_socket(socket.socket(), server_hostname=url)
        conn.connect((url, 443))
        cert = conn.getpeercert()
        result.append("SSL Certificate:")
        result.append(json.dumps(cert, indent=4))
    except Exception as e:
        result.append(f"Error fetching SSL info: {e}")

    # DNS Records
    try:
        dns_records = dns.resolver.resolve(url, 'A')
        result.append("DNS Records:")
        result.append('\n'.join([str(record) for record in dns_records]))
    except Exception as e:
        result.append(f"Error fetching DNS records: {e}")

    # HTTP Headers
    try:
        headers = requests.get(url).headers
        result.append("HTTP Headers:")
        result.append(json.dumps(dict(headers), indent=4))
    except Exception as e:
        result.append(f"Error fetching HTTP headers: {e}")

    # Web Technologies
    try:
        tech = builtwith.parse(url)
        result.append("Web Technologies:")
        result.append(json.dumps(tech, indent=4))
    except Exception as e:
        result.append(f"Error fetching web technologies: {e}")

    # Subdomains
    try:
        subdomains = subprocess.check_output(['sublist3r', '-d', url])
        result.append("Subdomains:")
        result.append(subdomains.decode('utf-8'))
    except Exception as e:
        result.append(f"Error fetching subdomains: {e}")

    return '\n'.join(result)

def stats(update: Update, context: CallbackContext):
    if update.message.from_user.id != OWNER_ID:
        update.message.reply_text("You are not authorized to use this command.")
        return

    total_users = len(user_data)
    total_groups = len(context.bot_data.get('groups', []))
    update.message.reply_text(f"Total users: {total_users}\nTotal groups: {total_groups}")

def broadcast(update: Update, context: CallbackContext):
    if update.message.from_user.id != OWNER_ID:
        update.message.reply_text("You are not authorized to use this command.")
        return

    message = ' '.join(context.args)
    for user_id in user_data:
        try:
            context.bot.send_message(chat_id=user_id, text=message)
        except Exception:
            continue

def add_premium(update: Update, context: CallbackContext):
    if update.message.from_user.id != OWNER_ID:
        update.message.reply_text("You are not authorized to use this command.")
        return

    user_id = int(context.args[0])
    search_count = int(context.args[1])
    if user_id in user_data:
        user_data[user_id]['premium_searches'] += search_count
        save_user_data()
        update.message.reply_text(f"Added {search_count} premium searches to user {user_id}.")
    else:
        update.message.reply_text(f"User {user_id} not found.")

def global_ban(update: Update, context: CallbackContext):
    if update.message.from_user.id != OWNER_ID:
        update.message.reply_text("You are not authorized to use this command.")
        return

    user_id = int(context.args[0])
    if user_id in user_data:
        user_data[user_id]['is_banned'] = True
        save_user_data()
        update.message.reply_text(f"User {user_id} has been banned.")
    else:
        update.message.reply_text(f"User {user_id} not found.")

def history(update: Update, context: CallbackContext):
    if update.message.from_user.id != OWNER_ID:
        update.message.reply_text("You are not authorized to use this command.")
        return

    user_id = int(context.args[0])
    if user_id in user_data:
        history = user_data[user_id]['scan_history']
        update.message.reply_text(f"Scan history for user {user_id}:\n" + '\n'.join(history))
    else:
        update.message.reply_text(f"User {user_id} not found.")

def main():
    install_dependencies()

    updater = Updater(TELEGRAM_BOT_TOKEN, use_context=True)
    dispatcher = updater.dispatcher

    dispatcher.add_handler(CommandHandler("start", start))
    dispatcher.add_handler(CommandHandler("stats", stats))
    dispatcher.add_handler(CommandHandler("broadcast", broadcast, pass_args=True))
    dispatcher.add_handler(CommandHandler("premium", add_premium, pass_args=True))
    dispatcher.add_handler(CommandHandler("gban", global_ban, pass_args=True))
    dispatcher.add_handler(CommandHandler("history", history, pass_args=True))
    dispatcher.add_handler(MessageHandler(Filters.text & Filters.regex(r'^/url '), handle_message))
    dispatcher.add_handler(CallbackQueryHandler(button))

    updater.start_polling()
    updater.idle()

if __name__ == '__main__':
    main()
        
