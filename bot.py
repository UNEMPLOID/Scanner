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
from telegram.error import NetworkError

# Replace placeholders with your actual API keys, bot token, and other details

# Replace placeholders with your actual API keys, bot token, and other details
SHODAN_API_KEY = 'YaLNvFBVpaTrMkW829nATM3xRTvMaVsH'
TELEGRAM_BOT_TOKEN = '7289883891:AAE-zMR_5Ln0GMknhgSeYZrmUGd0UsMt5qA'
OWNER_ID = 5460343986
OWNER_USERNAME = '@moon_god_khonsu'

REQUIRED_GROUP = '@fakaoanl'
REQUIRED_CHANNELS = ['@found_us', '@hacking_Mathod']

# Setup Shodan API
shodan_api = shodan.Shodan(SHODAN_API_KEY)

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

    # Check if user is part of required group and channels
    if not check_subscription(user_id, context.bot):
        keyboard = [
            [InlineKeyboardButton("Check Joined", callback_data='check_joined')]
        ]
        reply_markup = InlineKeyboardMarkup(keyboard)
        update.message.reply_text(
            "Please join all required channels and groups before using the bot.\n"
            f"Group: {REQUIRED_GROUP}\n"
            f"Channels: {', '.join(REQUIRED_CHANNELS)}",
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
    chat_id = update.message.chat_id
    if chat_id in context.bot_data and context.bot_data['waiting_for_url'] == chat_id:
        url = update.message.text

        if not url.startswith(('http://', 'https://')):
            update.message.reply_text("Invalid URL. Please provide a URL starting with http:// or https://")
            return

        # Start scanning process
        update.message.reply_text("Scanning... This might take a few minutes.")
        scan_data = scan_url(url)
        
        # Send scan results
        update.message.reply_text(scan_data)
        context.bot_data['waiting_for_url'] = None

def scan_url(url):
    result = []

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
        shodan_info = shodan_api.host(url)
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
        result.append("Subdomains:")
        subdomains = subprocess.check_output(['sublist3r', '-d', url, '-o', 'subdomains.txt'])
        with open('subdomains.txt', 'r') as file:
            result.append(file.read())
    except Exception as e:
        result.append(f"Error fetching subdomains: {e}")

    result.append(f"\nJoin us - {REQUIRED_GROUP}")
    return "\n".join(result)

def main():
    updater = Updater(TELEGRAM_BOT_TOKEN, use_context=True)
    dispatcher = updater.dispatcher

    dispatcher.add_handler(CommandHandler("start", start))
    dispatcher.add_handler(CallbackQueryHandler(button))
    dispatcher.add_handler(MessageHandler(Filters.text & ~Filters.command, handle_message))
    dispatcher.add_handler(MessageHandler(Filters.command, handle_command))

    updater.start_polling()
    updater.idle()

def handle_command(update: Update, context: CallbackContext):
    command = update.message.text
    if command.startswith('/url '):
        url = command.split(' ', 1)[1]
        if url.startswith(('http://', 'https://')):
            update.message.reply_text("Scanning... This might take a few minutes.")
            scan_data = scan_url(url)
            update.message.reply_text(scan_data)
        else:
            update.message.reply_text("Invalid URL. Please provide a URL starting with http:// or https://")
    else:
        update.message.reply_text("Unknown command. Use /url {web url} to scan a website.")

if __name__ == '__main__':
    install_dependencies()
    main()
