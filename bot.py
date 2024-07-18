# bot.py
import json
import os
import whois
import requests
import dns.resolver
import builtwith
import shodan
import socket
import ssl
import subprocess
import threading
from telegram import InlineKeyboardButton, InlineKeyboardMarkup, Update
from telegram.ext import Updater, CommandHandler, CallbackQueryHandler, MessageHandler, Filters, CallbackContext
from telegram.error import BadRequest

# Replace placeholders with your actual API keys, bot token, and other details
SHODAN_API_KEY = 'YOUR_SHODAN_API_KEY'
TELEGRAM_BOT_TOKEN = 'YOUR_TELEGRAM_BOT_TOKEN'
OWNER_ID = YOUR_OWNER_ID
OWNER_USERNAME = 'YOUR_OWNER_USERNAME'

REQUIRED_GROUP = '@your_required_group'
REQUIRED_CHANNELS = ['@your_required_channel1', '@your_required_channel2']

# Initialize Shodan API
shodan_api = shodan.Shodan(SHODAN_API_KEY)

# Load or initialize user data
if not os.path.exists('users.json'):
    with open('users.json', 'w') as f:
        json.dump({}, f)

def load_user_data():
    global users
    try:
        with open('users.json', 'r') as f:
            users = json.load(f)
    except json.JSONDecodeError:
        users = {}

def save_user_data():
    with open('users.json', 'w') as f:
        json.dump(users, f)

def check_subscription(user_id, bot):
    try:
        bot.get_chat_member(REQUIRED_GROUP, user_id)
    except BadRequest as e:
        if "user not found" in str(e):
            return False
    
    for channel in REQUIRED_CHANNELS:
        try:
            bot.get_chat_member(channel, user_id)
        except BadRequest as e:
            if "user not found" in str(e):
                return False
    return True

def add_premium(update: Update, context: CallbackContext) -> None:
    if update.message.from_user.id != OWNER_ID:
        update.message.reply_text("You are not authorized to use this command.")
        return
    
    args = context.args
    if len(args) != 2:
        update.message.reply_text("Usage: /add <user_id> <searches>")
        return
    
    user_id, searches = int(args[0]), int(args[1])
    if user_id not in users:
        users[user_id] = {"searches": 0, "banned": False}
    users[user_id]["searches"] += searches
    save_user_data()
    update.message.reply_text(f"Added {searches} searches to user {user_id}.")

def remove_premium(update: Update, context: CallbackContext) -> None:
    if update.message.from_user.id != OWNER_ID:
        update.message.reply_text("You are not authorized to use this command.")
        return
    
    args = context.args
    if len(args) != 1:
        update.message.reply_text("Usage: /remove <user_id>")
        return
    
    user_id = int(args[0])
    if user_id in users:
        del users[user_id]
        save_user_data()
        update.message.reply_text(f"Removed premium status from user {user_id}.")
    else:
        update.message.reply_text(f"User {user_id} not found.")

def ban_user(update: Update, context: CallbackContext) -> None:
    if update.message.from_user.id != OWNER_ID:
        update.message.reply_text("You are not authorized to use this command.")
        return
    
    args = context.args
    if len(args) != 1:
        update.message.reply_text("Usage: /gban <user_id>")
        return
    
    user_id = int(args[0])
    if user_id not in users:
        users[user_id] = {"searches": 0, "banned": True}
    else:
        users[user_id]["banned"] = True
    save_user_data()
    update.message.reply_text(f"Banned user {user_id}.")

def broadcast(update: Update, context: CallbackContext) -> None:
    if update.message.from_user.id != OWNER_ID:
        update.message.reply_text("You are not authorized to use this command.")
        return
    
    message = ' '.join(context.args)
    for user_id in users.keys():
        context.bot.send_message(chat_id=user_id, text=message)
    update.message.reply_text("Broadcast message sent.")

def stats(update: Update, context: CallbackContext) -> None:
    if update.message.from_user.id != OWNER_ID:
        update.message.reply_text("You are not authorized to use this command.")
        return

    total_users = len(users)
    premium_users = len([u for u in users.values() if u.get("searches", 0) > 0])
    banned_users = len([u for u in users.values() if u.get("banned", False)])

    groups = [REQUIRED_GROUP] + REQUIRED_CHANNELS

    stats_message = (
        f"Total users: {total_users}\n"
        f"Premium users: {premium_users}\n"
        f"Banned users: {banned_users}\n"
        f"Groups/Channels: {', '.join(groups)}"
    )
    update.message.reply_text(stats_message)

def start(update: Update, context: CallbackContext) -> None:
    user_id = update.message.from_user.id
    if not check_subscription(user_id, context.bot):
        update.message.reply_text("Please join all the required channels/groups to use the bot.")
        return

    keyboard = [[InlineKeyboardButton("Start Scan", callback_data='start_scan')]]
    reply_markup = InlineKeyboardMarkup(keyboard)
    update.message.reply_text("Welcome to the Bot! Click the button below to start scanning.", reply_markup=reply_markup)

def start_scan(update: Update, context: CallbackContext) -> None:
    query = update.callback_query
    query.answer()

    user_id = query.from_user.id
    if not check_subscription(user_id, context.bot):
        query.edit_message_text("Please join all the required channels/groups to use the bot.")
        return

    context.user_data['scanning'] = True
    keyboard = [[InlineKeyboardButton("Cancel", callback_data='cancel_scan')]]
    reply_markup = InlineKeyboardMarkup(keyboard)
    query.edit_message_text("Please enter the URL you want to scan.", reply_markup=reply_markup)

def scan_url(update: Update, context: CallbackContext) -> None:
    if 'scanning' not in context.user_data or not context.user_data['scanning']:
        return

    user_id = update.message.from_user.id
    url = update.message.text
    context.user_data['url'] = url

    update.message.reply_text("Scanning process started. Please wait for the results.", reply_markup=InlineKeyboardMarkup([[InlineKeyboardButton("Scanning...", callback_data='scanning')]]))
    threading.Thread(target=perform_scan, args=(update.message, user_id, context.bot)).start()

def perform_scan(message, user_id, bot):
    try:
        url = message.text.split()[-1]

        domain = url.split()[-1]

        information = [
            ("WHOIS Info", get_whois_info(domain)),
            ("IP Geolocation", get_ip_geolocation(domain)),
            ("Real IP Address", get_real_ip(domain)),
            ("SSL Certificate", get_ssl_info(domain)),
            ("DNS Records", get_dns_records(domain)),
            ("HTTP Headers", get_http_headers(domain)),
            ("Web Technologies", get_web_technologies(domain)),
            ("Subdomains", find_subdomains(domain)),
        ]
        response_text = "\n\n".join([f"{title}:\n{info}" for title, info in information])
        message.reply_text(response_text + f"\n\nJoin us - {REQUIRED_GROUP}")
    except Exception as e:
        message.reply_text(f"Error during scan: {e}")

# WHOIS Info
def get_whois_info(domain):
    try:
        w = whois.whois(domain)
        return json.dumps(w, indent=2)
    except Exception as e:
        return f"Error fetching WHOIS info: {e}"

# IP Geolocation
def get_ip_geolocation(domain):
    try:
        ip = socket.gethostbyname(domain)
        response = requests.get(f"http://ip-api.com/json/{ip}")
        return json.dumps(response.json(), indent=2)
    except Exception as e:
        return f"Error fetching IP geolocation: {e}"

# Real IP Address
def get_real_ip(domain):
    try:
        ip = socket.gethostbyname(domain)
        return ip
    except Exception as e:
        return f"Error fetching real IP: {e}"

# SSL Certificate
def get_ssl_info(domain):
    try:
        cert = ssl.get_server_certificate((domain, 443))
        x509 = ssl.DER_cert_to_PEM_cert(cert.encode())
        return x509
    except Exception as e:
        return f"Error fetching SSL info: {e}"

# DNS Records
def get_dns_records(domain):
    try:
        answers = dns.resolver.resolve(domain, 'ANY')
        return "\n".join([str(rdata) for rdata in answers])
    except Exception as e:
        return f"Error fetching DNS records: {e}"

# HTTP Headers
def get_http_headers(domain):
    try:
        response = requests.get(f"http://{domain}")
        return json.dumps(dict(response.headers), indent=2)
    except Exception as e:
        return f"Error fetching HTTP headers: {e}"

# Web Technologies
def get_web_technologies(domain):
    try:
        tech = builtwith.parse(f"http://{domain}")
        return json.dumps(tech, indent=2)
    except Exception as e:
        return f"Error fetching web technologies: {e}"

# Subdomains
def find_subdomains(domain):
    try:
        result = subprocess.run(['python3', 'Sublist3r/sublist3r.py', '-d', domain, '-o', 'subdomains.txt'], capture_output=True, text=True)
        with open('subdomains.txt', 'r') as f:
            subdomains = f.read().splitlines()
        return json.dumps(subdomains, indent=2)
    except Exception as e:
        return f"Error fetching subdomains: {e}"

def button(update: Update, context: CallbackContext) -> None:
    query = update.callback_query
    query.answer()

    if query.data == 'start_scan':
        start_scan(update, context)
    elif query.data == 'cancel_scan':
        query.edit_message_text("Scanning process canceled.")
        if 'scanning' in context.user_data:
            del context.user_data['scanning']
    elif query.data == 'scanning':
        query.edit_message_text("Scanning in progress...")

def main():
    load_user_data()

    # Install Sublist3r if not already installed
    if not os.path.exists('Sublist3r'):
        subprocess.run(['git', 'clone', 'https://github.com/aboul3la/Sublist3r.git'])
        subprocess.run(['pip', 'install', '-r', 'Sublist3r/requirements.txt'])

    updater = Updater(TELEGRAM_BOT_TOKEN, use_context=True)
    dispatcher = updater.dispatcher

    dispatcher.add_handler(CommandHandler("start", start))
    dispatcher.add_handler(CommandHandler("add", add_premium))
    dispatcher.add_handler(CommandHandler("remove", remove_premium))
    dispatcher.add_handler(CommandHandler("gban", ban_user))
    dispatcher.add_handler(CommandHandler("broadcast", broadcast))
    dispatcher.add_handler(CommandHandler("stats", stats))
    dispatcher.add_handler(MessageHandler(Filters.text & Filters.regex(r'^/url '), scan_url))
    dispatcher.add_handler(MessageHandler(Filters.text & ~Filters.command, lambda update, context: None))
    dispatcher.add_handler(CallbackQueryHandler(button))

    updater.start_polling()
    updater.idle()

if __name__ == '__main__':
    main()
