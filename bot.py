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
SHODAN_API_KEY = 'YaLNvFBVpaTrMkW829nATM3xRTvMaVsH'
TELEGRAM_BOT_TOKEN = '7289883891:AAFIMGy9T9-V8iklbHc3Gl3jPE30ogMIBdY'
OWNER_ID = 5460343986
OWNER_USERNAME = '@moon_god_khonsu'

REQUIRED_GROUP = '@fakaoanl'
REQUIRED_CHANNELS = ['@found_us', '@hacking_Mathod']

users = {}

def load_user_data():
    global users
    if os.path.exists('users.json'):
        with open('users.json', 'r') as f:
            users = json.load(f)

def save_user_data():
    with open('users.json', 'w') as f:
        json.dump(users, f, indent=2)

def check_subscription(user_id, bot):
    try:
        group_status = bot.get_chat_member(REQUIRED_GROUP, user_id).status
        channels_status = [bot.get_chat_member(channel, user_id).status for channel in REQUIRED_CHANNELS]
        return all(status in ['member', 'administrator', 'creator'] for status in [group_status, *channels_status])
    except NetworkError:
        return False

def add_premium(update: Update, context: CallbackContext) -> None:
    if update.message.from_user.id != OWNER_ID:
        update.message.reply_text("You are not authorized to use this command.")
        return
    
    args = context.args
    if len(args) != 1:
        update.message.reply_text("Usage: /add <user_id>")
        return
    
    user_id = int(args[0])
    if user_id in users:
        users[user_id]["searches"] += 10
    else:
        users[user_id] = {"searches": 10, "banned": False}
    
    save_user_data()
    update.message.reply_text(f"Added premium status to user {user_id}.")

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
    if user_id in users:
        users[user_id]["banned"] = True
        save_user_data()
        update.message.reply_text(f"Banned user {user_id}.")
    else:
        users[user_id] = {"searches": 0, "banned": True}
        save_user_data()
        update.message.reply_text(f"Banned user {user_id}.")

def broadcast(update: Update, context: CallbackContext) -> None:
    if update.message.from_user.id != OWNER_ID:
        update.message.reply_text("You are not authorized to use this command.")
        return
    
    message = ' '.join(context.args)
    if not message:
        update.message.reply_text("Usage: /broadcast <message>")
        return
    
    for user_id in users:
        try:
            context.bot.send_message(chat_id=user_id, text=message)
        except Exception as e:
            print(f"Failed to send message to {user_id}: {e}")
    
    update.message.reply_text("Broadcast message sent.")

def stats(update: Update, context: CallbackContext) -> None:
    if update.message.from_user.id != OWNER_ID:
        update.message.reply_text("You are not authorized to use this command.")
        return
    
    total_users = len(users)
    premium_users = sum(1 for u in users.values() if u["searches"] > 0)
    banned_users = sum(1 for u in users.values() if u["banned"])
    
    stats_message = (f"Total users: {total_users}\n"
                     f"Premium users: {premium_users}\n"
                     f"Banned users: {banned_users}")
    
    update.message.reply_text(stats_message)

def start(update: Update, context: CallbackContext) -> None:
    user_id = update.message.from_user.id
    if user_id in users and users[user_id]["banned"]:
        update.message.reply_text("You are banned from using this bot.")
        return
    
    if not check_subscription(user_id, context.bot):
        keyboard = [
            [InlineKeyboardButton("Join Group", url=f"https://t.me/{REQUIRED_GROUP[1:]}")],
            [InlineKeyboardButton("Join Channel 1", url=f"https://t.me/{REQUIRED_CHANNELS[0][1:]}")],
            [InlineKeyboardButton("Join Channel 2", url=f"https://t.me/{REQUIRED_CHANNELS[1][1:]}")],
            [InlineKeyboardButton("Check Joined", callback_data='check_joined')]
        ]
        reply_markup = InlineKeyboardMarkup(keyboard)
        update.message.reply_text("Please join all required channels and groups before using the bot.", reply_markup=reply_markup)
        return
    
    users[user_id] = {"searches": 0, "banned": False}
    save_user_data()
    
    keyboard = [[InlineKeyboardButton("Start Scan", callback_data='start_scan')]]
    reply_markup = InlineKeyboardMarkup(keyboard)
    update.message.reply_text("Welcome! Click the button below to start a scan.", reply_markup=reply_markup)

def check_joined(update: Update, context: CallbackContext) -> None:
    query = update.callback_query
    user_id = query.from_user.id
    if check_subscription(user_id, context.bot):
        context.bot.send_message(chat_id=user_id, text="You have joined all required channels and groups. You can now use the bot.")
        start(update, context)
    else:
        query.answer()
        query.message.reply_text("Please join all required channels and groups before using the bot.")

def start_scan(update: Update, context: CallbackContext) -> None:
    query = update.callback_query
    user_id = query.from_user.id
    if user_id in users and users[user_id]["banned"]:
        query.message.reply_text("You are banned from using this bot.")
        return
    
    if not check_subscription(user_id, context.bot):
        query.message.reply_text("Please join all required channels and groups before using the bot.")
        return
    
    context.user_data['scanning'] = True
    query.message.reply_text("Please enter the URL you want to scan.")

def scan_url(update: Update, context: CallbackContext) -> None:
    user_id = update.message.from_user.id
    if user_id in users and users[user_id]["banned"]:
        update.message.reply_text("You are banned from using this bot.")
        return
    
    if 'scanning' not in context.user_data:
        update.message.reply_text("Please start a scan first by clicking the button in the /start command.")
        return
    
    context.user_data.pop('scanning', None)
    
    url = update.message.text
    domain = url.replace('http://', '').replace('https://', '').split('/')[0]
    
    # Start scanning the URL
    result = {
        "WHOIS Info": get_whois_info(domain),
        "IP Geolocation": get_ip_geolocation(domain),
        "Real IP Address": get_real_ip(domain),
        "SSL Certificate": get_ssl_info(domain),
        "DNS Records": get_dns_records(domain),
        "HTTP Headers": get_http_headers(domain),
        "Web Technologies": get_web_technologies(domain),
        "Subdomains": find_subdomains(domain)
    }
    
    message = "\n\n".join([f"{key}:\n{value}" for key, value in result.items()])
    update.message.reply_text(message + f"\n\nJoin us - {REQUIRED_GROUP}")

# Utility functions for scanning
def get_whois_info(domain):
    try:
        whois_info = whois.whois(domain)
        return json.dumps(whois_info, indent=2, default=str)
    except Exception as e:
        return f"Error fetching WHOIS info: {e}"

def get_ip_geolocation(domain):
    try:
        ip_address = socket.gethostbyname(domain)
        response = requests.get(f"https://api.shodan.io/shodan/host/{ip_address}?key={SHODAN_API_KEY}")
        return json.dumps(response.json(), indent=2)
    except Exception as e:
        return f"Error fetching IP geolocation: {e}"

def get_real_ip(domain):
    try:
        result = subprocess.run(['dig', '+short', domain], stdout=subprocess.PIPE)
        return result.stdout.decode('utf-8').strip()
    except Exception as e:
        return f"Error fetching real IP: {e}"

def get_ssl_info(domain):
    try:
        context = ssl.create_default_context()
        with socket.create_connection((domain, 443)) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                ssl_info = ssock.getpeercert()
        return json.dumps(ssl_info, indent=2)
    except Exception as e:
        return f"Error fetching SSL info: {e}"

def get_dns_records(domain):
    try:
        resolver = dns.resolver.Resolver()
        records = resolver.resolve(domain, 'A')
        return "\n".join([str(record) for record in records])
    except Exception as e:
        return f"Error fetching DNS records: {e}"

def get_http_headers(domain):
    try:
        response = requests.head(f"http://{domain}")
        return json.dumps(dict(response.headers), indent=2)
    except Exception as e:
        return f"Error fetching HTTP headers: {e}"

def get_web_technologies(domain):
    try:
        tech = builtwith.parse(f"http://{domain}")
        return json.dumps(tech, indent=2)
    except Exception as e:
        return f"Error fetching web technologies: {e}"

def find_subdomains(domain):
    try:
        result = subprocess.run(['sublist3r', '-d', domain], stdout=subprocess.PIPE)
        return result.stdout.decode('utf-8')
    except Exception as e:
        return f"Error fetching subdomains: {e}"

def button(update: Update, context: CallbackContext) -> None:
    query = update.callback_query
    query.answer()

    if query.data == 'start_scan':
        start_scan(update, context)
    elif query.data == 'check_joined':
        check_joined(update, context)

def main() -> None:
    load_user_data()
    
    updater = Updater(TELEGRAM_BOT_TOKEN)
    dispatcher = updater.dispatcher

    dispatcher.add_handler(CommandHandler("start", start))
    dispatcher.add_handler(CommandHandler("add", add_premium, pass_args=True))
    dispatcher.add_handler(CommandHandler("remove", remove_premium, pass_args=True))
    dispatcher.add_handler(CommandHandler("gban", ban_user, pass_args=True))
    dispatcher.add_handler(CommandHandler("broadcast", broadcast, pass_args=True))
    dispatcher.add_handler(CommandHandler("stats", stats))
    dispatcher.add_handler(CallbackQueryHandler(button))
    dispatcher.add_handler(MessageHandler(Filters.text & Filters.regex(r'^/url '), scan_url))

    updater.start_polling()
    updater.idle()

if __name__ == '__main__':
    main()
    
