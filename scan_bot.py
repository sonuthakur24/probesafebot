import logging
import re
import time
from io import BytesIO

import nmap
from telegram import Update
from telegram.constants import ParseMode
from telegram.ext import ApplicationBuilder, CommandHandler, ContextTypes

# --- Logging ---
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# --- Bot token ---
TOKEN = "8417663559:AAG3TRppAn_2-qDGS8PBkm8jGmHX-iUt0do"

# --- Security: Set your Telegram user ID here ---
ALLOWED_USER_ID = 1478652869  # <-- Replace with your Telegram ID

# --- Nmap ---
nm = nmap.PortScanner()

# --- Validators ---
IP_REGEX = re.compile(r"^(?:\d{1,3}\.){3}\d{1,3}$")
HOST_REGEX = re.compile(r"^[a-zA-Z0-9.-]{1,253}$")

def is_valid_target(target: str) -> bool:
    target = target.strip()
    if IP_REGEX.match(target):
        parts = target.split(".")
        return all(p.isdigit() and 0 <= int(p) <= 255 for p in parts)
    return bool(HOST_REGEX.match(target))

# --- Security check ---
def is_authorized(update: Update) -> bool:
    return update.effective_user and update.effective_user.id == ALLOWED_USER_ID

# --- Rate limit ---
SCAN_COOLDOWN = 30
last_scan_time = {}

def can_scan(user_id: int) -> bool:
    now = time.time()
    last = last_scan_time.get(user_id, 0)
    if now - last >= SCAN_COOLDOWN:
        last_scan_time[user_id] = now
        return True
    return False

# --- Formatting helpers ---
def format_scan_results(nm: nmap.PortScanner) -> str:
    lines = []
    for host in nm.all_hosts():
        state = nm[host].state() if 'status' in nm[host] else "unknown"
        lines.append(f"Host: {host}  State: {state}")
        for proto in nm[host].all_protocols():
            ports = sorted(nm[host][proto].keys())
            lines.append("")
            lines.append(f"{proto.upper()} ports")
            lines.append("---------------------------------------------------------")
            lines.append(f"{'Port':<8} {'State':<10} {'Service':<18} {'Version'}")
            lines.append(f"{'-'*8} {'-'*10} {'-'*18} {'-'*20}")
            for port in ports:
                info = nm[host][proto][port]
                state = info.get('state', 'unknown')
                name = info.get('name', '') or 'unknown'
                product = info.get('product', '')
                version = info.get('version', '')
                ver = f"{product} {version}".strip()
                lines.append(f"{str(port):<8} {state:<10} {name:<18} {ver}")
        if 'osmatch' in nm[host] and nm[host]['osmatch']:
            lines.append("")
            lines.append("OS detection")
            lines.append("---------------------------------------------------------")
            for os in nm[host]['osmatch'][:3]:
                name = os.get('name', 'unknown')
                accuracy = os.get('accuracy', '0')
                lines.append(f"{name} (accuracy: {accuracy}%)")
        lines.append("")
    return "```text\n" + "\n".join(lines).strip() + "\n```"

def build_export_file(result_text: str, target: str) -> BytesIO:
    bio = BytesIO(result_text.encode("utf-8"))
    bio.name = f"scan_{target.replace('.', '_')}.txt"
    return bio

# --- Commands ---
async def whoami(update: Update, context: ContextTypes.DEFAULT_TYPE):
    uid = update.effective_user.id if update.effective_user else None
    await update.message.reply_text(f"Your Telegram ID: `{uid}`", parse_mode=ParseMode.MARKDOWN)

async def start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    msg = (
        "👋 Welcome to *ProbeSafeBot*!\n\n"
        "Available commands:\n"
        "• `/scan <target>` → Fast scan (common ports)\n"
        "• `/scanfull <target>` → Deep scan with service & OS detection\n"
        "• `/osdetect <target>` → OS fingerprinting only\n"
        "• `/ping <target>` → Host discovery (ping scan)\n"
        "• `/traceroute <target>` → Trace network path\n"
        "• `/servicedetect <target>` → Service version detection\n"
        "• `/vulnscan <target>` → Vulnerability script scan\n"
        "• `/whoami` → Show your Telegram ID\n\n"
        "⚠️ *Important:* Only authorized users can run scans.\n"
        "⏱ Rate limit: one scan every 30 seconds."
    )
    await update.message.reply_text(msg, parse_mode=ParseMode.MARKDOWN)

# --- Generic scan handler ---
async def run_scan(update: Update, context: ContextTypes.DEFAULT_TYPE, args: str, caption: str):
    if not is_authorized(update):
        await update.message.reply_text("Access denied.")
        return
    uid = update.effective_user.id
    if not can_scan(uid):
        await update.message.reply_text("Rate limit exceeded. Please wait.")
        return
    if not context.args:
        await update.message.reply_text(f"Usage: {caption} <ip_or_hostname>")
        return
    target = " ".join(context.args).strip()
    if not is_valid_target(target):
        await update.message.reply_text("Invalid target.")
        return
    try:
        nm.scan(hosts=target, arguments=args)
        if not nm.all_hosts():
            await update.message.reply_text(f"No hosts found for: {target}")
            return
        result = format_scan_results(nm)
        if len(result) > 3800:
            file_obj = build_export_file(result, target)
            await update.message.reply_document(document=file_obj, caption=f"{caption} results")
        else:
            await update.message.reply_text(result, parse_mode=ParseMode.MARKDOWN)
    except Exception as e:
        logger.exception("Scan failed.")
        await update.message.reply_text(f"Error: {str(e)}")

# --- Specific commands ---
async def scan(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await run_scan(update, context, "-T4 -F", "/scan")

async def scanfull(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await run_scan(update, context, "-T4 -A", "/scanfull")

async def osdetect(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await run_scan(update, context, "-T4 -O", "/osdetect")

async def ping(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await run_scan(update, context, "-sn", "/ping")

async def traceroute(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await run_scan(update, context, "--traceroute", "/traceroute")

async def servicedetect(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await run_scan(update, context, "-sV", "/servicedetect")

async def vulnscan(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await run_scan(update, context, "--script vuln", "/vulnscan")

# --- App setup ---
app = ApplicationBuilder().token(TOKEN).build()
app.add_handler(CommandHandler("whoami", whoami))
app.add_handler(CommandHandler("start", start))
app.add_handler(CommandHandler("scan", scan))
app.add_handler(CommandHandler("scanfull", scanfull))
app.add_handler(CommandHandler("osdetect", osdetect))
app.add_handler(CommandHandler("ping", ping))
app.add_handler(CommandHandler("traceroute", traceroute))
app.add_handler(CommandHandler("servicedetect", servicedetect))
app.add_handler(CommandHandler("vulnscan", vulnscan))

if __name__ == "__main__":
    logger.info("Bot starting with polling...")
    app.run_polling()
