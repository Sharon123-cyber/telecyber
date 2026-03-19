import asyncio
import requests
from telethon import TelegramClient, events
from telethon.sessions import StringSession

import os
from dotenv import load_dotenv

load_dotenv()

# Telegram
api_id = int(os.getenv("API_ID"))
api_hash = os.getenv("API_HASH")
channel_name = "TeleCyber"

# Supabase
supabase_url = os.getenv("SUPABASE_URL")
supabase_key = os.getenv("SUPABASE_KEY")

REST_URL = f"{supabase_url}/rest/v1/POSTS"

headers = {
    "apikey": supabase_key,
    "Authorization": f"Bearer {supabase_key}",
    "Content-Type": "application/json",
    "Prefer": "return=representation",
}

session = os.getenv("SESSION")
client = TelegramClient(StringSession(session), api_id, api_hash)

@client.on(events.NewMessage(chats=channel_name))
async def handler(event):
    text = event.message.text or ""

    print("New message:", text)

    data = {
        "source_name": "TeleCyber",
        "message_text": text,
        "attack_type": "unknown",
        "target_entity": "",
        "sector": "",
        "posted_at": str(event.message.date),
    }

    r = requests.post(REST_URL, json=data, headers=headers, timeout=20)
    print("Status:", r.status_code)
    print(r.text)

async def main():
    await client.start()
    print("Listening for new messages in TeleCyber...")
    await client.run_until_disconnected()

asyncio.run(main())
