import asyncio
import json
import os
import time
from datetime import date
from os import path

import httpx
from dotenv import load_dotenv

from OAuthGenerator import OAuthGenerator

load_dotenv()

OAUTH_SECRET = os.getenv("OAUTH_SECRET")
EMAIL = os.getenv("EMAIL")
PASSWORD = os.getenv("PASSWORD")
if OAUTH_SECRET is None or EMAIL is None or PASSWORD is None:
    print("Please create a valid .env file with a OAUTH_SECRET, EMAIL and PASSWORD pair")
    exit(0)

loginUrl = 'https://discord.com/api/v8/auth/login'
totpUrl = 'https://discord.com/api/v8/auth/mfa/totp'
statusUrl = 'https://discord.com/api/v8/users/@me/settings'
token = ''


def generateStatusPayload():
    lastDay = date(date.today().year, 12, 31)
    today = date.today()
    diff = lastDay - today
    return {"custom_status": {
        # I got the emoji id from using dev mode on discord
        "text": str(diff.days) + " days left until " + str(date.today().year + 1), "emoji_id": "647643062310273024",
        "emoji_name": "blobDance"
    }
    }


async def update():
    global token

    async with httpx.AsyncClient() as client:
        payload = generateStatusPayload()
        statusResponse = await client.patch(statusUrl,
                                            data=json.dumps(payload),
                                            headers={
                                                "Content-Type": "application/json",
                                                "Authorization": token}
                                            )
        if statusResponse.status_code == 200:
            print("Successfully updated status to: " + payload["custom_status"]["text"])
            return True
        else:
            print("Failed to update status: " + statusResponse.text)
            return False


async def login():
    global token

    if path.exists('token.txt'):
        print("Found token file, checking if it is still valid")
        file = open('token.txt', "r")
        token = file.read()
        if await update():
            print("Found valid token is file")
            return True

    loginPayload = {
        "login": EMAIL, "password": PASSWORD,
        "captcha_key": None, "gift_code_sku_id": None,
        "undelete": None, "login_source": None
    }
    async with httpx.AsyncClient() as client:
        loginResponse = await client.post(loginUrl,
                                          data=json.dumps(loginPayload),
                                          headers={"Content-Type": "application/json"})
        if loginResponse.status_code == 200:
            loginJson = loginResponse.json()
            if loginJson["mfa"]:
                generator = OAuthGenerator()
                code = generator.generate_code_from_time(
                    secret_key="".join(OAUTH_SECRET.split()).upper()  # Capitalize all letters and remove spaces I think
                )[0]
                totpPayload = {
                    "code": code,
                    "ticket": loginJson["ticket"],
                    "gift_code_sku_id": None,
                    "login_source": None
                }
                totpResponse = await client.post(totpUrl,
                                                 data=json.dumps(totpPayload),
                                                 headers={"Content-Type": "application/json"})
                if totpResponse.status_code == 200:
                    token = totpResponse.json()["token"]
                    return True
                else:
                    print("Failed to authorize 2FA -> %s | %s" % (totpResponse.status_code, totpResponse.text))
            else:
                # TODO: Find out if this actually works, I have only tested with oauth
                token = loginJson["token"]
                return True
        else:
            print("Failed to login -> %s | %s" % (loginResponse.status_code, loginResponse.text))
            exit(0)
    return False


loop = asyncio.get_event_loop()
running = True


async def main():
    print('Attempting to log into discord')
    status = await login()
    if status:
        print("Successfully logged into discord, got oauth token -> %s" % token)

        file = open("token.txt", "w")
        file.write(token)
        file.close()

        while running:
            print("Updating discord status")
            await update()  # TODO: Skip this update if it was already ran as a check to login
            time.sleep(3 * 60 * 60)  # How often to update, this is 3 hours in seconds
    else:
        print("Failed to login to discord")


loop.run_until_complete(main())
