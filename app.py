import asyncio
import time
import httpx
import json
import os
from collections import defaultdict
from flask import Flask, request, jsonify
from flask_cors import CORS
from cachetools import TTLCache
from typing import Tuple
from proto import FreeFire_pb2, main_pb2, AccountPersonalShow_pb2
from google.protobuf import json_format
from Crypto.Cipher import AES
import base64

# === Settings ===
MAIN_KEY = base64.b64decode('WWcmdGMlREV1aDYlWmNeOA==')
MAIN_IV = base64.b64decode('Nm95WkRyMjJFM3ljaGpNJQ==')
RELEASEVERSION = "OB54"
USERAGENT = "Dalvik/2.1.0 (Linux; U; Android 13; CPH2095 Build/RKQ1.211119.001)"
SUPPORTED_REGIONS = {"IND", "BR", "US", "SAC", "NA", "SG", "RU", "ID", "TW", "VN", "TH", "ME", "PK", "CIS", "BD", "EU"}

# === Flask App Setup ===
app = Flask(__name__)
CORS(app)
cached_tokens = defaultdict(dict)

# === Helper Functions ===
def pad(text: bytes) -> bytes:
    padding_length = AES.block_size - (len(text) % AES.block_size)
    return text + bytes([padding_length] * padding_length)

def aes_cbc_encrypt(key: bytes, iv: bytes, plaintext: bytes) -> bytes:
    aes = AES.new(key, AES.MODE_CBC, iv)
    return aes.encrypt(pad(plaintext))

def decode_protobuf(encoded_data: bytes, message_type) -> any:
    instance = message_type()
    instance.ParseFromString(encoded_data)
    return instance

async def json_to_proto(json_data: str, proto_message) -> bytes:
    json_format.ParseDict(json.loads(json_data), proto_message)
    return proto_message.SerializeToString()

def get_account_credentials(region: str) -> str:
    r = region.upper()
    # Environment variables se credentials lo
    default_uid = os.environ.get("FF_UID", "4269012488")
    default_pass = os.environ.get("FF_PASS", "MG24_GAMER_U27YB_BY_SPIDEERIO_GAMING_0PNCN")
    
    if r == "ME":
        return f"uid={default_uid}&password={default_pass}"
    elif r == "BD":
        return "uid=4270778393&password=MG24_GAMER_9NMYG_BY_SPIDEERIO_GAMING_FXK8R"
    elif r in {"BR", "US", "SAC"}:
        return f"uid={default_uid}&password={default_pass}"
    else:
        return "uid=4269013803&password=MG24_GAMER_XSBOS_BY_SPIDEERIO_GAMING_TE5NG"

# === Token Generation ===
async def get_access_token(account: str):
    url = "https://ffmconnect.live.gop.garenanow.com/oauth/guest/token/grant"
    payload = account + "&response_type=token&client_type=2&client_secret=2ee44819e9b4598845141067b281621874d0d5d7af9d8f7e00c1e54715b7d1e3&client_id=100067"
    headers = {
        'User-Agent': USERAGENT,
        'Connection': "Keep-Alive",
        'Accept-Encoding': "gzip",
        'Content-Type': "application/x-www-form-urlencoded"
    }
    async with httpx.AsyncClient(timeout=30.0) as client:
        resp = await client.post(url, data=payload, headers=headers)
        data = resp.json()
        return data.get("access_token", "0"), data.get("open_id", "0")

async def create_jwt(region: str):
    try:
        account = get_account_credentials(region)
        token_val, open_id = await get_access_token(account)
        
        body = json.dumps({
            "open_id": open_id,
            "open_id_type": "4",
            "login_token": token_val,
            "orign_platform_type": "4"
        })
        
        proto_bytes = await json_to_proto(body, FreeFire_pb2.LoginReq())
        payload = aes_cbc_encrypt(MAIN_KEY, MAIN_IV, proto_bytes)
        
        url = "https://loginbp.ggblueshark.com/MajorLogin"
        headers = {
            'User-Agent': USERAGENT,
            'Connection': "Keep-Alive",
            'Accept-Encoding': "gzip",
            'Content-Type': "application/octet-stream",
            'Expect': "100-continue",
            'X-Unity-Version': "2018.4.11f1",
            'X-GA': "v1 1",
            'ReleaseVersion': RELEASEVERSION
        }
        
        async with httpx.AsyncClient(timeout=30.0) as client:
            resp = await client.post(url, data=payload, headers=headers)
            msg = json.loads(json_format.MessageToJson(
                decode_protobuf(resp.content, FreeFire_pb2.LoginRes)
            ))
            
            cached_tokens[region] = {
                'token': f"Bearer {msg.get('token','0')}",
                'region': msg.get('lockRegion','0'),
                'server_url': msg.get('serverUrl','0'),
                'expires_at': time.time() + 25200
            }
            return True
    except Exception as e:
        print(f"Error creating JWT for {region}: {e}")
        return False

async def initialize_tokens():
    tasks = [create_jwt(r) for r in SUPPORTED_REGIONS]
    await asyncio.gather(*tasks)

async def refresh_tokens_periodically():
    while True:
        await asyncio.sleep(25200)
        await initialize_tokens()

async def get_token_info(region: str) -> Tuple[str, str, str]:
    info = cached_tokens.get(region)
    if info and time.time() < info['expires_at']:
        return info['token'], info['region'], info['server_url']
    
    await create_jwt(region)
    info = cached_tokens[region]
    return info['token'], info['region'], info['server_url']

async def GetAccountInformation(uid, unk, region, endpoint):
    try:
        # Fix: main_pb2.GetPlayerPersonalShow use karein
        payload = await json_to_proto(
            json.dumps({'a': int(uid), 'b': int(unk)}),
            main_pb2.GetPlayerPersonalShow()
        )
        data_enc = aes_cbc_encrypt(MAIN_KEY, MAIN_IV, payload)
        token, lock, server = await get_token_info(region)
        
        headers = {
            'User-Agent': USERAGENT,
            'Connection': "Keep-Alive",
            'Accept-Encoding': "gzip",
            'Content-Type': "application/octet-stream",
            'Expect': "100-continue",
            'Authorization': token,
            'X-Unity-Version': "2018.4.11f1",
            'X-GA': "v1 1",
            'ReleaseVersion': RELEASEVERSION
        }
        
        async with httpx.AsyncClient(timeout=30.0) as client:
            resp = await client.post(server + endpoint, data=data_enc, headers=headers)
            if resp.status_code == 200:
                return json.loads(json_format.MessageToJson(
                    decode_protobuf(resp.content, AccountPersonalShow_pb2.AccountPersonalShowInfo)
                ))
            else:
                print(f"API returned status: {resp.status_code} for region {region}")
                return None
    except Exception as e:
        print(f"Error in GetAccountInformation for {region}: {e}")
        return None

def format_response(data):
    if not data:
        return {}
    
    basic = data.get("basicInfo", {})
    profile = data.get("profileInfo", {})
    clan = data.get("clanBasicInfo", {})
    
    return {
        "AccountInfo": {
            "AccountAvatarId": basic.get("headPic"),
            "AccountBPBadges": basic.get("badgeCnt"),
            "AccountBPID": basic.get("badgeId"),
            "AccountBannerId": basic.get("bannerId"),
            "AccountCreateTime": basic.get("createAt"),
            "AccountEXP": basic.get("exp"),
            "AccountLastLogin": basic.get("lastLoginAt"),
            "AccountLevel": basic.get("level"),
            "AccountLikes": basic.get("liked"),
            "AccountName": basic.get("nickname"),
            "AccountRegion": basic.get("region"),
            "AccountSeasonId": basic.get("seasonId"),
            "AccountType": basic.get("accountType"),
            "BrMaxRank": basic.get("maxRank"),
            "BrRankPoint": basic.get("rankingPoints"),
            "CsMaxRank": basic.get("csMaxRank"),
            "CsRankPoint": basic.get("csRankingPoints"),
            "EquippedWeapon": basic.get("weaponSkinShows", []),
            "ReleaseVersion": basic.get("releaseVersion"),
            "ShowBrRank": basic.get("showBrRank"),
            "ShowCsRank": basic.get("showCsRank"),
            "Title": basic.get("title")
        },
        "AccountProfileInfo": {
            "EquippedOutfit": profile.get("clothes", []),
            "EquippedSkills": profile.get("equipedSkills", [])
        },
        "GuildInfo": {
            "GuildCapacity": clan.get("capacity"),
            "GuildID": str(clan.get("clanId", "")),
            "GuildLevel": clan.get("clanLevel"),
            "GuildMember": clan.get("memberNum"),
            "GuildName": clan.get("clanName"),
            "GuildOwner": str(clan.get("captainId", ""))
        },
        "captainBasicInfo": data.get("captainBasicInfo", {}),
        "creditScoreInfo": data.get("creditScoreInfo", {}),
        "petInfo": data.get("petInfo", {}),
        "socialinfo": data.get("socialInfo", {})
    }

# === API Routes ===
@app.route('/')
def home():
    return jsonify({
        "status": "Online",
        "message": "FreeFire API is running!",
        "endpoints": {
            "/get?uid=UID": "Get account information",
            "/refresh": "Refresh tokens"
        }
    })

@app.route('/get')
async def get_account_info():
    uid = request.args.get('uid')
    
    if not uid:
        return jsonify({"error": "Please provide UID."}), 400
    
    if not uid.isdigit():
        return jsonify({"error": "UID must be numeric."}), 400
    
    # Try multiple regions
    regions = ["ME", "IND", "BR", "US", "SAC"]
    
    for region in regions:
        try:
            return_data = await GetAccountInformation(
                uid,
                "7",
                region,
                "/GetPlayerPersonalShow"
            )
            
            if return_data and return_data.get("basicInfo"):
                formatted = format_response(return_data)
                return jsonify(formatted), 200
        except Exception as e:
            print(f"Region {region} failed: {e}")
            continue
    
    return jsonify({
        "error": "Invalid UID or server error. Please try again later."
    }), 500

@app.route('/refresh', methods=['GET', 'POST'])
def refresh_tokens():
    try:
        asyncio.run(initialize_tokens())
        return jsonify({
            'message': 'Tokens refreshed successfully for all regions.',
            'regions': list(cached_tokens.keys())
        }), 200
    except Exception as e:
        return jsonify({'error': f'Refresh failed: {str(e)}'}), 500

# === Startup ===
async def startup():
    print("Initializing tokens...")
    await initialize_tokens()
    print("Tokens initialized successfully!")
    asyncio.create_task(refresh_tokens_periodically())

# For Gunicorn (Production)
def create_app():
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    loop.run_until_complete(startup())
    return app

# For Local Testing (Development)
if __name__ == '__main__':
    import asyncio
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    loop.run_until_complete(startup())
    
    # Development server
    app.run(host='0.0.0.0', port=int(os.environ.get("PORT", 5000)), debug=False)