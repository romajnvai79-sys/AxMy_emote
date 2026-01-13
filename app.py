import requests, os, sys, time, urllib3, asyncio, threading, ssl, random, json
from flask import Flask, request, jsonify
from aiohttp import ClientSession
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

# আপনার আপলোড করা ফাইলগুলো থেকে ইমপোর্ট
from xC4 import *
from xHeaders import *
from Pb2 import DEcwHisPErMsG_pb2, MajoRLoGinrEs_pb2, PorTs_pb2, MajoRLoGinrEq_pb2, sQ_pb2

# ==========================================
# [CONFIGURATION] আপনার দেওয়া ৩টি আইডি সেট করা হলো
# ==========================================
BOT_ACCOUNTS = [
    {"uid": "4371478370", "pw": "JANVA_T4IVG_BY_SPIDEERIO_GAMING_HKMEZ"},
    {"uid": "4396655201", "pw": "JANVAI_M4X7P_BY_SPIDEERIO_GAMING_N31YL"},
    {"uid": "4396655200", "pw": "JANVAI_LDEKG_BY_SPIDEERIO_GAMING_GZVH5"}
]
# ==========================================

CURRENT_BOT_INDEX = 0
online_writer = None
whisper_writer = None
BOT_UID = None
loop = None

app = Flask(__name__)
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# --- Headers ---
Hr = {
    'User-Agent': "Dalvik/2.1.0 (Linux; U; Android 11; ASUS_Z01QD Build/PI)",
    'Connection': "Keep-Alive",
    'Accept-Encoding': "gzip",
    'Content-Type': "application/x-www-form-urlencoded",
    'X-Unity-Version': "2018.4.11f1",
    'ReleaseVersion': "OB51"
}

# --- Helper Functions ---

async def encrypted_proto(encoded_hex):
    key = b'Yg&tc%DEuh6%Zc^8'
    iv = b'6oyZDr22E3ychjM%'
    cipher = AES.new(key, AES.MODE_CBC, iv)
    padded = pad(encoded_hex, AES.block_size)
    return cipher.encrypt(padded)

async def GeNeRaTeAccEss(uid, password):
    url = "https://100067.connect.garena.com/oauth/guest/token/grant"
    data = {
        "uid": uid,
        "password": password,
        "response_type": "token",
        "client_type": "2",
        "client_id": "100067"
    }
    async with ClientSession() as session:
        try:
            async with session.post(url, headers=Hr, data=data, timeout=10) as resp:
                if resp.status != 200: return None, None
                res = await resp.json()
                return res.get("open_id"), res.get("access_token")
        except: return None, None

async def EncRypTMajoRLoGin(open_id, access_token):
    proto = MajoRLoGinrEq_pb2.MajorLogin()
    proto.client_version = "1.118.1"
    proto.open_id = open_id
    proto.access_token = access_token
    proto.login_open_id_type = 4
    return await encrypted_proto(proto.SerializeToString())

async def MajorLogin(payload):
    url = "https://loginbp.ggblueshark.com/MajorLogin"
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    async with ClientSession() as session:
        async with session.post(url, data=payload, headers=Hr, ssl=ctx) as resp:
            if resp.status == 200: return await resp.read()
            return None

async def DecRypTMajoRLoGin(payload):
    key = b'Yg&tc%DEuh6%Zc^8'
    iv = b'6oyZDr22E3ychjM%'
    cipher = AES.new(key, AES.MODE_CBC, iv)
    decrypted = unpad(cipher.decrypt(payload), AES.block_size)
    proto = MajoRLoGinrEs_pb2.MajorLoginRes()
    proto.ParseFromString(decrypted)
    return proto

async def GetLoginData(base_url, payload, token):
    url = f"{base_url}/GetLoginData"
    headers = Hr.copy()
    headers['Authorization'] = f"Bearer {token}"
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    async with ClientSession() as session:
        async with session.post(url, data=payload, headers=headers, ssl=ctx) as resp:
            if resp.status == 200: return await resp.read()
            return None

async def DecRypTLoGinDaTa(payload):
    key = b'Yg&tc%DEuh6%Zc^8'
    iv = b'6oyZDr22E3ychjM%'
    cipher = AES.new(key, AES.MODE_CBC, iv)
    decrypted = unpad(cipher.decrypt(payload), AES.block_size)
    proto = PorTs_pb2.GetLoginData()
    proto.ParseFromString(decrypted)
    return proto

async def xAuThSTarTuP(target, token, timestamp, key, iv):
    # সিম্পল অথেনটিকেশন প্যাকেট বিল্ডার
    uid_hex = hex(target)[2:]
    try:
        enc_timestamp = await DecodE_HeX(timestamp) # xC4.py থেকে
        enc_token = token.encode().hex()
        enc_packet = await EnC_PacKeT(enc_token, key, iv) # xC4.py থেকে
        length = hex(len(enc_packet) // 2)[2:]
        return f"011500000000{uid_hex}{enc_timestamp}00000{length}{enc_packet}"
    except:
        return None

# --- API & Emote Logic ---

async def perform_emote(team_code, uids, emote_id):
    global online_writer, key, iv, region
    if not online_writer: return
    try:
        # ১. জয়েন গ্রুপ
        join_pkt = await GenJoinSquadsPacket(team_code, key, iv)
        online_writer.write(bytes.fromhex(join_pkt))
        await online_writer.drain()
        await asyncio.sleep(0.2) # একটু সময় দেওয়া

        # ২. ইমোট দেওয়া
        for uid_str in uids:
            uid = int(uid_str)
            emote_pkt = await Emote_k(uid, int(emote_id), key, iv, region)
            online_writer.write(bytes.fromhex(emote_pkt))
            await online_writer.drain()
            
        # ৩. কোনো লিভ কমান্ড নেই - বট লবিতে থাকবে
    except Exception as e:
        print(f"Emote Error: {e}")

@app.route('/')
def home():
    return "Bot is Running! Use /join endpoint."

@app.route('/join')
def join_api():
    global loop
    tc = request.args.get('tc')
    # ৬টি UID পর্যন্ত সাপোর্ট
    uids = [request.args.get(f'uid{i}') for i in range(1, 7) if request.args.get(f'uid{i}')]
    eid = request.args.get('emote_id')

    if tc and eid and loop:
        asyncio.run_coroutine_threadsafe(perform_emote(tc, uids, eid), loop)
        return jsonify({"status": "Success", "bot_uid": BOT_UID})
    return jsonify({"status": "Failed", "msg": "Missing tc or emote_id"})

# --- Main Connection Logic ---

async def TcPOnLine(ip, port, token):
    global online_writer
    while True:
        try:
            reader, writer = await asyncio.open_connection(ip, int(port))
            online_writer = writer
            writer.write(bytes.fromhex(token))
            await writer.drain()
            while True:
                data = await reader.read(1024)
                if not data: break
                # এখানে ডাটা রিড করে কানেকশন ধরে রাখা হচ্ছে
        except:
            pass
        await asyncio.sleep(2) # ডিসকানেক্ট হলে রিট্রাই

async def TcPChaT(ip, port, token, ready_event):
    global whisper_writer
    while True:
        try:
            reader, writer = await asyncio.open_connection(ip, int(port))
            whisper_writer = writer
            writer.write(bytes.fromhex(token))
            await writer.drain()
            ready_event.set() # চ্যাট কানেক্ট হলে মেইন লুপ শুরু হবে
            while True:
                data = await reader.read(1024)
                if not data: break
        except:
            pass
        await asyncio.sleep(2)

async def MaiiiinE():
    global loop, key, iv, region, BOT_UID, CURRENT_BOT_INDEX
    
    acc = BOT_ACCOUNTS[CURRENT_BOT_INDEX]
    print(f"[*] Trying ID: {acc['uid']}")

    oid, token = await GeNeRaTeAccEss(acc['uid'], acc['pw'])
    if not oid: return False

    try:
        # 1. Major Login
        pyl = await EncRypTMajoRLoGin(oid, token)
        res = await MajorLogin(pyl)
        if not res: return False
        
        auth = await DecRypTMajoRLoGin(res)
        key, iv, timestamp = auth.key, auth.iv, auth.timestamp
        region, url = auth.region, auth.url
        BOT_UID = auth.account_uid

        # 2. Get Ports
        ld = await GetLoginData(url, pyl, auth.token)
        dec_ld = await DecRypTLoGinDaTa(ld)
        
        online_ip, online_port = dec_ld.Online_IP_Port.split(":")
        chat_ip, chat_port = dec_ld.AccountIP_Port.split(":")
        
        # 3. Auth Token Generation
        auth_token = await xAuThSTarTuP(int(BOT_UID), auth.token, int(timestamp), key, iv)
        if not auth_token: return False

        # 4. Connect TCP
        ready_event = asyncio.Event()
        loop = asyncio.get_running_loop()
        
        # চ্যাট এবং অনলাইন সার্ভারে আলাদা টাস্ক
        asyncio.create_task(TcPChaT(chat_ip, chat_port, auth_token, ready_event))
        await ready_event.wait()
        asyncio.create_task(TcPOnLine(online_ip, online_port, auth_token))
        
        print(f"[+] Bot Online: {dec_ld.AccountName}")
        return True

    except Exception as e:
        print(f"Error: {e}")
        return False

async def StarTinG():
    global CURRENT_BOT_INDEX
    while True:
        try:
            success = await MaiiiinE()
            if not success:
                print(f"[!] Login Failed for {BOT_ACCOUNTS[CURRENT_BOT_INDEX]['uid']}. Switching...")
                CURRENT_BOT_INDEX = (CURRENT_BOT_INDEX + 1) % len(BOT_ACCOUNTS)
                await asyncio.sleep(5)
            else:
                # কানেক্ট হলে ১ ঘণ্টা অপেক্ষা করবে, তারপর আবার চেক করবে
                await asyncio.sleep(3600)
        except:
            await asyncio.sleep(5)

def run_flask():
    # Render PORT ভ্যারিয়েবল থেকে পোর্ট নেবে, না পেলে 10000
    port = int(os.environ.get("PORT", 10000))
    app.run(host='0.0.0.0', port=port, debug=False, use_reloader=False)

if __name__ == '__main__':
    # Flask আলাদা থ্রেডে রান হবে
    t = threading.Thread(target=run_flask)
    t.daemon = True
    t.start()
    
    # মেইন বট লুপ
    asyncio.run(StarTinG())