import requests , os , psutil , sys , jwt , pickle , json , binascii , time , urllib3 , base64 , datetime , re , socket , threading , ssl , pytz , aiohttp , asyncio
from flask import Flask, request, jsonify
from protobuf_decoder.protobuf_decoder import Parser
from xC4 import * ; from xHeaders import *
from datetime import datetime
from google.protobuf.timestamp_pb2 import Timestamp
from concurrent.futures import ThreadPoolExecutor
from threading import Thread
from Pb2 import DEcwHisPErMsG_pb2 , MajoRLoGinrEs_pb2 , PorTs_pb2 , MajoRLoGinrEq_pb2 , sQ_pb2 , Team_msg_pb2
from cfonts import render, say

# --- কনফিগারেশন: আপনার যত খুশি আইডি এখানে অ্যাড করুন ---
BOT_ACCOUNTS = [
    {"uid": "4371478370", "pw": "JANVA_T4IVG_BY_SPIDEERIO_GAMING_HKMEZ"},
    {"uid": "4396655201", "pw": "JANVAI_M4X7P_BY_SPIDEERIO_GAMING_N31YL"},
    {"uid": "4396655200", "pw": "JANVAI_LDEKG_BY_SPIDEERIO_GAMING_GZVH5"}
]

CURRENT_BOT_INDEX = 0 
# --------------------------------------------------

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)  

online_writer = None
whisper_writer = None
app = Flask(__name__)

Hr = {
    'User-Agent': "Dalvik/2.1.0 (Linux; U; Android 11; ASUS_Z01QD Build/PI)",
    'Connection': "Keep-Alive",
    'Accept-Encoding': "gzip",
    'Content-Type': "application/x-www-form-urlencoded",
    'Expect': "100-continue",
    'X-Unity-Version': "2018.4.11f1",
    'X-GA': "v1 1",
    'ReleaseVersion': "OB51"}

async def encrypted_proto(encoded_hex):
    key = b'Yg&tc%DEuh6%Zc^8'
    iv = b'6oyZDr22E3ychjM%'
    cipher = AES.new(key, AES.MODE_CBC, iv)
    padded_message = pad(encoded_hex, AES.block_size)
    encrypted_payload = cipher.encrypt(padded_message)
    return encrypted_payload
    
async def GeNeRaTeAccEss(uid , password):
    url = "https://100067.connect.garena.com/oauth/guest/token/grant"
    data = {
        "uid": uid,
        "password": password,
        "response_type": "token",
        "client_type": "2",
        "client_secret": "2ee44819e9b4598845141067b281621874d0d5d7af9d8f7e00c1e54715b7d1e3",
        "client_id": "100067"}
    async with aiohttp.ClientSession() as session:
        async with session.post(url, headers=Hr, data=data) as response:
            if response.status != 200: return None, None
            res_data = await response.json()
            return res_data.get("open_id"), res_data.get("access_token")

async def EncRypTMajoRLoGin(open_id, access_token):
    major_login = MajoRLoGinrEq_pb2.MajorLogin()
    major_login.client_version = "1.118.1"
    major_login.open_id = open_id
    major_login.access_token = access_token
    major_login.login_open_id_type = 4
    string = major_login.SerializeToString()
    return await encrypted_proto(string)

async def MajorLogin(payload):
    url = "https://loginbp.ggblueshark.com/MajorLogin"
    ssl_context = ssl.create_default_context()
    ssl_context.check_hostname = False
    ssl_context.verify_mode = ssl.CERT_NONE
    async with aiohttp.ClientSession() as session:
        async with session.post(url, data=payload, headers=Hr, ssl=ssl_context) as response:
            if response.status == 200: return await response.read()
            return None

async def DecRypTMajoRLoGin(payload):
    key = b'Yg&tc%DEuh6%Zc^8'
    iv = b'6oyZDr22E3ychjM%'
    cipher = AES.new(key, AES.MODE_CBC, iv)
    decrypted_payload = cipher.decrypt(payload)
    unpadded_payload = unpad(decrypted_payload, AES.block_size)
    major_login_res = MajoRLoGinrEs_pb2.MajorLoginRes()
    major_login_res.ParseFromString(unpadded_payload)
    return major_login_res

async def GetLoginData(base_url, payload, token):
    url = f"{base_url}/GetLoginData"
    ssl_context = ssl.create_default_context()
    ssl_context.check_hostname = False
    ssl_context.verify_mode = ssl.CERT_NONE
    headers = Hr.copy()
    headers['Authorization'] = f"Bearer {token}"
    async with aiohttp.ClientSession() as session:
        async with session.post(url, data=payload, headers=headers, ssl=ssl_context) as response:
            if response.status == 200: return await response.read()
            return None

async def DecRypTLoGinDaTa(payload):
    key = b'Yg&tc%DEuh6%Zc^8'
    iv = b'6oyZDr22E3ychjM%'
    cipher = AES.new(key, AES.MODE_CBC, iv)
    decrypted_payload = cipher.decrypt(payload)
    unpadded_payload = unpad(decrypted_payload, AES.block_size)
    login_data_res = PorTs_pb2.GetLoginDataRes()
    login_data_res.ParseFromString(unpadded_payload)
    return login_data_res

async def xAuThSTarTuP(TarGeT, token, timestamp, key, iv):
    uid_hex = hex(TarGeT)[2:].zfill(8)
    encrypted_timestamp = await DecodE_HeX(timestamp)
    encrypted_account_token = token.encode().hex()
    encrypted_packet = await EnC_PacKeT(encrypted_account_token, key, iv)
    encrypted_packet_length = hex(len(encrypted_packet) // 2)[2:].zfill(4)
    return f"011500000000{uid_hex}{encrypted_timestamp}00000{encrypted_packet_length}{encrypted_packet}"

async def SEndPacKeT(OnLinE, ChaT, TypE, PacKeT):
    if TypE == 'ChaT' and whisper_writer:
        whisper_writer.write(bytes.fromhex(PacKeT))
        await whisper_writer.drain()
    elif TypE == 'OnLine' and online_writer:
        online_writer.write(bytes.fromhex(PacKeT))
        await online_writer.drain()

async def perform_emote(team_code: str, uids: list, emote_id: int):
    global key, iv, region, online_writer, BOT_UID
    if online_writer is None: return
    try:
        EM = await GenJoinSquadsPacket(team_code, key, iv)
        await SEndPacKeT(None, online_writer, 'OnLine', EM)
        await asyncio.sleep(0.12)
        for uid_str in uids:
            uid = int(uid_str)
            H = await Emote_k(uid, emote_id, key, iv, region)
            await SEndPacKeT(None, online_writer, 'OnLine', H)
        # লিভ কমান্ড রিমুভ করা হয়েছে যেন বট লবিতে বসে থাকে
        return True
    except: return False

@app.route('/join')
def join_team():
    global loop
    team_code = request.args.get('tc')
    uids = [request.args.get(f'uid{i}') for i in range(1, 7) if request.args.get(f'uid{i}')]
    emote_id_str = request.args.get('emote_id')
    if team_code and emote_id_str:
        asyncio.run_coroutine_threadsafe(perform_emote(team_code, uids, int(emote_id_str)), loop)
    return jsonify({"status": "Success", "bot_id": BOT_UID})

async def TcPOnLine(ip, port, key, iv, AutHToKen):
    global online_writer
    while True:
        try:
            reader, writer = await asyncio.open_connection(ip, int(port))
            online_writer = writer
            online_writer.write(bytes.fromhex(AutHToKen))
            await online_writer.drain()
            while True:
                data = await reader.read(1024)
                if not data: break
        except: pass
        await asyncio.sleep(2)

async def TcPChaT(ip, port, AutHToKen, key, iv, LoGinDaTaUncRypTinG, ready_event, region):
    global whisper_writer
    while True:
        try:
            reader, writer = await asyncio.open_connection(ip, int(port))
            whisper_writer = writer
            whisper_writer.write(bytes.fromhex(AutHToKen))
            await whisper_writer.drain()
            ready_event.set()
            while True:
                data = await reader.read(1024)
                if not data: break
        except: pass
        await asyncio.sleep(2)

async def MaiiiinE():
    global loop, key, iv, region, BOT_UID, CURRENT_BOT_INDEX
    acc = BOT_ACCOUNTS[CURRENT_BOT_INDEX]
    Uid, Pw = acc["uid"], acc["pw"]
    BOT_UID = int(Uid)
    
    open_id, access_token = await GeNeRaTeAccEss(Uid, Pw)
    if not open_id: return False
    
    try:
        PyL = await EncRypTMajoRLoGin(open_id, access_token)
        res = await MajorLogin(PyL)
        if not res: return False
        auth = await DecRypTMajoRLoGin(res)
        ToKen, TarGeT, key, iv, timestamp = auth.token, auth.account_uid, auth.key, auth.iv, auth.timestamp
        region, UrL = auth.region, auth.url
        LoGinDaTa = await GetLoginData(UrL, PyL, ToKen)
        data_dec = await DecRypTLoGinDaTa(LoGinDaTa)
        OnLineiP, OnLineporT = data_dec.Online_IP_Port.split(":")
        ChaTiP, ChaTporT = data_dec.AccountIP_Port.split(":")
        AutHToKen = await xAuThSTarTuP(int(TarGeT), ToKen, int(timestamp), key, iv)
        ready_event = asyncio.Event()
        loop = asyncio.get_running_loop()
        asyncio.create_task(TcPChaT(ChaTiP, ChaTporT, AutHToKen, key, iv, data_dec, ready_event, region))
        await ready_event.wait()
        asyncio.create_task(TcPOnLine(OnLineiP, OnLineporT, key, iv, AutHToKen))
        print(f"Bot Online: {data_dec.AccountName}")
        return True
    except: return False

async def StarTinG():
    global CURRENT_BOT_INDEX
    while True:
        try:
            success = await MaiiiinE()
            if not success:
                CURRENT_BOT_INDEX = (CURRENT_BOT_INDEX + 1) % len(BOT_ACCOUNTS)
                await asyncio.sleep(5)
                continue
            await asyncio.sleep(3600)
        except:
            CURRENT_BOT_INDEX = (CURRENT_BOT_INDEX + 1) % len(BOT_ACCOUNTS)
            await asyncio.sleep(5)

if __name__ == '__main__':
    t = threading.Thread(target=lambda: app.run(host='0.0.0.0', port=10000))
    t.daemon = True
    t.start()
    asyncio.run(StarTinG())