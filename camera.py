import os
import json
import time
import uuid
import hmac
import hashlib
import base64
import requests
import cv2
import datetime
import getpass

from functools import wraps
from urllib.parse import quote_plus
from flask import Flask, Response, jsonify, request, redirect, url_for, render_template, session, flash
from tuya_connector import TuyaOpenAPI, TUYA_LOGGER
from dotenv import load_dotenv

from flask_bcrypt import Bcrypt
import jwt

from sqlalchemy import create_engine, Column, Integer, String
from sqlalchemy.orm import sessionmaker, declarative_base, scoped_session

# CONFIGURAÇÃO INICIAL
load_dotenv()
app = Flask(__name__)
app.secret_key = os.getenv("SECRET_KEY", "sua-chave-secreta-muito-forte")
bcrypt = Bcrypt(app)

# CONFIGURAÇÃO DO BANCO DE DADOS
def _build_engine_from_env():
    host, name, user, pwd, port = (
        os.getenv("DB_HOST"), os.getenv("DB_NAME", "defaultdb"),
        os.getenv("DB_USER"), os.getenv("DB_PASSWORD", ""), os.getenv("DB_PORT", "3306"),
    )
    if not all([host, name, user, pwd, port]):
        raise RuntimeError("Defina: DB_HOST, DB_NAME, DB_USER, DB_PASSWORD e DB_PORT.")
    db_url = f"mysql+mysqlconnector://{quote_plus(user)}:{quote_plus(pwd)}@{host}:{port}/{name}"
    engine = create_engine(db_url, pool_pre_ping=True)
    return engine

engine = _build_engine_from_env()
SessionLocal = scoped_session(sessionmaker(bind=engine, autocommit=False, autoflush=False))
Base = declarative_base()

class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True)
    email = Column(String(255), unique=True, nullable=False)
    password_hash = Column(String(255), nullable=False)

Base.metadata.create_all(bind=engine)

# CONFIGURAÇÃO DA TUYA
ACCESS_ID, ACCESS_KEY, API_ENDPOINT, DEVICE_ID_CAMERA = (
    os.getenv("TUYA_ACCESS_ID"), os.getenv("TUYA_ACCESS_KEY"),
    os.getenv("TUYA_API_ENDPOINT", "https://openapi.tuyaus.com"),
    os.getenv("TUYA_DEVICE_ID_CAMERA", os.getenv("TUYA_DEVICE_ID")),
)
REGION, CLIENT_ID, CLIENT_SECRET, DEVICE_ID_GATE, TUYA_CODE, PULSE_MS = (
    os.getenv("TUYA_REGION", "openapi.tuyaus.com").strip(),
    os.getenv("TUYA_CLIENT_ID", "").strip(), os.getenv("TUYA_CLIENT_SECRET", "").strip(),
    os.getenv("TUYA_DEVICE_ID", "").strip(), os.getenv("TUYA_CODE", "").strip(),
    int(os.getenv("PULSE_MS", "800")),
)
openapi = TuyaOpenAPI(API_ENDPOINT, ACCESS_ID, ACCESS_KEY)
if ACCESS_ID and ACCESS_KEY: openapi.connect()

# FUNÇÕES AUXILIARES
_last_stream_resp, _last_stream_url, _last_error = None, None, None
def _allocate_stream():
    global _last_stream_resp, _last_stream_url, _last_error; _last_error = None
    if not DEVICE_ID_CAMERA: _last_error = "DEVICE_ID_CAMERA não definido no .env"; return None
    try:
        resp = openapi.post(f"/v1.0/devices/{DEVICE_ID_CAMERA}/stream/actions/allocate", {"type": "RTSP"})
        _last_stream_resp = resp
        if not resp.get("success"): _last_error = f"allocate falhou: {resp}"; return None
        url = resp.get("result", {}).get("url"); _last_stream_url = url
        if not url: _last_error = f"allocate sem URL: {resp}"
        return url
    except Exception as e: _last_error = f"exceção no allocate: {e}"; return None

def _as_mjpeg_error(msg: str): return (b'--frame\r\n' b'Content-Type: text/plain\r\n\r\n' + (f"ERRO: {msg}\n").encode("utf-8") + b'\r\n')
def generate_frames(stream_url: str):
    cap = cv2.VideoCapture(stream_url, cv2.CAP_FFMPEG)
    if not cap.isOpened(): yield _as_mjpeg_error("Não foi possível abrir o RTSP."); return
    while True:
        ok, frame = cap.read()
        if not ok or frame is None: time.sleep(0.3); continue
        ok, buf = cv2.imencode('.jpg', frame)
        if ok: yield (b'--frame\r\nContent-Type: image/jpeg\r\n\r\n' + buf.tobytes() + b'\r\n')
    cap.release()

EMPTY_BODY_SHA256, _cached_hmac_token, _token_expires_at = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", None, 0
def now_ms(): return str(int(time.time() * 1000))
def hmac_upper(msg, secret): return hmac.new(secret.encode(), msg.encode(), hashlib.sha256).hexdigest().upper()
def build_string_to_sign(method, content_sha256, headers_block, path): return f"{method}\n{content_sha256}\n{headers_block}\n{path}"
def get_token_hmac():
    global _cached_hmac_token, _token_expires_at
    if _cached_hmac_token and time.time() < (_token_expires_at - 60): return _cached_hmac_token
    path, url = "/v1.0/token?grant_type=1", f"https://{REGION}{path}"
    t, nonce = now_ms(), uuid.uuid4().hex
    string_to_sign = build_string_to_sign("GET", EMPTY_BODY_SHA256, "", path)
    sign = hmac_upper(CLIENT_ID + t + nonce + string_to_sign, CLIENT_SECRET)
    headers = {"client_id": CLIENT_ID, "t": t, "nonce": nonce, "sign_method": "HMAC-SHA256", "sign": sign}
    r = requests.get(url, headers=headers); r.raise_for_status(); data = r.json()
    result = data["result"]; _cached_hmac_token = result["access_token"]; _token_expires_at = time.time() + result["expire_time"]
    return _cached_hmac_token

def send_command_hmac(token, cmds):
    path = f"/v1.0/iot-03/devices/{DEVICE_ID_GATE}/commands"
    url, body_json = f"https://{REGION}{path}", json.dumps({"commands": cmds}, separators=(',', ':'))
    content_sha = hashlib.sha256(body_json.encode()).hexdigest()
    t, nonce = now_ms(), uuid.uuid4().hex
    string_to_sign = build_string_to_sign("POST", content_sha, "", path)
    sign = hmac_upper(CLIENT_ID + token + t + nonce + string_to_sign, CLIENT_SECRET)
    headers = {"client_id": CLIENT_ID, "access_token": token, "t": t, "nonce": nonce, "sign_method": "HMAC-SHA256", "sign": sign, "Content-Type": "application/json"}
    r = requests.post(url, data=body_json.encode(), headers=headers); r.raise_for_status(); return r.json()

def pulse_gate():
    token = get_token_hmac()
    resp_on = send_command_hmac(token, [{"code": TUYA_CODE, "value": True}])
    time.sleep(PULSE_MS / 1000.0)
    resp_off = send_command_hmac(token, [{"code": TUYA_CODE, "value": False}])
    return resp_on, resp_off

# DECORATORS DE AUTENTICAÇÃO
def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
        if 'Authorization' in request.headers:
            try: token = request.headers['Authorization'].split(" ")[1]
            except IndexError: return jsonify({'message': 'Formato do token inválido!'}), 401
        if not token: return jsonify({'message': 'Token não encontrado!'}), 401
        try:
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=["HS256"])
            db = SessionLocal(); user = db.query(User).filter_by(id=data['user_id']).first(); db.close()
            if not user: raise Exception()
        except Exception: return jsonify({'message': 'Token inválido ou expirado!'}), 401
        return f(user, *args, **kwargs)
    return decorated

def login_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if not session.get("user_id"): return redirect(url_for("login", next=request.path))
        return f(*args, **kwargs)
    return wrapper

# API ENDPOINTS
@app.route('/api/register', methods=['POST'])
def register():
    data = request.get_json()
    if not data or not data.get('email') or not data.get('password'): return jsonify({'message': 'Email e senha são obrigatórios'}), 400
    db = SessionLocal()
    if db.query(User).filter_by(email=data['email']).first(): db.close(); return jsonify({'message': 'Usuário já existe'}), 409
    hashed_password = bcrypt.generate_password_hash(data['password']).decode('utf-8')
    new_user = User(email=data['email'], password_hash=hashed_password)
    db.add(new_user); db.commit(); db.close()
    return jsonify({'message': 'Novo usuário criado!'}), 201

@app.route('/api/login', methods=['POST'])
def api_login():
    auth = request.get_json()
    if not auth or not auth.get('email') or not auth.get('password'): return jsonify({'message': 'Login requer email e senha'}), 401
    db = SessionLocal(); user = db.query(User).filter_by(email=auth['email']).first(); db.close()
    if not user or not bcrypt.check_password_hash(user.password_hash, auth['password']): return jsonify({'message': 'Credenciais inválidas!'}), 401
    token = jwt.encode({'user_id': user.id, 'exp': datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(hours=24)}, app.config['SECRET_KEY'], algorithm="HS256")
    return jsonify({'token': token})

@app.route('/api/camera/stream_url', methods=['GET'])
@token_required
def get_camera_stream_url(current_user):
    url = _allocate_stream()
    if not url: return jsonify({'ok': False, 'error': _last_error or "Falha"}), 500
    return jsonify({'ok': True, 'stream_url': url})

@app.route('/api/gate/pulse', methods=['POST'])
@token_required
def gate_pulse_api(current_user):
    try:
        resp_on, resp_off = pulse_gate()
        return jsonify({"ok": True, "on_response": resp_on, "off_response": resp_off})
    except Exception as e: return jsonify({"ok": False, "error": str(e)}), 500

# WEB APP ROUTES
@app.route("/")
def index():
    if session.get("user_id"): return redirect(url_for("app_home"))
    return redirect(url_for("login"))

@app.route("/login", methods=["GET", "POST"])
def login():
    if session.get("user_id"): return redirect(url_for("app_home"))
    error = None
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "").strip()
        db = SessionLocal()
        try:
            user = db.query(User).filter_by(email=email).first()
            login_success = False
            if user:
                is_hashed = user.password_hash.startswith(('$2a$', '$2b$', '$2y$'))
                if is_hashed:
                    if bcrypt.check_password_hash(user.password_hash, password):
                        login_success = True
                else:
                    if user.password_hash == password:
                        login_success = True
                        print(f"Atualizando senha para o usuário: {user.email}")
                        new_hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
                        user.password_hash = new_hashed_password
                        db.commit()
            if login_success:
                session["user_id"] = user.id
                db.close()
                return redirect(request.args.get("next") or url_for("app_home"))
            else:
                error = "Credenciais inválidas."
        finally:
            if db.is_active: db.close()
    return render_template("login.html", error=error)

@app.route('/app')
@login_required
def app_home(): return render_template("app.html", device_id_gate=DEVICE_ID_GATE, tuya_code=TUYA_CODE, pulse_ms=PULSE_MS)

@app.route('/video_feed')
@login_required
def video_feed():
    url = _allocate_stream()
    if not url: return Response(_as_mjpeg_error(_last_error or "Falha"), mimetype='multipart/x-mixed-replace; boundary=frame')
    return Response(generate_frames(url), mimetype='multipart/x-mixed-replace; boundary=frame')

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True, threaded=True)
