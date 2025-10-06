# camera.py
import os
import json
import time
import uuid
import hmac
import hashlib
import requests
import cv2
from flask import Flask, Response, jsonify
from tuya_connector import TuyaOpenAPI, TUYA_LOGGER
from dotenv import load_dotenv

# =========================================
# Carrega variáveis do .env
# =========================================
load_dotenv()

# ====== CÂMERA (TuyaOpenAPI/SDK) ======
ACCESS_ID  = os.getenv("TUYA_ACCESS_ID")
ACCESS_KEY = os.getenv("TUYA_ACCESS_KEY")
API_ENDPOINT = os.getenv("TUYA_API_ENDPOINT", "https://openapi.tuyaus.com")
# Se TUYA_DEVICE_ID_CAMERA não existir, usa TUYA_DEVICE_ID por fallback:
DEVICE_ID_CAMERA = os.getenv("TUYA_DEVICE_ID_CAMERA", os.getenv("TUYA_DEVICE_ID"))

# ====== PORTÃO (HMAC direto) ======
REGION = os.getenv("TUYA_REGION", "openapi.tuyaus.com").strip()  # apenas host, sem https://
CLIENT_ID = os.getenv("TUYA_CLIENT_ID", "").strip()
CLIENT_SECRET = os.getenv("TUYA_CLIENT_SECRET", "").strip()
DEVICE_ID_GATE = os.getenv("TUYA_DEVICE_ID", "").strip()
TUYA_CODE = os.getenv("TUYA_CODE", "").strip()  # ex: switch_1
PULSE_MS = int(os.getenv("PULSE_MS", "800"))

# ====== LOG Tuya SDK ======
TUYA_LOGGER.setLevel(os.environ.get("TUYA_LOGGER_LEVEL", "INFO"))

# =========================================
# Inicializa API para a CÂMERA (alocação RTSP/HLS)
# =========================================
openapi = TuyaOpenAPI(API_ENDPOINT, ACCESS_ID, ACCESS_KEY)
try:
    if ACCESS_ID and ACCESS_KEY:
        openapi.connect()  # token interno do SDK
except Exception as e:
    print("[AVISO] Falha ao conectar TuyaOpenAPI (câmera):", e)

app = Flask(__name__)

_last_stream_resp = None
_last_stream_url = None
_last_error = None

# =========================================
# Helpers CÂMERA (MJPEG)
# =========================================
def _allocate_stream():
    """
    Aloca uma URL de stream via Tuya Cloud.
    Troque payload para {"type":"HLS"} se sua conta liberar apenas HLS.
    """
    global _last_stream_resp, _last_stream_url, _last_error
    _last_error = None
    if not DEVICE_ID_CAMERA:
        _last_error = "DEVICE_ID_CAMERA ausente (defina TUYA_DEVICE_ID_CAMERA ou TUYA_DEVICE_ID no .env)."
        return None
    try:
        payload = {"type": "RTSP"}  # mude para "HLS" se necessário
        resp = openapi.post(f"/v1.0/devices/{DEVICE_ID_CAMERA}/stream/actions/allocate", payload)
        _last_stream_resp = resp
        if not resp.get("success"):
            _last_error = f"allocate falhou: {resp}"
            return None
        result = resp.get("result") or {}
        url = result.get("url") or result.get("rtsp_url") or result.get("stream_url")
        _last_stream_url = url
        if not url:
            _last_error = f"allocate sem URL utilizável: {resp}"
        return url
    except Exception as e:
        _last_error = f"excecao no allocate: {e}"
        return None

def _as_mjpeg_error(msg: str):
    chunk = (f"ERRO: {msg}\n").encode("utf-8")
    return (b'--frame\r\n'
            b'Content-Type: text/plain\r\n\r\n' + chunk + b'\r\n')

def generate_frames(stream_url: str):
    """
    Converte RTSP -> MJPEG (multipart/x-mixed-replace) para <img>.
    """
    cap = None
    try:
        cap = cv2.VideoCapture(stream_url, cv2.CAP_FFMPEG)
        cap.set(cv2.CAP_PROP_BUFFERSIZE, 1)

        if not cap.isOpened():
            yield _as_mjpeg_error("Nao foi possivel abrir o RTSP com OpenCV.")
            return

        ok, frame = cap.read()
        if not ok or frame is None:
            yield _as_mjpeg_error("Stream aberto, mas nenhum frame foi recebido.")
            return

        ok, buf = cv2.imencode('.jpg', frame)
        if ok:
            yield (b'--frame\r\nContent-Type: image/jpeg\r\n\r\n' + buf.tobytes() + b'\r\n')

        while True:
            ok, frame = cap.read()
            if not ok or frame is None:
                yield _as_mjpeg_error("Perda de frame... tentando continuar.")
                time.sleep(0.3)
                continue
            ok, buf = cv2.imencode('.jpg', frame)
            if not ok:
                yield _as_mjpeg_error("Falha ao codificar JPEG.")
                continue
            yield (b'--frame\r\nContent-Type: image/jpeg\r\n\r\n' + buf.tobytes() + b'\r\n')
    except Exception as e:
        yield _as_mjpeg_error(f"Excecao no gerador: {e}")
    finally:
        if cap is not None and cap.isOpened():
            cap.release()

# =========================================
# Rotas CÂMERA
# =========================================
@app.route('/video_feed')
def video_feed():
    url = _allocate_stream()
    if not url:
        def err_stream():
            yield _as_mjpeg_error(_last_error or "Falha desconhecida.")
        return Response(err_stream(), mimetype='multipart/x-mixed-replace; boundary=frame')
    return Response(generate_frames(url), mimetype='multipart/x-mixed-replace; boundary=frame')

@app.route('/debug_stream')
def debug_stream():
    return jsonify({
        "last_error": _last_error,
        "last_stream_url": _last_stream_url,
        "last_stream_resp": _last_stream_resp
    })

# =========================================
# Helpers PORTÃO (HMAC)
# =========================================
EMPTY_BODY_SHA256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

def now_ms() -> str:
    return str(int(time.time() * 1000))

def hmac_upper(msg: str, secret: str) -> str:
    mac = hmac.new(secret.encode('utf-8'), msg.encode('utf-8'), hashlib.sha256)
    return mac.hexdigest().upper()

def build_string_to_sign(method: str, content_sha256: str, headers_block: str, path_with_query: str) -> str:
    return f"{method}\n{content_sha256}\n{headers_block}\n{path_with_query}"

def get_token_hmac() -> str:
    if not (CLIENT_ID and CLIENT_SECRET):
        raise RuntimeError("CLIENT_ID/CLIENT_SECRET ausentes (ver .env).")
    path = "/v1.0/token?grant_type=1"
    url = f"https://{REGION}{path}"
    t = now_ms()
    nonce = uuid.uuid4().hex
    string_to_sign = build_string_to_sign("GET", EMPTY_BODY_SHA256, "", path)
    sign_src = CLIENT_ID + t + nonce + string_to_sign
    sign = hmac_upper(sign_src, CLIENT_SECRET)
    headers = {
        "client_id": CLIENT_ID,
        "t": t,
        "nonce": nonce,
        "sign_method": "HMAC-SHA256",
        "sign": sign,
        "User-Agent": "camera-gate/1.0"
    }
    r = requests.get(url, headers=headers, timeout=15)
    r.raise_for_status()
    data = r.json()
    if not data.get("success"):
        raise RuntimeError("Falha ao obter token: " + str(data))
    return data["result"]["access_token"]

def send_command_hmac(access_token: str, commands: list) -> dict:
    if not DEVICE_ID_GATE:
        raise RuntimeError("TUYA_DEVICE_ID ausente no .env para o portao.")
    body = {"commands": commands}
    body_json = json.dumps(body, separators=(',',':'))
    content_sha = hashlib.sha256(body_json.encode('utf-8')).hexdigest()
    path = f"/v1.0/iot-03/devices/{DEVICE_ID_GATE}/commands"
    url = f"https://{REGION}{path}"

    t = now_ms()
    nonce = uuid.uuid4().hex
    string_to_sign = build_string_to_sign("POST", content_sha, "", path)
    sign_src = CLIENT_ID + access_token + t + nonce + string_to_sign
    sign = hmac_upper(sign_src, CLIENT_SECRET)

    headers = {
        "client_id": CLIENT_ID,
        "access_token": access_token,
        "t": t,
        "nonce": nonce,
        "sign_method": "HMAC-SHA256",
        "sign": sign,
        "Content-Type": "application/json",
        "User-Agent": "camera-gate/1.0"
    }

    r = requests.post(url, data=body_json.encode('utf-8'), headers=headers, timeout=15)
    try:
        r.raise_for_status()
    except requests.HTTPError:
        print("Erro HTTP ao enviar comando:", r.status_code, r.text)
        raise
    return r.json()

def pulse_gate():
    """
    Envia ON -> aguarda PULSE_MS -> OFF (pulso no relé do portão).
    """
    if not TUYA_CODE:
        raise RuntimeError("TUYA_CODE ausente no .env (ex: switch_1).")
    token = get_token_hmac()
    resp_on = send_command_hmac(token, [{"code": TUYA_CODE, "value": True}])
    time.sleep(PULSE_MS / 1000.0)
    resp_off = send_command_hmac(token, [{"code": TUYA_CODE, "value": False}])
    return resp_on, resp_off

# =========================================
# Rotas PORTÃO
# =========================================
@app.route('/gate/pulse', methods=['POST'])
def gate_pulse():
    """
    Chame via fetch POST para acionar o portão.
    Responde JSON com os retornos ON/OFF.
    """
    try:
        resp_on, resp_off = pulse_gate()
        return jsonify({"ok": True, "on": resp_on, "off": resp_off})
    except requests.HTTPError as e:
        return jsonify({"ok": False, "error": f"HTTP {e.response.status_code}", "body": e.response.text}), 500
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500

@app.route('/')
def index():
    return f"""
    <!DOCTYPE html>
    <html>
    <head>
        <meta charset="utf-8"/>
        <title>Tuya Camera + Portão</title>
        <style>
            :root {{
                --gap: 24px;
                --radius: 12px;
                --card-shadow: 0 2px 8px rgba(0,0,0,.05);
            }}
            * {{ box-sizing: border-box; }}
            body{{font-family:system-ui,Segoe UI,Arial;margin:24px}}
            .row{{display:flex;gap:var(--gap);align-items:flex-start;flex-wrap:wrap}}
            .card{{border:1px solid #ddd;border-radius:var(--radius);padding:16px;box-shadow:var(--card-shadow);background:#fff}}
            .card.live{{flex: 1 1 100%;}} /* câmera ocupa toda a linha */
            .card.gate{{flex: 1 1 360px;max-width: 520px;}} /* portão ao lado/abaixo conforme espaço */

            .toolbar{{display:flex;gap:10px;margin-bottom:10px;align-items:center;flex-wrap:wrap}}
            button{{padding:10px 16px;border-radius:10px;border:1px solid #888;cursor:pointer;background:#fafafa}}
            button:disabled{{opacity:.5;cursor:not-allowed}}
            #status{{margin-top:8px;font-family:Consolas,monospace;white-space:pre-wrap}}

            /* Caixa do vídeo grandona */
            .video-box{{position:relative;width:100%;}}
            /* O truque pra “aumentar a tela” está aqui: usa quase toda a altura da janela */
            .video-box img{{
                display:block;
                width:100%;
                height:auto;
                max-height:85vh; /* <<< aumenta/diminui aqui se quiser */
                background:#000;
                border:1px solid #ccc;
                border-radius:var(--radius);
                object-fit:contain;
            }}

            .hint{{color:#555}}
        </style>
    </head>
    <body>
        <h1>Câmera Tuya - Visualização em tempo real</h1>

        <div class="row">
            <div class="card live">
                <div class="toolbar">
                    <div class="hint">
                        Se não aparecer, veja <a href="/debug_stream" target="_blank">/debug_stream</a>.
                    </div>
                    <button onclick="toggleFull()">⛶ Tela cheia</button>
                </div>
                <div id="liveBox" class="video-box">
                    <img id="liveImg" src="/video_feed" alt="Tuya Camera Stream">
                </div>
            </div>

            <div class="card gate">
                <h3>Portão</h3>
                <p>Dispositivo: <b>{DEVICE_ID_GATE or '(defina TUYA_DEVICE_ID no .env)'}</b><br>
                   Code: <b>{TUYA_CODE or '(defina TUYA_CODE no .env)'}</b><br>
                   Pulso: <b>{PULSE_MS} ms</b></p>
                <button id="btn" onclick="abrir()">🔓 Abrir portão</button>
                <div id="status" class="hint"></div>
            </div>
        </div>

        <script>
        // Tela cheia do container da camera
        function toggleFull(){{
            const box = document.getElementById('liveBox');
            if (!document.fullscreenElement){{
                if (box.requestFullscreen) box.requestFullscreen();
            }} else {{
                if (document.exitFullscreen) document.exitFullscreen();
            }}
        }}

        async function abrir() {{
            const btn = document.getElementById('btn');
            const status = document.getElementById('status');
            btn.disabled = true;
            status.textContent = "Acionando portão...";
            try {{
                const r = await fetch('/gate/pulse', {{
                    method: 'POST',
                    headers: {{'Content-Type':'application/json'}},
                    body: JSON.stringify({{}})
                }});
                const data = await r.json();
                if (!r.ok || !data.ok) {{
                    status.textContent = "Falha: " + (data.error || r.statusText);
                }} else {{
                    status.textContent = "OK!\\nON: " + JSON.stringify(data.on) + "\\nOFF: " + JSON.stringify(data.off);
                }}
            }} catch (e) {{
                status.textContent = "Erro de rede: " + e;
            }} finally {{
                setTimeout(() => {{ btn.disabled = false; }}, 1500);
            }}
        }}
        </script>
    </body>
    </html>
    """

# =========================================
# Healthcheck
# =========================================
@app.route('/health')
def health():
    return "ok"

# =========================================
# Main
# =========================================
if __name__ == '__main__':
    # threaded=True mantém o stream fluido e o botão responsivo
    app.run(host='0.0.0.0', port=5000, debug=True, threaded=True)
