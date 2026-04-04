

import sys
sys.stdout.reconfigure(encoding='utf-8')
print("importing libraries...")

from http.server import BaseHTTPRequestHandler, HTTPServer
import traceback
from urllib.parse import urlparse
from urllib.parse import parse_qs
import ngrok
import time
from datetime import datetime, timezone, timedelta
import json
from config import Config
from interfaces import AttackLLMInterface


def load_model(model_name, hf_token) -> AttackLLMInterface:
    if model_name == "FAKE":
        from model_versions.simulator.model import SimulateModel
        model = SimulateModel(hf_token, load_immediately=True)
    elif model_name == "GEMMA_2B":
        from model_versions.gemma2_2b.model import Gemma2_2B
        model = Gemma2_2B(hf_token, load_immediately=True)
    else:
        print(f"Model {model_name} not found.")
        exit(1)
    return model


def generate_response(model: AttackLLMInterface, data: dict) -> str:
    prompt = data.get("prompt", None)
    if prompt is None:
        return "Error: No prompt provided."
    response = model.generate(
        prompt=prompt,
        max_new_tokens=data.get("max_new_tokens", 128),
        temperature=data.get("temperature", 0.7),
        adapter_name=data.get("adapter_name", "")
    )
    return response


def build_prompt(model: AttackLLMInterface, data: dict) -> str:
    success, prompt = model.build_prompt(data)
    return prompt


def generate_payload(model: AttackLLMInterface, data: dict) -> str:
    return model.generate_payload(data)



class LLMServer(BaseHTTPRequestHandler):
    def now(self):
        return datetime.now(timezone(timedelta(hours=7))).strftime("%Y-%m-%d %H:%M:%S")
    def log_message(self, format, *args):
        return
    def do_POST(self):
        try:
            # Đọc dữ liệu truyền đến trong body request
            content_len = int(self.headers.get("Content-Length"))
            parsed_url = urlparse(self.path)
            params = parse_qs(parsed_url.query)
            post_body = self.rfile.read(content_len).decode("utf-8")
            data = json.loads(post_body)
            
            action = params.get("action", [None])[0]
            print(f"[{self.now()}] - {self.command} : '{self.path}'")
            print(f"[{self.now()}] - Action: {action}...")
            
            if action == "generate":
                response = generate_response(model, data)
            elif action == "build_prompt":
                response = build_prompt(model, data)
            elif action == "generate_payload":
                response = generate_payload(model, data)
            else:
                response = f"Error: Unknown action '{action}'"
            print(f"[{self.now()}] - Response:")
            print("\t" + response.replace("\n", "\n\t"))
            
            # Phản hồi
            self.send_response(200)
            self.end_headers()
            self.wfile.write(response.encode("utf-8"))
        except Exception as e:
            tb = traceback.format_exc()
            print("Trace : " + tb)
            self.send_error(500, str(e))


if __name__ == "__main__":
    print("Config model name :", Config.MODEL_NAME)
    # Load HF token from command line argument or file
    if len(sys.argv) >= 2:
        Config.HF_TOKEN = sys.argv[1]
        with open("hf_token.txt", "w") as f:
            f.write(Config.HF_TOKEN)
    else:
        with open("hf_token.txt", "r") as f:
            Config.HF_TOKEN = f.read().strip()
    
    # Validate HF token
    if not Config.HF_TOKEN:
        print("HF_TOKEN not provided.")
        exit(1)
    
    model = load_model(Config.MODEL_NAME, Config.HF_TOKEN)
    httpd = HTTPServer((Config.HOST_NAME, Config.PORT), LLMServer)
    ngrok.set_auth_token(Config.NGROK_AUTHTOKEN)
    listener = ngrok.forward(addr=f"{Config.HOST_NAME}:{Config.PORT}", domain=Config.NGROK_DOMAIN)
    ADDRESS = listener.url()
    print(f"NGROK FORWARD ADDRESS : {ADDRESS}")

    # Start HTTPServer
    print(time.asctime(), "Start Server - %s:%s" % (Config.HOST_NAME, Config.PORT))
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    httpd.server_close()
    print(time.asctime(), "Stop Server - %s:%s" % (Config.HOST_NAME, Config.PORT))
