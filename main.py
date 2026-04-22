

import sys
sys.stdout.reconfigure(encoding='utf-8')
print("importing libraries...")

import traceback
import ngrok
import json
import threading
import os
from config import Config
from datetime import datetime, timezone, timedelta
from llm.interfaces import AttackLLMInterface
from rag.rag_service import get_rag_service
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse
from urllib.parse import parse_qs


def generate_response(model: AttackLLMInterface, data: dict) -> str:
    prompt = data.get("prompt", None)
    if prompt is None:
        return "Error: No prompt provided."
    response = model.generate(
        prompt=prompt,
        max_new_tokens=data.get("max_new_tokens", 128),
        temperature=data.get("temperature", 0.7),
        adapter_name=data.get("adapter_name", ""),
    )
    return response

def build_prompt(model: AttackLLMInterface, data: dict) -> str:
    success, prompt = model.build_prompt(data)
    return prompt

def generate_payload(model: AttackLLMInterface, data: dict) -> str:
    return model.generate_payload(data)

def rag_retrieve(data: dict) -> str:
    try:
        # Import tại chỗ để tránh circular dependency khi server start
        from rag.rag_service import get_relevant_context

        attack_type = data.get("attack_type", "")
        waf_name = data.get("waf_name", {})
        bypassed_payloads = data.get("bypassed_payloads", [])
        initial_k = data.get("initial_k", 10)
        final_k = data.get("final_k", 3)
        filter_rules_only = data.get("filter_rules_only", False)

        result = get_relevant_context(
            attack_type=attack_type,
            waf_name=waf_name,
            bypassed_payloads=bypassed_payloads,
            initial_k=initial_k,
            final_k=final_k,
            filter_rules_only=filter_rules_only
        )
        return json.dumps(result, indent=4, ensure_ascii=False)
    except Exception as e:
        return json.dumps({
            "type": "error",
            "message": str(e)
        }, indent=4, ensure_ascii=False)


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
            data = {}
            try:
                data = json.loads(post_body)
            except json.JSONDecodeError:
                pass
            for key in params:
                if key not in data:
                    data[key] = params[key][0] if len(params[key]) == 1 else params[key]
            
            action = data.get("action", None)
            print(f"[{self.now()}] - {self.command} : '{self.path}'")
            print(f"[{self.now()}] - Action: {action}...")
            print(json.dumps(data, indent=4, ensure_ascii=False))
            
            if action == "generate":
                response = generate_response(Config.MODEL, data)
            elif action == "build_prompt":
                response = build_prompt(Config.MODEL, data)
            elif action == "generate_payload":
                response = generate_payload(Config.MODEL, data)
            elif action == "rag_retrieve":
                response = rag_retrieve(data)
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


def load_HF_token():
    """Load HF token to Config"""
    # Load HF token from command line argument or file
    hf_token = None
    if len(sys.argv) >= 2:
        hf_token = sys.argv[1]
        with open("hf_token.txt", "w") as f:
            f.write(hf_token)
    else:
        with open("hf_token.txt", "r") as f:
            hf_token = f.read().strip()
    # Validate HF token
    if not hf_token:
        print("HF_TOKEN not provided.")
        exit(1)
    return hf_token


def load_model(hf_token, model_name) -> AttackLLMInterface:
    
    model = Config.MODEL_LOADERS[model_name](hf_token, load_immediately=True)
    return model


def main():
    try:
        print("python main.py [HF_TOKEN] [MODEL_NAME] [ENABLE_RAG:y/n]")
        # Select model
        if len(sys.argv) >= 3:
            model_name = sys.argv[2]
            print(f"Using model from command line argument: {model_name}")
        else:
            print(f"Available models:", list(Config.MODEL_LOADERS.keys()))
            print("Enter model name: ", end="")
            model_name = input().strip()
        if model_name not in Config.MODEL_LOADERS:
            print(f"Model {model_name} not found.")
            exit(1)
        
        if len(sys.argv) >= 4:
            enable_rag = sys.argv[3].strip().lower() in ["yes", "y", "true", "1"]
            print(f"Enable RAG: {enable_rag} (from command line argument)")
        else:
            enable_rag = input("Enable RAG? (yes/no): ").strip().lower() in ["yes", "y", "true", "1"]
        
        
        # Load HF token
        Config.HF_TOKEN = load_HF_token()
        Config.MODEL = load_model(Config.HF_TOKEN, model_name)
        
        rag_docs_folder = os.path.join(os.path.abspath(os.path.dirname(__file__)), "rag", "docs")
        get_rag_service(
            docs_folder=rag_docs_folder,
            enable_rag=enable_rag
        )
        
        # Start HTTPServer
        httpd = ThreadingHTTPServer((Config.HOST_NAME, Config.PORT), LLMServer)
        def run_server():
            try:
                httpd.serve_forever()
            except Exception as e:
                traceback.print_exc()
        thread = threading.Thread(target=run_server)
        thread.start()
        
        # NGROK port forwarding
        ngrok.set_auth_token(Config.NGROK_AUTHTOKEN)
        listener = ngrok.forward(addr=f"{Config.HOST_NAME}:{Config.PORT}", domain=Config.NGROK_DOMAIN)
        ADDRESS = listener.url()
        print(f"NGROK: {Config.HOST_NAME}:{Config.PORT} -> {ADDRESS}")

        # Handle exit command
        try:
            while input("Type 'exit' to stop server: ").strip() != "exit":
                pass
        except Exception:
            pass
        
        print("Shutting down server...")
        httpd.shutdown()
        thread.join()
        print("Server stopped. Exiting.")
    except KeyboardInterrupt:
        pass

main()