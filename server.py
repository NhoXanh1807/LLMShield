
from http.server import BaseHTTPRequestHandler, HTTPServer
import json
import time
import traceback
import ngrok


class TrackerHTTPServer(BaseHTTPRequestHandler):
    def do_POST(self):
        try:
            # Đọc dữ liệu truyền đến trong body request
            content_len = int(self.headers.get("Content-Length"))
            post_body = self.rfile.read(content_len)
            
            # Phản hồi
            self.send_response(200)
            self.end_headers()
            self.wfile.write(f"hello this is message response from gpu host. Your post body is : {post_body.decode('utf-8')}".encode("utf-8"))
        except Exception as e:
            tb = traceback.format_exc()
            print("Trace : " + tb)
            self.send_error(500, str(e))

NGROK_AUTHTOKEN = "3BsAFITReQh3QiJIsB40v8gPy7p_4mDoBhSHJuTopT1KysYgT"
NGROK_DOMAIN = "overrigged-savingly-nelle.ngrok-free.dev"
HOST_NAME = "127.0.0.1"
PORT = 89
httpd = HTTPServer((HOST_NAME, PORT), TrackerHTTPServer)
ngrok.set_auth_token(NGROK_AUTHTOKEN)
listener = ngrok.forward(addr=f"{HOST_NAME}:{PORT}", domain=NGROK_DOMAIN)
ADDRESS = listener.url()
print(f"NGROK FORWARD ADDRESS : {ADDRESS}")


# Start HTTPServer
print(time.asctime(), "Start Server - %s:%s" % (HOST_NAME, PORT))
try:
    httpd.serve_forever()
except KeyboardInterrupt:
    pass
httpd.server_close()
print(time.asctime(), "Stop Server - %s:%s" % (HOST_NAME, PORT))