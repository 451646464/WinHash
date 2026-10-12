# -*- coding: utf-8 -*-
"""Local dev server for WinHash with cache disabled (fresh files every load)."""
import http.server
import socketserver

PORT = 8766


class NoCacheHandler(http.server.SimpleHTTPRequestHandler):
    def end_headers(self):
        self.send_header('Cache-Control', 'no-store, no-cache, must-revalidate, max-age=0')
        self.send_header('Pragma', 'no-cache')
        self.send_header('Expires', '0')
        super().end_headers()

    def log_message(self, fmt, *args):
        pass


if __name__ == '__main__':
    socketserver.TCPServer.allow_reuse_address = True
    with socketserver.TCPServer(('0.0.0.0', PORT), NoCacheHandler) as httpd:
        print('WinHash dev server on http://0.0.0.0:%d' % PORT)
        httpd.serve_forever()
