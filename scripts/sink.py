import os, socketserver

OUT = "/home/runzzx1/otpsvc/mailbox"
os.makedirs(OUT, exist_ok=True)
counter = [0]

class SMTPHandler(socketserver.StreamRequestHandler):
    def handle(self):
        self.wfile.write(b"220 sink ESMTP\r\n")
        data_mode = False
        buf, rcpt = [], []
        while True:
            line = self.rfile.readline()
            if not line:
                break
            if data_mode:
                if line.strip() == b".":
                    data_mode = False
                    counter[0] += 1
                    raw = b"".join(buf).decode(errors="replace")
                    with open(os.path.join(OUT, "mail%02d.txt" % counter[0]), "w") as f:
                        f.write("RCPT: %s\n\n%s" % (rcpt, raw))
                    print("captured", counter[0], rcpt, flush=True)
                    self.wfile.write(b"250 OK\r\n")
                    buf = []
                else:
                    buf.append(line)
                continue
            cmd = line.strip().upper()
            if cmd.startswith((b"EHLO", b"HELO")):
                self.wfile.write(b"250-sink\r\n250 OK\r\n")
            elif cmd.startswith(b"MAIL FROM"):
                self.wfile.write(b"250 OK\r\n")
            elif cmd.startswith(b"RCPT TO"):
                rcpt.append(line.decode(errors="replace").split(":", 1)[1].strip())
                self.wfile.write(b"250 OK\r\n")
            elif cmd.startswith(b"DATA"):
                data_mode = True
                self.wfile.write(b"354 go ahead\r\n")
            elif cmd.startswith(b"QUIT"):
                self.wfile.write(b"221 bye\r\n")
                break
            elif cmd.startswith(b"RSET"):
                buf, rcpt = [], []
                self.wfile.write(b"250 OK\r\n")
            else:
                self.wfile.write(b"250 OK\r\n")

class Server(socketserver.ThreadingTCPServer):
    allow_reuse_address = True

Server(("127.0.0.1", 1025), SMTPHandler).serve_forever()
