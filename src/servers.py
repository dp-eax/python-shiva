import socket

class servers():
  # creates server for use with mode 3 (client)
  def server(self):
    self.s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    self.s.bind((self.hostname, self.port))
    self.s.listen(1)
    conn, addr = self.s.accept()
    self.sock = conn
    
  # creates client for use with mode 4 (server)
  def client(self):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((self.hostname, self.port))
    self.sock = s

