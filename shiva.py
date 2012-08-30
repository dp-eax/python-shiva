#   Shiva - The Destroyer, shiva.py
#   (C) 2012 vorbis
#
#   This program is free software; you can redistribute it and/or modify
#   it under the terms of the GNU General Public License as published by
#   the Free Software Foundation; either version 1, or (at your option)
#   any later version.
#
#   This program is distributed in the hope that it will be useful,
#   but WITHOUT ANY WARRANTY; without even the implied warranty of
#   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#   GNU General Public License for more details.
# 
#   You should have received a copy of the GNU General Public License
#   along with this program; if not, write to the Free Software
#   Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.

import os, socket, time

class Shiva():
  """
    Shiva is a fuzzer library in Python. Usage is simple. To initialize:
      * Shiva() -- arguments for this are filename, mode, arguments, hostname, port, and outfile.
         * filename and mode are required. filename is the path to the binary to be fuzzed,
         * mode is the fuzzer type to use, "file", "args", "env", "client", and "server" are valid arguments.
         * "file" is for file fuzzing additionally, the "outfile" variable must be passed, this is where to store the
         * fuzzcases. e.g. xorg.conf
         * "args" is for command line argument fuzzing, only the "arguments" variable is required.
         * "env" is an environment variable fuzzer, no other arguments are required.
         * "client" fuzzes a client socket, hostname and port are required.
         * "server" fuzzes a server socket, hostname and port are required.
         * In all but "args" mode, the arguments variable is optional.

    There are three functions that the user will use:
      * Shiva.load() -- creates the fuzzcases, in socket modes it will send() the fuzzcase, as well.
        * The "file" argument is required in all modes except for "args".
        * In "file" and either socket mode, this argument specifies the file to get fuzzcases from.
        * In "env" mode, this should be the value of the environment variable being fuzzed, (the name of the environment variable will be passed to start()).

      * Shiva.start() -- starts the process to be fuzzed, will also debug and catch exceptions once that feature is added.
        * Only the "env" mode requires an argument for this function, this is the name of the environment variable to be fuzzed.

      * Shiva.stop() -- stops the process and removes any open sockets.
        * No arguments are required for this.

    Notes: 
      * stop() cannot be executed without having start()'ed the fuzzer. 
      * load() should be executed before start() in all cases except for socket modes.

    Example usage:
      > import shiva
      > fuzzer = shiva.Shiva("/usr/bin/ncat", "server", arguments="-lp4444", hostname="127.0.0.1", port=4444)
      > for i in range(1, 10):
      >  fuzzer.start()
      >  fuzzer.load("test/packet1")
      >  for i in range(1,200):
      >    fuzzer.load("test/packet2")
      >  fuzzer.stop()

      test/packet1:
        "GET || HTTP\1.1"
      test/packet2:
        "HEAD || HTTP\1.1"

    In all cases, the || delimeter will specify where to put fuzzcases, in this example cases, a fuzzcase may look like:
      * "GET AA HTTP\1.1"
  """

  def __init__(self, filename, mode, arguments=None, hostname=None, port=None, outfile=None):
    if arguments == None:
      self.arguments = ""
    else:
      self.arguments = arguments

    if port != None:
      self.port = int(port)

    self.crash = 1 # initialize the crash variable, this will be used when debugging is implemented.
    self.filename = filename
    self.hostname = hostname
    self.placeholder = ""  # this holds the state of the fuzz cases, ie: "AAAA"
    self.outfile = outfile
    self.sock = None
    self.pid = None

    self.mode = { "file":0, "args":1, "env":2, "client":3, "server":4 }[mode]
    self.check_init()

  # make sure that all of the arguments are right, otherwise raise an exception.
  def check_init(self):
    if self.mode == 0:
      if self.outfile == None:
        raise Exception("Set 'outfile' for 'file' mode.")

    elif self.mode == 1:
      if self.arguments == "":
        raise Exception("Set 'arguments' for 'args' mode.")

    elif self.mode == 3 or self.mode == 4:
      if self.hostname == None:
        raise Exception("Set 'hostname' for socket modes.")
      if self.port == None:
        raise Exception("Set 'port' for socket modes.")

  # creates server for use with mode 3 (client)
  def server(self):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind((self.hostname, self.port))
    s.listen(1)
    conn, addr = s.accept()
    self.sock = conn
    
  # creates client for use with mode 4 (server)
  def client(self):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((self.hostname, self.port))
    self.sock = s

  # will debug the fuzzed process, also will spawn the servers and clients for modes 3 and 4
  def start(self, env=None):
    if env == None and self.mode == 2:
      raise Exception("Set 'env' for 'env' mode.")

    self.pid = os.fork()
    if self.pid == 0:
      if self.mode == 3:
        time.sleep(0.1) # wait a tenth of a second to make sure the fuzz server has loaded before spawning client.

      if self.mode == 1:  # if args fuzz, the arguments are the fuzzcase.
        os.execl(self.filename, self.filename, self.fuzzcase)
      elif self.mode == 2: # sets the environment variables for an env fuzz.
        os.execle(self.filename, self.filename, {env:self.fuzzcase})
      else:  # everything else use the self.arguments variable, straight from the user
        os.execl(self.filename, self.filename, self.arguments)

    else:
      if self.mode == 3:
        self.server()
      elif self.mode == 4:
        time.sleep(0.1) # wait a tenth of a second to make sure the process has loaded before spawning the fuzzer client.
        self.client()

  # generator function, the core of the fuzzer, this will be vastly improved...
  def generator(self):
    self.placeholder += "A"

  # parse file for location to inject fuzzcase... this needs to be improved. it's ugly as hell.
  def split(self, line):
    self.fuzzcase = ""
    temp = line.split('|')
    x = 0
    for i in temp:
      if x == 0:
        self.fuzzcase += i
        x = 1
      else:
        self.generator()
        self.fuzzcase += self.placeholder
        x = 0

  # creates a fuzzcase, loads from file (or arguments, etc.).
  def load(self, file=None):
    if self.mode != 1 and file == None:
      raise Exception("Set the 'file' argument.")

    if self.mode == 1:
      self.split(self.arguments)

    elif self.mode == 2:
      self.split(file)

    else:
      f = open(file, 'r')
      for line in f.readlines():
        self.split(line)
      f.close()
      
    if self.mode == 0:
      f = open(self.outfile, "w")
      f.writelines(self.fuzzcase)
      f.close

    elif self.mode == 3 or self.mode == 4: 
      self.sock.send(bytes(self.fuzzcase, "utf-8"))

  # stops the fuzzer and processes, closes any open sockets, as well, (to either restart or to end altogether).
  def stop(self):
    if self.pid == None:
      raise Exception("You have to start() the fuzzer in order to stop() it.")

    if self.sock != None:
      self.sock.close()
      self.sock = None

    os.kill(self.pid, 9)
    self.pid = None
