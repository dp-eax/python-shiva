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

import signal
from shiva.servers import servers
from shiva.proc_methods import proc_methods
from shiva.generator import generator

class Shiva(servers, proc_methods, generator):
  """
    Shiva is a fuzzer library in Python.

    Dependencies:
      python-ptrace (https://bitbucket.org/haypo/python-ptrace/overview)

    To install the library, simply:
      $ sudo python setup.py install

    Usage is simple. To initialize:
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
        * The index argument is required, this is the position the fuzzer is at (see example below for clarification).
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

    Upon a crash the self.crash variable is set to 1 and the EIP and fuzzcase are written to a file (filename + ".log").

    Example usage:
      > import shiva
      > fuzzer = shiva.Shiva("/usr/bin/ncat", "server", arguments="-lp4444", hostname="127.0.0.1", port=4444)
      > fuzzer.start()
      > fuzzer.load(0, "test/packet1")
      > for i in range(1,len(fuzzer.cases)):
      >   fuzzer.load(i, "test/packet2")
      >   if fuzzer.crash:
      >     fuzzer.stop()
      > fuzzer.stop()

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

    self.crash = 0
    self.filename = filename
    self.hostname = hostname
    self.cases = ()
    self.outfile = outfile
    self.sock = None
    self.s = None
    self.pid = None
    self.env = None
    self.mode = { "file":0, "args":1, "env":2, "client":3, "server":4 }[mode]

    self.check_init()
    self.generator()
    signal.signal(signal.SIGUSR1, self.handler)

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

  # crash handler for the target process, write the naughty fuzzcase to a file
  def handler(self, signum, frame):
    self.crash = 1
    f = open(self.filename.split('/')[-1] + ".log", "a+")
    f.writelines("Crash with: \n" + str(self.fuzzcase) + "\n")
    f.close()
 
  # creates a fuzzcase, loads from file (or arguments, etc.).
  def load(self, index, file=None):
    self.index = index

    if self.mode != 1 and file == None:
      raise Exception("Set the 'file' argument.")

    if self.mode == 1:
      self.split(self.arguments, index)

    elif self.mode == 2:
      self.split(file, index)

    else:
      f = open(file, 'r')
      for line in f.readlines():
        self.split(line, index)
      f.close()
      
    if self.mode == 0:
      f = open(self.outfile, "w")
      f.writelines(self.fuzzcase)
      f.close

    elif self.mode == 3 or self.mode == 4: 
      try:
        self.sock.send(bytes(self.fuzzcase, "utf-8"))
      except:
        return

