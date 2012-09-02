#!/usr/bin/python
import time, sys
from shiva.shiva import Shiva

def test_file():
  fuzzer = Shiva("/usr/bin/opera", "file", arguments="test/test1.html", outfile="test/test1.html")
  for i in range(1, len(fuzzer.cases)):
    fuzzer.start()
    fuzzer.load(i, "test/test.html")
    fuzzer.stop()

def test_client():
  fuzzer = Shiva("/usr/bin/irssi", "client", hostname="127.0.0.1", port=6667)

  fuzzer.start()
  fuzzer.load(0, file="test/packet1")
  for i in range(1,len(fuzzer.cases)):
    fuzzer.load(i, file="test/packet2")
  fuzzer.stop()

def test_server():
  fuzzer = Shiva("/usr/bin/ncat", "server", arguments="-lp4444", hostname="127.0.0.1", port=4444)

  fuzzer.start()
  fuzzer.load(0, "test/packet1")
  for i in range(1,len(fuzzer.cases)):
    fuzzer.load(1, "test/packet2")
  fuzzer.stop()

def test_args():
  fuzzer = Shiva("/usr/bin/ncat", "args", arguments="127.0.0.1 ||")
  for i in range(1,len(fuzzer.cases)):
    fuzzer.load(i)
    fuzzer.start()
    fuzzer.stop()

def test_env():
  fuzzer = Shiva("/usr/bin/ncat", "env", arguments="127.0.0.1 4444")
  for i in range(1,len(fuzzer.cases)):
    fuzzer.load(i, "||")
    fuzzer.start("HAHA")
    fuzzer.stop()

def main():
  if len(sys.argv) != 2:
    print("Usage: " + sys.argv[0] + " <client/server/args/env/file>")
    exit()

  if sys.argv[1] == "client":
    test_client()
  elif sys.argv[1] == "server":
    test_server()
  elif sys.argv[1] == "args":
    test_args()
  elif sys.argv[1] == "env":
    test_env()
  elif sys.argv[1] == "file":
    test_file()
  else:
    print("Please select a valid fuzz type.")

if __name__=="__main__":
  main()
