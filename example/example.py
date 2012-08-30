#!/usr/bin/python
import shiva, time, sys


def test_file():
  fuzzer = shiva.Shiva("/usr/bin/opera", "file", arguments="test/test1.html", outfile="test/test1.html")
  for i in range(1, 10):
    fuzzer.start()
    fuzzer.load("test/test.html")
    fuzzer.stop()

def test_client():
  fuzzer = shiva.Shiva("/usr/bin/irssi", "client", hostname="127.0.0.1", port=6667)
  for i in range(1, 10):
    fuzzer.start()
    fuzzer.load("test/packet1")
    for i in range(1,200):
      fuzzer.load("test/packet2")
    fuzzer.stop()

def test_server():
  fuzzer = shiva.Shiva("/usr/bin/ncat", "server", arguments="-lp4444", hostname="127.0.0.1", port=4444)
  for i in range(1, 10):
    fuzzer.start()
    fuzzer.load("test/packet1")
    for i in range(1,200):
      fuzzer.load("test/packet2")
    fuzzer.stop()

def test_args():
  fuzzer = shiva.Shiva("/usr/bin/ncat", "args", arguments="127.0.0.1 ||")
  for i in range(1,10):
    fuzzer.load()
    fuzzer.start()
    fuzzer.stop()

def test_env():
  fuzzer = shiva.Shiva("/usr/bin/ncat", "env", arguments="127.0.0.1 4444")
  for i in range(1,10):
    fuzzer.load("||")
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
