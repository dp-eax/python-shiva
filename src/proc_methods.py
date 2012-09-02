import os, time, signal
import platform

if os.name == "posix":
  from ptrace.ptrace import *

class proc_methods():
  def handler2(self, signum, frame):
    try:
      os.kill(self.gcpid, signal.SIGKILL)
    except:
      exit()
    exit()

  # linux debugger
  def linux_dbg(self, env):
    if self.mode == 2:
      env = {env:self.fuzzcase}

    self.gcpid = os.fork()
    if self.gcpid == 0:
      ptrace(PTRACE_TRACEME, 0, None, None)
      if self.mode == 1:  # if args fuzz, the arguments are the fuzzcase.
        os.execv(self.filename, [self.filename.split('/')[-1],] + self.fuzzcase.split())
      elif self.mode == 2: # sets the environment variables for an env fuzz.
        os.execve(self.filename, [self.filename.split('/')[-1],] + self.arguments.split(), {env:self.fuzzcase})
      else:  # everything else use the self.arguments variable, straight from the user
        os.execv(self.filename, [self.filename.split('/')[-1],] + self.arguments.split())

    else:
      signal.signal(signal.SIGUSR2, self.handler2)
      regs = user_regs_struct()
      sig = siginfo()

      while 1:
        ptrace(PTRACE_CONT, self.gcpid, None, None)
        status = wait()
        if WIFEXITED(status):
          break

        ptrace(PTRACE_GETSIGINFO, self.gcpid, None, sig)

        if sig.si_signo == 6 or sig.si_signo == 11:
          os.kill(self.ppid, signal.SIGUSR1)
          ptrace(PTRACE_GETREGS, self.gcpid, None, regs)
          f = open(self.filename.split('/')[-1] + ".log", "a+")
          if platform.machine() == "x86_64":
            f.writelines("\nReceived signal: " + strsignal(sig.si_signo) + "\nRIP: " + str(hex(regs.rip)) + "\n")
          else:
            f.writelines("\nReceived signal: " + strsignal(sig.si_signo) + "\nEIP: " + str(hex(regs.eip)) + "\n")
          f.close()
          ptrace(PTRACE_DETACH, self.gcpid, None, None)
          break
          

  # will debug the fuzzed process, also will spawn the servers and clients for modes 3 and 4
  def start(self, env=None):
    if env == None and self.mode == 2:
      raise Exception("Set 'env' for 'env' mode.")

    self.ppid = os.getpid()
    self.pid = os.fork()

    if self.pid == 0:
      if self.mode == 3:
        time.sleep(0.1)

      if os.name == "posix":
        self.linux_dbg(env)

    else:
      if self.mode == 3:
        self.server()
      elif self.mode == 4:
        time.sleep(0.1) # wait a tenth of a second to make sure the process has loaded before spawning the fuzzer client.
        self.client()

  # stops the fuzzer and processes, closes any open sockets, as well, (to either restart or to end altogether).
  def stop(self):
    if self.pid == None:
      raise Exception("You have to start() the fuzzer in order to stop() it.")

    if self.sock != None:
      self.sock.close()
      self.sock = None

    if self.s != None:
      self.s.close()
      self.s = None

    if self.crash == 1:
      self.crash = 0
      os.kill(self.pid, signal.SIGKILL)
    else:
      os.kill(self.pid, signal.SIGUSR2)

    self.pid = None
