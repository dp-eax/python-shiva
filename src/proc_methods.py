import os, time
if os.name == "posix":
  from ptrace.ptrace import *

class proc_methods():
  # linux debugger
  def linux_dbg(self, env):
    if self.mode == 2:
      env = {env:self.fuzzcase}

    pid = os.fork()
    if pid == 0:
      ptrace(PTRACE_TRACEME, 0, None, None)
      if self.mode == 1:  # if args fuzz, the arguments are the fuzzcase.
          os.execl(self.filename, self.filename, self.fuzzcase)
      elif self.mode == 2: # sets the environment variables for an env fuzz.
        os.execle(self.filename, self.filename, {env:self.fuzzcase})
      else:  # everything else use the self.arguments variable, straight from the user
        os.execl(self.filename, self.filename, self.arguments)

    else:
      regs = user_regs_struct()
      sig = siginfo()

      while 1:
        status = wait()
        if WIFEXITED(status) != 0:
          break

        ptrace(PTRACE_GETSIGINFO, pid, None, sig)

        if sig.si_signo == 6 or sig.si_signo == 11:
          ptrace(PTRACE_GETREGS, pid, None, regs)
          f = open(self.filename.split('/')[-1] + ".log", "a+")
          f.writelines("Received signal: " + strsignal(sig.si_signo) + "\nRIP: " + str(regs.rip))
          f.close()
          print("RIP: " + str(hex(regs.rip)))
          break

        ptrace(PTRACE_CONT, pid, None, None)

      ptrace(PTRACE_DETACH, pid, None, None)

      try:
        os.kill(self.ppid, 10)
      except:
        return

  # will debug the fuzzed process, also will spawn the servers and clients for modes 3 and 4
  def start(self, env=None):
    if env == None and self.mode == 2:
      raise Exception("Set 'env' for 'env' mode.")

    self.ppid = os.getpid()
    self.pid = os.fork()

    if self.pid == 0:
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

    os.system("kill $(ps -o pid= -s $(ps -o sess --no-heading --pid " + str(self.pid) + "))")
    #os.kill(self.pid, 9)
    self.pid = None
