import os, time, signal
import platform

if os.name == "posix":
  from ptrace.ptrace import *

class proc_methods():
  # handler for SIGUSR2 to alert the debugger when it's time to kill off the process
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
      ptrace(PTRACE_TRACEME, 0, None, None) # prepare process for ptrace
      if self.mode == 1:  # if args fuzz, the arguments are the fuzzcase.
        os.execv(self.filename, [self.filename.split('/')[-1],] + self.fuzzcase.split())
      elif self.mode == 2: # sets the environment variables for an env fuzz.
        os.execve(self.filename, [self.filename.split('/')[-1],] + self.arguments.split(), {env:self.fuzzcase})
      else:  # everything else use the self.arguments variable, straight from the user
        os.execv(self.filename, [self.filename.split('/')[-1],] + self.arguments.split())

    else:
      signal.signal(signal.SIGUSR2, self.handler2)
      regs = user_regs_struct() # create struct for the registers
      sig = siginfo()           # struct for signals

      while 1:
        ptrace(PTRACE_CONT, self.gcpid, None, None) # continue the child process
        status = wait() # wait for signals
        if WIFEXITED(status): # if the child exited break
          break

        ptrace(PTRACE_GETSIGINFO, self.gcpid, None, sig) # get signal info

        if sig.si_signo == 6 or sig.si_signo == 11:  # if it's SIGSEGV or SIGABRT
          os.kill(self.ppid, signal.SIGUSR1)  # send SIGUSR1 to the parent to alert of a crash
          ptrace(PTRACE_GETREGS, self.gcpid, None, regs) # get the registers and write the crash to file
          f = open(self.filename.split('/')[-1] + ".log", "a+")
          if platform.machine() == "x86_64":
            f.writelines("\nReceived signal: " + strsignal(sig.si_signo) + "\nRIP: " + str(hex(regs.rip)) + "\n")
          else:
            f.writelines("\nReceived signal: " + strsignal(sig.si_signo) + "\nEIP: " + str(hex(regs.eip)) + "\n")
          f.close()
          ptrace(PTRACE_DETACH, self.gcpid, None, None) # detach
          break
          

  # will debug the fuzzed process, also will spawn the servers and clients for modes 3 and 4
  def start(self, env=None):
    if env == None and self.mode == 2:
      raise Exception("Set 'env' for 'env' mode.")

    self.ppid = os.getpid() # get the parent process id so the children can remember
    self.pid = os.fork()

    if self.pid == 0:
      if self.mode == 3:
        time.sleep(0.1)  # wait for server to start

      if os.name == "posix":  # if it's a posix machine start the debugger
        self.linux_dbg(env)

    else:
      if self.mode == 3:
        self.server()   # start server
      elif self.mode == 4:
        time.sleep(0.1) # wait a tenth of a second to make sure the process has loaded before spawning the fuzzer client.
        self.client()   # start client

  # stops the fuzzer and processes, closes any open sockets, as well, (to either restart or to end altogether).
  def stop(self):
    if self.pid == None:
      raise Exception("You have to start() the fuzzer in order to stop() it.")

    if self.sock != None: # close any sockets
      self.sock.close()
      self.sock = None

    if self.s != None:
      self.s.close()
      self.s = None

    if self.crash == 1: # if it crashed, send a sigkill to the child (why did I put this here?)
      self.crash = 0   # reset self.crash
      os.kill(self.pid, signal.SIGKILL)
    else:  # if it's not, send a SIGUSR2 to the child to tell it stop
      os.kill(self.pid, signal.SIGUSR2)

    self.pid = None
