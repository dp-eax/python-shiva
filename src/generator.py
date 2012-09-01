class generator():
  # generator function, the core of the fuzzer, this will be vastly improved...
  def generator(self):
    nums = range(1, 8000, 50)
    fmt_strings = ("%s%p%x%d", ".1024d", "%.2049d", "%p%p%p%p", "%x%x%x%x", "%d%d%d%d", "%s%s%s%s",
       "%99999999999s", "%08x", "%%20d", "%%20n", "%%20x", "%%20s", "%s%s%s%s%s%s%s%s%s%s",
       "%p%p%p%p%p%p%p%p%p%p", "%#0123456x%08x%x%s%p%d%n%o%u%c%h%l%q%j%z%Z%t%i%e%g%f%a%C%S%08x%%",
       "%s" * 129, "%x" * 257)
    ints = (-1, 0, 0x100, 0x1000, 0x3fffffff, 0x7ffffffe, 0x7fffffff, 0x80000000, 0xfffffffe,
       0xffffffff, 0x10000, 0x100000)

    for i in nums:
      self.cases += ("A"*i, "P"*i, chr(0x15)*i)

    self.cases += fmt_strings
    self.cases += ints

  # parse file for location to inject fuzzcase... this needs to be improved. it's ugly as hell.
  def split(self, line, index):
    self.fuzzcase = ""
    temp = line.split('|')
    x = 0
    for i in temp:
      if x == 0:
        self.fuzzcase += i
        x = 1
      else:
        self.fuzzcase += str(self.cases[index])
        x = 0

