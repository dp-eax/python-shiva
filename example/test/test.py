def mutate(string):
  mutated = list()
  for i in range(0, len(string)):
    for j in range(0, 255):
      if i > 0:
        mutated += [string[:i-1] + chr(j) + string[i+1:], ]
      else:
        mutated += [chr(j) + string[i+1:], ]
  return mutated

string = "123456"
print(mutate(string))
