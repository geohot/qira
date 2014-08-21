import random

c = []
for i in range(40):
  r = random.randint(40, 192)
  g = random.randint(40, 192)
  b = random.randint(40, 192)
  c.append("#%02X%02X%02X" % (r,g,b))

print c

