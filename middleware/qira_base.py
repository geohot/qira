def ghex(a):
  if a == None:
    return None
  return hex(a).strip("L")

def fhex(a):
  try:
    return int(a, 16)
  except:
    return None

