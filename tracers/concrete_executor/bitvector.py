import abc

class BitVector(object):
  __metaclass__ = abc.ABCMeta

  """ Properties """

  @abc.abstractproperty
  def get_bits(self, low, high):
    return

  def get_high_bits(self, num):
    size = self.get_size()
    assert num <= size, "Cannot get {} bits from {}-bit bitvector".format(num, size)
    return self.get_bits(size-num, size-1)

  def get_low_bits(self, num):
    size = self.get_size()
    assert num <= size, "Cannot get {} bits from {}-bit bitvector".format(num, size)
    return self.get_bits(0, num-1)

  @abc.abstractproperty
  def get_size(self):
    return

  @abc.abstractmethod
  def signed(self):
    return


  """ Operations """

  @abc.abstractmethod
  def concat(self, other):
    return

  """ Arithmetic operations """

  @abc.abstractmethod
  def add(self, other):
    return

  @abc.abstractmethod
  def sub(self, other):
    return

  @abc.abstractmethod
  def mul(self, other):
    return

  @abc.abstractmethod
  def div(self, other):
    return

  @abc.abstractmethod
  def mod(self, other):
    return

  @abc.abstractmethod
  def neg(self):
    return

  """ Bitwise operations """

  @abc.abstractmethod
  def band(self, other):
    return

  @abc.abstractmethod
  def xor(self, other):
    return

  @abc.abstractmethod
  def bor(self, other):
    return

  @abc.abstractmethod
  def bnot(self):
    return

  @abc.abstractmethod
  def lshift(self, shift):
    return

  @abc.abstractmethod
  def rshift(self, shift):
    return

  @abc.abstractmethod
  def arshift(self, shift):
    return

  """ Comparison operations """

  @abc.abstractmethod
  def eq(self, other):
    return

  @abc.abstractmethod
  def neq(self, other):
    return

  @abc.abstractmethod
  def lt(self, other):
    return

  @abc.abstractmethod
  def le(self, other):
    return

  @abc.abstractmethod
  def gt(self, other):
    return

  @abc.abstractmethod
  def ge(self, other):
    return

  @abc.abstractmethod
  def slt(self, other):
    return

  @abc.abstractmethod
  def sle(self, other):
    return

  """ Overloading """

  def reverse(op):
    return lambda a,b : op(a.__class__(a.get_size(), b), a)

  def __add__(self, other):
    return self.add(other)
  __radd__ = __add__

  def __sub__(self, other):
    return self.sub(other)
  __rsub__ = reverse(__sub__)

  def __mul__(self, other):
    return self.mul(other)
  __rmul__ = __mul__

  def __div__(self, other):
    return self.div(other)
  __rdiv__ = reverse(__div__)

  def __mod__(self, other):
    return self.mod(other)
  __rmod__ = reverse(__mod__)

  def __neg__(self):
    return self.neg()

  def __and__(self, other):
    return self.band(other)
  __rand__ = __and__

  def __xor__(self, other):
    return self.xor(other)
  __rxor__ = __xor__

  def __or__(self, other):
    return self.bor(other)
  __ror__ = __or__

  def __invert__(self):
    return self.bnot()

  def __lshift__(self, other):
    return self.lshift(other)
  __rlshift__ = reverse(__lshift__)

  def __rshift__(self, other):
    return self.rshift(other)
  __rrshift__ = reverse(__rshift__)

  def __eq__(self, other):
    return self.eq(other)

  def __ne__(self, other):
    return self.neq(other)

  def __lt__(self, other):
    return self.lt(other)

  def __le__(self, other):
    return self.le(other)

  def __gt__(self, other):
    return self.gt(other)

  def __ge__(self, other):
    return self.ge(other)

class ConcreteBitVector(BitVector):

  def __init__(self, size, value=0):
    super(ConcreteBitVector, self).__init__()
    self.size = size
    self.value = value
    bitmask = (1 << self.size) - 1
    self.value &= bitmask

  def get_bits(self, low, high):
    length = high - low + 1
    bitmask = (1 << length) - 1
    value = self >> low
    return ConcreteBitVector(length, int(value & bitmask))

  def get_size(self):
    return self.size

  def signed(self):
    mask = (1 << (self.get_size() - 1))
    if self.value & mask:
      return -(2**self.get_size() - self.value)
    else:
      return self.value

  """ Operations """

  def concat(self, other):
    return ConcreteBitVector(self.size+other.size, (self.value << self.size) | other.value)

  """ Arithmetic operations """

  def add(self, other):
    if isinstance(other, ConcreteBitVector):
      size = max(self.size, other.size)
      value = self.value + other.value
    else:
      size = self.size
      value = self.value + other
    return ConcreteBitVector(size, value)

  def sub(self, other):
    if isinstance(other, ConcreteBitVector):
      size = max(self.size, other.size)
      value = self.value - other.value
    else:
      size = self.size
      value = self.value - other
    return ConcreteBitVector(size, value)

  def mul(self, other):
    if isinstance(other, ConcreteBitVector):
      size = max(self.size, other.size)
      value = self.value * other.value
    else:
      size = self.size
      value = self.value * other
    return ConcreteBitVector(size, value)

  def div(self, other):
    if isinstance(other, ConcreteBitVector):
      size = max(self.size, other.size)
      value = self.value / other.value
    else:
      size = self.size
      value = self.value / other
    return ConcreteBitVector(size, value)

  def mod(self, other):
    if isinstance(other, ConcreteBitVector):
      size = max(self.size, other.size)
      value = self.value % other.value
    else:
      size = self.size
      value = self.value % other
    return ConcreteBitVector(size, value)

  def neg(self, other):
    return self.bnot().add(1)

  """ Bitwise operations """

  def band(self, other):
    if isinstance(other, ConcreteBitVector):
      size = max(self.size, other.size)
      value = self.value & other.value
    else:
      size = self.size
      value = self.value & other
    return ConcreteBitVector(size, value)

  def xor(self, other):
    if isinstance(other, ConcreteBitVector):
      size = max(self.size, other.size)
      value = self.value ^ other.value
    else:
      size = self.size
      value = self.value ^ other
    return ConcreteBitVector(size, value)

  def bor(self, other):
    if isinstance(other, ConcreteBitVector):
      size = max(self.size, other.size)
      value = self.value | other.value
    else:
      size = self.size
      value = self.value | other
    return ConcreteBitVector(size, value)

  def bnot(self):
    bitmask = (1 << self.size) - 1
    value = self.value ^ bitmask
    size = self.size
    return ConcreteBitVector(size, value)

  def lshift(self, other):
    size = self.size
    if isinstance(other, ConcreteBitVector):
      value = self.value << other.value
    else:
      value = self.value << other
    return ConcreteBitVector(size, value)

  def rshift(self, other):
    size = self.size
    if isinstance(other, ConcreteBitVector):
      value = self.value >> other.value
    else:
      value = self.value >> other
    return ConcreteBitVector(size, value)

  def arshift(self, other):
    if isinstance(other, ConcreteBitVector):
      otherval = other.value
    else:
      otherval = other
    highbit = (self.value & (1 << (self.size - 1))) >> (self.size - 1)
    mask = ((1 << otherval) - 1) * highbit #111.. if hb == 1, 000.. otherwise
    mask <<= (self.size - otherval) # shift to high bits of bitvector

    newval = self.value >> otherval
    newval |= mask # set the high bits correctly
    return ConcreteBitVector(self.size, newval)

  """ Comparison operations """

  def eq(self, other):
    if isinstance(other, ConcreteBitVector):
      return self.value == other.value
    else:
      return self.value == other

  def neq(self, other):
    if isinstance(other, ConcreteBitVector):
      return self.value != other.value
    else:
      return self.value != other

  def lt(self, other):
    if isinstance(other, ConcreteBitVector):
      return self.value < other.value
    else:
      return self.value < other

  def le(self, other):
    if isinstance(other, ConcreteBitVector):
      return self.value <= other.value
    else:
      return self.value <= other

  def gt(self, other):
    if isinstance(other, ConcreteBitVector):
      return self.value > other.value
    else:
      return self.value > other

  def ge(self, other):
    if isinstance(other, ConcreteBitVector):
      return self.value >= other.value
    else:
      return self.value >= other

  def slt(self, other):
    if isinstance(other, ConcreteBitVector):
      return self.signed() < other.signed()
    else:
      return self.signed() < other

  def sle(self, other):
    if isinstance(other, ConcreteBitVector):
      return self.signed() <= other.signed()
    else:
      return self.signed() <= other

  def __str__(self):
      return str(self.value)

  def __repr__(self):
    return self.__str__()

  def __int__(self):
    return self.value
