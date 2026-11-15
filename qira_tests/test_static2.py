from qira.legacy import static2
from conftest import LOOP


def test_static2_loop():
  static = static2.Static(LOOP, debug=1)
  assert static['arch'] == 'x86-64'
  assert static['entry'] == 0x400440
  main = static.get_address_by_name('main')
  assert main == 0x400536

  static.process()
  starts = sorted(f.start for f in static['functions'])
  assert main in starts
  assert static['entry'] in starts

  ins = static[main]['instruction']
  assert str(ins) == "push\trbp"
  assert ins.size() == 1
  # the loop's jump to the condition at 0x40055f
  jmp = static[0x400545]['instruction']
  assert jmp.is_jump() and not jmp.is_call()
  assert (0x40055f, static2.DESTTYPE.jump) in jmp.dests()

  # memory comes from the ELF segments
  assert static.memory(main, 4) == bytes.fromhex("554889e5")
  assert static.memory(0x10, 4) == b""
