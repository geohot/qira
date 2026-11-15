from qira.legacy import qira_log
from conftest import LOOP_CHANGES


def test_write_read_round_trip(tmp_path):
  fn = tmp_path / "log"
  qira_log.write_log(str(fn), LOOP_CHANGES)
  assert fn.stat().st_size == 0x18 * (len(LOOP_CHANGES) + 1)
  with open(fn, "rb") as f:
    # change_count counts the header entry, as written by the tracer
    assert qira_log.get_log_length(f) == len(LOOP_CHANGES) + 1
    assert qira_log.read_log(f) == LOOP_CHANGES
    assert qira_log.read_log(f, seek=2, cnt=3) == LOOP_CHANGES[1:4]


def test_read_stops_at_invalid_entry(tmp_path):
  fn = tmp_path / "log"
  qira_log.write_log(str(fn), LOOP_CHANGES[:2] + [(0, 0, 0, 0)] + LOOP_CHANGES[2:])
  with open(fn, "rb") as f:
    assert qira_log.read_log(f) == LOOP_CHANGES[:2]


def test_flag_to_type():
  V, W, M, S = qira_log.IS_VALID, qira_log.IS_WRITE, qira_log.IS_MEM, qira_log.IS_START
  assert qira_log.flag_to_type(V | S) == "I"
  assert qira_log.flag_to_type(V | W | M | 32) == "S"
  assert qira_log.flag_to_type(V | M | 32) == "L"
  assert qira_log.flag_to_type(V | W | 64) == "W"
  assert qira_log.flag_to_type(V | 64) == "R"
