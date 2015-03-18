import sys
sys.path.append("static2/")
sys.path.append("middleware/")
import static2
import testing

def test():
  fns = testing.get_file_list([testing.TEST_PATH], recursive=True)
  testing.test_files(fns, quiet=True, profile=False, runtime=True)
