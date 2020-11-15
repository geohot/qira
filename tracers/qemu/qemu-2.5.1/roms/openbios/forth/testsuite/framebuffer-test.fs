
: test-screen
  10 10 pci-l@
  f0 0 do
    dup d# 1280 i * +
    500 i fill
  loop
  ;

  test-screen
