from middleware import qira_log
logs = qira_log.read_log(qira_log.LOGFILE)
for l in logs:
  print "address: %8x  data: %8x   clnum: %4d  flags: %s" % (l[0], l[1], l[2], qira_log.flag_to_type(l[3]))

