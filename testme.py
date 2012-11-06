#!/usr/bin/python
import sys
import subprocess

kbuild = sys.argv[1]
logfile = sys.argv[2]
name = "./trace_analyze.py"
db = "db"
acc = ".tmp.txt"
ring = ".tmp.png"

test_names = [ \
"WITHOUT LOG, STATIC ONLY, DEFAULT RING CHART NAME", \
"WITHOUT LOG, STATIC ONLY", \
"RING CHART: STATIC ", \
"RING CHART: DYNAMIC ", \
"RING CHART: DYNAMIC+STATIC", \
"RING CHART: TOTAL DYNAMIC", \
"RING CHART: WASTE", \
"START BRANCH: drivers/", \
"START BRANCH: fs/ext2", \
"MALLOC EVENTS ONLY", \
"CACHE EVENTS ONLY", \
"ACCOUNT: DYNAMIC", \
"ACCOUNT: TOTAL DYNAMIC", \
"ACCOUNT: ALLOC COUNT", \
"ACCOUNT: WASTE", \
"ACCOUNT: DEFAULT", \
"SAVE DB FILE", \
"DB FILE: NO USAGE", \
"DB FILE: OUTPUT ACCOUNT", \
"DB FILE: OUTPUT ACCOUNT, W/ START BRANCH", \
"DB FILE: OUTPUT RING CHART", \
"DB FILE: OUTPUT RING CHART, W/ START BRANCH", \
]

test_args = [ \
[name, "-k", kbuild], \
[name, "-k", kbuild, "-r", "tmp.png"], \
[name, "-k", kbuild, "-f", logfile, "-r", ring, "-a", "static"], \
[name, "-k", kbuild, "-f", logfile, "-r", ring, "-a", "current_dynamic"], \
[name, "-k", kbuild, "-f", logfile, "-r", ring, "-a", "current"], \
[name, "-k", kbuild, "-f", logfile, "-r", ring, "-a", "total_dynamic"], \
[name, "-k", kbuild, "-f", logfile, "-r", ring, "-a", "waste"], \
[name, "-k", kbuild, "-f", logfile, "-r", ring, "-a", "waste", "-b", "drivers/"], \
[name, "-k", kbuild, "-f", logfile, "-r", ring, "-a", "waste", "-b", "fs/ext2"], \
[name, "-k", kbuild, "-f", logfile, "-r", ring, "-a", "waste", "--malloc"], \
[name, "-k", kbuild, "-f", logfile, "-r", ring, "-a", "waste", "--cache"], \
[name, "-k", kbuild, "-f", logfile, "-c", acc, "-o", "current_dynamic"], \
[name, "-k", kbuild, "-f", logfile, "-c", acc, "-o", "total_dynamic"], \
[name, "-k", kbuild, "-f", logfile, "-c", acc, "-o", "alloc_count"], \
[name, "-k", kbuild, "-f", logfile, "-c", acc, "-o", "waste"], \
[name, "-k", kbuild, "-f", logfile, "-c", acc], \
[name, "-k", kbuild, "-f", logfile, "--save-db", db], \
[name, "-k", kbuild, "--db-file", db], \
[name, "-k", kbuild, "--db-file", db, "-c", acc, "-o", "waste"], \
[name, "-k", kbuild, "--db-file", db, "-c", acc, "-o", "waste", "-b", "fs/"], \
[name, "-k", kbuild, "--db-file", db, "-r", ring, "-a", "waste"], \
[name, "-k", kbuild, "--db-file", db, "-r", ring, "-a", "waste", "-b", "mm/"], \
[]]

def do_test(name, test):
    print("TEST: {}".format(name))
    rc = subprocess.call(test)
    if rc:
        print("TEST FAILED!")
        sys.exit(1)

if len(sys.argv) < 4:
    for test in zip(test_names, test_args):
        do_test(test[0], test[1])
else:
    i = int(sys.argv[3]) - 1
    do_test(test_names[i], test_args[i])
