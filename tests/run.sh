#!/usr/bin/env bash
# Fixture checks for rule-doctor-lite. No docker needed.
set -uo pipefail
cd "$(dirname "$0")/.."; F=tests/fixture; fail=0
# git does not keep file times: age the rotated fixtures so the --days window test means something
python3 -c "import os,time;n=time.time();os.utime('$F/logs/alerts/2026/Sep/ossec-alerts-20.json.gz',(n-30*86400,)*2);os.utime('$F/logs/ossec-old-load.log',(n-8*86400,)*2)"
check() { if printf '%s\n' "$2" | grep -Eq "$3"; then echo "PASS $1"; else echo "FAIL $1"; fail=1; fi; }
a=$(python3 rule-doctor-lite.py --ossec-dir $F)
check "910010 dropped, read from ossec.log" "$a" '910010 .*DROPPED-AT-LOAD +ossec.log 7617'
check "910011 dropped, missing parent"       "$a" '910011 .*DROPPED-AT-LOAD +predicted: parent 57150 is not defined'
check "3 shadow candidates"                  "$a" 'SHADOW-CANDIDATE=3'
check "910012 dropped, child of dropped 910010" "$a" '910012 .*DROPPED-AT-LOAD +predicted: parent 910010 is itself dropped'
check "910013 dropped, grandchild (chain)"   "$a" '910013 .*DROPPED-AT-LOAD +predicted: parent 910012 is itself dropped'
b=$(python3 rule-doctor-lite.py --ossec-dir $F --ossec-log /nonexistent)
check "910010 predicted from load order"     "$b" '910010 .*predicted: parent 5715 is in 0095-sshd_rules.xml'
check "chain followed without ossec.log"     "$b" '910013 .*DROPPED-AT-LOAD +predicted: parent 910012 is itself dropped'
c=$(python3 rule-doctor-lite.py --ossec-dir $F --days 60)
check "rotated .gz alerts read (--days 60)"    "$c" 'SHADOW-CANDIDATE=2'
d=$(python3 rule-doctor-lite.py --ossec-dir $F --ossec-log $F/logs/ossec-old-load.log --ossec-log $F/logs/ossec.log)
check "old load's warning not reported"      "$d" '910001 .*SHADOW-CANDIDATE'
e=$(python3 rule-doctor-lite.py --ossec-dir $F --ossec-log $F/logs/ossec-old-load.log)
check "old load alone: 910001 dropped"       "$e" '910001 .*DROPPED-AT-LOAD +ossec.log 7617'
exit $fail
