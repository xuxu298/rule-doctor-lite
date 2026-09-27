#!/usr/bin/env bash
# Fixture checks for rule-doctor-lite. No docker needed.
set -uo pipefail
cd "$(dirname "$0")/.."; F=tests/fixture; fail=0
check() { if printf '%s\n' "$2" | grep -Eq "$3"; then echo "PASS $1"; else echo "FAIL $1"; fail=1; fi; }
a=$(python3 rule-doctor-lite.py --ossec-dir $F)
check "910010 dropped, read from ossec.log" "$a" '910010 .*DROPPED-AT-LOAD +ossec.log 7617'
check "910011 dropped, missing parent"       "$a" '910011 .*DROPPED-AT-LOAD +predicted: parent 57150 is not defined'
check "3 shadow candidates"                  "$a" 'SHADOW-CANDIDATE=3'
b=$(python3 rule-doctor-lite.py --ossec-dir $F --ossec-log /nonexistent)
check "910010 predicted from load order"     "$b" '910010 .*predicted: parent 5715 is in 0095-sshd_rules.xml'
exit $fail
