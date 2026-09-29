#!/usr/bin/env python3
"""ATK Rule Doctor Lite — why do my custom Wazuh rules never fire?

Free, read-only, Python 3 standard library only. Run it on the Wazuh manager (or point it at a
copy of /var/ossec). It lists every custom rule that did not fire inside the measurement window
and gives the most likely reason:

  DROPPED-AT-LOAD        Wazuh threw the rule away while loading it (its if_sid parent was not
                         loaded yet, or does not exist). The manager still starts and
                         `wazuh-analysisd -t` still exits 0; only ossec.log says so (7617/7619).
                         Chains are followed: a child of a dropped rule is dropped too. Reads
                         if_sid only, not if_matched_sid or if_group.
  SHADOW-CANDIDATE       a sibling that Wazuh evaluates first did fire. Only a candidate: it
                         proves the sibling matched something, not that this rule would have
                         matched the same event. Confirming it needs a replay (full version).
  NEVER-REACHES-MANAGER  no relative fired and the manager logged event loss (rules 203/204).
  NO-MATCH               a relative fired, or nothing suggests event loss.

The three-way split (shadowed / never reaches the manager / no match) is Kislley Rodrigues's.
Sibling precedence (Wazuh 4.x): higher level first; equal level, the one loaded first (file name
order across ruleset/rules and etc/rules, then order inside the file).
"""
import argparse, glob, gzip, json, os, re, sys, time

VERSION = "0.2.2"
URL_FULL = "https://vct.atkvn.com/rule-doctor.html"
CONTACT = "dongnx@atkvn.com"

BLK = re.compile(r'<rule\b[^>]*\bid="(\d+)"[^>]*>(.*?)</rule>', re.S | re.I)
LVL = re.compile(r'\blevel="(\d+)"', re.I)
IFS = re.compile(r'<if_sid>\s*([0-9,\s]+)\s*</if_sid>', re.I)
# measured on Wazuh 4.14.7 (26/09/2026):
#   WARNING: (7617): Signature ID '5715' was not found and will be ignored in the 'if_sid' option of rule '100080'.
#   WARNING: (7619): Empty 'if_sid' value. Rule '100080' will be ignored.
W7619 = re.compile(r"\(7619\).*?Rule '(\d+)' will be ignored")
W7617 = re.compile(r"\(7617\): Signature ID '(\d+)' was not found.*?rule '(\d+)'")

DROPPED, CANDIDATE, NEVER, NOMATCH = "DROPPED-AT-LOAD", "SHADOW-CANDIDATE", "NEVER-REACHES-MANAGER", "NO-MATCH"


def read_ruleset(stock_dir, custom_dir):
    files = []
    for d, mine in ((stock_dir, False), (custom_dir, True)):
        for f in glob.glob(os.path.join(d, "*.xml")):
            files.append((os.path.basename(f), f, mine))
    files.sort(key=lambda x: x[0])
    rules, idx, n_stock = {}, 0, 0
    for _, f, mine in files:
        try:
            txt = open(f, encoding="utf-8", errors="replace").read()
        except OSError:
            continue
        for m in BLK.finditer(txt):
            rid, body = m.group(1), m.group(2)
            lm = LVL.search(m.group(0)[:300])
            im = IFS.search(body)
            rules[rid] = {"level": int(lm.group(1)) if lm else None,
                          "parents": [p.strip() for p in im.group(1).split(",") if p.strip()] if im else [],
                          "file": os.path.basename(f), "load_order": idx, "custom": mine}
            idx += 1
            n_stock += 0 if mine else 1
    return rules, n_stock


def _open(p):
    """Rotated Wazuh logs are gzip-compressed (.gz); read them the same way as plain ones."""
    if p.endswith(".gz"):
        return gzip.open(p, "rt", encoding="utf-8", errors="replace")
    return open(p, encoding="utf-8", errors="replace")


def default_alerts(root, days):
    """Current alerts.json plus the rotated files (plain or .gz) modified in the last `days` days."""
    cur = glob.glob(os.path.join(root, "logs/alerts/*.json"))
    old = glob.glob(os.path.join(root, "logs/alerts/*/*/ossec-alerts-*.json*"))
    cutoff = time.time() - days * 86400
    return sorted(set(cur) | {f for f in old if os.path.getmtime(f) >= cutoff})


def read_alerts(paths):
    fired, first, last = set(), None, None
    for p in paths:
        try:
            fh = _open(p)
        except OSError:
            continue
        with fh:
            for line in fh:
                try:
                    o = json.loads(line)
                except ValueError:
                    continue
                rid = str(((o.get("rule") or {}).get("id")) or "")
                ts = o.get("timestamp") or ""
                if rid:
                    fired.add(rid)
                if ts:
                    first = ts if first is None or ts < first else first
                    last = ts if last is None or ts > last else last
    return fired, (first, last)


LOADED = re.compile(r"wazuh-analysisd: INFO: Total rules enabled")


def read_ossec_log(paths):
    """rule id -> reason, from the load-time warnings of the LATEST rule load in ossec.log.

    Each load writes its 7617/7619 warnings and then "Total rules enabled". Only the last
    completed load counts, so a warning from a load before you fixed the rule is not reported.
    Lines from `wazuh-analysisd -t` (wazuh-testrule) are ignored: they describe a test, not the
    running manager. Files are read oldest first.
    """
    last, pending = None, {}
    for p in sorted(paths, key=lambda f: os.path.getmtime(f) if os.path.exists(f) else 0):
        try:
            fh = _open(p)
        except OSError:
            continue
        with fh:
            for line in fh:
                if "wazuh-testrule" in line:
                    continue
                if LOADED.search(line):
                    last, pending = pending, {}
                    continue
                m = W7617.search(line)
                if m:
                    pending[m.group(2)] = "ossec.log 7617: parent %s not found when the rule loaded" % m.group(1)
                    continue
                m = W7619.search(line)
                if m and m.group(1) not in pending:
                    pending[m.group(1)] = "ossec.log 7619: empty if_sid, rule ignored"
    if pending:  # warnings after the last "Total rules enabled" belong to the newest load
        return pending
    return last or {}


def static_drops(rules, stock_read, known=None):
    """Custom rules whose if_sid parents are ALL unavailable at load time (Wazuh ignores the rule).

    Follows chains: a parent that is itself dropped is not there when its children load, so they
    are dropped too (Wazuh logs 7617/7619 for each of them). `known` holds drops already read from
    ossec.log, so a chain is also followed from a drop that only the log shows. Repeats until
    nothing changes.
    """
    known = dict(known or {})
    out = {}
    changed = True
    while changed:
        changed = False
        for rid, r in rules.items():
            if not r["custom"] or not r["parents"] or rid in out or rid in known:
                continue
            why = []
            for p in r["parents"]:
                if p in out or p in known:
                    why.append("parent %s is itself dropped at load" % p)
                elif p in rules:
                    if p == rid:
                        why.append("if_sid %s points to the rule itself" % p)
                    elif rules[p]["load_order"] > r["load_order"]:
                        if rules[p]["file"] == r["file"]:
                            why.append("parent %s is defined later in the same file %s" % (p, r["file"]))
                        else:
                            why.append("parent %s is in %s, which loads after %s" % (p, rules[p]["file"], r["file"]))
                    else:
                        break  # at least one parent is loaded already: the rule survives
                elif stock_read:
                    why.append("parent %s is not defined anywhere" % p)
                else:
                    break  # stock ruleset not read: cannot tell
            else:
                if why:
                    out[rid] = "predicted: " + "; ".join(why)
                    changed = True
    return out


def _before(a, b, rules):
    la, lb = rules[a]["level"], rules[b]["level"]
    if la is None or lb is None:
        return False
    return la > lb if la != lb else rules[a]["load_order"] < rules[b]["load_order"]


def classify(rules, fired, dropped):
    children = {}
    for rid, r in rules.items():
        for p in r["parents"]:
            children.setdefault(p, []).append(rid)
    loss = ("203" in fired) or ("204" in fired)
    out = {}
    for rid, r in rules.items():
        if not r["custom"] or rid in fired:
            continue
        if rid in dropped:
            out[rid] = (DROPPED, dropped[rid])
            continue
        shadow, relative = [], None
        for p in r["parents"]:
            if p in fired and relative is None:
                relative = ("parent", p)
            for s in children.get(p, []):
                if s == rid or s not in fired or s in dropped:
                    continue
                if relative is None:
                    relative = ("sibling", s)
                if _before(s, rid, rules):
                    shadow.append(s)
        if shadow:
            out[rid] = (CANDIDATE, "fired sibling(s) evaluated first: " + ", ".join(
                "%s (level %s)" % (s, rules[s]["level"]) for s in shadow[:3]))
        elif relative:
            out[rid] = (NOMATCH, "%s %s fired; this rule matched nothing" % relative)
        elif loss:
            out[rid] = (NEVER, "no relative fired and the manager logged event loss (203/204)")
        else:
            out[rid] = (NOMATCH, "no relative fired and no sign of event loss")
    return out, loss


def main(argv=None):
    ap = argparse.ArgumentParser(prog="rule-doctor-lite", description="ATK Rule Doctor Lite: why do my custom Wazuh rules never fire?")
    ap.add_argument("--version", action="version", version="rule-doctor-lite " + VERSION)
    ap.add_argument("--ossec-dir", default="/var/ossec", help="Wazuh install dir (default /var/ossec)")
    ap.add_argument("--alerts", action="append", help="alerts file(s) or glob(s), plain or .gz; default: current alerts.json plus rotated files of the last --days days")
    ap.add_argument("--days", type=int, default=7, help="how many days of rotated alerts to read by default (default 7)")
    ap.add_argument("--ossec-log", action="append", help="ossec.log file(s) or glob(s); default <ossec-dir>/logs/ossec.log")
    ap.add_argument("--json", help="also write a JSON report here")
    a = ap.parse_args(argv)

    root = a.ossec_dir
    if not os.path.isdir(root):
        sys.exit("rule-doctor-lite: %s not found; pass --ossec-dir" % root)
    alerts = sorted(f for pat in a.alerts for f in glob.glob(pat)) if a.alerts else default_alerts(root, a.days)
    logs = sorted(f for pat in (a.ossec_log or [os.path.join(root, "logs/ossec.log")]) for f in glob.glob(pat))

    rules, n_stock = read_ruleset(os.path.join(root, "ruleset/rules"), os.path.join(root, "etc/rules"))
    fired, (first, last) = read_alerts(alerts)
    logged = read_ossec_log(logs)
    dropped = static_drops(rules, n_stock > 0, logged)
    dropped.update(logged)  # the log, when present, beats the prediction
    res, loss = classify(rules, fired, dropped)

    n_custom = sum(1 for r in rules.values() if r["custom"])
    print("ATK Rule Doctor Lite %s — silent custom rules" % VERSION)
    print("measurement window: %s -> %s   (%d alerts file(s), %d ossec.log file(s))" % (first, last, len(alerts), len(logs)))
    print("rules read: %d (stock %d, custom %d)   rule ids that fired: %d   silent custom: %d   event loss (203/204): %s"
          % (len(rules), n_stock, n_custom, len(fired), len(res), "yes" if loss else "no"))
    if first is None:
        print("WARNING: no alerts read, so every custom rule looks silent. Only DROPPED-AT-LOAD below is a finding.")
    if n_stock == 0:
        print("WARNING: stock ruleset not read (%s/ruleset/rules); missing parents cannot be checked." % root)
    print()
    counts = {}
    for rid in sorted(res, key=int):
        lab, why = res[rid]
        counts[lab] = counts.get(lab, 0) + 1
        print("  %-8s level %-3s %-26s %-22s %s" % (rid, rules[rid]["level"], rules[rid]["file"], lab, why))
    print()
    print("totals: " + (", ".join("%s=%d" % kv for kv in sorted(counts.items())) or "no silent custom rules"))
    print("A rule written for a rare event is not dead after a short window: check the dates above.")
    if counts.get(DROPPED):
        print("DROPPED-AT-LOAD: rename the file so it sorts after the file holding the parent, or fix the if_sid.")
    if counts.get(CANDIDATE):
        print("SHADOW-CANDIDATE is not proven yet. The full ATK Rule Doctor replays real events through a")
        print("throwaway manager of your version to confirm or clear each one: " + URL_FULL)
    if res:
        print("Want it fixed for you? Rule Fix Pack, fixed price, you pay only after the fix fires on your cluster: " + CONTACT)
    if a.json:
        with open(a.json, "w") as fh:
            json.dump({"version": VERSION, "window": [first, last], "event_loss_signal": loss,
                       "results": {k: {"label": v[0], "why": v[1]} for k, v in res.items()}}, fh, indent=1)
        print("report written to " + a.json)


if __name__ == "__main__":
    main()
