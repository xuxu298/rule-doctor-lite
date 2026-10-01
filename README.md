# ATK Rule Doctor Lite: why do my custom Wazuh rules never fire?

A free, read-only check for Wazuh 4.x. It lists every custom rule that did not fire and tells you the most likely reason, including rules that **Wazuh silently threw away while loading them**.

One Python 3 file, standard library only. It reads files; it changes nothing on your manager and sends nothing anywhere.

```bash
curl -sLO https://github.com/xuxu298/rule-doctor-lite/releases/latest/download/rule-doctor-lite.py
sudo python3 rule-doctor-lite.py                 # on the manager, reads /var/ossec
python3 rule-doctor-lite.py --ossec-dir ./copy   # or on a copy of /var/ossec
```

Or from PyPI (same file, with a `rule-doctor-lite` command):

```bash
pipx install rule-doctor-lite                    # or pip install rule-doctor-lite inside a venv
sudo "$(command -v rule-doctor-lite)"             # on the manager, reads /var/ossec
```

Manager in docker? Copy the four things it reads, then point `--ossec-dir` at the copy:

```bash
C=single-node-wazuh.manager-1; mkdir -p copy/ruleset copy/etc copy/logs/alerts
docker cp $C:/var/ossec/ruleset/rules copy/ruleset/ && docker cp $C:/var/ossec/etc/rules copy/etc/
docker cp $C:/var/ossec/logs/ossec.log copy/logs/ && docker cp $C:/var/ossec/logs/alerts/alerts.json copy/logs/alerts/
```

## What the labels mean

| label | meaning |
|---|---|
| `DROPPED-AT-LOAD` | Wazuh ignored the rule at load time: its `if_sid` parent was not loaded yet (the file name sorts before the parent's file, or the parent is defined later in the same file), points to the rule itself, or does not exist. The manager still starts and `wazuh-analysisd -t` still exits 0; the only trace is warnings 7617/7619, printed by `-t` and written to `ossec.log`, that nothing fails on. Read from `ossec.log` when present, otherwise predicted from the load order. Chains are followed: a rule whose parent was itself dropped is dropped too, however deep. |
| `SHADOW-CANDIDATE` | a sibling that Wazuh evaluates first (higher level, or same level and loaded earlier) did fire. **A candidate, not a finding:** it proves the sibling matched something, not that your rule would have matched the same event. |
| `NEVER-REACHES-MANAGER` | no related rule fired and the manager logged event loss (rules 203/204). Only loss that raised 203/204 is seen: an agent with its client buffer off, or a manager dropping events at its EPS limit, raises neither, and Lite then says `NO-MATCH`. |
| `NO-MATCH` | a related rule fired but this one did not, or nothing suggests event loss. |

The shadowed / never-reaches-the-manager / no-match split is Kislley Rodrigues's.

**`LOCATION-ANCHORED`** (0.2.3) is a separate list, not a silence label: custom rules whose `<location>` is anchored at the start of a path, like `^/var/log/auth.log`. An agent that reads host logs through a mount, for example `/hostfs` in a containerised agent, reports `location` as `/hostfs/var/log/auth.log`. Measured on Wazuh 4.14.7 with `wazuh-logtest`: `<location>/var/log/auth.log</location>` still fires (it is a substring match), `<location>^/var/log/auth.log</location>` does not. Not yet measured with a live containerised agent. The idea comes from Mattias Hemmingsson's [wazuh-help](https://github.com/samma-io/wazuh-help) notes on running agents in containers.

Every result is printed with the time window it was measured over. A rule written for a quarterly event is not dead after a day.

**What it reads by default** (0.2.1): the current `logs/alerts/alerts.json` plus the rotated alert files of the last 7 days (`logs/alerts/<year>/<Mon>/ossec-alerts-<dd>.json`, plain or `.gz`, as Wazuh writes them); change the window with `--days N`. From `ossec.log` it takes the 7617/7619 warnings of the **latest** rule load only (the block before the last `Total rules enabled`), so a rule you already fixed is not reported from an older load, and lines from `wazuh-analysisd -t` are ignored.

## Tested on a real manager

`wazuh/wazuh-manager:4.14.7`, 27/09/2026. Two identical custom rules on `if_sid 5715`, one in `0094-test.xml` (sorts before the stock `0095-sshd_rules.xml`), one in `0500-ok.xml`. A real `sshd` "Accepted password" event fired `100081` from `0500-ok.xml`; `100080` in `0094-test.xml` never fired. Rule Doctor Lite reported:

```
100080   level 10  0094-test.xml   DROPPED-AT-LOAD   ossec.log 7617: parent 5715 not found when the rule loaded
```

and, with `ossec.log` withheld, the same verdict from the load order alone:

```
100080   level 10  0094-test.xml   DROPPED-AT-LOAD   predicted: parent 5715 is in 0095-sshd_rules.xml, which loads after 0094-test.xml
```

### Chains (0.2.0, 28/09/2026)

Same image. Anchor `910010` on `if_sid 5715` in `0094-early.xml`, child `910012` on `if_sid 910010` and grandchild `910013` on `if_sid 910012` in `0500-chain.xml`. `wazuh-analysisd -t` exited 0; `ossec.log` had 7617 + 7619 for all three, each naming the rule above it as the missing parent. Lite, with `ossec.log` withheld:

```
910010   level 10  0094-early.xml   DROPPED-AT-LOAD   predicted: parent 5715 is in 0095-sshd_rules.xml, which loads after 0094-early.xml
910012   level 10  0500-chain.xml   DROPPED-AT-LOAD   predicted: parent 910010 is itself dropped at load
910013   level 12  0500-chain.xml   DROPPED-AT-LOAD   predicted: parent 910012 is itself dropped at load
```

The prediction matters because `ossec.log` can miss warnings: analysisd buffers the warnings of each rules file in a list capped at 50 (`ERRORLIST_MAXSIZE`) and flushes it after the file, so a file that produces more than 50 warnings loses the oldest ones (`src/analysisd/analysisd.c` L708-750 on v4.14.7).

`tests/run.sh` runs the fixture checks without docker.

## Limits

- Wazuh 4.x rule syntax. Only `if_sid` parents are read; `if_group`, `if_matched_sid` and `if_matched_group` are not followed yet.
- `NEVER-REACHES-MANAGER` only sees loss that raised rule 203 or 204 (see the table above).
- `SHADOW-CANDIDATE` needs a replay to confirm or clear. Lite does not replay.
- "Never fired" means never fired in the alerts it read (7 days by default). Older alerts need `--days` or `--alerts`.

## Guides

Step-by-step notes for what Lite points at, each with a one-minute check you can run yourself (measured on Wazuh 4.14.7):

- [Wazuh rule dropped at load: 7617 and 7619, while `wazuh-analysisd -t` exits 0](https://atkvn.com/fix-rule-dropped-at-load-7617-7619.html?src=gh)
- [Wazuh rule matches in wazuh-logtest but never fires in production](https://atkvn.com/fix-rule-passes-logtest-but-never-fires.html?src=gh)
- [Wazuh rule shadowed by a sibling rule](https://atkvn.com/fix-rule-shadowed-by-sibling.html?src=gh)
- [mapper_parsing_exception: the alert is in alerts.json but never reaches the dashboard](https://atkvn.com/fix-mapper-parsing-exception.html?src=gh)
- [Wazuh "Cannot read 'srcip' from data"](https://atkvn.com/fix-cannot-read-srcip-from-data.html?src=gh)
- [Wazuh rule with `<hostname>` matches in logtest but never fires for agent events](https://atkvn.com/fix-hostname-rule-never-fires-for-agent-events.html?src=gh)

## Full version and done-for-you fixes

- **Silent Rule Review** (USD 49, refunded if it finds nothing): send the `--json` report and your custom rule files, and within one business day you get a written note on every silent rule, why it does not fire and what to change: https://vct.atkvn.com/rule-doctor.html?src=gh#review
- **ATK Rule Doctor** (USD 490 per cluster per year) replays the real events behind every `SHADOW-CANDIDATE` through a throwaway manager of your version to confirm or clear it, and fixes alerts the indexer rejects with `mapper_parsing_exception`: https://vct.atkvn.com/rule-doctor.html
- **Rule Fix Pack**: we fix a silent rule or a mapping conflict on your version, fixed price, and you pay only after the fix fires on your cluster. Write to dongnx@atkvn.com.

Licence: Apache-2.0. Made by ATK New Technology, Hanoi.
