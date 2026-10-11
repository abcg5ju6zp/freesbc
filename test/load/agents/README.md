# Agent prompts for the three-server run

One prompt per host, for a coding agent with a root shell on that host
(`s1.md` SIPp, `s2.md` FreeSBC, `s3.md` switches). Each is self-contained: the
lab table, the `env` block and the working rules are repeated in all three
and must stay identical.

Before pasting, replace the placeholders in every file: `S1_PUBLIC_IP1`,
`S1_PUBLIC_IP2`, `S1_PRIVATE_IP`, `S2_PUBLIC_IP1`, `S2_PUBLIC_IP2`,
`S2_PRIVATE_IP`, `S3_PRIVATE_IP`, `CHANGE_ME_ADMIN`, `CHANGE_ME_USERS`,
`SIGNALWIRE_PAT`. For example:

```sh
sed -i -e 's/S1_PUBLIC_IP1/198.51.100.10/g' -e 's/S1_PUBLIC_IP2/198.51.100.11/g' \
       -e 's/S1_PRIVATE_IP/10.77.0.30/g'   -e 's/S2_PUBLIC_IP1/203.0.113.7/g' \
       -e 's/S2_PUBLIC_IP2/203.0.113.8/g'  -e 's/S2_PRIVATE_IP/10.77.0.2/g' \
       -e 's/S3_PRIVATE_IP/10.77.0.20/g'   -e 's/CHANGE_ME_ADMIN/<admin pw>/g' \
       -e 's/CHANGE_ME_USERS/<user pw>/g'  -e 's/SIGNALWIRE_PAT/<pat or empty>/g' s1.md s2.md s3.md
```

The agents do not talk to each other. You relay between them at the
checkpoints each one prints (`CHECKPOINT <name>`).

## Order

| # | Host | Until | Then |
|---|---|---|---|
| 1 | S2 | steps 1-4 done (FreeSBC running against Asterisk, which is not up yet) | `s3-internet`: tell it whether S3 has internet |
| 2 | S3 | `need-proxy` (only without internet) | have S2 start its proxy (S2 step 5) |
| 3 | S3 | `s3-done`, `switches-up` | S2 stops the proxy; give S2 the S3 report |
| 4 | S2 | step 6 (collector, latency helper) | |
| 5 | S1 | `isolation`, `preflight-s2`, `smoke-gauges` | relay to S2, which checks the NIC and the gauges |
| 6 | S1 | test plan; per step `latency-<label>`; `switch-freeswitch`, `shield-default`, `shield-load` | S2 runs the matching `activate.sh` / `latency.sh` |
| 7 | all | `REPORT-<host>.md` under `/root/freesbc-lab/` | collect the three reports and the `results/` dirs |

## Address roles

`S1_PUBLIC_IP1` is the carrier and `S1_PUBLIC_IP2` the phones and agents
(README §2.4: one source IP cannot play both honestly). `S2_PUBLIC_IP1` is
FreeSBC's only public address; `S2_PUBLIC_IP2` and `S1_PRIVATE_IP` carry
management only. S3 accepts SIP and RTP from `S2_PRIVATE_IP` alone and drops
S1. Because all hosts share one LAN, every prompt sets `arp_ignore=1` /
`arp_announce=2`: without them S3 can learn the wrong MAC for
`S2_PRIVATE_IP`, and FreeSBC's private ingress filter then drops switch
traffic that arrives on the public NIC, with no log.
