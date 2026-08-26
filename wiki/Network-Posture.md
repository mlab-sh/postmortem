# Machine network posture

A [`system`](System) backend, and one of the [Windows](Windows) layers — the
only one that is **off by default**. It reads incident-response material rather
than supply-chain material, so it is asked for:

```bash
postmortem system --manager network --deep
```

Without `--deep` the layer refuses rather than quietly returning nothing.

## What is read

| Reading | Finding | Severity |
| --- | --- | --- |
| A non-comment line in `hosts` | A name redirected by hand | Medium |
| A system-wide WinHTTP proxy | | Medium |
| A `netsh` port proxy | A pivot on the machine itself | High |
| A DNS-over-HTTPS resolver Windows does not ship | | High |
| A root certificate issued in the last three years | | Medium |
| An inbound firewall rule for a non-Windows program | Recorded | Info |

## Three readings that need calibrating

### DNS-over-HTTPS

A stock machine has **12** DoH servers configured, and every one is a template
Windows ships — Quad9, Google, Cloudflare. A resolver worth reporting is one
that is not among them.

### Firewall rules

**156** inbound Allow rules are enabled, of which **138 carry a `Group`** — they
belong to a Windows feature. The **18** without one are the third-party
applications: browsers, games, launchers. They are recorded at `Info` and scored
at nothing; what admits them is ordinary desktop software.

### Root certificates — what postmortem cannot tell you

A trusted root CA is what makes TLS interception invisible, so it belongs here.
But **postmortem cannot separate a root that shipped with Windows from one that
was added**, offline:

- **Issuer names do not work.** Microsoft's own roots sign as `O=MSFT`,
  `O=Microsoft Trust Network`, and even
  `CN=Symantec Enterprise Mobile Root for Microsoft`. Any exclusion list built
  from what you happen to see misses the rest.
- **The `AuthRoot` thumbprint list does not work either.** 12 of a stock
  machine's 39 roots are absent from it — and all 12 are Microsoft roots built
  into the OS. `AuthRoot` holds the auto-updated third-party program, not the
  shipped set.

What *is* measurable is **age**. The most recently issued legitimate root on the
reference machine dates from 2021 — six years old. A root generated in the last
three years has the shape of an interception CA, and that is the only claim made.

The store size is reported as a caveat so the limitation is stated rather than
implied:

```
39 certificates are trusted as root CAs. postmortem cannot tell offline which of
them shipped with Windows and which were added, so only those issued in the last
three years are reported
```

## Not covered yet

Listening sockets bound to an unsigned binary (`Get-NetTCPConnection` joined to
its owning process), IP Helper and 6to4 configuration.
