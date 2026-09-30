# Home Network Visibility & Anomaly Detection Dashboard

A local dashboard for monitoring devices on your own home network: live
device discovery, new-device alerting, DNS-level activity visibility, and
exportable audit logs. Built as a learning project in defensive network
monitoring — the kind of visibility a small home network otherwise lacks
by default.

## What it does

- **Device discovery** — periodic `nmap` scans identify every device
  currently on the network (IP, MAC address, vendor).
- **Device history** — a local SQLite database tracks every MAC address
  ever seen, with first-seen/last-seen timestamps and an optional
  human-readable name you assign.
- **New device alerting** — any MAC address seen for the first time is
  flagged in the UI. This is the core primitive behind rogue-device /
  unauthorized-access detection on a home network.
- **DNS-level activity visibility** — integrates with a local
  [AdGuard Home](https://adguard.com/en/adguard-home/overview.html)
  instance to show which domains each device has been contacting.
  This is domain metadata only (see **Scope and limitations** below).
- **Network health summary** — an at-a-glance panel (devices online,
  total known devices, new devices this scan, DNS query/block counts).
- **CSV export** — device history and activity logs can be exported for
  offline review, matching how audit trails are typically expected to
  work in security tooling.
- **Basic auth on the dashboard itself** — the dashboard is protected by
  a username/password so it isn't wide open to anyone else on the LAN.

## Architecture

```
 ┌────────────┐     nmap -sn      ┌──────────────┐
 │   Flask     │ ───────────────▶ │ Local network │
 │  (app.py)   │                  └──────────────┘
 │             │
 │             │   REST API        ┌──────────────┐
 │             │ ───────────────▶ │ AdGuard Home  │
 │             │                  │ (DNS logs)    │
 │             │                  └──────────────┘
 │             │
 │             │   read/write      ┌──────────────┐
 │             │ ───────────────▶ │ SQLite         │
 └────────────┘                   │ (devices.db)  │
                                   └──────────────┘
```

- `app.py` — Flask backend: scanning loop, device history, AdGuard API
  client, CSV export, basic auth.
- `templates/index.html` — single-page dashboard UI (vanilla JS, no
  build step).
- `config.py` — your real configuration (git-ignored). Copy from
  `config.example.py`.
- `devices.db` — SQLite database of device history (git-ignored,
  created automatically on first run).

## Setup

1. Install [Nmap](https://nmap.org/download.html) and add it to your PATH.
2. Install [AdGuard Home](https://github.com/AdguardTeam/AdGuardHome)
   locally and note the admin credentials you set during its setup wizard.
3. Clone this repo, then:
   ```
   pip install -r requirements.txt
   cp config.example.py config.py
   ```
4. Edit `config.py`:
   - `NETWORK_RANGE` — your LAN subnet (check with `ipconfig` / `ifconfig`)
   - `ADGUARD_USERNAME` / `ADGUARD_PASSWORD` — your AdGuard admin login
   - `DASHBOARD_USERNAME` / `DASHBOARD_PASSWORD` — credentials to protect
     this dashboard itself
5. Run (as Administrator on Windows, so nmap can resolve MAC addresses):
   ```
   python app.py
   ```
6. Open `http://127.0.0.1:5000` and log in with your dashboard credentials.

## Scope and limitations (read before extending)

This project is intentionally scoped to **passive, metadata-level
visibility** on a network you own or administer:

- It discovers devices and reads **which domains** they contact via DNS.
  It does **not** intercept, decrypt, or inspect any traffic content —
  that's a deliberate boundary. The vast majority of real traffic is
  HTTPS-encrypted, so content-level inspection isn't something this
  tool attempts or is designed to grow into.
- It does not perform ARP spoofing, deauthentication, or any
  man-in-the-middle technique to reroute other devices' traffic.
  Those techniques attack the network connection itself rather than
  observing traffic you're already the legitimate resolver for, and
  are out of scope for this project by design.
- It's built for use on a network you personally own/administer. Using
  it (or any similar tool) to covertly monitor a specific person's
  activity without their knowledge raises real legal and ethical
  concerns that vary by relationship and jurisdiction — this project
  does not address or condone that use case.

## Possible extensions

- Anomaly detection: flag a burst of new devices in a short window, or
  a MAC vendor mismatch against expected device types.
  a lightweight baseline/deviation model (a real IDS building block)
  if extended to track bandwidth or ping latency over time.
- Notifications (email/webhook) on new-device detection.
- Scheduled reports (daily/weekly CSV summary via email).

## Why this project

Built as a hands-on introduction to network visibility and defensive
monitoring concepts: device discovery, DNS-level telemetry, anomaly
flagging, and audit logging — the same fundamental building blocks
behind commercial network security and SOC tooling, at a scale that's
learnable and self-hostable.