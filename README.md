# AdShield

A system-wide ad & tracker blocker for Android — one toggle, a live counter, no root.

AdShield runs a **local, server-less VPN** on the device. It intercepts only DNS
lookups and answers `NXDOMAIN` for known ad/tracker domains, so ads can't load in
any app or browser. Everything else is forwarded untouched. **No traffic leaves
your phone through any server** — the "VPN" is entirely on-device. This is the
same approach used by DNS66, AdGuard, and Blokada.

## Features

- Single on/off master switch.
- Live count of blocked ads and total DNS requests seen.
- Blocklist seeded offline, then auto-updated from the
  [StevenBlack/hosts](https://github.com/StevenBlack/hosts) list (~150k domains).
- Foreground service with an ongoing notification while protecting.

## Get the APK (no local tools needed)

1. Push this repo to GitHub (branch `main`).
2. GitHub Actions builds it automatically — see the **Actions** tab.
3. Open the latest **Build APK** run → download the **`adshield-debug-apk`**
   artifact → unzip → `app-debug.apk`.
4. Copy it to your Android phone and install (allow "install from unknown
   sources" when prompted). On first launch, approve the VPN consent dialog.

You can also trigger a build manually from **Actions → Build APK → Run workflow**.

## Build locally (optional)

Requires Android Studio (bundles JDK 17 + SDK + Gradle). Open the project and
run, or:

```bash
./gradlew assembleDebug   # after generating the Gradle wrapper
```

## How it works

```
App makes DNS query ──► virtual DNS 10.0.0.53 (routed into our tun)
                          │
                   AdVpnService reads the domain
                          │
        ┌─────────────────┴─────────────────┐
   on blocklist?                        not blocked
        │                                    │
  reply NXDOMAIN                     forward to 8.8.8.8,
  (ad never loads)                    relay answer back
```

Only the virtual DNS address (`10.0.0.53/32`) is routed into the tunnel, so
normal traffic is never proxied and browsing stays fast.

## Limitations

- Can't block ads served from an app's **own** domain (e.g. some YouTube ads).
- Apps that hardcode their own DNS resolver bypass the system DNS.
- Not on Google Play (ad blockers are disallowed there) — sideload only.

## License

MIT. Blocklist data © their respective maintainers.
