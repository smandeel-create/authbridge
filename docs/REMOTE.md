# Using AuthBridge away from home (Tailscale)

The Mac daemon listens on `0.0.0.0:47900`, and every request is signed by the iPhone's Secure Enclave
key, with secrets sealed (X25519 + ChaCha20-Poly1305). So plain HTTP over a Tailscale tunnel is fine:
once both devices are on the same tailnet, the phone can reach the Mac on its Tailscale address.

The iPhone app keeps a list of Mac addresses (the LAN address you paired with comes first). It tries
the address that last worked first. If that address doesn't answer, it checks the others in order,
giving each about 2.5 s to accept a connection. Signatures don't depend on the host (the signed PATH
leaves the host out), so no re-pairing is needed.

## What you do

### On the Mac (one time)
1. Install Tailscale from the Mac App Store or from tailscale.com (or with Homebrew:
   `brew install --cask tailscale-app`).
2. Open **Tailscale** from /Applications. Allow the VPN / network extension when macOS asks:
   System Settings → General → Login Items & Extensions → Network Extensions → Tailscale on.
   Then **Log in** from the menu-bar icon.
3. In the menu-bar Tailscale → Settings, turn on **Launch at login** (or "Start on login").
4. In the Tailscale admin console (login.tailscale.com → DNS), make sure **MagicDNS** is enabled
   (it is on by default for new tailnets).
5. Note the Mac's Tailscale name (menu-bar icon → this device). For example `my-mac`.
   Also note its `100.x.y.z` address.
6. Optional: in the admin console → Machines → this Mac → **Disable key expiry**, so the Mac
   doesn't drop off the tailnet every 180 days.

### On the iPhone (one time)
1. Install **Tailscale** from the App Store and sign in with the **same account** (same tailnet)
   as the Mac. Allow the VPN configuration.
2. Open AuthBridge → **Requests** → ⋯ menu → **Mac addresses…** → add `my-mac`.
   Optionally add the `100.x.y.z` address too, as a fallback in case MagicDNS fails. A green tick
   means the address answers right now.
3. Test it: turn Wi-Fi off and make sure Tailscale is connected. Pull to refresh Requests and
   check there is no error.

### Day to day
- Leave Tailscale connected on the iPhone (or turn on its "VPN On Demand"). Push notifications go
  through APNs and work without Tailscale. **Approving** a request needs Tailscale.
- At home the LAN address is reached directly. When you're away, the app falls back to the
  Tailscale address on its own.

## Notes
- **The Mac must stay awake.** Disable system sleep: `sudo pmset -a sleep 0`, or in System Settings →
  Energy (Battery on laptops) turn on "Prevent automatic sleeping when the display is off". Display
  sleep is fine. `pmset -g` shows the current settings.
- **Tailscale must start at login on the Mac** (step 3 above). After a power cut, the Mac
  auto-restarts (if enabled in Energy settings) but needs a user login for both the authbridge LaunchAgent and the Tailscale app.
  So either enable automatic login, or accept that a reboot needs someone at the Mac.
- If the macOS application firewall is on, allow `node` (the daemon)
  to accept incoming connections, or the Tailscale address will time out.
- There's nothing to change in the daemon. It already accepts connections on every interface,
  including Tailscale's `utun`.
- Full MagicDNS names (`my-mac.tailXXXX.ts.net`) also work: the app's ATS exception
  allows plain HTTP to any host.
