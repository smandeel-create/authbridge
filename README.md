# AuthBridge

**Let Claude log in to websites for you, without ever seeing your passwords.**

When Claude (Claude Code with Claude in Chrome) hits a login page during a task you gave it, it asks
AuthBridge. Your iPhone shows the request, you approve it with Face ID, and the Mac fills in the
login in that Chrome tab. Claude only ever gets back a status such as `signed_in` or `denied`.

- **One Face ID approval per login.** Credentials can't be decrypted without a key share that
  only your iPhone releases, and only after Face ID or your passcode.
- **Email codes are handled.** If the site emails a verification code, the Mac reads it from your
  mailbox over read-only IMAP. SMS or authenticator-app codes are entered on the phone, with
  iOS AutoFill.
- **Strict domain matching.** A login is only filled into the top frame of an `https://` page on the
  exact domain it was saved for. The Mac checks this, and the page script checks it again just
  before filling.
- **Everything runs locally.** There's no server or cloud account, and nothing leaves your Mac or
  phone. The one exception is optional push notifications, which go through Apple's APNs and carry
  only the domain name.
- **Sites are added on first use.** The first time Claude needs a site, your phone asks you to pick
  the login. AutoFill from Apple Passwords works.

> **Status: personal project, unaudited.** It is used daily by its author on booking.com, Airbnb,
> Smoobu, PriceLabs and others. It has not had an independent security review. Read the
> [security model](#security-model), and use it at your own risk (MIT licence, no warranty).

## How it works

```
Claude Code ── MCP (request_login) ──► AuthBridge daemon on your Mac ◄── HTTP, signed + sealed ── iPhone app
                                         │   (Node, launchd)                                      (Face ID)
Chrome tab ◄── extension ◄─ native msg ──┘
                                         └── Secure Enclave helper, read-only IMAP for email codes
```

1. Claude calls `request_login(domain, tab_id, task)`.
2. The daemon checks the tab really is on that domain, then notifies your phone.
3. You approve with Face ID. The phone sends its key share for that site, sealed to the Mac.
4. The Mac combines that share with a Secure Enclave secret, decrypts the login in memory, fills
   it in through the extension, and handles any code steps.
5. Claude gets back `signed_in`, `denied`, `needs_more`, and so on, never the credential.

## Requirements

- **Mac:** Apple silicon or a T2 Intel Mac, for the Secure Enclave. You also need Node 20+,
  Google Chrome and Xcode (to build the iPhone app). Install
  [XcodeGen](https://github.com/yonaskolb/XcodeGen) with `brew install xcodegen`.
- **iPhone:** iOS 17+, with Face ID or a passcode set.
- **Claude Code**, with [Claude in Chrome](https://claude.ai/chrome) for the tabs.
- **An Apple Developer account:**
  - A **paid** account ($99/yr) gives you push notifications, and builds that don't expire.
  - A **free** Apple ID also works. There are no push notifications, so you open the app to see
    requests, and you have to rebuild the app every 7 days.
- The phone must be able to reach the Mac on TCP port 47900: the same Wi-Fi, or
  [Tailscale](docs/REMOTE.md) when you're away.

## Install

### 1. Mac

```bash
git clone https://github.com/smandeel-create/authbridge.git ~/code/authbridge
cd ~/code/authbridge
./install.sh
```

This installs the dependencies and builds the Secure Enclave helper. It then sets up the daemon
as a LaunchAgent (`com.authbridge.daemon`), the Chrome native-messaging host, the `authbridge` MCP
server for Claude Code, and the `website-login` skill. Run it again at any time; it's idempotent.

### 2. Chrome extension

1. Open `chrome://extensions` and turn on **Developer mode**.
2. Click **Load unpacked** and choose the `extension/` folder in the repo.
3. The extension ID is fixed (`dkajlimbibjhfcjjppjoidaiajckmbao`), so the native host already
   trusts it.

### 3. iPhone app

```bash
cd ios
cp Config.example.xcconfig Config.xcconfig
# edit Config.xcconfig: DEVELOPMENT_TEAM = your team ID, AB_BUNDLE_ID = com.yourname.authbridge
xcodegen generate
open AuthBridge.xcodeproj
```

Plug in your iPhone, select it as the run destination, and press Run. On a free account, trust
the developer certificate on the phone: Settings → General → VPN & Device Management.

> With a **free** account, delete the `aps-environment` entry from `AuthBridge.entitlements`
> before building. Free teams can't sign push notifications.

### 4. Pair the phone

```bash
node daemon/cli.mjs pair
```

Open AuthBridge on the phone and enter the Mac's local IP address (System Settings → Wi-Fi →
Details) and the pairing code. Allow local-network access when iOS asks. If the macOS firewall is
on, allow incoming connections for `node`.

### 5. Push notifications (paid account, optional)

1. In the Apple Developer portal, create an **APNs key**: Certificates, IDs & Profiles → Keys →
   + → Apple Push Notifications service. Download the `.p8` file.
2. Store it in the keychain and turn on push:

```bash
node daemon/cli.mjs push-setup --key-id ABC123DEFG --team-id YOURTEAMID \
  --bundle-id com.yourname.authbridge --p8 ~/Downloads/AuthKey_ABC123DEFG.p8
launchctl kickstart -k gui/$(id -u)/com.authbridge.daemon
node daemon/cli.mjs test-push
```

Builds from Xcode use the development APNs environment, which is the default. Add `--production`
only for TestFlight or App Store builds. After `push-setup`, delete the `.p8` file from Downloads:
the keychain has it now.

### 6. Email codes (optional)

AuthBridge can read verification codes from your mailbox. It needs an **app password**, not your
normal password; Yahoo, Gmail, iCloud and Fastmail can all create one.

```bash
node daemon/cli.mjs mail-add personal you@yahoo.com --provider yahoo
node daemon/cli.mjs mail-add work you@gmail.com --provider gmail
node daemon/cli.mjs mail-list
```

`security` prompts you for the password and stores it in the keychain (service
`authbridge-mail`), so it never appears in your shell history or in a file. Codes are only accepted
from the site's own domain, or a same-brand sibling such as `free-mobile.fr` for `free.fr`. Spam
and junk folders are checked too. If no mailbox is set up, or the code can't be found, the phone
asks you for it.

## Using it

Just give Claude a task on a website. When a Claude in Chrome tab lands on a login page, the
`website-login` skill tells Claude to call `request_login`. Claude tells you an approval is waiting
on your phone; you approve it and the task carries on.

The first time for a site, the approval screen asks for the login. Tap the username field and use
AutoFill from Passwords. If the site signs in by email but your username isn't an email, add the
email too (you can save your addresses in the app's ⋯ menu for one-tap filling).

In the app, swipe a site to edit or delete it. Editing doesn't need the password again.

Handy commands:

```bash
node daemon/cli.mjs status            # paired? extension connected? saved domains
node daemon/cli.mjs reload-extension  # after editing extension/
tail -f ~/.authbridge/daemon.log      # redacted log, no secrets
```

### What it can't do

- **CAPTCHAs and passkeys.** It stops with `needs_more`, and you finish that login yourself.
- **Very unusual login forms.** These return `unsupported_form`. Login pages change, and fixes are
  welcome.
- **Browsers other than Chrome.**

## Security model

Credential storage is split between the Mac and the phone:

- **Mac half:** a Secure Enclave key-agreement key gives a secret `S1` per site. The key can't be
  exported, even by root.
- **Phone half:** the phone holds a random 32-byte share `P` per site in its keychain, behind
  `.userPresence` (Face ID or passcode), on this device only.
- **Encryption:** the login is AES-256-GCM encrypted with `HKDF(S1 ‖ P, salt=record id,
  info=domain)`. A stolen Mac disk or backup is useless without the phone and your face, and the
  phone alone is useless without that Mac's Secure Enclave.

What the design protects against, and what it doesn't:

- **Claude never sees secrets.** The MCP tool only returns `{status, detail}`. Passwords, key
  shares and email codes are never logged, written to disk, put in URLs or returned over the socket.
  The logger redacts sensitive field names.
- **Phone-to-Mac traffic** is plain HTTP on your LAN or tailnet. That's safe because:
  - every request is signed by a Secure Enclave key on the phone, with timestamps and replay
    protection;
  - every secret is sealed to the Mac with X25519 + ChaCha20-Poly1305.
- **Domain binding:** a login is only filled into an `https` top frame whose hostname is the saved
  domain or a subdomain of it. Hidden, off-screen or zero-size decoy fields are ignored.
- **Prompt injection:** the skill tells Claude never to call `request_login` because a page or
  email asked it to. Even if it did, every login still needs your Face ID, and the phone shows the
  domain and task.
- **Out of scope:** a compromised Mac. Malware running as you could read the page after login, or
  keep an extension you loaded. AuthBridge reduces exposure (no stored plaintext, approval per
  login), but it can't defend a machine that's already owned.

The full protocol is in [SPEC.md](SPEC.md).

## Away from home

See [docs/REMOTE.md](docs/REMOTE.md) for setting up Tailscale, so you can approve logins from
anywhere. The phone can keep several Mac addresses and falls back between them automatically.

## Tests

```bash
npm test
```

This covers unit tests, an end-to-end run against a local test site, decoy-field tests in real
Chrome (Playwright), mail parsing, the native host and the MCP server.

## Uninstall

```bash
./uninstall.sh           # removes the LaunchAgent, native host, MCP server and skill; keeps ~/.authbridge
./uninstall.sh --purge   # also deletes ~/.authbridge (saved logins become unrecoverable)
```

Then delete the app from your phone, and remove the extension from `chrome://extensions`.

## Licence

MIT. See [LICENSE](LICENSE).
