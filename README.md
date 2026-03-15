# Family Vault – Password & Notes Manager

## How it works (flowchart)

![Flowchart of how Family Vault works](Images/Screenshot%202026-03-15%20003842.png)

---

A self-hosted password and notes manager for your family. Data is stored in JSON files and encrypted with AES-256-GCM using a key derived from your keyword. Runs on Node.js so you can host it on a tablet (e.g. via Termux) and access it from other devices on the same WiFi, or over Tailscale for remote access.

## Features

- **Profiles** – Netflix-style profile picker; each family member has their own profile.
- **Keyword** – One keyword per profile: used to unlock the profile and derive an encryption key. Not stored in plain text; only a secure hash is saved for verification.
- **Passwords** – Store entries with URL, username, password, email, extra info. Search by URL or extra info. Built-in strong password generator.
- **Notes** – Title and description. Search by title.
- **JSON storage** – All vault data is in `data/vaults/<userId>.json`, encrypted so that without the keyword the files are unreadable.

## Import passwords from Brave (or Chrome)

You can export saved passwords from Brave (or Chrome) as a CSV file and import them into Family Vault.

1. **Export from Brave**
   - Open Brave → **Settings** (or `brave://settings/passwords`).
   - Go to **Passwords** (under “Autofill” or “Additional settings”).
   - Click the **⋮** menu next to “Saved passwords” → **Export passwords**.
   - Confirm with your device login if asked, then save the CSV file.

2. **Import into Family Vault**
   - Log in to your profile in Family Vault.
   - Open **Settings** (gear icon) → under **Import from browser**, click **Import from CSV (Brave/Chrome)**.
   - Choose the CSV file you exported. All rows (url, username, password, and optional name) are added to your Passwords list.

**Security:** The CSV file is plain text. After importing, delete the CSV from your device and don’t share it.

## How it works

1. **Create a profile** – Name + keyword (min 4 characters). The keyword is hashed with scrypt and never stored in plain text.
2. **Open a profile** – Click a profile and enter the keyword. The server verifies the hash and keeps the keyword in the session only for that browser session.
3. **Vault** – Passwords and notes are stored in a JSON structure, then encrypted with AES-256-GCM using a key derived from the keyword (scrypt) and written to `data/vaults/<userId>.json`.
4. **Legacy migration** – If an older XOR-formatted vault is detected, it is decrypted once with the correct keyword and re-saved automatically in AES-GCM format.

## Run locally (PC)

```bash
cd "d:\projects\password manager"
npm install
npm start
```

Open http://localhost:3000

## Host on tablet (Termux) and access via Tailscale

### 1. Termux (tablet)

- Install [Termux](https://termux.dev/) from F-Droid (recommended) or the official site.
- Open Termux and update packages:
  ```bash
  pkg update && pkg upgrade
  ```
- Install Node.js:
  ```bash
  pkg install nodejs
  ```
- Copy the project to the tablet (e.g. with `scp`, Syncthing, or USB). Example from your PC (replace with your tablet’s Tailscale IP and path):
  ```bash
  scp -r "d:\projects\password manager" 100.x.x.x:~/family-vault
  ```
- On the tablet in Termux:
  ```bash
  cd ~/family-vault
  npm install
  node server.js
  ```
  Or run on a specific port:
  ```bash
  PORT=3000 node server.js
  ```
  The app listens on `0.0.0.0`, so it’s reachable from other devices on the same network (and over Tailscale).

### 2. Access over WiFi (no Tailscale)

Anyone on the **same WiFi** as the tablet can use Family Vault without Tailscale:

1. **On the tablet:** After starting the server, find its local IP address:
   - In Termux: run `ip addr` or `ifconfig` and look for the WiFi interface (often `wlan0`). The IP is something like `192.168.1.105` or `192.168.0.42`.
   - Or in Android: **Settings → Network & internet → (your WiFi) → Details** and note the IP address.
2. **On any device connected to the same WiFi** (phone, laptop, another tablet): Open a browser and go to:
   ```
   http://<tablet-ip>:3000
   ```
   Example: `http://192.168.1.105:3000`

No Tailscale or internet required—only the local WiFi. Restrict who can join your WiFi if you want to limit who can reach the server.

### 3. Tailscale (tablet + laptop, for remote access)

- On both tablet and laptop: install [Tailscale](https://tailscale.com/download) and sign in to the same Tailscale account.
- On the tablet: note its Tailscale IP (e.g. `100.x.x.x`) in the Tailscale app or in Termux with `ifconfig` / `ip addr`.
- On the laptop: open the browser and go to `http://100.x.x.x:3000` (use the tablet’s Tailscale IP and the port you used, e.g. `3000`).

You can also use a Tailscale hostname if you’ve enabled MagicDNS (e.g. `http://tablet-name:3000`).

### 4. Run in background on Termux

- To keep the server running after closing Termux, use something like `nohup` or a simple loop:
  ```bash
  cd ~/family-vault
  nohup node server.js > server.log 2>&1 &
  ```
- To stop it later:
  ```bash
  pkill -f "node server.js"
  ```

## Project layout

```
password manager/
├── server.js           # Express server and API
├── crypto-utils.js     # User hash, AES-GCM encrypt/decrypt, vault read/write
├── .env.example        # Example env vars (copy to .env and edit)
├── data/
│   ├── users.json     # Profile list + keyword hashes (no plain keywords)
│   └── vaults/
│       └── <userId>.json   # AES-GCM encrypted vault (passwords + notes)
├── public/
│   ├── index.html
│   ├── style.css
│   └── app.js
├── package.json
└── README.md
```

## Forgotten keyword

**The main keyword is never stored.** Only a one-way hash is saved for verification, and the vault is encrypted with a key derived from the keyword.

- **If they set a recovery keyword at signup:** They can use **Forgot keyword?** on the login screen: enter the recovery keyword and a new main keyword. **All passwords and notes are kept.** No data is wiped.
- **If they never set a recovery keyword:** You can use **Dev recovery** (see below) to reset the profile so they can log in again with a new keyword. **That reset wipes the vault** (empty); old data cannot be recovered. So encourage family members to set an optional recovery keyword when creating their profile.

## Dev recovery (reset profile after forgotten keyword)

Optional. Only available when you set `DEV_RECOVERY_SECRET`. If you don’t set it, the reset endpoint is not registered.

**Using a `.env` file (recommended):**

1. Copy the example env file and add your recovery secret:
   ```bash
   cp .env.example .env
   ```
   Edit `.env` and set (uncomment and change the value):
   ```
   DEV_RECOVERY_SECRET=your-recovery-secret-phrase
   ```
   The server loads `.env` on startup (via `dotenv`). Do **not** commit `.env`; it is in `.gitignore`.

2. Get the profile’s **userId** from `data/users.json` (the `id` field of the user).

3. Call the reset endpoint. Use a **new keyword** that meets the app’s rules (length, upper, lower, number, symbol).

   **PowerShell (Windows):**
   ```powershell
   Invoke-RestMethod -Method POST -Uri "http://localhost:3000/api/dev/reset-profile" -ContentType "application/json" -Body '{"secret":"your-recovery-secret-phrase","userId":"THE-UUID","newKeyword":"NewSecure1!"}'
   ```
   Replace `your-recovery-secret-phrase`, `THE-UUID`, and `NewSecure1!` with your `.env` secret, the user’s id from `users.json`, and the new keyword.

   **curl (Git Bash / WSL / Linux / macOS):**
   ```bash
   curl -X POST http://localhost:3000/api/dev/reset-profile \
     -H "Content-Type: application/json" \
     -d "{\"secret\": \"your-recovery-secret-phrase\", \"userId\": \"THE-UUID\", \"newKeyword\": \"NewSecure1!\"}"
   ```

4. That profile can now log in with the new keyword. Their vault is **empty**; old data cannot be recovered.

**Without `.env`:** You can still set the variable in the shell before starting the server (e.g. `set DEV_RECOVERY_SECRET=...` on Windows, `export DEV_RECOVERY_SECRET=...` on Linux/macOS).

## Security notes

- **Keyword**: Choose a strong, unique keyword per profile. It is never stored; only a scrypt hash is saved for verification.
- **Encryption**: Vault files are encrypted with AES-256-GCM and include an authentication tag, so tampering and wrong-key decrypt attempts fail safely.
- **HTTPS**: Over Tailscale the connection is encrypted. If you expose the app on a normal LAN only, use it on a trusted network.
- **Session**: The keyword is kept in server memory only for the duration of the session and is used to encrypt/decrypt on the server. Log out when leaving the device.
- **Brute-force protection**: Login attempts are rate limited per IP/profile with temporary lockout after repeated failures.

## Configuration (.env)

Optional. Create a `.env` file in the project root (copy from `.env.example`) to set:

- **PORT** – Port to listen on (default `3000`).
- **SESSION_SECRET** – Secret for signing session cookies (default: random at startup). Set a fixed value for stable sessions across restarts.
- **DEV_RECOVERY_SECRET** – *(Optional.)* If set, enables the dev-only `POST /api/dev/reset-profile` endpoint to reset a profile’s keyword (vault is wiped). **Leave unset or omit to disable recovery**; the route will not be registered.

The server loads `.env` automatically on start. Do not commit `.env` (it is listed in `.gitignore`). See **Dev recovery** above for how to use `DEV_RECOVERY_SECRET`.

---

You can now create profiles for each family member, store passwords and notes, and access the vault from your laptop via your tablet’s Tailscale IP.
