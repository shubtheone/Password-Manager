# Family Vault – Password & Notes Manager

A self-hosted password and notes manager for your family. Data is stored in JSON files and encrypted with AES-256-GCM using a key derived from your keyword. Runs on Node.js so you can host it on a tablet via Termux and access it from your laptop over Tailscale.

## Features

- **Profiles** – Netflix-style profile picker; each family member has their own profile.
- **Keyword** – One keyword per profile: used to unlock the profile and derive an encryption key. Not stored in plain text; only a secure hash is saved for verification.
- **Passwords** – Store entries with URL, username, password, email, extra info. Search by URL or extra info. Built-in strong password generator.
- **Notes** – Title and description. Search by title.
- **JSON storage** – All vault data is in `data/vaults/<userId>.json`, encrypted so that without the keyword the files are unreadable.

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

### 2. Tailscale (tablet + laptop)

- On both tablet and laptop: install [Tailscale](https://tailscale.com/download) and sign in to the same Tailscale account.
- On the tablet: note its Tailscale IP (e.g. `100.x.x.x`) in the Tailscale app or in Termux with `ifconfig` / `ip addr`.
- On the laptop: open the browser and go to `http://100.x.x.x:3000` (use the tablet’s Tailscale IP and the port you used, e.g. `3000`).

You can also use a Tailscale hostname if you’ve enabled MagicDNS (e.g. `http://tablet-name:3000`).

### 3. Run in background on Termux

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
├── crypto-utils.js    # User hash, AES-GCM encrypt/decrypt, vault read/write
├── data/
│   ├── users.json      # Profile list + keyword hashes (no plain keywords)
│   └── vaults/
│       └── <userId>.json   # AES-GCM encrypted vault (passwords + notes)
├── public/
│   ├── index.html
│   ├── style.css
│   └── app.js
├── package.json
└── README.md
```

## Security notes

- **Keyword**: Choose a strong, unique keyword per profile. It is never stored; only a scrypt hash is saved for verification.
- **Encryption**: Vault files are encrypted with AES-256-GCM and include an authentication tag, so tampering and wrong-key decrypt attempts fail safely.
- **HTTPS**: Over Tailscale the connection is encrypted. If you expose the app on a normal LAN only, use it on a trusted network.
- **Session**: The keyword is kept in server memory only for the duration of the session and is used to encrypt/decrypt on the server. Log out when leaving the device.
- **Brute-force protection**: Login attempts are rate limited per IP/profile with temporary lockout after repeated failures.

## Optional: environment variables

- `PORT` – Port to listen on (default `3000`).
- `SESSION_SECRET` – Secret for signing session cookies (default: random at startup). Set a fixed value in production for stable sessions across restarts.

Example:

```bash
PORT=3000 SESSION_SECRET=your-secret-here node server.js
```

---

You can now create profiles for each family member, store passwords and notes, and access the vault from your laptop via your tablet’s Tailscale IP.
