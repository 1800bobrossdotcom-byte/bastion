# Bastion Agent Token Distribution

## First Run: Auto-Generation

When a user **first runs the bastion agent** after download, it automatically generates a **32-byte hex authentication token** and stores it locally:

```
%APPDATA%\bastion\bastion\data\token.txt
```

This file contains the token in plaintext (hex format, 64 characters).

### Token Generation Flow

1. Agent starts → checks if token file exists
2. If missing → generates via `rand::thread_rng().fill_bytes()` (cryptographically secure random)
3. Encodes as hex string (uppercase)
4. Writes to `%APPDATA%\bastion\bastion\data\token.txt`
5. Prints to stdout on startup: `[ok] agent token: 0abc123def456...`

## Dashboard Setup: Pasting the Token

When the user **opens the dashboard** (browser at `http://127.0.0.1:7878`), they see:

```
[auth] paste agent bearer token
agent stdout, also: %APPDATA%\bastion\bastion\data\token.txt
```

The user either:
- **Copy from terminal**: Grab the token printed in the agent startup output
- **Copy from file**: Open `%APPDATA%\bastion\bastion\data\token.txt` and paste the contents
- **Type manually**: Copy-paste the 64-char hex string

Once pasted into the password field and localStorage is set, the dashboard authenticates all API calls with:

```
Authorization: Bearer <TOKEN>
```

## Security Properties

- **Token is local-only**: Never sent to any cloud service (unless user intentionally configures a Sentinel connector with their own Azure credentials)
- **No network auth**: Agent only listens on `127.0.0.1:7878` (localhost), not exposed to the internet by default
- **Persistent**: Token survives app restarts; only regenerated if the `token.txt` file is deleted
- **Per-installation**: Each bastion installation gets a unique token

## Download & Distribution

When you distribute bastion via a website:

1. **Pre-build**: Release the `.exe` or `.zip` containing the agent + dashboard
2. **No token included**: Token is generated fresh on first run per installation
3. **User-facing docs**: Include a README explaining:
   - "Run bastion-agent.exe first"
   - "Copy the token from the startup output or from `%APPDATA%\bastion\bastion\data\token.txt`"
   - "Paste into the dashboard when it opens"
4. **Optional**: Provide a shortcut batch file that runs the agent, displays the token, and waits for user input

## Sentinel Integration + Token

If the user configures **Microsoft Sentinel pull mode**, the flow is:

1. Agent stores Sentinel workspace details in local SQLite (`connectors` table)
2. Dashboard calls `/api/connectors/sentinel/auth-status` to check Azure CLI auth
3. User runs `az login` (separate Azure CLI auth, independent of bastion token)
4. Pull endpoint uses `az account get-access-token` to authenticate ARM API calls
5. **Bastion token still required** to authenticate the user's browser → agent API calls

This means:
- **Bastion token**: Secures the dashboard UI ↔ agent channel
- **Azure CLI token**: Authenticates the agent's Sentinel API calls to Azure

Both are independent and required for full functionality.

## Token Rotation

To rotate the token:
1. Delete `%APPDATA%\bastion\bastion\data\token.txt`
2. Restart the agent → new token generated
3. Update the dashboard by pasting the new token

---

**TL;DR for website copy:**

> Bastion generates a unique security token on first run. Copy it from the startup message or from `%APPDATA%\bastion\bastion\data\token.txt`, then paste it into the dashboard prompt. This token is only used locally and never leaves your computer.
