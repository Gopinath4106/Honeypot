# Honeypot Deployment & Local Lab Runbook

## 1. Safety & Ethical Operations Protocol

> [!CAUTION]
> **CRITICAL SECURITY RULES**:
> 1. **Do NOT expose the honeypot to the public internet** without a hardened, isolated DMZ or dedicated evaluation network.
> 2. **Never implement automated retaliation or offensive probing** against attacking IP addresses.
> 3. Honeypots are purely passive deception traps designed to log unauthorized telemetry safely.

---

## 2. Supported Honeypot Modes

The system natively supports two operation modes:

### Mode 1: Simulated / Offline Sample Mode (Default)
- **Use Case**: Offline demonstration, project evaluation, academic paper presentations, viva reviews, and UI development.
- **Log Source**: `honeypot/sample_logs/cowrie.sample.json`.
- **How to Activate**:
  In `.env` (or default configuration):
  ```ini
  HONEYPOT_MODE=sample
  HONEYPOT_LOG_PATH=honeypot/sample_logs/cowrie.sample.json
  ```
  Run ingestion:
  ```powershell
  flask ingest-logs
  ```

---

### Mode 2: Live Cowrie Honeypot in an Isolated Lab

**Cowrie** is an industry-standard medium-to-high interaction SSH and Telnet honeypot designed to log brute force attacks and shell interaction.

#### Step 1: Deploy Cowrie in an Isolated Docker Container or VM
On a local Linux host or dedicated VirtualBox VM (Host-Only / Internal Network):

```bash
# Create local directory for Cowrie logs
mkdir -p ~/cowrie-lab/cowrie/var/log/cowrie

# Run Cowrie container binding trapped ports (2222 for SSH, 2223 for Telnet)
docker run -d \
  --name sentinel-cowrie \
  -p 2222:2222 \
  -p 2223:2223 \
  -v ~/cowrie-lab/cowrie/var/log/cowrie:/cowrie/cowrie-git/var/log/cowrie \
  cowrie/cowrie:latest
```

#### Step 2: Configure Sentinel Application Path
Point the application to the shared Cowrie JSON log output (`cowrie.json`):

In `.env`:
```ini
HONEYPOT_MODE=real
HONEYPOT_LOG_PATH=/path/to/cowrie/var/log/cowrie/cowrie.json
```

#### Step 3: Trigger Controlled Test Attacks from a Lab Client
From another machine or terminal on the isolated lab subnet:

```bash
# Test 1: SSH Brute-Force Simulation
ssh -p 2222 root@<HONEYPOT_IP>
# Enter wrong password

# Test 2: Shell Interaction Simulation
# Authenticate with credentials accepted by Cowrie (e.g. root/root)
uname -a
whoami
cat /etc/passwd
cat /etc/shadow
exit
```

#### Step 4: Ingest Real Telemetry into Sentinel
In the Sentinel project terminal:
```powershell
flask ingest-logs
```
The new events will be normalized, classified by deterministic threat rules, and displayed live on the dashboard!

---

## 3. Production Hardening Checklist
- [x] Password hashing using Werkzeug PBKDF2/SHA256.
- [x] Parameterized SQLite queries to prevent SQL injection.
- [x] HTTP Security response headers (`X-Content-Type-Options`, `X-Frame-Options`, `X-XSS-Protection`).
- [x] Session cookie security (`HTTPOnly`, `SameSite=Lax`).
- [x] Open Redirect mitigation on authentication redirects.
- [x] Resilient parser ensuring malformed logs never cause service disruption.
