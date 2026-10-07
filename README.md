Markdown
# Microsoft Sentinel Linux Threat Detection & Attack Simulation Lab

An end-to-end detection engineering and SOC analysis lab validating Microsoft Sentinel detection capabilities on an Azure Arc-managed Kali Linux endpoint using Atomic Red Team simulations.

---

## Architecture & Data Flow

[ Kali Linux Endpoint ]
│
├── (rsyslog socket) ──> Azure Monitor Agent (AMA)
│
└── (DCR Ingestion) ──> Azure Log Analytics / Microsoft Sentinel


---

## Step 1: Onboarding Endpoint via Azure Arc & AMA

1. **Register Host to Azure Arc**:
   Connect the Kali Linux machine to Azure Resource Manager using the Azure Arc onboarding script:
bash
sudo ./OnboardArc.sh

2. **Install Azure Monitor Agent (AMA)**:
Deploy the AMA extension to the Arc-enabled server via Azure Portal or CLI.
3. **Configure Custom `rsyslog` Socket**:
To ensure authentication logs (`auth`/`authpriv`) are captured across `info` and `notice` levels, configure the custom socket `/run/azure-ama/ama_syslog.sock` in `/etc/rsyslog.d/99-azure-ama.conf`:
syslog
auth,authpriv.* /run/azure-ama/ama_syslog.sock

Restart the service:
bash
sudo systemctl restart rsyslog

4. **Deploy Data Collection Rule (DCR)**:
Link a DCR in Azure Monitor targeting the Arc server to forward `Syslog` events (`auth` & `authpriv` facilities) to the Log Analytics Workspace.

---

## Step 2: Analytics Rules Configuration & Detection Logic

### Alert 1: SSH Brute-Force Attempt (Credential Access)

* **MITRE ATT&CK**: T1110.001 – Brute Force: Password Guessing
* **Why it's created**: High-frequency SSH authentication failures indicate automated password guessing or brute-force attacks against SSH services.
* **KQL Detection Logic**:
kusto
Syslog
| where Facility in ("auth", "authpriv")
| where SyslogMessage has_any ("Failed password", "authentication failure")
| summarize FailureCount = count() by Computer, HostIP, ProcessName, bin(TimeGenerated, 5m)
| where FailureCount >= 5

* **Scheduling**: Run every `5 minutes`, lookup past `5 minutes`.
* **Threshold**: Generate incident when results > 0.

---

### Alert 2: New Linux Account Created (Persistence)

* **MITRE ATT&CK**: T1136.001 – Create Account: Local Account
* **Why it's created**: Adversaries often establish persistence by creating new local users or adding accounts to privileged groups (`useradd`, `groupadd`, `new user`).
* **KQL Detection Logic**:
kusto
Syslog
| where Facility in ("auth", "authpriv")
| where SyslogMessage has_any ("new user", "useradd", "new group")
| summarize EventCount = count() by Computer, ProcessName, bin(TimeGenerated, 5m)

* **Scheduling**: Run every `5 minutes`, lookup past `1 hour`.
* **Threshold**: Generate incident when results > 0.

---

### Alert 3: Unauthorized Sudo Privilege Escalation Attempt (Privilege Escalation)

* **MITRE ATT&CK**: T1548.003 – Abuse Elevation Control Mechanism: Sudo and Sudo Caching
* **Why it's created**: Non-root users attempting unauthorized `sudo` executions generate security events in `auth.log` (`NOT in sudoers` or `incorrect password attempts`). Tracking these pinpoints insider threats and privilege escalation attempts.
* **KQL Detection Logic**:
kusto
Syslog
| where Facility in ("auth", "authpriv")
| where ProcessName == "sudo"
| where SyslogMessage has_any ("NOT in sudoers", "authentication failure", "1 incorrect password attempt")
| summarize FailedSudoCount = count() by Computer, SyslogMessage, bin(TimeGenerated, 5m)

* **Scheduling**: Run every `5 minutes`, lookup past `15 minutes`.
* **Threshold**: Generate incident when results > 0.

---

## Step 3: Attack Simulation & Validation

### Attack 1: SSH Brute-Force Simulation
Execute a loop simulating multiple failed SSH login attempts:
bash
for i in {1..10}; do ssh invalid_user@localhost -o NumberOfPasswordPrompts=1; done


### Attack 2: Local Account Creation (Atomic Red Team T1136.001)
Run MITRE ATT&CK Technique T1136.001 using Atomic Red Team in PowerShell:
bash
sudo -E pwsh -c "Import-Module Invoke-AtomicRedTeam; Invoke-AtomicTest T1136.001 -TestNumbers 1"

*Cleanup Command*:
bash
sudo -E pwsh -c "Import-Module Invoke-AtomicRedTeam; Invoke-AtomicTest T1136.001 -TestNumbers 1 -Cleanup"


### Attack 3: Unauthorized Sudo Attempt Simulation
Trigger a failed `sudo` execution with an unauthorized context:
bash
sudo -u nobody sudo -l


---

## Step 4: Verification in Microsoft Sentinel

Navigate to **Microsoft Sentinel $\rightarrow$ Threat management $\rightarrow$ Incidents** to verify all three alerts generate live incidents:

1. `SSH Brute-Force Attempt - Kali` (Category: **Suspicious Activity / Credential Access**)
2. `New Linux Account Created - Kali` (Category: **Persistence**)
3. `Unauthorized Sudo Privilege Escalation Attempt - Kali` (Category: **Privilege Escalation**)
