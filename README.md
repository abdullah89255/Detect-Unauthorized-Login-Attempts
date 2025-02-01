# Detect-Unauthorized-Login-Attempts
### **🔍 Detect Unauthorized Login Attempts in Linux**  

Unauthorized login attempts can be a sign of **brute-force attacks** or **suspicious activity** on your server. This Bash script scans system logs and extracts failed login attempts, helping you **identify potential security threats**.  

---

## **📌 1️⃣ Simple Script: Display Failed Login Attempts**
This script searches for failed SSH login attempts in `/var/log/auth.log` (Debian/Ubuntu) or `/var/log/secure` (RHEL/CentOS).  

```bash
#!/bin/bash
LOG_FILE="/var/log/auth.log"  # Change to /var/log/secure for CentOS/RHEL

echo "🔍 Scanning for failed login attempts..."

# Extract failed login attempts
grep "Failed password" "$LOG_FILE" | awk '{print $1, $2, $3, $9, $11}' | sort | uniq -c | sort -nr
```
✅ **Usage**:  
- Run `./failed_logins.sh`  
- Displays **failed login attempts**, including **date, time, username, and IP address**  

---

## **📌 2️⃣ Advanced Script: Count Attempts & Block Suspicious IPs**
This script does **3 things**:  
1. **Extracts failed login attempts** from logs  
2. **Lists top attacking IPs**  
3. **Blocks IPs with more than 5 failed attempts** using `iptables`  

```bash
#!/bin/bash
LOG_FILE="/var/log/auth.log"  # Change to /var/log/secure for CentOS/RHEL
THRESHOLD=5  # Block IPs with more than 5 failed attempts

echo "🔍 Checking failed login attempts..."

# Extract failed login attempts and list top attacking IPs
awk '/Failed password/ {print $(NF-3)}' "$LOG_FILE" | sort | uniq -c | sort -nr > /tmp/failed_ips.txt

echo "🔢 Top attacking IPs:"
cat /tmp/failed_ips.txt

# Block suspicious IPs
echo "🚨 Blocking IPs with more than $THRESHOLD failed attempts..."
while read -r count ip; do
    if [ "$count" -ge "$THRESHOLD" ]; then
        echo "Blocking $ip (failed $count times)"
        sudo iptables -A INPUT -s "$ip" -j DROP
    fi
done < /tmp/failed_ips.txt

echo "✅ Done! Suspicious IPs are blocked."
```
✅ **Usage**:  
- Run `./block_failed_ips.sh`  
- Blocks **IPs with more than 5 failed login attempts**  

---

## **📌 3️⃣ Real-Time Monitoring Script**  
This script **monitors login attempts in real-time** and alerts if an attack is detected.  

```bash
#!/bin/bash
LOG_FILE="/var/log/auth.log"
THRESHOLD=5

echo "📡 Monitoring SSH login attempts in real-time..."
tail -Fn0 "$LOG_FILE" | while read line; do
    if [[ "$line" == *"Failed password"* ]]; then
        IP=$(echo "$line" | awk '{print $(NF-3)}')
        COUNT=$(grep -c "$IP" "$LOG_FILE")

        echo "🚨 Unauthorized attempt detected from $IP (Total: $COUNT)"

        if [ "$COUNT" -ge "$THRESHOLD" ]; then
            echo "🚫 Blocking $IP..."
            sudo iptables -A INPUT -s "$IP" -j DROP
        fi
    fi
done
```
✅ **Usage**:  
- Run `./real_time_monitor.sh`  
- Monitors **live failed SSH attempts** and blocks suspicious IPs  

---

## **📌 4️⃣ Send Email Alerts for Unauthorized Logins**  
This script sends **email notifications** if multiple failed login attempts occur.  

```bash
#!/bin/bash
LOG_FILE="/var/log/auth.log"
THRESHOLD=5
EMAIL="admin@example.com"

# Check failed login attempts
ATTACKERS=$(awk '/Failed password/ {print $(NF-3)}' "$LOG_FILE" | sort | uniq -c | awk -v limit="$THRESHOLD" '$1 >= limit {print $2}')

if [ -n "$ATTACKERS" ]; then
    echo -e "🚨 ALERT: Unauthorized SSH attempts detected!\n\n$ATTACKERS" | mail -s "Unauthorized Login Attempts" "$EMAIL"
    echo "📧 Alert email sent to $EMAIL"
else
    echo "✅ No suspicious activity detected."
fi
```
✅ **Usage**:  
- Run `./send_alerts.sh`  
- Sends **email alerts** if an IP fails login **more than 5 times**  
- Requires `mailutils` (`sudo apt install mailutils -y`)  

---

## **📌 5️⃣ Auto-Ban Attackers with `fail2ban` (Recommended)**
Instead of writing custom scripts, you can use **fail2ban**, a security tool that automatically bans suspicious IPs.  

### **Step 1: Install fail2ban**
```bash
sudo apt install fail2ban -y  # Ubuntu/Debian
sudo yum install fail2ban -y  # CentOS/RHEL
```

### **Step 2: Configure Fail2Ban**
Edit `/etc/fail2ban/jail.local`:
```ini
[sshd]
enabled = true
bantime = 3600  # Ban for 1 hour
findtime = 600  # Count failures in 10 min
maxretry = 5    # Block after 5 failed attempts
```

### **Step 3: Restart Fail2Ban**
```bash
sudo systemctl restart fail2ban
```
✅ **fail2ban automatically detects & blocks** attackers!  

---

## **🚀 Summary**  
🔹 `failed_logins.sh` → **Lists failed login attempts**  
🔹 `block_failed_ips.sh` → **Blocks attackers with iptables**  
🔹 `real_time_monitor.sh` → **Monitors logins in real-time**  
🔹 `send_alerts.sh` → **Sends email alerts for attacks**  
🔹 `fail2ban` → **Automatically bans attackers (Recommended)**  

---

# **🔍 Detect and Auto-Ban Attackers for Unauthorized Login Attempts in Windows**  

In Windows, failed login attempts are logged in the **Event Viewer**, and we can use **PowerShell** to detect and block suspicious IPs automatically.

---

## **📌 1️⃣ View Failed Login Attempts in Windows**  
You can manually check failed login attempts in **Event Viewer**:  
1. Open **Event Viewer** (`eventvwr.msc`)  
2. Go to:  
   ```
   Windows Logs → Security → Event ID 4625 (Failed Logon)
   ```
3. Look for **Source Network Address** (IP) of the failed attempts.

---

## **📌 2️⃣ Detect Unauthorized Login Attempts using PowerShell**  
This script scans **Event Logs**, extracts failed login attempts, and lists attacking IPs.

```powershell
# Get the last 100 failed login attempts
Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4625} -MaxEvents 100 | 
ForEach-Object {
    $Ip = ($_ | Select-String -Pattern 'Source Network Address:\s(\S+)').Matches.Groups[1].Value
    if ($Ip) { $Ip }
} | Group-Object | Sort-Object Count -Descending
```
✅ **Usage**:  
- Run this script in **PowerShell (Admin)**  
- It lists **failed login attempts** grouped by IP.

---

## **📌 3️⃣ Auto-Ban Attackers with Windows Firewall**  
This script:  
✅ **Scans Windows Event Logs** for **failed logins** (Event ID 4625)  
✅ **Blocks IPs** with more than `5` failed attempts  

```powershell
# Set failed login threshold
$Threshold = 5

# Get the last 200 failed login attempts
$FailedLogins = Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4625} -MaxEvents 200 | 
    ForEach-Object {
        if ($_.Message -match "Source Network Address:\s(\S+)") {
            $matches[1]
        }
    } | Group-Object | Where-Object {$_.Count -ge $Threshold} | Sort-Object Count -Descending

# Block IPs with too many failed attempts
foreach ($entry in $FailedLogins) {
    $IP = $entry.Name
    Write-Host "🚨 Blocking IP: $IP (Failed Logins: $($entry.Count))"

    # Add firewall rule to block the IP
    New-NetFirewallRule -DisplayName "Block_IP_$IP" -Direction Inbound -Action Block -RemoteAddress $IP
}

Write-Host "✅ Done! All suspicious IPs are blocked."
```
✅ **Usage**:  
- Run this script in **PowerShell (Admin)**  
- It **automatically bans suspicious IPs**  

---

## **📌 4️⃣ Auto Monitor & Block Attackers in Real-Time**  
This script **monitors login attempts in real-time** and **blocks attackers instantly**.

```powershell
# Set threshold for failed attempts
$Threshold = 3

# Monitor Security Logs in real-time
Write-Host "📡 Monitoring failed logins..."
$Watcher = New-Object System.Management.EventArrivedEventArgs
$Query = "SELECT * FROM __InstanceCreationEvent WITHIN 5 WHERE TargetInstance ISA 'Win32_NTLogEvent' AND TargetInstance.EventCode = '4625'"

# Create Event Watcher
$EventWatcher = New-Object System.Management.ManagementEventWatcher -ArgumentList "root\CIMV2", $Query
$EventWatcher.EventArrived += {
    $Event = $_.NewEvent.TargetInstance
    if ($Event.Message -match "Source Network Address:\s(\S+)") {
        $IP = $matches[1]

        # Count failed attempts
        $Count = (Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4625} | 
            Where-Object { $_.Message -match "Source Network Address:\s$IP" }).Count

        Write-Host "🚨 Detected Failed Login from $IP (Count: $Count)"

        if ($Count -ge $Threshold) {
            Write-Host "🚫 Blocking IP: $IP"
            New-NetFirewallRule -DisplayName "Block_IP_$IP" -Direction Inbound -Action Block -RemoteAddress $IP
        }
    }
}

$EventWatcher.Start()
```
✅ **Usage**:  
- Run **PowerShell as Administrator**  
- Run `./real_time_ban.ps1`  
- **Blocks IPs in real-time** after 3 failed attempts  

---

## **📌 5️⃣ Unblock an IP (If Needed)**  
If an IP was mistakenly blocked, use this command to **remove the firewall rule**:  

```powershell
Remove-NetFirewallRule -DisplayName "Block_IP_192.168.1.100"
```
✅ Replace `192.168.1.100` with the blocked IP.

---

## **📌 6️⃣ Automate with Task Scheduler**
To run the script **automatically every 5 minutes**, you can use **Task Scheduler**:  

1️⃣ Open **Task Scheduler** (`taskschd.msc`)  
2️⃣ Click **Create Basic Task** → Name it **Auto-Ban Failed Logins**  
3️⃣ Set **Trigger** → **Daily** or **Every 5 minutes**  
4️⃣ Set **Action** → **Start a Program**  
5️⃣ Program:  
   ```
   powershell.exe -ExecutionPolicy Bypass -File "C:\path\to\script.ps1"
   ```
6️⃣ Click **Finish**  

Now, the script will **run automatically** and block attackers!

---

## **🚀 Summary**
✅ `detect_failed_logins.ps1` → **Lists failed login attempts**  
✅ `auto_ban.ps1` → **Automatically blocks attackers**  
✅ `real_time_ban.ps1` → **Real-time monitoring & auto-ban**  
✅ `unblock_ip.ps1` → **Unblocks a blocked IP**  
✅ **Task Scheduler** → **Runs the script automatically**  

---

# **Windows 10**

### 1. **Enable Windows Security Features**

#### **A. Enable Account Lockout Policy**
Windows has a built-in account lockout policy that can help protect against brute-force attacks by locking the account after a set number of failed login attempts.

1. **Open Local Security Policy**:
   - Press `Win + R`, type `secpol.msc`, and press Enter.

2. **Navigate to Account Lockout Policy**:
   - In the Local Security Policy window, expand **Account Policies** and click on **Account Lockout Policy**.

3. **Configure the Lockout Policy**:
   - **Account lockout duration**: Set the duration for how long the account will remain locked (e.g., 15 or 30 minutes).
   - **Account lockout threshold**: Set the number of failed login attempts before locking the account (e.g., 3 to 5 attempts).
   - **Reset account lockout counter after**: Set a time limit (e.g., 15 or 30 minutes) for when the counter will reset, allowing a fresh set of login attempts.

4. **Apply the Policy**:
   - Once you set these policies, click **Apply** and **OK**.

#### **B. Enable Windows Firewall Protection**
Ensure that the Windows Firewall is enabled and configured to block suspicious activity.

1. Open **Control Panel**, go to **System and Security**, and click **Windows Defender Firewall**.
2. Ensure **Windows Firewall** is turned on for all networks (Private, Public, and Domain).

---

### 2. **Use Event Viewer to Monitor Login Attempts**

You can monitor suspicious login attempts using **Event Viewer**, and based on the logs, take action (e.g., alerting or banning IPs manually).

1. **Open Event Viewer**:
   - Press `Win + R`, type `eventvwr.msc`, and press Enter.

2. **Navigate to Security Logs**:
   - In the Event Viewer, expand **Windows Logs** > **Security**.

3. **Monitor Event IDs for Failed Logins**:
   - Look for Event IDs related to failed login attempts:
     - **Event ID 4625**: Failed logon attempts.
     - **Event ID 4740**: Account lockout.

4. **Create a Custom View (Optional)**:
   - You can create a **Custom View** to filter only failed login attempts and alerts. To do so, in Event Viewer, right-click **Custom Views** > **Create Custom View** and set filters for Event IDs 4625 and 4740.

---

### 3. **Use Windows Defender to Block Malicious IPs**

If you are using **Windows Defender Antivirus**, it can help to block malicious IP addresses by configuring the **Windows Firewall** to automatically block repeated failed login attempts.

1. **Access Windows Firewall**:
   - Open **Control Panel** > **System and Security** > **Windows Defender Firewall**.

2. **Advanced Settings**:
   - On the left side, click **Advanced settings** to open the **Windows Firewall with Advanced Security**.
   - Under **Inbound Rules**, create a new rule to block specific IP addresses or ranges that are making repeated failed login attempts.

---

### 4. **Implement Third-Party Tools for Auto-Banning**

For automated and more advanced protection, you can use third-party tools that offer brute-force protection and automatic IP blocking for repeated failed login attempts. Some popular tools are:

#### **A. Fail2Ban (via Cygwin)**
While originally designed for Linux, **Fail2Ban** can be installed on Windows via Cygwin (a Linux-like environment for Windows). It monitors log files and can automatically ban IPs that show signs of brute-force attempts.

1. Install **Cygwin** (to simulate a Linux environment on Windows).
2. Set up **Fail2Ban** in Cygwin to monitor the **Security Event Log** and ban IPs with too many failed login attempts.

#### **B. RdpGuard (for RDP attacks)**
If you use **Remote Desktop Protocol (RDP)**, **RdpGuard** can help monitor and automatically block IPs that make too many failed RDP login attempts.

1. Install **RdpGuard** from their [official website](https://rdpguard.com/).
2. Configure the tool to detect repeated RDP login failures and automatically block the offending IPs.

---

### 5. **Configure Group Policies for Extra Protection**
You can further configure Group Policy to tighten security and limit login attempts.

1. **Open Group Policy Editor**:
   - Press `Win + R`, type `gpedit.msc`, and press Enter.

2. **Configure User Rights Assignment**:
   - Go to **Computer Configuration** > **Windows Settings** > **Security Settings** > **Local Policies** > **User Rights Assignment**.
   - Make sure only authorized users have **Log on locally** and **Log on through Remote Desktop Services** rights.

3. **Audit Failed Logins**:
   - You can enable auditing for logon attempts. Go to **Security Settings** > **Advanced Audit Policy Configuration** > **Logon/Logoff** > Enable **Logon/Logoff** auditing.

---

### 6. **Consider Using Remote Desktop Security Tools (if applicable)**
If you're using **RDP**, make sure you're using advanced security features, such as:

- **Network Level Authentication (NLA)**: Ensures users are authenticated before a session is established.
- **RDP Gateway**: Acts as a middle layer to handle RDP traffic securely.
- **Limit IP ranges**: Only allow specific IP addresses to connect via RDP.

---

### Conclusion

By combining Windows' built-in security features, auditing logs, and third-party tools, you can detect and block unauthorized login attempts on your Windows 10 system. Implementing automated actions (e.g., account lockouts and IP bans) based on failed login attempts will help protect your computer from brute-force and other unauthorized access attempts.
