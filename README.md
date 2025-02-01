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

## **🔥 Want More Custom Security Scripts?**  
Let me know **what security feature** you need! 🚀😊
