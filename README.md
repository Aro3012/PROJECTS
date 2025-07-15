# 🛡️ DDoS Attack Detector

A simple Python-based script that monitors TCP port 80 network activity and detects potential DDoS attacks based on statistical anomalies in connection count.

---

## 📌 Features

- 📈 Monitors number of TCP connections on port `:80`
- 📊 Uses rolling statistics (mean and standard deviation) to detect abnormal spikes
- ⚠️ Logs warnings on potential DDoS detection
- 🚫 Optional IP blocking using Windows Firewall
- 🕒 Runs in continuous loop with customizable interval

---

## 🧠 How It Works

1. The script monitors network activity using the `netstat` command.
2. It collects connection counts at regular intervals (`sleep_interval`).
3. After collecting enough data (10 readings), it calculates the mean and standard deviation.
4. If the current connection count exceeds:
   - A hardcoded threshold (`connection_threshold`)
   - AND `mean + 2 * standard deviation`  
   it flags a possible DDoS attack.
5. Optionally blocks the first detected attacker's IP using Windows Firewall (`block_attacker = True`).

---

## ⚙️ Requirements

- OS: **Windows**
- Python 3.x
- Admin privileges (for firewall blocking)

---

## 🚀 Usage

```bash
# Run the script with Python 3
python ddos_detector.py
