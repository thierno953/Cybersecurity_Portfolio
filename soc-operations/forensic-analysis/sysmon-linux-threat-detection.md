# Detecting Suspicious Activities Using SysmonForLinux

## Installing SysmonForLinux

- Sysmon for Linux is now [available](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon).

```sh
# Register Microsoft’s key and repository
wget -q https://packages.microsoft.com/config/ubuntu/$(lsb_release -rs)/packages-microsoft-prod.deb -O packages-microsoft-prod.deb
sudo dpkg -i packages-microsoft-prod.deb

# Update and install Sysmon
sudo apt-get update
sudo apt-get install sysmonforlinux
```

- Create a Custom Configuration File

```sh
nano sysmon-config.xml
```

- Example config file available from: [MSTIC Sysmon Resources](https://github.com/microsoft/MSTIC-Sysmon/blob/main/linux/configs/main.xml)

```sh
# Install configuration
sysmon -i sysmon-config.xml

# Restart the service
sudo systemctl restart sysmon
sudo systemctl status sysmon

# Check the logs
tail -f /var/log/syslog | grep sysmon
```

## Prepare ELK to Detect Sysmon Events

- In Kibana: `Management > Integrations`

- Search: **Sysmon for Linux**

- Add the integration and configure it:

  - Log path: `/var/log/syslog*`

  - Assign to an **Agent Policy**

- Validate the integration -> Available dashboard: `[Sysmon] Sysmon for Linux Logs Overview`

- In **Kibana Discover** (quick search):

```sh
process.name: sysmon
```

![ELK](/soc-operations/forensic-analysis/assets/01-sysmon-linux-threat-detection.png)

## Simulate Malicious Activity

- Simulate suspicious system activity (used in attacks or misconfigurations).
- You can reference sites like [MalwareBazaar](https://bazaar.abuse.ch/) for harmless test traffic.

```sh
# Create suspicious configuration files
touch /etc/apt/apt.conf.d/99-suspicious-config

sudo bash -c "echo 'malicious config' > /etc/apt/apt.conf.d/99-malicious-config"

# Simulate access to a known malware-related URL
curl -X GET "https://bazaar.abuse.ch/" -v
```

- **View events in Kibana Discover:**

```sh
process.name: sysmon and message: "99"
```

![ELK](/soc-operations/forensic-analysis/assets/02-sysmon-linux-threat-detection.png)

```sh
process.name: sysmon and message: "bazaar.abuse.ch"
```

![ELK](/soc-operations/forensic-analysis/assets/03-sysmon-linux-threat-detection.png)

```sh
process.name: sysmon and message: "*malicious"
```

![ELK](/soc-operations/forensic-analysis/assets/04-sysmon-linux-threat-detection.png)

## Incident Response

- Identify and remove suspicious files:

```sh
find / -name "99-malicious-config" -type f
rm -rf /etc/apt/apt.conf.d/99-suspicious-config
rm -rf /etc/apt/apt.conf.d/99-malicious-config
find / -name "99-malicious-config" -type f
```

- Check active network connections:

```sh
sudo apt install net-tools -y
netstat -ltnp
```

- Validate the integration -> Available dashboard: `[Sysmon] Sysmon for Linux Logs Overview`

![ELK](/soc-operations/forensic-analysis/assets/05-sysmon-linux-threat-detection.png)

![ELK](/soc-operations/forensic-analysis/assets/06-sysmon-linux-threat-detection.png)

![ELK](/soc-operations/forensic-analysis/assets/07-sysmon-linux-threat-detection.png)

![ELK](/soc-operations/forensic-analysis/assets/08-sysmon-linux-threat-detection.png)

![ELK](/soc-operations/forensic-analysis/assets/09-sysmon-linux-threat-detection.png)
