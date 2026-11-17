# VPN SOPR Pro v5.3

Unified **3x-ui Style** Management Panel for **WireGuard**, **AmneziaWG**, **OpenVPN**, and **IP-Authenticated Private DNS** on **Ubuntu 22.04+**.

## One-Line Installation (Ubuntu 22.04 / 24.04+)

Run this single command on your VPS as `root`:

```bash
bash <(curl -Ls https://raw.githubusercontent.com/mohsenz3188-hash/PANEL-SOPR-/main/install.sh)
```

During installation (just like **3x-ui**), you can either enter your custom Port, Username, Password, and Secret Web Path—or simply press `Enter` to auto-generate secure random credentials. At the end of installation, the installer prints a summary box with your exact **Web Panel URL**, **Username**, and **Password**.

## CLI Management Menu (`vpnsopr`)
Type `vpnsopr` anytime in your VPS terminal to open the interactive **x-ui style** menu:
- `1-4`: Start / Stop / Restart / Status
- `5`: View Live Panel & DNS Logs
- `6`: **Show Web Panel URL, Username & Password** (`vpnsopr info`)
- `7`: **Reset / Change Username, Password & Secret Web Path**
- `8`: Change Panel Web Port
- `9`: Connect Domain & Issue Free SSL (`Certbot`)
- `10`: Update Panel from GitHub (`vpnsopr update`)
- `11`: Uninstall VPN SOPR Pro
