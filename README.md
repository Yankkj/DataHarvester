# DataHarvester

A comprehensive data collection tool for **educational and security testing purposes**.

## ⚠️ Disclaimer
> This tool is for **EDUCATIONAL PURPOSES ONLY**. Use only on systems you own or have explicit permission to test. The developer is not responsible for any misuse.

## Features
- System information collection
- Browser data extraction (cookies, passwords, history)
- Social media tokens (Discord, Twitter, Instagram, etc.)
- Sensitive information detection (phone numbers, emails)
- Screenshot capture
- Geolocation data
- Payment information detection

## Exemple
![Example](images/image.png)

## Installation

1. Install Python 3.8+
2. Install dependencies:
```bash
pip install -r requirements.txt
```

3. Configure webhook in `main.py`:
   - Open `main.py`
   - Find `SECONDARY_WEBHOOK = "Webhook_URL_HERE"`
   - Replace with your Discord webhook URL

4. Run the tool:
```bash
python main.py
```

## Building Executable

Use `builder.py` to create a standalone executable:

```bash
python builder.py
```

This will generate an executable file that can be distributed.

## Legal
This tool is intended for:
- Security research
- Educational purposes
- Authorized penetration testing
- Personal use on owned systems

**DO NOT USE FOR ILLEGAL ACTIVITIES**