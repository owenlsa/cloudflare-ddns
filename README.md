# DDNS Script for CloudFlare

Support IPv4 and IPv6. 


Requirements

- Python 3.5+
- Requests 2.26.0

## How to Run

Rename `config-demo.json` to `config.json` before running.

```python
python cloudflare-ddns.py
```

## How to Deploy

- Use `sync_ip.bat` for Windows `taskschd.msc`.
- Use `sync_ip.sh` for Linux `crontab`. 