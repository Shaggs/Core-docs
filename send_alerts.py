"""
Send the expiry-alert email digest. Run daily from cron:

    0 7 * * *  cd /path/to/Core-docs && .venv/bin/python send_alerts.py

Set APP_BASE_URL in .env (e.g. https://vault.example.com) so the email contains links.
Alerts must be switched on and recipients set under Admin > Expiry alerts.
"""
import sys

from app import app
import ops

with app.app_context():
    result = ops.run_alerts()
print(result["message"])
sys.exit(1 if result.get("errors") else 0)
