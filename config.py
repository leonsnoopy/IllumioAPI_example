import os

def load_env(env_path='.env'):
    """Loads environment variables from a .env file if it exists."""
    if os.path.exists(env_path):
        with open(env_path, 'r', encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith('#'):
                    continue
                if '=' in line:
                    key, val = line.split('=', 1)
                    # Strip quotes if present
                    val_str = val.strip()
                    if val_str.startswith('"') and val_str.endswith('"'):
                        val_str = val_str[1:-1]
                    elif val_str.startswith("'") and val_str.endswith("'"):
                        val_str = val_str[1:-1]
                    os.environ[key.strip()] = val_str

# Load local .env automatically when config is imported
load_env()

# Config variables with sensible defaults
PCE_FQDN = os.getenv('ILLUMIO_PCE_FQDN', 'pce.my-company.com')
PCE_PORT = int(os.getenv('ILLUMIO_PCE_PORT', '8443'))
ORG_ID = int(os.getenv('ILLUMIO_ORG_ID', '1'))
API_KEY_ID = os.getenv('ILLUMIO_API_KEY_ID', '')
API_SECRET_TOKEN = os.getenv('ILLUMIO_API_SECRET_TOKEN', '')

# Email and SMTP configuration for alerts
SMTP_SERVER = os.getenv('SMTP_SERVER', '')
SMTP_PORT = int(os.getenv('SMTP_PORT', '587'))
SMTP_USER = os.getenv('SMTP_USER', '')
SMTP_PASSWORD = os.getenv('SMTP_PASSWORD', '')
EMAIL_SENDER = os.getenv('EMAIL_SENDER', '')
EMAIL_RECEIVER = os.getenv('EMAIL_RECEIVER', '')

