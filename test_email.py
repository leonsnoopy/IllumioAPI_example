import sys
import logging
import config

# Reconfigure stdout to use utf-8 to prevent encoding issues on Windows consoles
if sys.platform.startswith("win"):
    try:
        sys.stdout.reconfigure(encoding='utf-8')
    except AttributeError:
        import io
        sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8')

# Set up basic console logging for the test script
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

import method

def test_email():
    print("=" * 60)
    print(" 開始測試 VEN 狀態異常郵件通知 ".center(60, "="))
    print("=" * 60)
    
    # Check current email configuration
    print(f"SMTP 伺服器: {config.SMTP_SERVER or '未設定 (將使用模擬模式)'}")
    print(f"SMTP 連接埠: {config.SMTP_PORT}")
    print(f"寄件者信箱: {config.EMAIL_SENDER or '未設定'}")
    print(f"收件者信箱: {config.EMAIL_RECEIVER or '未設定'}")
    print("-" * 60)
    
    # Mock abnormal VEN data for testing
    mock_abnormal_vens = [
        {
            "hostname": "test-db-server-01",
            "status": "suspended",
            "href": "/orgs/3277168/vens/mock-db-id-12345"
        },
        {
            "hostname": "test-web-server-02",
            "status": "unpaired",
            "href": "/orgs/3277168/vens/mock-web-id-67890"
        }
    ]
    
    print(f"準備發送含 {len(mock_abnormal_vens)} 筆異常 VEN 的測試郵件...")
    method.send_email_notification(mock_abnormal_vens)
    print("=" * 60)
    print(" 測試完成 ".center(60, "="))
    print("=" * 60)

if __name__ == "__main__":
    test_email()
