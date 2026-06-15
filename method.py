import json
import logging
import sys
import smtplib
from email.mime.text import MIMEText
from email.header import Header
import config

# Reconfigure stdout to use utf-8 to prevent encoding issues on Windows consoles
if sys.platform.startswith("win"):
    try:
        sys.stdout.reconfigure(encoding='utf-8')
    except AttributeError:
        import io
        sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8')

logger = logging.getLogger("illumio_client")

def print_separator(title):
    print("\n" + "=" * 60)
    print(f" {title} ".center(60, "="))
    print("=" * 60)

def send_email_notification(abnormal_vens):
    """Sends an email notification if there are abnormal VENs."""
    if not config.EMAIL_RECEIVER:
        logger.warning("Email receiver not configured, skipping email notification.")
        print("[警告] 未設定收件者信箱 (EMAIL_RECEIVER)，無法寄送通知。")
        return
        
    subject = "【警告】Illumio PCE 偵測到異常 VEN 狀態"
    
    # Construct email content
    body = "偵測到以下 VEN 狀態異常，請儘速確認：\n\n"
    body += f"{'Hostname':<25} {'Status':<15} {'HREF':<40}\n"
    body += "-" * 80 + "\n"
    for ven in abnormal_vens:
        hostname = ven.get("hostname") or "N/A"
        status = ven.get("status") or "N/A"
        href = ven.get("href") or "N/A"
        body += f"{hostname:<25} {status:<15} {href:<40}\n"
    
    # If SMTP is configured
    if config.SMTP_SERVER:
        try:
            msg = MIMEText(body, 'plain', 'utf-8')
            msg['Subject'] = Header(subject, 'utf-8')
            sender = config.EMAIL_SENDER or "auto_reply@illumio_client.com"
            msg['From'] = sender
            msg['To'] = config.EMAIL_RECEIVER
            
            # Send via SMTP with connection timeout
            logger.info(f"Connecting to SMTP server {config.SMTP_SERVER}:{config.SMTP_PORT}...")
            with smtplib.SMTP(config.SMTP_SERVER, config.SMTP_PORT, timeout=10) as server:
                # 1. Optionally attempt STARTTLS if port is 587
                if config.SMTP_PORT == 587:
                    try:
                        server.starttls()
                    except Exception as tls_err:
                        logger.warning(f"STARTTLS not supported or failed: {tls_err}")
                
                # 2. Optionally login if SMTP_USER is configured and not 'false'/'none'
                smtp_user = config.SMTP_USER
                smtp_pass = config.SMTP_PASSWORD
                has_auth = smtp_user and smtp_user.lower() not in ("false", "none", "")
                
                if has_auth:
                    logger.info(f"Authenticating as {smtp_user}...")
                    server.login(smtp_user, smtp_pass)
                else:
                    logger.info("SMTP authentication skipped (no credentials provided).")
                
                receivers = [r.strip() for r in config.EMAIL_RECEIVER.split(",")]
                server.sendmail(sender, receivers, msg.as_string())
            
            logger.info(f"Notification email successfully sent to {config.EMAIL_RECEIVER}.")
            print(f"郵件通知: 已成功寄送至 {config.EMAIL_RECEIVER}")
        except Exception as e:
            logger.error(f"Failed to send notification email: {e}", exc_info=True)
            print(f"郵件通知: 寄送失敗 (錯誤: {e})")
    else:
        # Mock mode if SMTP is not configured
        print("\n" + "!" * 60)
        print("【郵件發送模擬】(SMTP 未完整配置，僅印出信件內容)")
        print(f"收件者: {config.EMAIL_RECEIVER}")
        print(f"主旨: {subject}")
        print(f"內容:\n{body}")
        print("!" * 60)


def check_health(client, filter_val=None):
    """Checks the PCE health status and prints essential connection verification."""
    print_separator("PCE Health Check")
    logger.info("Executing check_health...")
    
    # Print basic connection details on console
    print(f"PCE FQDN: {client.pce_fqdn}")
    print(f"PCE Port: {client.pce_port}")
    print(f"Org ID:   {client.org_id}")
    
    try:
        health_status = client.check_health()
        logger.debug(f"PCE Health Response: {json.dumps(health_status, ensure_ascii=False)}")
        
        status_str = "正常 (healthy)"
        if isinstance(health_status, dict) and "status" in health_status:
            status_str = health_status["status"]
            if status_str == "healthy":
                status_str = "正常 (healthy)"
                
        print(f"健康狀態: {status_str}")
        return health_status
    except Exception as e:
        logger.error(f"Failed to check PCE health: {e}", exc_info=True)
        print(f"健康狀態: 異常 (錯誤: {e})")
        return None

def get_labels(client, filter_val=None):
    """Retrieves and displays security labels, showing up to 10 entries on console."""
    print_separator("Get Security Labels")
    logger.info(f"Executing get_labels (filter: {filter_val})...")
    
    try:
        labels = client.get_labels()
        logger.debug(f"Retrieved {len(labels)} labels details: {json.dumps(labels, ensure_ascii=False)}")
        
        # Apply filter locally if provided
        if filter_val:
            filter_lower = filter_val.lower()
            labels = [
                label for label in labels
                if filter_lower in label.get("key", "").lower() or filter_lower in label.get("value", "").lower()
            ]
            print(f"過濾條件: '{filter_val}'")
            
        total_count = len(labels)
        print(f"安全標籤: 成功取得 {total_count} 個標籤")
        
        if total_count > 0:
            preview_count = min(total_count, 10)
            print(f"\n顯示前 {preview_count} 筆標籤資訊:")
            print(f"{'No.':<4} {'Key':<10} {'Value':<25} {'HREF':<30}")
            print("-" * 75)
            for idx, label in enumerate(labels[:preview_count], 1):
                key = label.get("key", "N/A")
                value = label.get("value", "N/A")
                href = label.get("href", "N/A")
                print(f"{idx:<4} {key:<10} {value:<25} {href:<30}")
            
            if total_count > preview_count:
                print(f"... 還有 {total_count - preview_count} 筆未顯示")
        return labels
    except Exception as e:
        logger.error(f"Failed to retrieve labels: {e}", exc_info=True)
        print(f"安全標籤: 取得失敗 (錯誤: {e})")
        return None

def get_workloads(client, filter_val=None):
    """Retrieves and displays workloads, showing up to 10 entries on console."""
    print_separator("Get Workloads")
    logger.info(f"Executing get_workloads (filter: {filter_val})...")
    
    try:
        workloads = client.get_workloads()
        logger.debug(f"Retrieved {len(workloads)} workloads details: {json.dumps(workloads, ensure_ascii=False)}")
        
        # Apply filter locally if provided
        if filter_val:
            filter_lower = filter_val.lower()
            workloads = [
                wl for wl in workloads
                if filter_lower in (wl.get("name") or "").lower() or filter_lower in (wl.get("hostname") or "").lower()
            ]
            print(f"過濾條件: '{filter_val}'")
            
        total_count = len(workloads)
        print(f"工作負載 (Workloads): 成功取得 {total_count} 個工作負載")
        
        if total_count > 0:
            preview_count = min(total_count, 10)
            print(f"\n顯示前 {preview_count} 筆工作負載資訊:")
            print(f"{'No.':<4} {'Name':<25} {'Hostname':<25} {'HREF':<30}")
            print("-" * 90)
            for idx, wl in enumerate(workloads[:preview_count], 1):
                name = wl.get("name") or "N/A"
                hostname = wl.get("hostname") or "N/A"
                href = wl.get("href", "N/A")
                # Handle name or hostname truncation if too long for layout
                if len(name) > 23:
                    name = name[:20] + "..."
                if len(hostname) > 23:
                    hostname = hostname[:20] + "..."
                print(f"{idx:<4} {name:<25} {hostname:<25} {href:<30}")
                
            if total_count > preview_count:
                print(f"... 還有 {total_count - preview_count} 筆未顯示")
        return workloads
    except Exception as e:
        logger.error(f"Failed to retrieve workloads: {e}", exc_info=True)
        print(f"工作負載: 取得失敗 (錯誤: {e})")
        return None

def get_vens(client, filter_val=None):
    """Retrieves VENs, displays their statuses, and triggers email notifications for abnormal VENs."""
    print_separator("Get Virtual Enforcement Nodes (VENs)")
    logger.info("Executing get_vens...")
    
    try:
        vens = client.get_vens()
        logger.debug(f"Retrieved {len(vens)} VENs details: {json.dumps(vens, ensure_ascii=False)}")
        
        # Apply filter locally if provided
        if filter_val:
            filter_lower = filter_val.lower()
            vens = [
                ven for ven in vens
                if filter_lower in (ven.get("name") or "").lower() or filter_lower in (ven.get("hostname") or "").lower() or filter_lower in (ven.get("status") or "").lower()
            ]
            print(f"過濾條件: '{filter_val}'")
            
        total_count = len(vens)
        print(f"VEN 數量: 成功取得 {total_count} 個 VEN")
        
        abnormal_vens = []
        
        if total_count > 0:
            preview_count = min(total_count, 10)
            print(f"\n顯示前 {preview_count} 筆 VEN 資訊:")
            print(f"{'No.':<4} {'Hostname':<25} {'Status':<15} {'HREF':<30}")
            print("-" * 80)
            for idx, ven in enumerate(vens[:preview_count], 1):
                hostname = ven.get("hostname") or "N/A"
                status = ven.get("status") or "N/A"
                href = ven.get("href", "N/A")
                
                # Check status and print
                status_display = status
                if status != "active":
                    status_display = f"{status} (異常)"
                
                print(f"{idx:<4} {hostname:<25} {status_display:<15} {href:<30}")
                
            if total_count > preview_count:
                print(f"... 還有 {total_count - preview_count} 筆未顯示")
                
        # Collect abnormal VENs from the entire fetched list (not just the preview)
        for ven in vens:
            status = ven.get("status")
            if status != "active":
                abnormal_vens.append(ven)
                
        # Trigger email alerts if any abnormal VENs are found
        if abnormal_vens:
            print_separator("VEN 異常狀態警報")
            print(f"偵測到 {len(abnormal_vens)} 個 VEN 狀態異常！觸發寄信通知機制...")
            send_email_notification(abnormal_vens)
        else:
            print("\n所有 VEN 狀態均正常。")
            
        return vens
    except Exception as e:
        logger.error(f"Failed to retrieve VENs: {e}", exc_info=True)
        print(f"VEN 資訊: 取得失敗 (錯誤: {e})")
        return None
