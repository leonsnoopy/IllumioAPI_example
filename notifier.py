import smtplib
from email.mime.text import MIMEText
from email.header import Header
import logging

logger = logging.getLogger("illumio_client")

class EmailNotifier:
    """
    A service class responsible for sending email notifications.
    Decoupled from global configurations by accepting configuration variables in the constructor.
    """
    def __init__(self, smtp_server, smtp_port, smtp_user, smtp_password, email_sender, email_receiver):
        self.smtp_server = smtp_server
        self.smtp_port = smtp_port
        self.smtp_user = smtp_user
        self.smtp_password = smtp_password
        self.email_sender = email_sender or "auto_reply@illumio_client.com"
        self.email_receiver = email_receiver

    def _send_email(self, subject, body):
        """
        Private helper method to send an email or mock the email sending.
        """
        # If SMTP is configured
        if self.smtp_server:
            try:
                msg = MIMEText(body, 'plain', 'utf-8')
                msg['Subject'] = Header(subject, 'utf-8')
                msg['From'] = self.email_sender
                msg['To'] = self.email_receiver
                
                # Send via SMTP with connection timeout
                logger.info(f"Connecting to SMTP server {self.smtp_server}:{self.smtp_port}...")
                with smtplib.SMTP(self.smtp_server, self.smtp_port, timeout=10) as server:
                    # 1. Optionally attempt STARTTLS if port is 587
                    if self.smtp_port == 587:
                        try:
                            server.starttls()
                        except Exception as tls_err:
                            logger.warning(f"STARTTLS not supported or failed: {tls_err}")
                    
                    # 2. Optionally login if SMTP_USER is configured and not 'false'/'none'
                    smtp_user = self.smtp_user
                    smtp_pass = self.smtp_password
                    has_auth = smtp_user and smtp_user.lower() not in ("false", "none", "")
                    
                    if has_auth:
                        logger.info(f"Authenticating as {smtp_user}...")
                        server.login(smtp_user, smtp_pass)
                    else:
                        logger.info("SMTP authentication skipped (no credentials provided).")
                    
                    receivers = [r.strip() for r in self.email_receiver.split(",")]
                    server.sendmail(self.email_sender, receivers, msg.as_string())
                
                logger.info(f"Notification email successfully sent to {self.email_receiver}.")
                print(f"郵件通知: 已成功寄送至 {self.email_receiver}")
                return True
            except Exception as e:
                logger.error(f"Failed to send notification email: {e}", exc_info=True)
                print(f"郵件通知: 寄送失敗 (錯誤: {e})")
                return False
        else:
            # Mock mode if SMTP is not configured
            print("\n" + "!" * 60)
            print("【郵件發送模擬】(SMTP 未完整配置，僅印出信件內容)")
            print(f"收件者: {self.email_receiver}")
            print(f"主旨: {subject}")
            print(f"內容:\n{body}")
            print("!" * 60)
            return True

    def send_abnormal_vens_alert(self, abnormal_vens):
        """
        Sends an email notification if there are abnormal VENs.
        """
        if not self.email_receiver:
            logger.warning("Email receiver not configured, skipping email notification.")
            print("[警告] 未設定收件者信箱 (EMAIL_RECEIVER)，無法寄送通知。")
            return False
            
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
            
        return self._send_email(subject, body)

    def send_events_alert(self, events):
        """
        Sends an email notification with a table of retrieved system events.
        """
        if not self.email_receiver:
            logger.warning("Email receiver not configured, skipping email notification.")
            print("[警告] 未設定收件者信箱 (EMAIL_RECEIVER)，無法寄送通知。")
            return False
            
        subject = "【通知】Illumio PCE 系統事件紀錄"
        
        # Construct email content
        body = f"成功取得 {len(events)} 筆系統事件記錄，詳細如下：\n\n"
        if len(events) > 0:
            # Column widths: No(4), Timestamp(20), Event Type(25), Severity(10), Status(10), Created By(16), Description
            body += f"{'No.':<4} {'Timestamp':<20} {'Event Type':<25} {'Severity':<10} {'Status':<10} {'Created By':<16} {'Description'}\n"
            body += "-" * 115 + "\n"
            
            from utils import convert_utc_to_taiwan_time, get_event_description
            for idx, event in enumerate(events, 1):
                timestamp = event.get("timestamp") or "N/A"
                if timestamp != "N/A":
                    timestamp = convert_utc_to_taiwan_time(timestamp)
                etype = event.get("event_type") or "N/A"
                sev = event.get("severity") or "N/A"
                stat = event.get("status") or "N/A"
                desc = get_event_description(event)
                
                # Get creator details
                created_by_data = event.get("created_by", {})
                creator = "N/A"
                if "user" in created_by_data:
                    creator = created_by_data["user"].get("username") or created_by_data["user"].get("email") or "User"
                elif "agent" in created_by_data:
                    creator = "Agent"
                elif "system" in created_by_data:
                    creator = "System"
                    
                # Truncate values if too long for column width (matching method.py)
                if len(etype) > 23:
                    etype = etype[:20] + "..."
                if len(timestamp) > 19:
                    timestamp = timestamp[:19]
                if len(creator) > 14:
                    creator = creator[:12] + "..."
                    
                body += f"{idx:<4} {timestamp:<20} {etype:<25} {sev:<10} {stat:<10} {creator:<16} {desc}\n"
        else:
            body += "無符合條件之系統事件記錄。\n"
            
        return self._send_email(subject, body)

    def send_blocked_traffic_alert(self, flows):
        """
        Sends an email notification when blocked traffic is detected.
        """
        if not self.email_receiver:
            logger.warning("Email receiver not configured, skipping email notification.")
            print("[警告] 未設定收件者信箱 (EMAIL_RECEIVER)，無法寄送通知。")
            return False
            
        subject = "【警告】Illumio PCE 偵測到被阻擋的連線流量"
        
        body = f"偵測到以下 {len(flows)} 筆被阻擋的連線記錄，請儘速確認：\n\n"
        if len(flows) > 0:
            # Column widths: No(4), Last Detected(20), Source(25), Destination(25), Proto/Port(15), Conns(8)
            body += f"{'No.':<4} {'Last Detected':<20} {'Source':<25} {'Destination':<25} {'Proto/Port':<15} {'Conns':<8}\n"
            body += "-" * 97 + "\n"
            
            from utils import convert_utc_to_taiwan_time
            for idx, flow in enumerate(flows, 1):
                # Retrieve from dict fields (matching CSV columns)
                raw_ts = flow.get("Last Detected") or "N/A"
                ts = convert_utc_to_taiwan_time(raw_ts) if raw_ts != "N/A" else "N/A"
                
                # Format source (prefer hostname/name over IP)
                src_str = flow.get("Source Hostname") or flow.get("Source Name") or flow.get("Source IP") or "N/A"
                
                # Format destination
                dst_str = flow.get("Destination Hostname") or flow.get("Destination Name") or flow.get("Destination IP") or "N/A"
                
                # Protocol/Port
                proto = flow.get("Protocol") or "N/A"
                port = flow.get("Port") or ""
                proto_port = f"{proto}/{port}" if port else proto
                
                # Connections count
                conns = flow.get("Num Flows") or "1"
                
                # Truncate to match console layout
                if len(src_str) > 23:
                    src_str = src_str[:20] + "..."
                if len(dst_str) > 23:
                    dst_str = dst_str[:20] + "..."
                if len(ts) > 19:
                    ts = ts[:19]
                    
                body += f"{idx:<4} {ts:<20} {src_str:<25} {dst_str:<25} {proto_port:<15} {conns:<8}\n"
        else:
            body += "無被阻擋的連線記錄。\n"
            
        return self._send_email(subject, body)
