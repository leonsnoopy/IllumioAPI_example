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

def parse_selection_indices(input_str, max_val):
    """
    Parses a string of comma-separated or space-separated numbers and ranges (e.g. '1, 2, 4-6').
    Returns a sorted list of unique valid 1-based indices.
    """
    indices = set()
    # Replace space delimiters with commas
    normalized = input_str.replace(" ", ",")
    parts = normalized.split(",")
    for part in parts:
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            try:
                start_str, end_str = part.split("-", 1)
                start_i = int(start_str.strip())
                end_i = int(end_str.strip())
                for i in range(min(start_i, end_i), max(start_i, end_i) + 1):
                    if 1 <= i <= max_val:
                        indices.add(i)
            except ValueError:
                pass
        else:
            try:
                i = int(part)
                if 1 <= i <= max_val:
                    indices.add(i)
            except ValueError:
                pass
    return sorted(list(indices))

def interactive_tagging(client, filter_val=None):
    """
    An interactive wizard to bulk assign/modify labels for multiple workloads.
    """
    print_separator("自動化貼標籤功能")
    print("本功能將引導您逐步選擇 Workloads 與 Labels，最後進行批次套用與合併。")
    
    selected_workloads = {}  # href -> workload dict
    selected_labels = {}     # href -> label dict

    try:
        # ----------------------------------------------------
        # 第一階段：挑選 Workload
        # ----------------------------------------------------
        while True:
            print_separator("步驟 1：挑選要貼上標籤的 Workloads")
            filter_keyword = input("請輸入搜尋 Workload 關鍵字 (直接 Enter 可查詢全部): ").strip()
            
            print("正在獲取 Workload 清單，請稍後...")
            try:
                workloads = client.get_workloads()
            except Exception as e:
                logger.error(f"Failed to fetch workloads: {e}", exc_info=True)
                print(f"[錯誤] 無法取得 Workload 清單 (錯誤: {e})")
                return
            
            # Apply filter locally
            filtered_wls = []
            for wl in workloads:
                name = wl.get("name") or ""
                hostname = wl.get("hostname") or ""
                if not filter_keyword or (filter_keyword.lower() in name.lower() or filter_keyword.lower() in hostname.lower()):
                    filtered_wls.append(wl)
            
            if not filtered_wls:
                print(f"找不到任何名稱或主機名稱含有 '{filter_keyword}' 的 Workload。")
            else:
                print(f"\n找到以下符合的 Workload 列表 (共 {len(filtered_wls)} 台):")
                print(f"{'編號':<6} {'狀態':<8} {'Name':<25} {'Hostname':<25}")
                print("-" * 70)
                for idx, wl in enumerate(filtered_wls, 1):
                    name = wl.get("name") or "N/A"
                    hostname = wl.get("hostname") or "N/A"
                    href = wl.get("href")
                    
                    if len(name) > 23:
                        name = name[:20] + "..."
                    if len(hostname) > 23:
                        hostname = hostname[:20] + "..."
                        
                    status_char = "[已勾選]" if href in selected_workloads else "[ ]"
                    print(f"{idx:<6} {status_char:<8} {name:<25} {hostname:<25}")
                
                select_input = input("\n請輸入要勾選/取消勾選的編號 (例如: 1, 2 或 1-3，直接 Enter 跳過): ").strip()
                if select_input:
                    parsed_idx = parse_selection_indices(select_input, len(filtered_wls))
                    for i in parsed_idx:
                        wl = filtered_wls[i - 1]
                        href = wl.get("href")
                        if href in selected_workloads:
                            del selected_workloads[href]
                            print(f"  [取消勾選] {wl.get('name') or wl.get('hostname') or href}")
                        else:
                            selected_workloads[href] = wl
                            print(f"  [已勾選] {wl.get('name') or wl.get('hostname') or href}")
            
            print(f"\n目前已挑選的 Workloads 數量: {len(selected_workloads)} 台")
            
            # Menu options
            print("\n請選擇後續動作:")
            print("  1. 再次挑選 Workload (使用不同關鍵字過濾)")
            print("  2. 完成挑選 Workload，進入下一步挑選標籤")
            print("  3. 離開並取消")
            
            choice = input("請輸入選項 (1/2/3): ").strip()
            if choice == "2":
                if not selected_workloads:
                    print("[提示] 您尚未挑選任何 Workload！")
                    confirm = input("確定要繼續前往下一步挑選標籤嗎？(y/n): ").strip().lower()
                    if confirm != 'y':
                        continue
                break
            elif choice == "3":
                print("取消操作。離開功能。")
                return
            # If option 1 or other input, loop again
            
        # ----------------------------------------------------
        # 第二階段：挑選 Label
        # ----------------------------------------------------
        while True:
            print_separator("步驟 2：挑選要貼上的 Labels")
            filter_keyword = input("請輸入搜尋 Label 關鍵字 (直接 Enter 可查詢全部): ").strip()
            
            print("正在獲取 Label 清單，請稍後...")
            try:
                labels = client.get_labels()
            except Exception as e:
                logger.error(f"Failed to fetch labels: {e}", exc_info=True)
                print(f"[錯誤] 無法取得 Label 清單 (錯誤: {e})")
                return
            
            # Apply filter locally
            filtered_lbls = []
            for lbl in labels:
                key = lbl.get("key") or ""
                value = lbl.get("value") or ""
                if not filter_keyword or (filter_keyword.lower() in key.lower() or filter_keyword.lower() in value.lower()):
                    filtered_lbls.append(lbl)
                    
            if not filtered_lbls:
                print(f"找不到任何維度(Key)或數值(Value)含有 '{filter_keyword}' 的 Label。")
            else:
                print(f"\n找到以下符合的 Label 列表 (共 {len(filtered_lbls)} 個):")
                print(f"{'編號':<6} {'狀態':<8} {'Key (維度)':<15} {'Value (標籤值)':<25}")
                print("-" * 60)
                for idx, lbl in enumerate(filtered_lbls, 1):
                    key = lbl.get("key") or "N/A"
                    val = lbl.get("value") or "N/A"
                    href = lbl.get("href")
                    status_char = "[已勾選]" if href in selected_labels else "[ ]"
                    print(f"{idx:<6} {status_char:<8} {key:<15} {val:<25}")
                    
                select_input = input("\n請輸入要勾選/取消勾選的編號 (例如: 1, 2 或 1-3，直接 Enter 跳過): ").strip()
                if select_input:
                    parsed_idx = parse_selection_indices(select_input, len(filtered_lbls))
                    for i in parsed_idx:
                        lbl = filtered_lbls[i - 1]
                        href = lbl.get("href")
                        if href in selected_labels:
                            del selected_labels[href]
                            print(f"  [取消勾選標籤] {lbl.get('key')}: {lbl.get('value')}")
                        else:
                            selected_labels[href] = lbl
                            print(f"  [已勾選標籤] {lbl.get('key')}: {lbl.get('value')}")
                            
            print(f"\n目前已挑選的 Labels 數量: {len(selected_labels)} 個")
            
            # Menu options
            print("\n請選擇後續動作:")
            print("  1. 再次挑選 Label (使用不同關鍵字過濾)")
            print("  2. 完成挑選 Label，進入最終確認")
            print("  3. 離開並取消")
            
            choice = input("請輸入選項 (1/2/3): ").strip()
            if choice == "2":
                if not selected_labels:
                    print("[提示] 您尚未挑選任何 Label！")
                    confirm = input("確定要繼續前往最終確認嗎？(y/n): ").strip().lower()
                    if confirm != 'y':
                        continue
                break
            elif choice == "3":
                print("取消操作。離開功能。")
                return
                
        # ----------------------------------------------------
        # 第三階段：最終確認與套用
        # ----------------------------------------------------
        print_separator("步驟 3：最終確認與批次套用")
        print(f"預計套用標籤的 Workloads (共 {len(selected_workloads)} 台):")
        for idx, wl in enumerate(selected_workloads.values(), 1):
            name = wl.get("name") or "N/A"
            hostname = wl.get("hostname") or "N/A"
            print(f"  [{idx}] {name} ({hostname})")
            
        print(f"\n預計新增/修改的 Labels (共 {len(selected_labels)} 個):")
        for idx, lbl in enumerate(selected_labels.values(), 1):
            print(f"  [{idx}] {lbl.get('key')}: {lbl.get('value')}")
            
        confirm = input("\n[警示] 請確認以上內容。是否立即執行貼標籤動作？ (Y/N): ").strip().lower()
        if confirm != 'y':
            print("操作已取消。離開功能。")
            return
            
        print("\n開始執行標籤更新...")
        success_count = 0
        failure_count = 0
        
        for wl in selected_workloads.values():
            wl_href = wl.get("href")
            wl_name = wl.get("name") or wl.get("hostname") or wl_href
            
            # Merge logic: Group existing labels by Key, and merge with new labels
            merged_labels = {}
            
            # Get current labels on the workload (if any)
            existing_labels = wl.get("labels") or []
            for el in existing_labels:
                el_key = el.get("key")
                el_href = el.get("href")
                if el_key and el_href:
                    merged_labels[el_key] = {"href": el_href}
                    
            # Overwrite/Add newly selected labels (which will overwrite any matching Key)
            for nl in selected_labels.values():
                nl_key = nl.get("key")
                nl_href = nl.get("href")
                if nl_key and nl_href:
                    merged_labels[nl_key] = {"href": nl_href}
                    
            # Construct final payload
            payload = {
                "labels": list(merged_labels.values())
            }
            
            try:
                client.update_workload(wl_href, payload)
                print(f"  [成功] Workload '{wl_name}' 貼標完成。")
                success_count += 1
            except Exception as e:
                logger.error(f"Failed to update workload labels for {wl_href}: {e}", exc_info=True)
                print(f"  [失敗] Workload '{wl_name}' 更新失敗 (錯誤: {e})")
                failure_count += 1
                
        print_separator("執行結果摘要")
        print(f"處理完成！ 成功: {success_count} 台, 失敗: {failure_count} 台。")
        
    except (KeyboardInterrupt, EOFError):
        print("\n\n[提示] 互動操作已被使用者中斷，離開功能。")
        return
