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
    logger.info("使用者啟動了『自動化貼標籤功能 (interactive_tagging)』")
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
            logger.info(f"步驟 1：輸入搜尋 Workload 關鍵字 '{filter_keyword}'")
            
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
                logger.info("搜尋 Workload 結果為空。")
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
                    logger.info(f"使用者輸入勾選 Workload 編號: '{select_input}'")
                    parsed_idx = parse_selection_indices(select_input, len(filtered_wls))
                    for i in parsed_idx:
                        wl = filtered_wls[i - 1]
                        href = wl.get("href")
                        wl_name = wl.get('name') or wl.get('hostname') or href
                        if href in selected_workloads:
                            del selected_workloads[href]
                            print(f"  [取消勾選] {wl_name}")
                            logger.info(f"取消勾選 Workload: {wl_name} ({href})")
                        else:
                            selected_workloads[href] = wl
                            print(f"  [已勾選] {wl_name}")
                            logger.info(f"已勾選 Workload: {wl_name} ({href})")
            
            print(f"\n目前已挑選的 Workloads 數量: {len(selected_workloads)} 台")
            
            # Menu options
            print("\n請選擇後續動作:")
            print("  1. 再次挑選 Workload (使用不同關鍵字過濾)")
            print("  2. 完成挑選 Workload，進入下一步挑選標籤")
            print("  3. 離開並取消")
            
            choice = input("請輸入選項 (1/2/3): ").strip()
            logger.info(f"步驟 1 後續動作選擇: {choice}")
            if choice == "2":
                if not selected_workloads:
                    print("[提示] 您尚未挑選任何 Workload！")
                    confirm = input("確定要繼續前往下一步挑選標籤嗎？(y/n): ").strip().lower()
                    if confirm != 'y':
                        continue
                wl_names = [w.get('name') or w.get('hostname') or w.get('href') for w in selected_workloads.values()]
                logger.info(f"進入步驟 2。目前已鎖定 Workloads 共 {len(selected_workloads)} 台: {wl_names}")
                break
            elif choice == "3":
                print("取消操作。離開功能。")
                logger.info("取消工作負載貼標流程。離開。")
                return
            # If option 1 or other input, loop again
            
        # ----------------------------------------------------
        # 第二階段：挑選 Label
        # ----------------------------------------------------
        while True:
            print_separator("步驟 2：挑選要貼上的 Labels")
            filter_keyword = input("請輸入搜尋 Label 關鍵字 (直接 Enter 可查詢全部): ").strip()
            logger.info(f"步驟 2：輸入搜尋 Label 關鍵字 '{filter_keyword}'")
            
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
                logger.info("搜尋 Label 結果為空。")
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
                    logger.info(f"使用者輸入勾選 Label 編號: '{select_input}'")
                    parsed_idx = parse_selection_indices(select_input, len(filtered_lbls))
                    for i in parsed_idx:
                        lbl = filtered_lbls[i - 1]
                        href = lbl.get("href")
                        lbl_desc = f"{lbl.get('key')}:{lbl.get('value')}"
                        if href in selected_labels:
                            del selected_labels[href]
                            print(f"  [取消勾選標籤] {lbl_desc}")
                            logger.info(f"取消勾選 Label: {lbl_desc} ({href})")
                        else:
                            selected_labels[href] = lbl
                            print(f"  [已勾選標籤] {lbl_desc}")
                            logger.info(f"已勾選 Label: {lbl_desc} ({href})")
                            
            print(f"\n目前已挑選的 Labels 數量: {len(selected_labels)} 個")
            
            # Menu options
            print("\n請選擇後續動作:")
            print("  1. 再次挑選 Label (使用不同關鍵字過濾)")
            print("  2. 完成挑選 Label，進入最終確認")
            print("  3. 離開並取消")
            
            choice = input("請輸入選項 (1/2/3): ").strip()
            logger.info(f"步驟 2 後續動作選擇: {choice}")
            if choice == "2":
                if not selected_labels:
                    print("[提示] 您尚未挑選任何 Label！")
                    confirm = input("確定要繼續前往最終確認嗎？(y/n): ").strip().lower()
                    if confirm != 'y':
                        continue
                label_descs = [f"{l.get('key')}:{l.get('value')}" for l in selected_labels.values()]
                logger.info(f"進入步驟 3。目前已鎖定 Labels 共 {len(selected_labels)} 個: {label_descs}")
                break
            elif choice == "3":
                print("取消操作。離開功能。")
                logger.info("取消標籤貼標流程。離開。")
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
        logger.info(f"最終貼標確認使用者輸入: '{confirm}'")
        if confirm != 'y':
            print("操作已取消。離開功能。")
            logger.info("使用者拒絕最終確認，貼標取消。")
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
            
            logger.info(f"正在更新 Workload '{wl_name}' ({wl_href}) 的標籤，Payload: {payload}")
            try:
                client.update_workload(wl_href, payload)
                print(f"  [成功] Workload '{wl_name}' 貼標完成。")
                logger.info(f"Workload '{wl_name}' 貼標成功。")
                success_count += 1
            except Exception as e:
                logger.error(f"Failed to update workload labels for {wl_href}: {e}", exc_info=True)
                print(f"  [失敗] Workload '{wl_name}' 更新失敗 (錯誤: {e})")
                failure_count += 1
                
        print_separator("執行結果摘要")
        print(f"處理完成！ 成功: {success_count} 台, 失敗: {failure_count} 台。")
        logger.info(f"互動貼標處理完畢。成功: {success_count} 台, 失敗: {failure_count} 台。")
        
    except (KeyboardInterrupt, EOFError):
        print("\n\n[提示] 互動操作已被使用者中斷，離開功能。")
        logger.info("互動貼標操作已被使用者中斷 (KeyboardInterrupt/EOFError)。")
        return

def validate_time(time_str):
    """
    Validates if a string is in HH:MM format (24-hour).
    """
    import re
    if not re.match(r"^\d{2}:\d{2}$", time_str):
        return False
    try:
        hh, mm = map(int, time_str.split(":"))
        return 0 <= hh <= 23 and 0 <= mm <= 59
    except ValueError:
        return False

def parse_weekdays(weekdays_str):
    """
    Parses and validates a comma-separated list of weekdays.
    Returns (list of valid weekdays, error_msg).
    """
    valid_set = {"MON", "TUE", "WED", "THU", "FRI", "SAT", "SUN"}
    if not weekdays_str:
        return None, "請輸入至少一個星期名稱。"
    
    parts = [p.strip().upper() for p in weekdays_str.replace(" ", ",").split(",")]
    cleaned = []
    for p in parts:
        if not p:
            continue
        if p not in valid_set:
            return None, f"無效的星期名稱: {p}。必須是 MON, TUE, WED, THU, FRI, SAT, SUN 之一。"
        if p not in cleaned:
            cleaned.append(p)
            
    if not cleaned:
        return None, "未解析到任何有效的星期。"
    return cleaned, None

def manage_schedule(client, filter_val=None):
    """
    Manages periodic check scheduling on Windows (via schtasks) and Linux (via crontab).
    Supports Daily start times, Weekly day selection, and immediate testing triggers.
    """
    import subprocess
    import os
    import sys

    logger.info("使用者啟動了『排程管理功能 (manage_schedule)』")
    print_separator("排程管理 (Schedule Management)")
    print("此功能可在本機設定定期檢查 VEN 狀態，並在發現異常時自動發送電子郵件通知。")

    is_windows = sys.platform.startswith("win")
    platform_name = "Windows" if is_windows else "Linux/macOS"
    print(f"偵測到當前作業系統為: {platform_name}")

    # sys.executable is the Python interpreter
    # sys.argv[0] is main.py
    main_py_path = os.path.abspath(sys.argv[0])
    task_name = "Illumio_VEN_Check"

    # Fallback to main.py path detection
    if not main_py_path.endswith("main.py"):
        possible_main = os.path.abspath("main.py")
        if os.path.exists(possible_main):
            main_py_path = possible_main
        else:
            main_py_path = os.path.join(os.getcwd(), "main.py")

    # Command to run under task scheduler / cron
    task_run_cmd = f'"{sys.executable}" "{main_py_path}" vens'

    def win_add_modify():
        print("\n請選擇定期檢查的頻率：")
        print("  1. 每隔幾分鐘 (minutes)")
        print("  2. 每隔幾小時 (hours)")
        print("  3. 每天定時 (daily)")
        print("  4. 每週定時 (weekly)")
        
        freq_choice = input("選擇頻率 (1/2/3/4): ").strip()
        logger.info(f"Windows 新增/修改排程：頻率選擇='{freq_choice}'")
        if freq_choice not in ["1", "2", "3", "4"]:
            print("[錯誤] 無效的選項，操作已取消。")
            logger.info("Windows 新增/修改排程：使用者輸入無效選項，操作已取消。")
            return
            
        if freq_choice == "1":
            interval_str = input("請輸入間隔分鐘數 (正整數，例如 15 或 30): ").strip()
            try:
                interval = int(interval_str)
                if interval <= 0:
                    raise ValueError
            except ValueError:
                print("[錯誤] 請輸入有效的正整數，操作已取消。")
                logger.info(f"Windows 新增/修改排程：使用者輸入無效的間隔分鐘數 '{interval_str}'")
                return
            cmd = ["schtasks", "/create", "/tn", task_name, "/tr", task_run_cmd, "/sc", "minute", "/mo", str(interval), "/f"]
            freq_desc = f"每隔 {interval} 分鐘"
            logger.info(f"設定 Windows 排程：{freq_desc}")
        elif freq_choice == "2":
            interval_str = input("請輸入間隔小時數 (正整數，例如 2 或 12): ").strip()
            try:
                interval = int(interval_str)
                if interval <= 0:
                    raise ValueError
            except ValueError:
                print("[錯誤] 請輸入有效的正整數，操作已取消。")
                logger.info(f"Windows 新增/修改排程：使用者輸入無效的間隔小時數 '{interval_str}'")
                return
            cmd = ["schtasks", "/create", "/tn", task_name, "/tr", task_run_cmd, "/sc", "hourly", "/mo", str(interval), "/f"]
            freq_desc = f"每隔 {interval} 小時"
            logger.info(f"設定 Windows 排程：{freq_desc}")
        elif freq_choice == "3":
            time_str = input("請輸入每日執行時間 (格式 HH:MM，例如 14:30): ").strip()
            if not validate_time(time_str):
                print("[錯誤] 時間格式無效。必須為 HH:MM 且在 00:00 到 23:59 之間，操作已取消。")
                logger.info(f"Windows 新增/修改排程：使用者輸入無效的每日時間 '{time_str}'")
                return
            cmd = ["schtasks", "/create", "/tn", task_name, "/tr", task_run_cmd, "/sc", "daily", "/st", time_str, "/f"]
            freq_desc = f"每天定時 {time_str}"
            logger.info(f"設定 Windows 排程：{freq_desc}")
        else:
            days_str = input("請輸入每週執行的星期 (多選請以逗號分隔，例如 MON, FRI 或 SUN): ").strip()
            days, err = parse_weekdays(days_str)
            if err:
                print(f"[錯誤] {err}")
                logger.info(f"Windows 新增/修改排程：使用者輸入無效的星期 '{days_str}' (錯誤: {err})")
                return
            time_str = input("請輸入執行時間 (格式 HH:MM，例如 14:30): ").strip()
            if not validate_time(time_str):
                print("[錯誤] 時間格式無效。操作已取消。")
                logger.info(f"Windows 新增/修改排程：使用者輸入無效的執行時間 '{time_str}'")
                return
            days_formatted = ",".join(days)
            cmd = ["schtasks", "/create", "/tn", task_name, "/tr", task_run_cmd, "/sc", "weekly", "/d", days_formatted, "/st", time_str, "/f"]
            freq_desc = f"每週 {days_formatted} 的 {time_str}"
            logger.info(f"設定 Windows 排程：{freq_desc}")
            
        try:
            logger.info(f"執行 Windows 建立排程指令: {' '.join(cmd)}")
            subprocess.run(cmd, capture_output=True, text=True, check=True)
            print(f"\n[成功] 已成功建立/更新 Windows 排程！")
            print(f"  排程名稱：{task_name}")
            print(f"  執行頻率：{freq_desc}")
            logger.info(f"Windows 排程建立/更新成功: {freq_desc}")
        except subprocess.CalledProcessError as err:
            print(f"\n[失敗] 無法建立 Windows 排程：")
            print(f"  Exit code: {err.returncode}")
            print(f"  Stderr: {err.stderr.strip()}")
            logger.error(f"Windows 排程建立/更新失敗, Exit code: {err.returncode}, Error: {err.stderr.strip()}")

    def win_list():
        cmd = ["schtasks", "/query", "/tn", task_name, "/fo", "list"]
        try:
            logger.info(f"執行 Windows 查詢排程指令: {' '.join(cmd)}")
            res = subprocess.run(cmd, capture_output=True, text=True, check=True)
            lines = res.stdout.splitlines()
            print(f"\n當前 Windows 排程 '{task_name}' 的狀態：")
            for line in lines:
                if any(key in line for key in ["TaskName:", "Next Run Time:", "Status:", "Logon Mode:"]):
                    print("  " + line.strip())
            logger.info("Windows 排程查詢成功")
        except subprocess.CalledProcessError:
            print(f"\n[提示] 目前未在 Windows 中設定 '{task_name}' 的定期檢查排程。")
            logger.info("Windows 排程查詢結果：目前未設定該排程。")

    def win_delete():
        cmd = ["schtasks", "/delete", "/tn", task_name, "/f"]
        try:
            logger.info(f"執行 Windows 刪除排程指令: {' '.join(cmd)}")
            subprocess.run(cmd, capture_output=True, text=True, check=True)
            print(f"\n[成功] 已成功刪除 Windows 中的排程 '{task_name}'。")
            logger.info(f"Windows 排程 '{task_name}' 刪除成功。")
        except subprocess.CalledProcessError as err:
            if "ERROR: The system cannot find the file specified" in err.stderr or "系統找不到指定的檔案" in err.stderr:
                print(f"\n[提示] 找不到排程 '{task_name}'，可能本來就未設定。")
                logger.info(f"Windows 刪除排程：找不到排程 '{task_name}'，可能本來就未設定。")
            else:
                print(f"\n[失敗] 刪除 Windows 排程時出錯：{err.stderr.strip()}")
                logger.error(f"Windows 刪除排程失敗: {err.stderr.strip()}")

    def win_trigger_test():
        print(f"\n正在向 Windows 排程器發送立即觸發任務 '{task_name}' 的指令...")
        cmd = ["schtasks", "/run", "/tn", task_name]
        try:
            logger.info(f"執行 Windows 立即觸發背景排程指令: {' '.join(cmd)}")
            subprocess.run(cmd, capture_output=True, text=True, check=True)
            print(f"[成功] 已成功觸發 Windows 背景排程！")
            print("  - 任務已開始在背景運行。")
            print("  - 您可以檢視 'illumio.log' 以確認最新執行結果，或檢查收件人信箱是否收到告警信。")
            logger.info("Windows 背景排程觸發成功。")
        except subprocess.CalledProcessError as err:
            print(f"[失敗] 無法觸發排程任務 (錯誤: {err.stderr.strip()})")
            print(f"  提示: 請確認是否已建立排程。")
            logger.error(f"Windows 觸發背景排程失敗: {err.stderr.strip()}")

    def linux_add_modify():
        print("\n請選擇定期檢查的頻率：")
        print("  1. 每隔幾分鐘 (minutes)")
        print("  2. 每隔幾小時 (hours)")
        print("  3. 每天定時 (daily)")
        print("  4. 每週定時 (weekly)")
        
        freq_choice = input("選擇頻率 (1/2/3/4): ").strip()
        logger.info(f"Linux 新增/修改排程：頻率選擇='{freq_choice}'")
        if freq_choice not in ["1", "2", "3", "4"]:
            print("[錯誤] 無效的選項，操作已取消。")
            logger.info("Linux 新增/修改排程：使用者輸入無效選項，操作已取消。")
            return
            
        if freq_choice == "1":
            interval_str = input("請輸入間隔分鐘數 (正整數，例如 15 或 30): ").strip()
            try:
                interval = int(interval_str)
                if interval <= 0:
                    raise ValueError
            except ValueError:
                print("[錯誤] 請輸入有效的正整數，操作已取消。")
                logger.info(f"Linux 新增/修改排程：使用者輸入無效的間隔分鐘數 '{interval_str}'")
                return
            cron_expr = f"*/{interval} * * * *"
            freq_desc = f"每隔 {interval} 分鐘"
            logger.info(f"設定 Linux 排程：{freq_desc}")
        elif freq_choice == "2":
            interval_str = input("請輸入間隔小時數 (正整數，例如 2 或 12): ").strip()
            try:
                interval = int(interval_str)
                if interval <= 0:
                    raise ValueError
            except ValueError:
                print("[錯誤] 請輸入有效的正整數，操作已取消。")
                logger.info(f"Linux 新增/修改排程：使用者輸入無效的間隔小時數 '{interval_str}'")
                return
            cron_expr = f"0 */{interval} * * *"
            freq_desc = f"每隔 {interval} 小時"
            logger.info(f"設定 Linux 排程：{freq_desc}")
        elif freq_choice == "3":
            time_str = input("請輸入每日執行時間 (格式 HH:MM，例如 14:30): ").strip()
            if not validate_time(time_str):
                print("[錯誤] 時間格式無效。操作已取消。")
                logger.info(f"Linux 新增/修改排程：使用者輸入無效的每日時間 '{time_str}'")
                return
            hh, mm = map(int, time_str.split(":"))
            cron_expr = f"{mm} {hh} * * *"
            freq_desc = f"每天定時 {time_str}"
            logger.info(f"設定 Linux 排程：{freq_desc}")
        else:
            days_str = input("請輸入每週執行的星期 (多選請以逗號分隔，例如 MON, FRI 或 SUN): ").strip()
            days, err = parse_weekdays(days_str)
            if err:
                print(f"[錯誤] {err}")
                logger.info(f"Linux 新增/修改排程：使用者輸入無效的星期 '{days_str}' (錯誤: {err})")
                return
            time_str = input("請輸入執行時間 (格式 HH:MM，例如 14:30): ").strip()
            if not validate_time(time_str):
                print("[錯誤] 時間格式無效。操作已取消。")
                logger.info(f"Linux 新增/修改排程：使用者輸入無效的執行時間 '{time_str}'")
                return
            
            hh, mm = map(int, time_str.split(":"))
            day_map = {"MON": "1", "TUE": "2", "WED": "3", "THU": "4", "FRI": "5", "SAT": "6", "SUN": "0"}
            cron_days = ",".join([day_map[d] for d in days])
            
            cron_expr = f"{mm} {hh} * * {cron_days}"
            freq_desc = f"每週 {','.join(days)} 的 {time_str}"
            logger.info(f"設定 Linux 排程：{freq_desc}")
            
        current_cron = ""
        try:
            logger.info("執行 Linux crontab -l 查詢當前排程以進行備份/更新")
            res = subprocess.run(["crontab", "-l"], capture_output=True, text=True)
            if res.returncode == 0:
                current_cron = res.stdout
        except Exception as e:
            logger.warning(f"Linux crontab -l 查詢失敗或無現有排程: {e}")
            
        cron_lines = current_cron.splitlines()
        new_cron_lines = [line for line in cron_lines if f"# {task_name}" not in line]
        
        new_line = f'{cron_expr} "{sys.executable}" "{main_py_path}" vens # {task_name}'
        new_cron_lines.append(new_line)
        
        new_cron_content = "\n".join(new_cron_lines) + "\n"
        try:
            logger.info(f"更新 Linux crontab 內容，新項目: {new_line}")
            subprocess.run(["crontab", "-"], input=new_cron_content, capture_output=True, text=True, check=True)
            print(f"\n[成功] 已成功建立/更新 Linux crontab 排程！")
            print(f"  排程項目：{new_line}")
            print(f"  執行頻率：{freq_desc}")
            logger.info(f"Linux crontab 排程更新成功: {freq_desc}")
        except subprocess.CalledProcessError as err:
            print(f"\n[失敗] 無法寫入 crontab (錯誤: {err.stderr.strip()})")
            logger.error(f"Linux crontab 排程更新失敗, Error: {err.stderr.strip()}")

    def linux_list():
        try:
            logger.info("執行 Linux crontab -l 查詢排程")
            res = subprocess.run(["crontab", "-l"], capture_output=True, text=True)
            if res.returncode != 0:
                print(f"\n[提示] 目前未在 Linux 中設定 '{task_name}' 的定期檢查排程 (無 crontab)。")
                logger.info("Linux crontab 查詢結果：目前未設定 crontab 排程。")
                return
                
            lines = res.stdout.splitlines()
            matched_lines = [line for line in lines if f"# {task_name}" in line]
            if not matched_lines:
                print(f"\n[提示] 目前未在 Linux 中設定 '{task_name}' 的定期檢查排程。")
                logger.info("Linux crontab 查詢結果：目前無相關排程項目。")
            else:
                print(f"\n當前 Linux crontab 中的相關排程：")
                for line in matched_lines:
                    print(f"  {line}")
                logger.info("Linux crontab 查詢成功。")
        except Exception as e:
            print(f"\n[錯誤] 查詢 crontab 時出錯: {e}")
            logger.error(f"Linux 查詢 crontab 時出錯: {e}")

    def linux_delete():
        try:
            logger.info("執行 Linux crontab -l 讀取排程以進行刪除")
            res = subprocess.run(["crontab", "-l"], capture_output=True, text=True)
            if res.returncode != 0:
                print(f"\n[提示] 找不到排程，目前沒有 crontab。")
                logger.info("Linux 刪除排程：找不到任何排程，目前沒有 crontab。")
                return
                
            lines = res.stdout.splitlines()
            new_lines = [line for line in lines if f"# {task_name}" not in line]
            
            has_other_jobs = any(line.strip() for line in new_lines)
            
            if not has_other_jobs:
                logger.info("執行 Linux crontab -r 清空 crontab")
                subprocess.run(["crontab", "-r"], capture_output=True)
                print(f"\n[成功] 已成功刪除 Linux crontab 中的排程 '{task_name}' (crontab 已清空)。")
                logger.info(f"Linux crontab 中的排程 '{task_name}' 刪除成功（且 crontab 已完全清空）。")
            else:
                new_cron_content = "\n".join(new_lines) + "\n"
                logger.info("執行 Linux crontab - 更新排程項目")
                subprocess.run(["crontab", "-"], input=new_cron_content, capture_output=True, text=True, check=True)
                print(f"\n[成功] 已成功刪除 Linux crontab 中的排程 '{task_name}'。")
                logger.info(f"Linux crontab 中的排程 '{task_name}' 刪除成功。")
        except Exception as e:
            print(f"\n[失敗] 刪除 Linux 排程時出錯: {e}")
            logger.error(f"Linux 刪除排程失敗: {e}")

    def linux_trigger_test():
        logger.info(f"執行 Linux 前景排程測試指令: {sys.executable} {main_py_path} vens")
        print(f"\n正在 Linux 上執行排程測試 (於前景執行 'python main.py vens')...")
        try:
            subprocess.run([sys.executable, main_py_path, "vens"], check=True)
            print(f"[成功] 測試執行完成！已於前景輸出結果。")
            logger.info("Linux 前景排程測試執行成功。")
        except Exception as e:
            print(f"[失敗] 執行測試任務時出錯: {e}")
            logger.error(f"Linux 前景排程測試執行失敗: {e}")

    try:
        while True:
            print_separator("排程管理選單")
            print("  1. 新增或修改定期檢查排程")
            print("  2. 查看現有排程狀態")
            print("  3. 刪除定期檢查排程")
            print("  4. 立即觸發排程的任務進行測試")
            print("  5. 離開")
            
            choice = input("請輸入選項 (1/2/3/4/5): ").strip()
            logger.info(f"排程管理選單選擇: '{choice}'")
            if choice == "1":
                if is_windows:
                    win_add_modify()
                else:
                    linux_add_modify()
            elif choice == "2":
                if is_windows:
                    win_list()
                else:
                    linux_list()
            elif choice == "3":
                if is_windows:
                    win_delete()
                else:
                    linux_delete()
            elif choice == "4":
                if is_windows:
                    win_trigger_test()
                else:
                    linux_trigger_test()
            elif choice == "5":
                print("離開排程管理選單。")
                logger.info("離開排程管理選單。")
                break
            else:
                print("[提示] 無效的選項，請重新輸入。")
                logger.info(f"排程管理選單：輸入了無效選項 '{choice}'")
    except (KeyboardInterrupt, EOFError):
        print("\n\n[提示] 互動操作已被使用者中斷，離開功能。")
        logger.info("排程管理操作已被使用者中斷 (KeyboardInterrupt/EOFError)。")
