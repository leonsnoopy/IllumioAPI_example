import json
import logging
import sys
import config
from utils import reconfigure_stdout, print_separator, parse_selection_indices, validate_time, parse_weekdays, convert_utc_to_taiwan_time, get_event_description
from notifier import EmailNotifier
from scheduler import get_scheduler

# Reconfigure stdout to use UTF-8 to prevent encoding issues on Windows consoles
reconfigure_stdout()

logger = logging.getLogger("illumio_client")


def send_email_notification(abnormal_vens):
    """
    Sends an email notification if there are abnormal VENs.
    Delegates to the EmailNotifier service using global configuration options.
    """
    notifier = EmailNotifier(
        smtp_server=config.SMTP_SERVER,
        smtp_port=config.SMTP_PORT,
        smtp_user=config.SMTP_USER,
        smtp_password=config.SMTP_PASSWORD,
        email_sender=config.EMAIL_SENDER,
        email_receiver=config.EMAIL_RECEIVER
    )
    return notifier.send_abnormal_vens_alert(abnormal_vens)


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


def manage_schedule(client, filter_val=None):
    """
    Manages periodic check scheduling by delegating to the platform-specific scheduler service.
    """
    logger.info("使用者啟動了『排程管理功能 (manage_schedule)』")
    print_separator("排程管理 (Schedule Management)")
    print("此功能可在本機設定定期檢查 VEN 狀態，並在發現異常時自動發送電子郵件通知。")

    scheduler = get_scheduler()
    is_windows = sys.platform.startswith("win")
    platform_name = "Windows" if is_windows else "Linux/macOS"
    print(f"偵測到當前作業系統為: {platform_name}")

    def add_modify_menu():
        print("\n請選擇定期檢查的頻率：")
        print("  1. 每隔幾分鐘 (minutes)")
        print("  2. 每隔幾小時 (hours)")
        print("  3. 每天定時 (daily)")
        print("  4. 每週定時 (weekly)")
        
        freq_choice = input("選擇頻率 (1/2/3/4): ").strip()
        logger.info(f"新增/修改排程：頻率選擇='{freq_choice}'")
        if freq_choice not in ["1", "2", "3", "4"]:
            print("[錯誤] 無效的選項，操作已取消。")
            return
            
        if freq_choice == "1":
            interval_str = input("請輸入間隔分鐘數 (正整數，例如 15 或 30): ").strip()
            try:
                interval = int(interval_str)
                if interval <= 0:
                    raise ValueError
            except ValueError:
                print("[錯誤] 請輸入有效的正整數，操作已取消。")
                return
            scheduler.add_or_modify("minute", interval)
        elif freq_choice == "2":
            interval_str = input("請輸入間隔小時數 (正整數，例如 2 或 12): ").strip()
            try:
                interval = int(interval_str)
                if interval <= 0:
                    raise ValueError
            except ValueError:
                print("[錯誤] 請輸入有效的正整數，操作已取消。")
                return
            scheduler.add_or_modify("hourly", interval)
        elif freq_choice == "3":
            time_str = input("請輸入每日執行時間 (格式 HH:MM，例如 14:30): ").strip()
            if not validate_time(time_str):
                print("[錯誤] 時間格式無效。必須為 HH:MM 且在 00:00 到 23:59 之間，操作已取消。")
                return
            scheduler.add_or_modify("daily", time_str)
        else:
            days_str = input("請輸入每週執行的星期 (多選請以逗號分隔，例如 MON, FRI 或 SUN): ").strip()
            days, err = parse_weekdays(days_str)
            if err:
                print(f"[錯誤] {err}")
                return
            time_str = input("請輸入執行時間 (格式 HH:MM，例如 14:30): ").strip()
            if not validate_time(time_str):
                print("[錯誤] 時間格式無效。操作已取消。")
                return
            scheduler.add_or_modify("weekly", time_str, weekdays=days)

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
                add_modify_menu()
            elif choice == "2":
                scheduler.list_jobs()
            elif choice == "3":
                scheduler.delete_job()
            elif choice == "4":
                scheduler.trigger_test()
            elif choice == "5":
                print("離開排程管理選單。")
                logger.info("離開排程管理選單。")
                break
            else:
                print("[提示] 無效的選項，請重新輸入。")
    except (KeyboardInterrupt, EOFError):
        print("\n\n[提示] 互動操作已被使用者中斷，離開功能。")
        logger.info("排程管理操作已被使用者中斷 (KeyboardInterrupt/EOFError)。")


def get_events(client, filter_val=None, notify_emails=None):
    """Retrieves and displays system events, showing up to 10 entries by default, or 20 entries when filtered."""
    print_separator("Get System Audit Events")
    
    # Decide max records based on filter presence
    max_results = 20 if filter_val else 10
    logger.info(f"Executing get_events (filter: {filter_val}, max_results: {max_results})...")
    
    status = None
    severity = None
    event_type = None
    
    if filter_val:
        # Check if filter contains key-value pairs (e.g. status=success severity=info)
        import re
        pairs = re.split(r'[,; ]+', filter_val)
        has_kv = False
        for pair in pairs:
            if '=' in pair:
                k, v = pair.split('=', 1)
                k_clean = k.strip().lower()
                v_clean = v.strip()
                if k_clean == 'status':
                    status = v_clean
                    has_kv = True
                elif k_clean == 'severity':
                    severity = v_clean
                    if severity.lower() == 'error':
                        severity = 'err'
                    has_kv = True
                elif k_clean in ('event_type', 'event_name', 'type'):
                    event_type = v_clean
                    has_kv = True
        
        # Fallback to smart detection if no key-value pairs are provided
        if not has_kv:
            val_lower = filter_val.strip().lower()
            if val_lower in ('success', 'failure'):
                status = val_lower
            elif val_lower in ('warning', 'err', 'error', 'info', 'emerg', 'alert', 'crit', 'notice', 'debug'):
                severity = 'err' if val_lower == 'error' else val_lower
            else:
                event_type = filter_val.strip()
                
    # Build filter log message
    filter_logs = []
    if status: filter_logs.append(f"status: '{status}'")
    if severity: filter_logs.append(f"severity: '{severity}'")
    if event_type: filter_logs.append(f"event_type: '{event_type}'")
    if filter_logs:
        print(f"篩選條件: {', '.join(filter_logs)}")
        
    try:
        events = client.get_events(status=status, severity=severity, event_type=event_type, max_results=max_results)
        logger.debug(f"Retrieved {len(events)} events details: {json.dumps(events, ensure_ascii=False)}")
        
        total_count = len(events)
        print(f"系統事件: 成功取得 {total_count} 筆事件記錄")
        
        if total_count > 0:
            print(f"\n顯示前 {total_count} 筆事件資訊:")
            # Column widths: No(4), Timestamp(20), Event Type(25), Severity(10), Status(10), Created By(16), Description
            print(f"{'No.':<4} {'Timestamp':<20} {'Event Type':<25} {'Severity':<10} {'Status':<10} {'Created By':<16} {'Description'}")
            print("-" * 115)
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
                    
                # Truncate values if too long for column width
                if len(etype) > 23:
                    etype = etype[:20] + "..."
                if len(timestamp) > 19:
                    timestamp = timestamp[:19]
                if len(creator) > 14:
                    creator = creator[:12] + "..."
                    
                print(f"{idx:<4} {timestamp:<20} {etype:<25} {sev:<10} {stat:<10} {creator:<16} {desc}")
        # Send email notification if notify_emails is provided (not None)
        if notify_emails is not None:
            receiver = notify_emails
            if not isinstance(receiver, str) or not receiver.strip():
                receiver = config.EMAIL_RECEIVER
            
            notifier = EmailNotifier(
                smtp_server=config.SMTP_SERVER,
                smtp_port=config.SMTP_PORT,
                smtp_user=config.SMTP_USER,
                smtp_password=config.SMTP_PASSWORD,
                email_sender=config.EMAIL_SENDER,
                email_receiver=receiver
            )
            notifier.send_events_alert(events if events is not None else [])
            
        return events
    except Exception as e:
        logger.error(f"Failed to retrieve events: {e}", exc_info=True)
        print(f"系統事件: 取得失敗 (錯誤: {e})")
        return None
