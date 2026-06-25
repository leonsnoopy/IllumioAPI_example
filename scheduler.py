import sys
import subprocess
import os
import logging
from abc import ABC, abstractmethod

logger = logging.getLogger("illumio_client")

class BaseScheduler(ABC):
    """
    Abstract Base Class for PCE Health / VEN check scheduling.
    Abstracts scheduling configurations across platforms.
    """
    def __init__(self, action="vens", task_name=None):
        # Backward compatibility: if action is custom and task_name is None, treat it as task_name
        if action not in ("vens", "blocked-traffic") and task_name is None:
            task_name = action
            action = "vens"
            
        self.action = action
        if task_name:
            self.task_name = task_name
        else:
            if action == "vens":
                self.task_name = "Illumio_VEN_Check"
            else:
                sanitized = action.replace("-", "_")
                self.task_name = f"Illumio_{sanitized}_Check"
        self.main_py_path = self._detect_main_py_path()
        self.task_run_cmd = f'"{sys.executable}" "{self.main_py_path}" {self.action} -notify'

    def _detect_main_py_path(self):
        """
        Attempts to resolve the absolute path to the main.py execution script.
        """
        main_py_path = os.path.abspath(sys.argv[0])
        if not main_py_path.endswith("main.py"):
            possible_main = os.path.abspath("main.py")
            if os.path.exists(possible_main):
                main_py_path = possible_main
            else:
                main_py_path = os.path.join(os.getcwd(), "main.py")
        return main_py_path

    @abstractmethod
    def add_or_modify(self, freq_type, interval_or_time, weekdays=None):
        """
        Creates or updates a periodic task schedule.
        
        Args:
            freq_type (str): Type of frequency ('minute', 'hourly', 'daily', 'weekly')
            interval_or_time (int/str): Interval value in minutes/hours (int) or target execution time 'HH:MM' (str)
            weekdays (list, optional): List of weekdays (e.g. ['MON', 'FRI']) if weekly frequency.
            
        Returns:
            tuple: (bool, str) status success flag and descriptive frequency message / error message.
        """
        pass

    @abstractmethod
    def list_jobs(self):
        """
        Queries and lists currently configured scheduler jobs for the application.
        
        Returns:
            bool: True if query execution completed successfully.
        """
        pass

    @abstractmethod
    def delete_job(self):
        """
        Removes the registered scheduler task if it exists.
        
        Returns:
            bool: True if delete operation succeeded.
        """
        pass

    @abstractmethod
    def trigger_test(self):
        """
        Manually triggers the schedule task for immediate background execution.
        
        Returns:
            bool: True if trigger successfully sent.
        """
        pass


class WindowsScheduler(BaseScheduler):
    """
    Windows implementation using task scheduler CLI tool 'schtasks'.
    """
    def add_or_modify(self, freq_type, interval_or_time, weekdays=None):
        if freq_type == "minute":
            cmd = ["schtasks", "/create", "/tn", self.task_name, "/tr", self.task_run_cmd, "/sc", "minute", "/mo", str(interval_or_time), "/f"]
            freq_desc = f"每隔 {interval_or_time} 分鐘"
        elif freq_type == "hourly":
            cmd = ["schtasks", "/create", "/tn", self.task_name, "/tr", self.task_run_cmd, "/sc", "hourly", "/mo", str(interval_or_time), "/f"]
            freq_desc = f"每隔 {interval_or_time} 小時"
        elif freq_type == "daily":
            cmd = ["schtasks", "/create", "/tn", self.task_name, "/tr", self.task_run_cmd, "/sc", "daily", "/st", str(interval_or_time), "/f"]
            freq_desc = f"每天定時 {interval_or_time}"
        elif freq_type == "weekly":
            days_formatted = ",".join(weekdays)
            cmd = ["schtasks", "/create", "/tn", self.task_name, "/tr", self.task_run_cmd, "/sc", "weekly", "/d", days_formatted, "/st", str(interval_or_time), "/f"]
            freq_desc = f"每週 {days_formatted} 的 {interval_or_time}"
        else:
            raise ValueError(f"Unsupported frequency type: {freq_type}")

        try:
            logger.info(f"執行 Windows 建立排程指令: {' '.join(cmd)}")
            subprocess.run(cmd, capture_output=True, text=True, check=True)
            print(f"\n[成功] 已成功建立/更新 Windows 排程！")
            print(f"  排程名稱：{self.task_name}")
            print(f"  執行頻率：{freq_desc}")
            logger.info(f"Windows 排程建立/更新成功: {freq_desc}")
            return True, freq_desc
        except subprocess.CalledProcessError as err:
            print(f"\n[失敗] 無法建立 Windows 排程：")
            print(f"  Exit code: {err.returncode}")
            print(f"  Stderr: {err.stderr.strip()}")
            logger.error(f"Windows 排程建立/更新失敗, Exit code: {err.returncode}, Error: {err.stderr.strip()}")
            return False, err.stderr.strip()

    def list_jobs(self):
        cmd = ["schtasks", "/query", "/tn", self.task_name, "/fo", "list"]
        try:
            logger.info(f"執行 Windows 查詢排程指令: {' '.join(cmd)}")
            res = subprocess.run(cmd, capture_output=True, text=True, check=True)
            lines = res.stdout.splitlines()
            print(f"\n當前 Windows 排程 '{self.task_name}' 的狀態：")
            for line in lines:
                if any(key in line for key in ["TaskName:", "Next Run Time:", "Status:", "Logon Mode:"]):
                    print("  " + line.strip())
            logger.info("Windows 排程查詢成功")
            return True
        except subprocess.CalledProcessError:
            print(f"\n[提示] 目前未在 Windows 中設定 '{self.task_name}' 的定期檢查排程。")
            logger.info("Windows 排程查詢結果：目前未設定該排程。")
            return False

    def delete_job(self):
        cmd = ["schtasks", "/delete", "/tn", self.task_name, "/f"]
        try:
            logger.info(f"執行 Windows 刪除排程指令: {' '.join(cmd)}")
            subprocess.run(cmd, capture_output=True, text=True, check=True)
            print(f"\n[成功] 已成功刪除 Windows 中的排程 '{self.task_name}'。")
            logger.info(f"Windows 排程 '{self.task_name}' 刪除成功。")
            return True
        except subprocess.CalledProcessError as err:
            if "ERROR: The system cannot find the file specified" in err.stderr or "系統找不到指定的檔案" in err.stderr:
                print(f"\n[提示] 找不到排程 '{self.task_name}'，可能本來就未設定。")
                logger.info(f"Windows 刪除排程：找不到排程 '{self.task_name}'，可能本來就未設定。")
                return True
            else:
                print(f"\n[失敗] 刪除 Windows 排程時出錯：{err.stderr.strip()}")
                logger.error(f"Windows 刪除排程失敗: {err.stderr.strip()}")
                return False

    def trigger_test(self):
        print(f"\n正在向 Windows 排程器發送立即觸發任務 '{self.task_name}' 的指令...")
        cmd = ["schtasks", "/run", "/tn", self.task_name]
        try:
            logger.info(f"執行 Windows 立即觸發背景排程指令: {' '.join(cmd)}")
            subprocess.run(cmd, capture_output=True, text=True, check=True)
            print(f"[成功] 已成功觸發 Windows 背景排程！")
            print("  - 任務已開始在背景運行。")
            print("  - 您可以檢視 'illumio.log' 以確認最新執行結果，或檢查收件人信箱是否收到告警信。")
            logger.info("Windows 背景排程觸發成功。")
            return True
        except subprocess.CalledProcessError as err:
            print(f"[失敗] 無法觸發排程任務 (錯誤: {err.stderr.strip()})")
            print(f"  提示: 請確認是否已建立排程。")
            logger.error(f"Windows 觸發背景排程失敗: {err.stderr.strip()}")
            return False


class LinuxScheduler(BaseScheduler):
    """
    Linux / macOS implementation using crontab CLI management.
    """
    def add_or_modify(self, freq_type, interval_or_time, weekdays=None):
        if freq_type == "minute":
            cron_expr = f"*/{interval_or_time} * * * *"
            freq_desc = f"每隔 {interval_or_time} 分鐘"
        elif freq_type == "hourly":
            cron_expr = f"0 */{interval_or_time} * * *"
            freq_desc = f"每隔 {interval_or_time} 小時"
        elif freq_type == "daily":
            hh, mm = map(int, interval_or_time.split(":"))
            cron_expr = f"{mm} {hh} * * *"
            freq_desc = f"每天定時 {interval_or_time}"
        elif freq_type == "weekly":
            hh, mm = map(int, interval_or_time.split(":"))
            day_map = {"MON": "1", "TUE": "2", "WED": "3", "THU": "4", "FRI": "5", "SAT": "6", "SUN": "0"}
            cron_days = ",".join([day_map[d] for d in weekdays])
            cron_expr = f"{mm} {hh} * * {cron_days}"
            freq_desc = f"每週 {','.join(weekdays)} 的 {interval_or_time}"
        else:
            raise ValueError(f"Unsupported frequency type: {freq_type}")

        current_cron = ""
        try:
            logger.info("執行 Linux crontab -l 查詢當前排程以進行備份/更新")
            res = subprocess.run(["crontab", "-l"], capture_output=True, text=True)
            if res.returncode == 0:
                current_cron = res.stdout
        except Exception as e:
            logger.warning(f"Linux crontab -l 查詢失敗或無現有排程: {e}")
            
        cron_lines = current_cron.splitlines()
        new_cron_lines = [line for line in cron_lines if f"# {self.task_name}" not in line]
        
        new_line = f'{cron_expr} "{sys.executable}" "{self.main_py_path}" {self.action} -notify # {self.task_name}'
        new_cron_lines.append(new_line)
        
        new_cron_content = "\n".join(new_cron_lines) + "\n"
        try:
            logger.info(f"更新 Linux crontab 內容，新項目: {new_line}")
            subprocess.run(["crontab", "-"], input=new_cron_content, capture_output=True, text=True, check=True)
            print(f"\n[成功] 已成功建立/更新 Linux crontab 排程！")
            print(f"  排程項目：{new_line}")
            print(f"  執行頻率：{freq_desc}")
            logger.info(f"Linux crontab 排程更新成功: {freq_desc}")
            return True, freq_desc
        except subprocess.CalledProcessError as err:
            print(f"\n[失敗] 無法寫入 crontab (錯誤: {err.stderr.strip()})")
            logger.error(f"Linux crontab 排程更新失敗, Error: {err.stderr.strip()}")
            return False, err.stderr.strip()

    def list_jobs(self):
        try:
            logger.info("執行 Linux crontab -l 查詢排程")
            res = subprocess.run(["crontab", "-l"], capture_output=True, text=True)
            if res.returncode != 0:
                print(f"\n[提示] 目前未在 Linux 中設定 '{self.task_name}' 的定期檢查排程 (無 crontab)。")
                logger.info("Linux crontab 查詢結果：目前未設定 crontab 排程。")
                return False
                
            lines = res.stdout.splitlines()
            matched_lines = [line for line in lines if f"# {self.task_name}" in line]
            if not matched_lines:
                print(f"\n[提示] 目前未在 Linux 中設定 '{self.task_name}' 的定期檢查排程。")
                logger.info("Linux crontab 查詢結果：目前無相關排程項目。")
                return False
            else:
                print(f"\n當前 Linux crontab 中的相關排程：")
                for line in matched_lines:
                    print(f"  {line}")
                logger.info("Linux crontab 查詢成功。")
                return True
        except Exception as e:
            print(f"\n[錯誤] 查詢 crontab 時出錯: {e}")
            logger.error(f"Linux 查詢 crontab 時出錯: {e}")
            return False

    def delete_job(self):
        try:
            logger.info("執行 Linux crontab -l 讀取排程以進行刪除")
            res = subprocess.run(["crontab", "-l"], capture_output=True, text=True)
            if res.returncode != 0:
                print(f"\n[提示] 找不到排程，目前沒有 crontab。")
                logger.info("Linux 刪除排程：找不到任何排程，目前沒有 crontab。")
                return True
                
            lines = res.stdout.splitlines()
            new_lines = [line for line in lines if f"# {self.task_name}" not in line]
            
            has_other_jobs = any(line.strip() for line in new_lines)
            
            if not has_other_jobs:
                logger.info("執行 Linux crontab -r 清空 crontab")
                subprocess.run(["crontab", "-r"], capture_output=True)
                print(f"\n[成功] 已成功刪除 Linux crontab 中的排程 '{self.task_name}' (crontab 已清空)。")
                logger.info(f"Linux crontab 中的排程 '{self.task_name}' 刪除成功（且 crontab 已完全清空）。")
                return True
            else:
                new_cron_content = "\n".join(new_lines) + "\n"
                logger.info("執行 Linux crontab - 更新排程項目")
                subprocess.run(["crontab", "-"], input=new_cron_content, capture_output=True, text=True, check=True)
                print(f"\n[成功] 已成功刪除 Linux crontab 中的排程 '{self.task_name}'。")
                logger.info(f"Linux crontab 中的排程 '{self.task_name}' 刪除成功。")
                return True
        except Exception as e:
            print(f"\n[失敗] 刪除 Linux 排程時出錯: {e}")
            logger.error(f"Linux 刪除排程失敗: {e}")
            return False

    def trigger_test(self):
        logger.info(f"執行 Linux 前景排程測試指令: {sys.executable} {self.main_py_path} {self.action} -notify")
        print(f"\n正在 Linux 上執行排程測試 (於前景執行 'python main.py {self.action} -notify')...")
        try:
            subprocess.run([sys.executable, self.main_py_path, self.action, "-notify"], check=True)
            print(f"[成功] 測試執行完成！已於前景輸出結果。")
            logger.info("Linux 前景排程測試執行成功。")
            return True
        except Exception as e:
            print(f"[失敗] 執行測試任務時出錯: {e}")
            logger.error(f"Linux 前景排程測試執行失敗: {e}")
            return False


def get_scheduler(action="vens", task_name=None):
    """
    Factory function returning the correct platform scheduler instance.
    """
    if sys.platform.startswith("win"):
        return WindowsScheduler(action=action, task_name=task_name)
    else:
        return LinuxScheduler(action=action, task_name=task_name)
