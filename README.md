# Python Illumio API Client & Agent Skill

此專案為根據 Illumio REST APIs 25.4 技術手冊所撰寫的 Python API 用戶端封裝。

## 🚀 特色與功能
* **環境變數配置 (`config.py`)**：自動載入 `.env` 設定檔，避免密鑰直接寫入程式碼。
* **PCE 用戶端封裝 (`illumio_client.py`)**：
  * 使用 Python `requests` 實現 persistent connection 階段。
  * 支援 **ApiKeyAuth** (HTTP Basic 驗證)，無須維護臨時會話期限。
  * 包含完整的網路異常與 HTTP 狀態碼異常捕捉機制。
* **核心 API 調用支援**：
  * `/health` (GET): 檢查 PCE 健康狀態。
  * `/orgs/{org_id}/workloads` (GET/POST/PUT/DELETE): 伺服器主機工作負載生命週期管理。
  * `/orgs/{org_id}/labels` (GET/POST/DELETE): 安全微隔離標籤（Role, App, Env, Loc）管理。
  * `/orgs/{org_id}/vens` (GET): 虛擬防護節點 (VEN) 狀態監控與警報。
* **主控進入點 (`main.py`) 與動作定義 (`method.py`)**：模組化的執行架構與乾淨的終端機輸出，並支援日誌存檔。
* **模擬測試 (`mock_test.py`)**：使用 Python `unittest.mock` 在無實體 PCE 環境下進行百分之百的請求邏輯與參數驗證。

---

## 🛠️ 安裝與準備工作

### 1. 系統需求與 Python 版本
*   **建議 Python 版本**：Python `3.8` 或以上版本（支援至最新 Python `3.13`）。
*   您可以從 [Python 官方網站](https://www.python.org/downloads/) 下載並安裝。安裝時請務必勾選 **"Add Python to PATH"** (將 Python 加入系統環境變數)。

### 2. 建立與使用虛擬環境 (建議)
為了避免套件版本衝突，建議為此專案建立獨立的虛擬環境 (Virtual Environment)。

#### **Windows 系統：**
1. 開啟命令提示字元 (CMD) 或 PowerShell，切換至專案根目錄。
2. 建立虛擬環境 (資料夾名稱為 `venv`)：
   ```bash
   python -m venv venv
   ```
3. 啟用虛擬環境：
   *   **CMD**:
       ```cmd
       venv\Scripts\activate
       ```
   *   **PowerShell**:
       ```powershell
       venv\Scripts\activate.ps1
       ```
       *(若出現執行原則錯誤，請先執行 `Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope Process`)*

#### **macOS / Linux 系統：**
1. 開啟終端機 (Terminal)，切換至專案根目錄。
2. 建立虛擬環境：
   ```bash
   python3 -m venv venv
   ```
3. 啟用虛擬環境：
   ```bash
   source venv/bin/activate
   ```

*(啟用後，終端機提示字元前方會顯示 `(venv)`，代表目前已進入虛擬環境。若要退出，直接輸入 `deactivate` 即可。)*

### 3. 安裝相依套件
啟用虛擬環境後，請執行以下命令安裝專案所需的所有套件 (目前僅需 `requests` 函式庫)：
```bash
pip install -r requirements.txt
```
或直接安裝：
```bash
pip install requests
```

### 4. 設定環境變數 `.env`
專案內附帶了一個環境變數範本檔 [.env.example](file:///c:/Users/U/Documents/Dev/IllumioAPI_example/.env.example)。請複製該檔案並命名為 `.env`：
*   **Windows (CMD/PowerShell)**: `copy .env.example .env`
*   **macOS / Linux**: `cp .env.example .env`

接著編輯 `.env`，填入您的 Illumio PCE 與郵件伺服器相關設定。

> 💡 *提示：在測試或開發環境中，如果您使用的是 PCE 自建 self-signed 憑證，用戶端預設的 `verify_ssl=False` 可以讓您免除證書不信任的錯誤。*

---

## 💻 程式調用範例

### 獨立腳本執行
在設定好 `.env` 後，可直接使用以下命令來執行與檢視輸出：

* **連線確認與健康狀態檢查 (預設值)**：
  ```bash
  python main.py
  ```
* **執行所有動作 (Health、Labels、Workloads、VENs)**：
  ```bash
  python main.py all
  ```
* **自訂連續執行與過濾查詢** (使用 `-f <filter_str>` 過濾關鍵字，支援順序調整)：
  ```bash
  # 僅查詢標籤並篩選包含 "app" 的資料
  python main.py labels -f app
  
  # 查詢標籤與工作負載，各自套用篩選
  python main.py labels -f app workloads -f prod
  ```
* **VEN 狀態監控與郵件警報**：
  ```bash
  python main.py vens
  ```
  *此命令會檢查所有 VEN 的連線狀態，若狀態不為 `active`，將自動發送電子郵件通知至 `.env` 中指定的收件者；若未設定 SMTP，則會於控制台輸出警報信件模擬。*

* **互動式工作負載貼標功能**：
  ```bash
  python main.py tag
  ```
  *此命令會開啟一個互動式的精靈，引導您透過關鍵字篩選、勾選多台 Workload，再篩選、勾選多個 Label，最終進行批次套用。貼標時採取安全合併（Merge）邏輯，僅會更新有變動的維度，保留其餘舊標籤。*

* **跨平台定期檢查排程管理**：
  ```bash
  python main.py schedule
  ```
  *此命令可在本機設定自動化排程。在 Windows 下自動整合「工作排程器 (schtasks)」，在 Linux/macOS 下則整合系統「crontab」，不佔用背景常駐記憶體。支援每分鐘、每小時、每天特定時間（格式 HH:MM）、每週特定星期與時間定時檢查，亦可由選單立即觸發背景任務進行測試。*

> 📝 *提示：詳細的 API 呼叫資料與除錯資訊會完整儲存在 `illumio.log` 中，而控制台 (Console) 只會顯示重要的摘要資訊，並以表格形式列出前 10 筆資料。*

---

## 📧 執行郵件警報測試 (Email Alert Test)
為了驗證異常 VEN 郵件發送排版與連線設定，您可以直接執行測試程式：
```bash
python test_email.py
```
*   **若未配置 SMTP**：控制台將輸出精美的電子郵件模擬排版。
*   **若已配置 SMTP**：將會透過您的郵件伺服器寄送測試信至指定的收件者。

---

## 🧪 執行單元測試 (Mock Tests)
若要在不安裝實體 PCE 伺服器的情況下驗證 API 客戶端的請求與參數解析邏輯是否正確，請在根目錄執行：
```bash
python -m unittest mock_test.py
```
若測試通過，您將看到類似如下的成功輸出：
```
......
----------------------------------------------------------------------
Ran 6 tests in 0.015s

OK
```



