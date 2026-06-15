# Python Illumio API Client & Agent Skill

此專案為根據 Illumio REST APIs 25.4 技術手冊所撰寫的 Python API 用戶端封裝。它不但可作為一個獨立的 Python 軟體套件，亦可作為 AI Agent 的「系統技能（Skill）/ 工具（Tool）」呼叫介面。

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

### 1. 安裝相依套件
本用戶端需要 Python `requests` 函式庫。請確保您的系統已安裝：
```bash
pip install requests
```

### 2. 設定環境變數 `.env`
在專案根目錄下建立一個名為 `.env` 的檔案，內容如下：
```ini
ILLUMIO_PCE_FQDN=pce.my-company.com
ILLUMIO_PCE_PORT=8443
ILLUMIO_ORG_ID=1
ILLUMIO_API_KEY_ID=api_xxxxxxxxxxxxxxxxxxxx
ILLUMIO_API_SECRET_TOKEN=token_xxxxxxxxxxxxxxxxxxxxxxxxxxxxx
```
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


### 程式碼整合
```python
from illumio_client import IllumioClient

# 初始化 Client 
client = IllumioClient(
    pce_fqdn="pce.my-company.com",
    api_key_id="api_xxx",
    api_secret_token="token_xxx",
    pce_port=8443,
    org_id=1,
    verify_ssl=False
)

# 獲取標籤列表
labels = client.get_labels(value="Web")
for label in labels:
    print(f"Label: {label['key']} = {label['value']}")
```

---

## 🤖 如何作為 AI Agent Skill (工具) 使用

此用戶端可作為 AI Agent (如 LangChain, AutoGen 或自製 LLM Agent) 的一個 Tool 集合。以下是向 AI Agent 描述此工具的 Spec 定義：

### 工具描述規範 (Tool Schema)
```json
{
  "name": "illumio_api_client",
  "description": "呼叫 Illumio PCE API 執行健康度檢查、管理主機工作負載與微隔離安全標籤。",
  "functions": [
    {
      "name": "check_health",
      "description": "檢查 PCE 的健康與運作狀態。無須參數。"
    },
    {
      "name": "get_workloads",
      "description": "查詢受管與非受管的主機工作負載清單。",
      "parameters": {
        "type": "object",
        "properties": {
          "representation": {
            "type": "string",
            "description": "進階擴展查詢，例如傳入 'workload_labels_vulnerabilities' 同時加載標籤與漏洞資訊。"
          }
        }
      }
    },
    {
      "name": "get_labels",
      "description": "查詢 PCE 的微隔離標籤。",
      "parameters": {
        "type": "object",
        "properties": {
          "value": {
            "type": "string",
            "description": "模糊查詢標籤名稱（例如 'Web' 或 'Prod'）。"
          }
        }
      }
    }
  ]
}
```

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

---

## 📧 執行郵件警報測試 (Email Alert Test)
為了驗證異常 VEN 郵件發送排版與連線設定，您可以直接執行測試程式：
```bash
python test_email.py
```
*   **若未配置 SMTP**：控制台將輸出精美的電子郵件模擬排版。
*   **若已配置 SMTP**：將會透過您的郵件伺服器寄送測試信至指定的收件者。

