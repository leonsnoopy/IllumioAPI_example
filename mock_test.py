import unittest
from unittest.mock import patch, MagicMock
import requests
from illumio_client import IllumioClient

class TestIllumioClient(unittest.TestCase):
    def setUp(self):
        # Create a client instance with mock configurations
        self.client = IllumioClient(
            pce_fqdn="pce-mock.local",
            api_key_id="api_mock_key_id",
            api_secret_token="api_mock_secret_token",
            pce_port=8443,
            org_id=1,
            verify_ssl=False
        )

    @patch('requests.Session.request')
    def test_check_health(self, mock_request):
        # Configure mock response
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {"status": "healthy", "version": "25.4.0"}
        mock_request.return_value = mock_resp

        # Trigger check_health endpoint
        result = self.client.check_health()
        
        # Validate target URI structure and return values
        self.assertEqual(result["status"], "healthy")
        mock_request.assert_called_once_with(
            method="GET",
            url="https://pce-mock.local:8443/api/v2/health",
            params=None,
            json=None,
            verify=False
        )

    @patch('requests.Session.request')
    def test_get_labels(self, mock_request):
        # Configure mock response
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = [
            {"href": "/orgs/1/labels/1", "key": "role", "value": "Web"},
            {"href": "/orgs/1/labels/2", "key": "app", "value": "DB"}
        ]
        mock_request.return_value = mock_resp

        # Trigger get_labels with filter parameter
        result = self.client.get_labels(value="Web")

        # Validate request parameters and outputs
        self.assertEqual(len(result), 2)
        self.assertEqual(result[0]["value"], "Web")
        mock_request.assert_called_once_with(
            method="GET",
            url="https://pce-mock.local:8443/api/v2/orgs/1/labels",
            params={"value": "Web"},
            json=None,
            verify=False
        )

    @patch('requests.Session.request')
    def test_get_workloads(self, mock_request):
        # Configure mock response
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = [
            {"href": "/orgs/1/workloads/w1", "hostname": "web-srv-1", "name": "Web Server 1"}
        ]
        mock_request.return_value = mock_resp

        # Trigger get_workloads with representation parameter
        result = self.client.get_workloads(representation="workload_labels_vulnerabilities")

        # Validate parameter passing and structure
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]["hostname"], "web-srv-1")
        mock_request.assert_called_once_with(
            method="GET",
            url="https://pce-mock.local:8443/api/v2/orgs/1/workloads",
            params={"representation": "workload_labels_vulnerabilities"},
            json=None,
            verify=False
        )

    @patch('requests.Session.request')
    def test_create_workload(self, mock_request):
        mock_resp = MagicMock()
        mock_resp.status_code = 201
        mock_resp.json.return_value = {
            "href": "/orgs/1/workloads/new-id",
            "name": "DB Server 1",
            "hostname": "db-srv-1"
        }
        mock_request.return_value = mock_resp

        payload = {"name": "DB Server 1", "hostname": "db-srv-1"}
        result = self.client.create_workload(payload)

        self.assertEqual(result["href"], "/orgs/1/workloads/new-id")
        mock_request.assert_called_once_with(
            method="POST",
            url="https://pce-mock.local:8443/api/v2/orgs/1/workloads",
            params=None,
            json=payload,
            verify=False
        )

    @patch('requests.Session.request')
    def test_get_vens(self, mock_request):
        # Configure mock response
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = [
            {"href": "/orgs/1/vens/1", "hostname": "ven-srv-1", "status": "active", "version": "24.2.20"},
            {"href": "/orgs/1/vens/2", "hostname": "ven-srv-2", "status": "suspended", "version": "24.2.20"}
        ]
        mock_request.return_value = mock_resp

        # Trigger get_vens
        result = self.client.get_vens()

        self.assertEqual(len(result), 2)
        self.assertEqual(result[0]["hostname"], "ven-srv-1")
        self.assertEqual(result[1]["status"], "suspended")
        mock_request.assert_called_once_with(
            method="GET",
            url="https://pce-mock.local:8443/api/v2/orgs/1/vens",
            params=None,
            json=None,
            verify=False
        )

    @patch('requests.Session.request')
    def test_http_error_handling(self, mock_request):
        # Setup mock error status
        mock_resp = MagicMock()
        mock_resp.status_code = 401
        mock_resp.text = "Unauthorized"
        
        http_error = requests.exceptions.HTTPError("401 Client Error: Unauthorized", response=mock_resp)
        mock_resp.raise_for_status.side_effect = http_error
        mock_request.return_value = mock_resp

        # Verify custom exception propagation
        with self.assertRaises(requests.exceptions.HTTPError):
            self.client.check_health()

    def test_parse_selection_indices(self):
        from method import parse_selection_indices
        # Test basic cases
        self.assertEqual(parse_selection_indices("1", 5), [1])
        self.assertEqual(parse_selection_indices("1,2,3", 5), [1, 2, 3])
        # Test spaces and commas
        self.assertEqual(parse_selection_indices("1 2 3", 5), [1, 2, 3])
        self.assertEqual(parse_selection_indices("1, 2,  3", 5), [1, 2, 3])
        # Test ranges
        self.assertEqual(parse_selection_indices("1-3", 5), [1, 2, 3])
        self.assertEqual(parse_selection_indices("1-3, 5", 5), [1, 2, 3, 5])
        self.assertEqual(parse_selection_indices("3-1", 5), [1, 2, 3])
        # Test out of bounds
        self.assertEqual(parse_selection_indices("1-10", 5), [1, 2, 3, 4, 5])
        self.assertEqual(parse_selection_indices("0, 6", 5), [])

    @patch('method.input')
    @patch('illumio_client.IllumioClient.update_workload')
    @patch('illumio_client.IllumioClient.get_labels')
    @patch('illumio_client.IllumioClient.get_workloads')
    def test_interactive_tagging_flow(self, mock_get_workloads, mock_get_labels, mock_update_workload, mock_input):
        # 1. Setup mocked workloads
        mock_get_workloads.return_value = [
            {
                "href": "/orgs/1/workloads/w1",
                "name": "win-db-01",
                "hostname": "win-db-01.local",
                "labels": [
                    {"key": "env", "href": "/orgs/1/labels/env-prod", "value": "Prod"},
                    {"key": "role", "href": "/orgs/1/labels/role-db", "value": "DB"}
                ]
            },
            {
                "href": "/orgs/1/workloads/w2",
                "name": "linux-web-01",
                "hostname": "linux-web-01.local",
                "labels": [
                    {"key": "env", "href": "/orgs/1/labels/env-dev", "value": "Dev"}
                ]
            }
        ]
        
        # 2. Setup mocked labels
        mock_get_labels.return_value = [
            {"href": "/orgs/1/labels/role-web", "key": "role", "value": "Web"},
            {"href": "/orgs/1/labels/loc-us", "key": "loc", "value": "US"}
        ]
        
        # 3. Setup input mock sequence
        mock_input.side_effect = [
            "win",      # Filter workloads
            "1",        # Select 1st workload (win-db-01)
            "2",        # Action 2 (complete workloads selection)
            "loc",      # Filter labels
            "1",        # Select 1st label (loc-us)
            "2",        # Action 2 (complete labels selection)
            "y"         # Confirm application
        ]
        
        from method import interactive_tagging
        interactive_tagging(self.client)
        
        # Verify get methods were called
        mock_get_workloads.assert_called_once()
        mock_get_labels.assert_called_once()
        
        # Verify update_workload was called with correct merged payload
        mock_update_workload.assert_called_once()
        args, kwargs = mock_update_workload.call_args
        self.assertEqual(args[0], "/orgs/1/workloads/w1")
        
        # Check that all expected merged elements are present
        payload_sent = args[1]
        labels_sent = payload_sent["labels"]
        self.assertEqual(len(labels_sent), 3)
        self.assertTrue({"href": "/orgs/1/labels/env-prod"} in labels_sent)
        self.assertTrue({"href": "/orgs/1/labels/role-db"} in labels_sent)
        self.assertTrue({"href": "/orgs/1/labels/loc-us"} in labels_sent)

    @patch('method.input')
    @patch('subprocess.run')
    @patch('sys.platform', 'win32')
    def test_manage_schedule_windows_add(self, mock_run, mock_input):
        # 1. Option 1 (Add/modify) -> Freq choice 1 (minute) -> Interval 15 -> Option 5 (Exit)
        mock_input.side_effect = ["1", "1", "15", "5"]
        mock_res = MagicMock()
        mock_res.returncode = 0
        mock_res.stdout = "SUCCESS: Created."
        mock_run.return_value = mock_res
        
        from method import manage_schedule
        manage_schedule(self.client)
        
        create_call_args = None
        for call in mock_run.call_args_list:
            args = call[0][0]
            if "schtasks" in args and "/create" in args:
                create_call_args = args
                break
                
        self.assertIsNotNone(create_call_args)
        self.assertIn("Illumio_VEN_Check", create_call_args)
        self.assertIn("minute", create_call_args)
        self.assertIn("15", create_call_args)

    @patch('method.input')
    @patch('subprocess.run')
    @patch('sys.platform', 'linux')
    def test_manage_schedule_linux_add(self, mock_run, mock_input):
        # 1. Option 1 (Add/modify) -> Freq choice 2 (hours) -> Interval 6 -> Option 5 (Exit)
        mock_input.side_effect = ["1", "2", "6", "5"]
        
        mock_res_l = MagicMock()
        mock_res_l.returncode = 0
        mock_res_l.stdout = "* * * * * other_job\n"
        
        mock_res_write = MagicMock()
        mock_res_write.returncode = 0
        
        mock_run.side_effect = [mock_res_l, mock_res_write]
        
        from method import manage_schedule
        manage_schedule(self.client)
        
        self.assertEqual(mock_run.call_count, 2)
        args, kwargs = mock_run.call_args_list[1]
        self.assertEqual(args[0], ["crontab", "-"])
        self.assertIn("0 */6 * * *", kwargs["input"])
        self.assertIn("vens # Illumio_VEN_Check", kwargs["input"])
        self.assertIn("other_job", kwargs["input"])

    def test_validate_time(self):
        from method import validate_time
        self.assertTrue(validate_time("14:30"))
        self.assertTrue(validate_time("00:00"))
        self.assertTrue(validate_time("23:59"))
        self.assertFalse(validate_time("24:00"))
        self.assertFalse(validate_time("12:60"))
        self.assertFalse(validate_time("abc"))
        self.assertFalse(validate_time("9:30"))

    def test_parse_weekdays(self):
        from method import parse_weekdays
        days, err = parse_weekdays("MON, FRI")
        self.assertEqual(days, ["MON", "FRI"])
        self.assertIsNone(err)
        
        days, err = parse_weekdays("mon,  tue")
        self.assertEqual(days, ["MON", "TUE"])
        
        days, err = parse_weekdays("ABC")
        self.assertIsNone(days)
        self.assertIsNotNone(err)

    @patch('method.input')
    @patch('subprocess.run')
    @patch('sys.platform', 'win32')
    def test_manage_schedule_windows_weekly(self, mock_run, mock_input):
        # Option 1 (Add/modify) -> Freq choice 4 (weekly) -> Weekdays MON,FRI -> Time 14:30 -> Option 5 (Exit)
        mock_input.side_effect = ["1", "4", "MON, FRI", "14:30", "5"]
        mock_res = MagicMock()
        mock_res.returncode = 0
        mock_run.return_value = mock_res
        
        from method import manage_schedule
        manage_schedule(self.client)
        
        create_call_args = None
        for call in mock_run.call_args_list:
            args = call[0][0]
            if "schtasks" in args and "/create" in args:
                create_call_args = args
                break
                
        self.assertIsNotNone(create_call_args)
        self.assertIn("Illumio_VEN_Check", create_call_args)
        self.assertIn("weekly", create_call_args)
        self.assertIn("MON,FRI", create_call_args)
        self.assertIn("14:30", create_call_args)

    @patch('method.input')
    @patch('subprocess.run')
    @patch('sys.platform', 'linux')
    def test_manage_schedule_linux_weekly(self, mock_run, mock_input):
        # Option 1 (Add/modify) -> Freq choice 4 (weekly) -> Weekdays MON,FRI -> Time 14:30 -> Option 5 (Exit)
        mock_input.side_effect = ["1", "4", "MON, FRI", "14:30", "5"]
        
        mock_res_l = MagicMock()
        mock_res_l.returncode = 0
        mock_res_l.stdout = ""
        
        mock_res_write = MagicMock()
        mock_res_write.returncode = 0
        
        mock_run.side_effect = [mock_res_l, mock_res_write]
        
        from method import manage_schedule
        manage_schedule(self.client)
        
        self.assertEqual(mock_run.call_count, 2)
        args, kwargs = mock_run.call_args_list[1]
        self.assertEqual(args[0], ["crontab", "-"])
        self.assertIn("30 14 * * 1,5", kwargs["input"])

    @patch('requests.Session.request')
    def test_client_get_events(self, mock_request):
        # Configure mock response
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = [{"event_type": "user.login", "status": "success"}]
        mock_request.return_value = mock_resp

        # Test defaults
        res = self.client.get_events()
        self.assertEqual(len(res), 1)
        mock_request.assert_called_with(
            method="GET",
            url="https://pce-mock.local:8443/api/v2/orgs/1/events",
            params={"max_results": 20},
            json=None,
            verify=False
        )

        # Test with custom filters
        self.client.get_events(status="failure", severity="err", event_type="workload.create", max_results=15)
        mock_request.assert_called_with(
            method="GET",
            url="https://pce-mock.local:8443/api/v2/orgs/1/events",
            params={"status": "failure", "severity": "err", "event_type": "workload.create", "max_results": 15},
            json=None,
            verify=False
        )

    @patch('illumio_client.IllumioClient.get_events')
    def test_method_get_events_no_filter(self, mock_get_events):
        mock_get_events.return_value = []
        from method import get_events
        get_events(self.client)
        mock_get_events.assert_called_once_with(status=None, severity=None, event_type=None, max_results=10)

    @patch('illumio_client.IllumioClient.get_events')
    def test_method_get_events_with_smart_filter(self, mock_get_events):
        mock_get_events.return_value = []
        from method import get_events

        # 1. Fuzzy match status
        get_events(self.client, "success")
        mock_get_events.assert_called_with(status="success", severity=None, event_type=None, max_results=20)

        # 2. Fuzzy match severity
        get_events(self.client, "warning")
        mock_get_events.assert_called_with(status=None, severity="warning", event_type=None, max_results=20)

        # 3. Fuzzy match event type
        get_events(self.client, "user.logout")
        mock_get_events.assert_called_with(status=None, severity=None, event_type="user.logout", max_results=20)

        # 4. Explicit key-value pairs
        get_events(self.client, "status=failure severity=err event_type=workload.delete")
        mock_get_events.assert_called_with(status="failure", severity="err", event_type="workload.delete", max_results=20)

        # 5. Fuzzy match 'error' mapping to 'err'
        get_events(self.client, "error")
        mock_get_events.assert_called_with(status=None, severity="err", event_type=None, max_results=20)

        # 6. Explicit key-value severity=error mapping to err
        get_events(self.client, "severity=error")
        mock_get_events.assert_called_with(status=None, severity="err", event_type=None, max_results=20)

    @patch('method.EmailNotifier')
    @patch('illumio_client.IllumioClient.get_events')
    def test_method_get_events_with_notification(self, mock_get_events, mock_email_notifier_class):
        mock_get_events.return_value = [{"event_type": "user.login", "status": "success", "timestamp": "2026-06-25T02:44:39Z"}]
        mock_notifier = MagicMock()
        mock_email_notifier_class.return_value = mock_notifier
        
        from method import get_events
        get_events(self.client, notify_emails="test_user@syscom.com.tw")
        
        # Verify EmailNotifier is constructed with the given email receiver
        mock_email_notifier_class.assert_called_once()
        _, kwargs = mock_email_notifier_class.call_args
        self.assertEqual(kwargs["email_receiver"], "test_user@syscom.com.tw")
        
        # Verify send_events_alert was called
        mock_notifier.send_events_alert.assert_called_once_with(mock_get_events.return_value)


class TestDecoupledComponents(unittest.TestCase):
    def test_utils_parse_selection_indices(self):
        from utils import parse_selection_indices
        self.assertEqual(parse_selection_indices("1-3,5", 5), [1, 2, 3, 5])

    def test_utils_validate_time(self):
        from utils import validate_time
        self.assertTrue(validate_time("12:34"))
        self.assertFalse(validate_time("25:00"))

    def test_utils_parse_weekdays(self):
        from utils import parse_weekdays
        days, err = parse_weekdays("MON, WED")
        self.assertEqual(days, ["MON", "WED"])
        self.assertIsNone(err)

    @patch('smtplib.SMTP')
    def test_email_notifier(self, mock_smtp_class):
        from notifier import EmailNotifier
        mock_smtp = MagicMock()
        mock_smtp_class.return_value.__enter__.return_value = mock_smtp

        notifier = EmailNotifier(
            smtp_server="smtp.test.com",
            smtp_port=587,
            smtp_user="user",
            smtp_password="pass",
            email_sender="sender@test.com",
            email_receiver="receiver@test.com"
        )
        
        abnormal_vens = [{"hostname": "test-host", "status": "suspended", "href": "/orgs/1/vens/1"}]
        res = notifier.send_abnormal_vens_alert(abnormal_vens)
        
        self.assertTrue(res)
        mock_smtp.starttls.assert_called_once()
        mock_smtp.login.assert_called_once_with("user", "pass")
        mock_smtp.sendmail.assert_called_once()

    @patch('subprocess.run')
    def test_windows_scheduler(self, mock_run):
        from scheduler import WindowsScheduler
        mock_res = MagicMock()
        mock_res.returncode = 0
        mock_run.return_value = mock_res

        scheduler = WindowsScheduler("Test_Task")
        success, desc = scheduler.add_or_modify("minute", 15)
        
        self.assertTrue(success)
        self.assertEqual(desc, "每隔 15 分鐘")
        
        called_args = mock_run.call_args[0][0]
        self.assertIn("schtasks", called_args)
        self.assertIn("/create", called_args)
        self.assertIn("Test_Task", called_args)

    @patch('subprocess.run')
    def test_linux_scheduler(self, mock_run):
        from scheduler import LinuxScheduler
        mock_res_l = MagicMock()
        mock_res_l.returncode = 0
        mock_res_l.stdout = ""
        mock_res_write = MagicMock()
        mock_res_write.returncode = 0
        mock_run.side_effect = [mock_res_l, mock_res_write]

        scheduler = LinuxScheduler("Test_Task")
        success, desc = scheduler.add_or_modify("hourly", 2)
        
        self.assertTrue(success)
        self.assertEqual(desc, "每隔 2 小時")
        
        self.assertEqual(mock_run.call_count, 2)
        first_call_args = mock_run.call_args_list[0][0][0]
        self.assertEqual(first_call_args, ["crontab", "-l"])
        
        second_call_args = mock_run.call_args_list[1][0][0]
        self.assertEqual(second_call_args, ["crontab", "-"])
        second_call_kwargs = mock_run.call_args_list[1][1]
        self.assertIn("0 */2 * * *", second_call_kwargs["input"])

    def test_utils_convert_utc_to_taiwan_time(self):
        from utils import convert_utc_to_taiwan_time
        # UTC Time: 2026-06-25T02:44:39.392Z -> Taiwan Time (UTC+8): 2026-06-25 10:44:39
        self.assertEqual(convert_utc_to_taiwan_time("2026-06-25T02:44:39.392Z"), "2026-06-25 10:44:39")
        self.assertEqual(convert_utc_to_taiwan_time("2026-06-25T02:44:39Z"), "2026-06-25 10:44:39")
        self.assertEqual(convert_utc_to_taiwan_time("N/A"), "N/A")

    @patch('smtplib.SMTP')
    def test_email_notifier_events_alert(self, mock_smtp_class):
        from notifier import EmailNotifier
        mock_smtp = MagicMock()
        mock_smtp_class.return_value.__enter__.return_value = mock_smtp

        notifier = EmailNotifier(
            smtp_server="smtp.test.com",
            smtp_port=587,
            smtp_user="user",
            smtp_password="pass",
            email_sender="sender@test.com",
            email_receiver="receiver1@test.com, receiver2@test.com"
        )
        
        events = [{"event_type": "user.login", "status": "success", "timestamp": "2026-06-25T02:44:39.392Z"}]
        res = notifier.send_events_alert(events)
        
        self.assertTrue(res)
        mock_smtp.starttls.assert_called_once()
        mock_smtp.login.assert_called_once_with("user", "pass")
        
        # Check sendmail arguments
        called_args = mock_smtp.sendmail.call_args[0]
        self.assertEqual(called_args[0], "sender@test.com")
        self.assertEqual(called_args[1], ["receiver1@test.com", "receiver2@test.com"])
        
        # Parse MIME message to verify body content
        import email
        msg_obj = email.message_from_string(called_args[2])
        body_text = msg_obj.get_payload(decode=True).decode('utf-8')
        self.assertIn("成功取得 1 筆系統事件記錄", body_text)
        self.assertIn("user.login", body_text)
        self.assertIn("success", body_text)
        self.assertIn("2026-06-25 10:44:39", body_text)


class TestMainCLI(unittest.TestCase):
    @patch('sys.argv', ['main.py', 'events', '-notify', 'leon_yc@syscom.com.tw, SW_Huang@syscom.com.tw'])
    @patch('main.IllumioClient')
    @patch('main.AVAILABLE_METHODS')
    @patch('main.config')
    def test_main_cli_notify_parsing(self, mock_config, mock_methods, mock_client_class):
        mock_config.API_KEY_ID = "api_key"
        mock_config.API_SECRET_TOKEN = "api_secret"
        
        mock_events = MagicMock()
        mock_methods.__contains__.side_effect = lambda x: x in ["events"]
        mock_methods.__getitem__.side_effect = lambda x: mock_events if x == "events" else MagicMock()
        mock_methods.keys.return_value = ["events"]
        
        from main import main
        main()
        
        mock_events.assert_called_once()
        args, kwargs = mock_events.call_args
        self.assertEqual(kwargs.get("notify_emails"), "leon_yc@syscom.com.tw, SW_Huang@syscom.com.tw")

    @patch('sys.argv', ['main.py', 'events', '-notify'])
    @patch('main.IllumioClient')
    @patch('main.AVAILABLE_METHODS')
    @patch('main.config')
    def test_main_cli_notify_default(self, mock_config, mock_methods, mock_client_class):
        mock_config.API_KEY_ID = "api_key"
        mock_config.API_SECRET_TOKEN = "api_secret"
        
        mock_events = MagicMock()
        mock_methods.__contains__.side_effect = lambda x: x in ["events"]
        mock_methods.__getitem__.side_effect = lambda x: mock_events if x == "events" else MagicMock()
        mock_methods.keys.return_value = ["events"]
        
        from main import main
        main()
        
        mock_events.assert_called_once()
        args, kwargs = mock_events.call_args
        self.assertEqual(kwargs.get("notify_emails"), "")


if __name__ == '__main__':
    unittest.main()
