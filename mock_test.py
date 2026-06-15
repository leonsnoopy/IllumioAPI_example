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

if __name__ == '__main__':
    unittest.main()
