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

if __name__ == '__main__':
    unittest.main()
