import logging
import urllib3
import requests
from requests.auth import HTTPBasicAuth

# Suppress insecure request warnings if SSL verification is disabled
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Set up logger
logger = logging.getLogger("illumio_client")
if not logger.handlers:
    handler = logging.StreamHandler()
    formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    handler.setFormatter(formatter)
    logger.addHandler(handler)
    logger.setLevel(logging.INFO)

class IllumioClient:
    """
    A Python client wrapper for the Illumio PCE REST API (version 25.4).
    Handles authentication, network error trapping, and core API operations.
    """
    def __init__(self, pce_fqdn, api_key_id, api_secret_token, pce_port=8443, org_id=1, verify_ssl=True):
        """
        Initializes the IllumioClient.
        
        Args:
            pce_fqdn (str): Fully Qualified Domain Name of the PCE (e.g., 'pce.my-company.com')
            api_key_id (str): The API Key ID (e.g., 'api_xxxxxx')
            api_secret_token (str): The API Secret Token (e.g., 'token_xxxxxx')
            pce_port (int, optional): Port for the PCE API. Defaults to 8443.
            org_id (int, optional): The Org ID. Defaults to 1.
            verify_ssl (bool, optional): Whether to verify SSL certificates. Defaults to True.
        """
        self.pce_fqdn = pce_fqdn
        self.pce_port = pce_port
        self.org_id = org_id
        self.api_key_id = api_key_id
        self.api_secret_token = api_secret_token
        self.verify_ssl = verify_ssl
        self.base_url = f"https://{self.pce_fqdn}:{self.pce_port}/api/v2"
        
        # Configure persistent session with HTTP Basic Authentication
        self.session = requests.Session()
        self.session.auth = HTTPBasicAuth(self.api_key_id, self.api_secret_token)
        self.session.headers.update({
            'Accept': 'application/json',
            'Content-Type': 'application/json'
        })
        
    def _request(self, method, path, params=None, json=None):
        """
        Private helper to process HTTP request actions safely.
        """
        # Ensure path starts with a slash
        if not path.startswith('/'):
            path = '/' + path
            
        url = f"{self.base_url}{path}"
        logger.debug(f"Sending request: {method} {url}")
        
        try:
            response = self.session.request(
                method=method,
                url=url,
                params=params,
                json=json,
                verify=self.verify_ssl
            )
            
            # Trap HTTP level status errors (4xx/5xx)
            response.raise_for_status()
            
            # Return True for 204 No Content success, or parse JSON response
            if response.status_code == 204:
                return True
                
            try:
                return response.json()
            except ValueError:
                return response.text
                
        except requests.exceptions.HTTPError as http_err:
            logger.error(f"HTTP error occurred: {http_err} - Response body: {response.text}")
            raise
        except requests.exceptions.ConnectionError as conn_err:
            logger.error(f"Connection error occurred: {conn_err}")
            raise
        except requests.exceptions.Timeout as timeout_err:
            logger.error(f"Timeout error occurred: {timeout_err}")
            raise
        except requests.exceptions.RequestException as req_err:
            logger.error(f"An unexpected request error occurred: {req_err}")
            raise

    # ==========================================
    # 1. PCE Health & General Information
    # ==========================================
    def check_health(self):
        """
        Checks the health status of the PCE.
        
        Returns:
            dict/str: Health check status response.
        """
        # Note: /health is a global API endpoint under /api/v2
        return self._request("GET", "/health")

    # ==========================================
    # 2. Workload & VEN Management
    # ==========================================
    def get_workloads(self, representation=None):
        """
        Retrieves a list of managed and unmanaged workloads.
        
        Args:
            representation (str, optional): Option to expand details like workload_labels_vulnerabilities.
            
        Returns:
            list: List of workload objects.
        """
        params = {}
        if representation:
            params['representation'] = representation
        return self._request("GET", f"/orgs/{self.org_id}/workloads", params=params)

    def create_workload(self, workload_data):
        """
        Manually registers an unmanaged workload in the PCE.
        
        Args:
            workload_data (dict): Workload metadata parameters.
            
        Returns:
            dict: The created workload details.
        """
        return self._request("POST", f"/orgs/{self.org_id}/workloads", json=workload_data)

    def update_workload(self, workload_id, workload_data):
        """
        Updates an existing workload's properties, such as mode and labels.
        
        Args:
            workload_id (str): The workload unique ID or href.
            workload_data (dict): The target workload fields to update.
            
        Returns:
            dict: Updated workload configuration.
        """
        # Work with either direct ID or full href
        path = workload_id if "/orgs/" in workload_id else f"/orgs/{self.org_id}/workloads/{workload_id}"
        return self._request("PUT", path, json=workload_data)

    def delete_workload(self, workload_id):
        """
        Deletes a workload configuration from the PCE.
        
        Args:
            workload_id (str): The workload unique ID or href.
            
        Returns:
            bool: True if successful.
        """
        path = workload_id if "/orgs/" in workload_id else f"/orgs/{self.org_id}/workloads/{workload_id}"
        return self._request("DELETE", path)

    # ==========================================
    # 3. Security Labels Management
    # ==========================================
    def get_labels(self, value=None):
        """
        Retrieves security labels deployed on the PCE.
        
        Args:
            value (str, optional): A query string to filter labels by value (fuzzy match).
            
        Returns:
            list: List of label objects.
        """
        params = {}
        if value:
            params['value'] = value
        return self._request("GET", f"/orgs/{self.org_id}/labels", params=params)

    def create_label(self, key, value):
        """
        Creates a new security label.
        
        Args:
            key (str): Label dimension (e.g. 'role', 'app', 'env', 'loc').
            value (str): Label display name/value (e.g. 'Web', 'Database', 'Prod', 'US').
            
        Returns:
            dict: The created label object.
        """
        label_payload = {"key": key, "value": value}
        return self._request("POST", f"/orgs/{self.org_id}/labels", json=label_payload)

    def delete_label(self, label_id):
        """
        Deletes an unreferenced security label.
        
        Args:
            label_id (str): The label unique ID or href.
            
        Returns:
            bool: True if successful.
        """
        path = label_id if "/orgs/" in label_id else f"/orgs/{self.org_id}/labels/{label_id}"
        return self._request("DELETE", path)

    # ==========================================
    # 4. VEN (Virtual Enforcement Node) Management
    # ==========================================
    def get_vens(self):
        """
        Retrieves a list of Virtual Enforcement Nodes (VENs).
        
        Returns:
            list: List of VEN objects.
        """
        return self._request("GET", f"/orgs/{self.org_id}/vens")

    # ==========================================
    # 5. System Events & Auditing Logs
    # ==========================================
    def get_events(self, status=None, severity=None, event_type=None, max_results=20):
        """
        Retrieves a list of system events/audit logs.
        
        Args:
            status (str, optional): Filter by status (e.g. 'success', 'failure')
            severity (str, optional): Filter by severity (e.g. 'info', 'warning', 'err')
            event_type (str, optional): Filter by event type/name (e.g. 'workload.create')
            max_results (int, optional): Max records to retrieve. Defaults to 20.
            
        Returns:
            list: List of system event objects.
        """
        params = {}
        if status:
            params['status'] = status
        if severity:
            params['severity'] = severity
        if event_type:
            params['event_type'] = event_type
        if max_results:
            params['max_results'] = max_results
            
        return self._request("GET", f"/orgs/{self.org_id}/events", params=params)

