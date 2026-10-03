from unittest.mock import Mock, patch
import pytest
import requests
from app.connectors.wazuh import WazuhConnector


@pytest.mark.parametrize('failure,expected', [
    (requests.exceptions.SSLError('submitted-secret'), 'certificate'),
    (requests.exceptions.ConnectTimeout('submitted-secret'), 'firewall'),
    (requests.exceptions.ConnectionError('submitted-secret'), 'Cannot reach'),
    (requests.exceptions.ReadTimeout('submitted-secret'), 'did not respond'),
])
def test_wazuh_failure_is_actionable_and_does_not_echo_credentials(failure, expected):
    connector = WazuhConnector(base_url='https://wazuh.example:55000',username='wazuh-wui',password='submitted-secret')
    with patch('app.connectors.wazuh.integration_request',side_effect=failure):
        with pytest.raises(ConnectionError) as error:
            connector._authenticate()
    assert expected in str(error.value)
    assert 'submitted-secret' not in str(error.value)


@pytest.mark.parametrize('status', [401,403])
def test_wazuh_authentication_error_explains_api_credentials(status):
    response = Mock(status_code=status)
    response.raise_for_status.side_effect = requests.exceptions.HTTPError('submitted-secret')
    with patch('app.connectors.wazuh.integration_request',return_value=response):
        with pytest.raises(ConnectionError, match='API_USERNAME and API_PASSWORD') as error:
            WazuhConnector(base_url='https://wazuh.example:55000')._authenticate()
    assert 'submitted-secret' not in str(error.value)
