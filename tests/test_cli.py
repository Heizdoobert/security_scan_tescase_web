import sys
import pytest
from unittest.mock import patch
import scripts.cli as cli

def test_scan_subcommand_routes_correctly():
    with patch('scripts.cli.SecurityScanner') as MockScanner, \
         patch.object(sys, 'argv', ['cli.py', 'scan', '.', '--severity', 'high']):
        
        mock_instance = MockScanner.return_value
        mock_instance.scan.return_value = []
        mock_instance.exit_code.return_value = 0
        
        with pytest.raises(SystemExit) as exc:
            cli.main()
            
        assert exc.value.code == 0
        MockScanner.assert_called_once_with('.', min_severity='high')
        mock_instance.scan.assert_called_once()
