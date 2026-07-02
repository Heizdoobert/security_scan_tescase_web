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

def test_assess_subcommand_routes_correctly():
    with patch('scripts.cli.VulnerabilityAssessor') as MockAssessor, \
         patch.object(sys, 'argv', ['cli.py', 'assess']):
        
        mock_instance = MockAssessor.return_value
        mock_instance.assess.return_value = []
        mock_instance.exit_code.return_value = 0
        
        with pytest.raises(SystemExit) as exc:
            cli.main()
            
        assert exc.value.code == 0
        MockAssessor.assert_called_once()
        mock_instance.assess.assert_called_once()

def test_check_subcommand_routes_correctly():
    with patch('scripts.cli.ComplianceChecker') as MockChecker, \
         patch.object(sys, 'argv', ['cli.py', 'check']):
        
        mock_instance = MockChecker.return_value
        mock_instance.check.return_value = []
        mock_instance.exit_code.return_value = 0
        
        with pytest.raises(SystemExit) as exc:
            cli.main()
            
        assert exc.value.code == 0
        MockChecker.assert_called_once()
        mock_instance.check.assert_called_once()
