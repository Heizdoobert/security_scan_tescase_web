import pytest

@pytest.hookimpl(hookwrapper=True)
def pytest_runtest_makereport(item, call):
    pytest_html = item.config.pluginmanager.getplugin('html')
    outcome = yield
    report = outcome.get_result()
    extras = getattr(report, 'extras', [])

    if report.when == 'call':
        # Try to extract the target URL if available in the test function arguments
        target_url = "N/A"
        if "base_url" in item.fixturenames and hasattr(item, "funcargs"):
            target_url = item.funcargs.get("base_url", "N/A")
        elif "client" in item.fixturenames and hasattr(item, "funcargs"):
            client = item.funcargs.get("client")
            if hasattr(client, "base_url"):
                target_url = client.base_url

        # Build custom detail log
        details = [
            "=== TEST EXECUTION DETAILS ===",
            f"Test Target : {target_url}",
            f"Node ID     : {item.nodeid}",
            f"Function    : {item.name}",
            f"Description : {item.function.__doc__ or 'No description provided'}",
            f"Status      : {report.outcome.upper()}",
            f"Duration    : {report.duration:.3f} seconds",
            "=============================="
        ]

        # Append captured stdout/stderr/log to our custom log view
        for section_name, section_content in report.sections:
            details.append(f"\n--- {section_name.upper()} ---")
            details.append(section_content)
        
        # In case there's no log output from sections
        if not report.sections:
            details.append("\n--- LOGS ---")
            details.append("No CLI log output was captured during this test.")

        log_content = "\n".join(details)
        
        # Use pytest_html.extras.text to safely inject into HTML
        extras.append(pytest_html.extras.text(log_content, "Target & Execution Log"))
        report.extras = extras
