"""
Password Policy Report Generator

This module takes the final "results" object from the analyzer
and generates output in one of three formats:
- Console Table
- JSON file
- HTML file
"""

import json
import html # For escaping HTML characters

def print_console(results):
    """
    Prints a human-readable summary table to the console.
    """
    print("\n--- Password Policy Audit Report ---")
    
    findings = results.get('findings', [])
    if not findings:
        print("No findings to report.")
        return

    # Define column widths
    param_col = 30
    value_col = 15
    status_col = 10
    
    # --- Define colors for console ---
    class bcolors:
        HEADER = '\033[95m'
        OKGREEN = '\033[92m'
        WARNING = '\033[93m'
        FAIL = '\033[91m'
        ENDC = '\033[0m'
        BOLD = '\033[1m'

    # --- Print Header ---
    print(f"{bcolors.BOLD}{'Parameter'.ljust(param_col)}{'Value'.ljust(value_col)}{'Status'.ljust(status_col)}Recommendation{bcolors.ENDC}")
    print("-" * (param_col + value_col + status_col + 30))

    # --- Print Findings ---
    for f in findings:
        param = f.get('parameter', 'N/A').ljust(param_col)
        value = f.get('value', 'N/A').ljust(value_col)
        status = f.get('status', 'N/A')
        rec = f.get('recommendation', 'N/A')
        
        # Color-code the status
        if status == 'Secure':
            status_color = f"{bcolors.OKGREEN}{status.ljust(status_col)}{bcolors.ENDC}"
        elif status == 'Moderate':
            status_color = f"{bcolors.WARNING}{status.ljust(status_col)}{bcolors.ENDC}"
        elif status == 'Weak':
            status_color = f"{bcolors.FAIL}{status.ljust(status_col)}{bcolors.ENDC}"
        else:
            status_color = status.ljust(status_col)
            
        print(f"{param}{value}{status_color}{rec}")

    print("\n" + ("-" * 80))
    
    # --- Print Source Files ---
    print(f"{bcolors.BOLD}Source Files Analyzed:{bcolors.ENDC}")
    raw_policy = results.get('raw_policy', {})
    if 'pam_file' in raw_policy:
        print(f"- PAM Config: {raw_policy['pam_file']}")
    if 'login_defs_file' in raw_policy:
        print(f"- Login Defs: {raw_policy['login_defs_file']}")
    
    print("--------------------------------------")


def save_json(results, output_file):
    """
    Saves the full results object to a JSON file.
    """
    print(f"Saving JSON report to {output_file}...")
    try:
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(results, f, indent=4)
        print("JSON report saved successfully.")
    except IOError as e:
        print(f"Error: Could not write JSON file: {e}")

def _generate_html_rows(findings):
    """Helper to generate <tr> elements for the HTML report."""
    rows = ""
    for f in findings:
        param = html.escape(f.get('parameter', 'N/A'))
        value = html.escape(f.get('value', 'N/A'))
        status = html.escape(f.get('status', 'N/A'))
        rec = html.escape(f.get('recommendation', 'N/A'))
        
        # Get CSS class for status
        if status == 'Secure':
            status_class = 'status-secure'
        elif status == 'Moderate':
            status_class = 'status-moderate'
        elif status == 'Weak':
            status_class = 'status-weak'
        else:
            status_class = ''
            
        rows += f"""
        <tr>
            <td>{param}</td>
            <td>{value}</td>
            <td class="{status_class}">{status}</td>
            <td>{rec}</td>
        </tr>
        """
    return rows

def save_html(results, output_file):
    """
    Generates and saves a simple, clean HTML report.
    """
    print(f"Saving HTML report to {output_file}...")
    
    findings = results.get('findings', [])
    table_rows = _generate_html_rows(findings)
    
    # --- Get Source File Info ---
    raw_policy = results.get('raw_policy', {})
    pam_file = html.escape(raw_policy.get('pam_file', 'Not Found'))
    login_defs_file = html.escape(raw_policy.get('login_defs_file', 'Not Found'))

    html_template = f"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Password Policy Audit Report</title>
    <style>
        body {{ 
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; 
            line-height: 1.6; 
            padding: 20px; 
            margin: 0 auto;
            max-width: 1200px;
            color: #333;
        }}
        h1 {{ 
            color: #111;
            border-bottom: 2px solid #f0f0f0;
            padding-bottom: 10px;
        }}
        h2 {{
            color: #444;
            margin-top: 30px;
        }}
        table {{ 
            width: 100%;
            border-collapse: collapse;
            margin-top: 20px;
            box-shadow: 0 2px 5px rgba(0,0,0,0.1);
        }}
        th, td {{ 
            border: 1px solid #ddd;
            padding: 12px 15px;
            text-align: left;
            vertical-align: top;
        }}
        th {{ 
            background-color: #f8f8f8;
            font-weight: 600;
        }}
        tr:nth-child(even) {{ 
            background-color: #fdfdfd;
        }}
        .status-secure {{ 
            background-color: #d4edda;
            color: #155724;
            font-weight: 600;
        }}
        .status-moderate {{ 
            background-color: #fff3cd;
            color: #856404;
            font-weight: 600;
        }}
        .status-weak {{ 
            background-color: #f8d7da;
            color: #721c24;
            font-weight: 600;
        }}
        .source-files {{
            background-color: #f4f4f4;
            padding: 15px;
            border-radius: 5px;
            font-family: "Courier New", Courier, monospace;
        }}
    </style>
</head>
<body>
    <h1>Password Policy Audit Report</h1>
    
    <h2>Audit Findings</h2>
    <table>
        <thead>
            <tr>
                <th>Parameter</th>
                <th>Value</th>
                <th>Status</th>
                <th>Recommendation</th>
            </tr>
        </thead>
        <tbody>
            {table_rows}
        </tbody>
    </table>
    
    <h2>Source Files Analyzed</h2>
    <div class="source-files">
        <p><strong>PAM Config:</strong> {pam_file}</p>
        <p><strong>Login Defs:</strong> {login_defs_file}</p>
    </div>
</body>
</html>
"""
    try:
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write(html_template)
        print("HTML report saved successfully.")
    except IOError as e:
        print(f"Error: Could not write HTML file: {e}")

# --- Test block ---
if __name__ == "__main__":
    """
    Test harness for running the report functions directly.
    
    To run:
    1. cd into the 'password_auditor' directory
    2. run `python3 report.py`
    """
    
    print("--- Running Report Test Harness ---")
    
    # This mock data is what we expect from analyzer.py
    MOCK_RESULTS = {
        'findings': [
            {'parameter': 'minlen', 'value': '12', 'status': 'Moderate', 'recommendation': 'Set minlen=14 or greater for strong security.'},
            {'parameter': 'dcredit', 'value': '-1', 'status': 'Secure', 'recommendation': 'Password digit requirement is enforced.'},
            {'parameter': 'lcredit', 'value': '0', 'status': 'Weak', 'recommendation': 'Set lcredit=-1 to require at least one lowercase letter.'},
            {'parameter': 'remember', 'value': '5', 'status': 'Secure', 'recommendation': 'Password history is set to a strong value (>= 5).'},
            {'parameter': 'PASS_MAX_DAYS', 'value': '99999', 'status': 'Weak', 'recommendation': 'Set PASS_MAX_DAYS=90 or less to force regular password rotation.'}
        ],
        'raw_policy': {
            'pam_file': './sample/common-password',
            'login_defs_file': '/etc/login.defs'
        }
    }
    
    print("\n[Testing print_console]")
    print_console(MOCK_RESULTS)
    
    TEST_JSON_FILE = 'test_report.json'
    TEST_HTML_FILE = 'test_report.html'
    
    print(f"\n[Testing save_json to {TEST_JSON_FILE}]")
    save_json(MOCK_RESULTS, TEST_JSON_FILE)
    
    print(f"\n[Testing save_html to {TEST_HTML_FILE}]")
    save_html(MOCK_RESULTS, TEST_HTML_FILE)
    
    print(f"\n--- Test Harness Complete ---")
    print(f"Check '{TEST_JSON_FILE}' and '{TEST_HTML_FILE}' to see the output.")