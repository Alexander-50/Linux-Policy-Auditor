#!/usr/bin/env python3
"""
Password Policy Auditor

This script is the main entry point for the auditor tool.
It coordinates the parser, analyzer, and report generator.
"""

import argparse
# IMPORTING our modules
import policy_parser
import policy_analyzer
import report

def main():
    """
    Main execution flow.
    """
    print("Password Policy Auditor - Starting...")
    
    # 1. Setup Argument Parser
    cli_parser = argparse.ArgumentParser(description="Linux Password Policy Auditor")
    
    # Output flags
    cli_parser.add_argument("--json", help="Output a JSON report to the specified file.", metavar="report.json")
    cli_parser.add_argument("--html", help="Output an HTML report to the specified file.", metavar="report.html")
    
    # Manual file path flags
    cli_parser.add_argument("--pam-file", help="Manually specify a PAM file to analyze.", metavar="<path>")
    cli_parser.add_argument("--login-defs", help="Manually specify the login.defs file.", metavar="<path>")
    
    args = cli_parser.parse_args()
    
    # 2. Call Parser
    # UNCOMMENTING logic:
    # Pass the manual file paths from args to the parser.
    # The parser's get_policy_config will handle them if they exist,
    # or auto-discover if they are None.
    print(f"Running parser... (Arguments: {args})")
    policy_config = policy_parser.get_policy_config(pam_path=args.pam_file, login_defs_path=args.login_defs)

    # 3. Call Analyzer
    # UNCOMMENTING logic:
    print("Running analyzer...")
    # UPDATED function call to use policy_analyzer
    audit_results = policy_analyzer.analyze_policy(policy_config)
    
    # 4. Call Report Generator
    # UNCOMMENTING logic:
    print("Generating report...")
    if args.json:
        report.save_json(audit_results, args.json)
    elif args.html:
        report.save_html(audit_results, args.html)
    else:
        # Default to console report
        report.print_console(audit_results)

    print("\nAuditor execution complete.")

if __name__ == "__main__":
    main()