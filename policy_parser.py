"""
Password Policy Parser

This module is responsible for finding and parsing the relevant
configuration files for password policy:
- PAM configuration (common-password, system-auth, etc.)
- /etc/login.defs
"""

import os
import re

# --- Constants ---
DEBIAN_PAM_PATH = "/etc/pam.d/common-password"
RHEL_PAM_PATHS = ["/etc/pam.d/system-auth", "/etc/pam.d/password-auth"]
LOGIN_DEFS_PATH = "/etc/login.defs"

# --- Regex for login.defs ---
# This regex captures a key (like "PASS_MAX_DAYS") and its value,
# from a non-commented line.
LOGIN_DEFS_RE = re.compile(r"^\s*([a-zA-Z_]+)\s+([\S]+).*$")
LOGIN_DEFS_KEYS = ["PASS_MAX_DAYS", "PASS_MIN_DAYS", "PASS_WARN_AGE"]

def get_policy_config(pam_path=None, login_defs_path=None):
    """
    Main function to discover and parse all policy configurations.
    
    Returns a single dictionary containing all found raw parameters.
    """
    
    policy = {}
    
    # --- 1. Find and Parse PAM file ---
    if pam_path:
        # User provided a manual path
        policy.update(parse_pam_file(pam_path))
    else:
        # Auto-discover
        found_pam_path = find_pam_file()
        if found_pam_path:
            policy.update(parse_pam_file(found_pam_path))
        else:
            print("Warning: Could not auto-discover a PAM policy file.")
            policy['pam_file'] = 'Not Found'

    # --- 2. Find and Parse login.defs ---
    target_login_defs = login_defs_path if login_defs_path else LOGIN_DEFS_PATH
    policy.update(parse_login_defs(target_login_defs))
    
    return policy

def find_pam_file():
    """
    Auto-discover the most likely PAM file path.
    """
    if os.path.exists(DEBIAN_PAM_PATH):
        return DEBIAN_PAM_PATH
    
    for path in RHEL_PAM_PATHS:
        if os.path.exists(path):
            return path # Return the first one found
            
    return None

def _parse_pam_line_args(line_args):
    """
    Helper function to parse key=value pairs from a PAM line.
    Example: "retry=3 minlen=12 ucredit=-1"
    Returns: {"retry": "3", "minlen": "12", "ucredit": "-1"}
    """
    params = {}
    for arg in line_args:
        if "=" in arg:
            try:
                key, value = arg.split("=", 1)
                params[key] = value
            except ValueError:
                # Ignore malformed args
                continue
    return params

def parse_pam_file(file_path):
    """
    Parses a single PAM file for pwquality and unix module settings.
    Finds the *first active* configuration for each module.
    """
    parsed_data = {
        'pam_file': file_path,
        'pwquality_module_found': False,
        'unix_module_found': False
    }

    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            for line in f:
                line = line.strip()

                # Ignore comments and empty lines
                if not line or line.startswith('#'):
                    continue

                # Split the line into words
                parts = line.split()
                if not parts:
                    continue

                # --- Check for pam_pwquality.so ---
                # We only parse the *first* one we find.
                if not parsed_data['pwquality_module_found'] and "pam_pwquality.so" in line:
                    parsed_data['pwquality_module_found'] = True
                    # Pass all arguments *after* the module name
                    try:
                        module_index = parts.index("pam_pwquality.so")
                        pwquality_args = parts[module_index + 1:]
                        parsed_data.update(_parse_pam_line_args(pwquality_args))
                    except ValueError:
                        # Handle case where .so is part of a larger string
                        for i, part in enumerate(parts):
                            if "pam_pwquality.so" in part:
                                pwquality_args = parts[i + 1:]
                                parsed_data.update(_parse_pam_line_args(pwquality_args))
                                break

                # --- Check for pam_unix.so ---
                # We only parse the *first* one we find.
                if not parsed_data['unix_module_found'] and "pam_unix.so" in line:
                    parsed_data['unix_module_found'] = True
                    try:
                        module_index = parts.index("pam_unix.so")
                        unix_args = parts[module_index + 1:]
                        # We only care about 'remember'
                        unix_params = _parse_pam_line_args(unix_args)
                        if 'remember' in unix_params:
                            parsed_data['remember'] = unix_params['remember']
                    except ValueError:
                            # Handle case where .so is part of a larger string
                            for i, part in enumerate(parts):
                                if "pam_unix.so" in part:
                                    unix_args = parts[i + 1:]
                                    unix_params = _parse_pam_line_args(unix_args)
                                    if 'remember' in unix_params:
                                        parsed_data['remember'] = unix_params['remember']
                                    break

    except FileNotFoundError:
        print(f"Warning: PAM file not found at: {file_path}")
        parsed_data['pam_file'] = 'Not Found'
    except IOError as e:
        print(f"Error: Could not read PAM file: {e}")
        parsed_data['pam_file'] = f"Error: {e}"

    return parsed_data

def parse_login_defs(file_path):
    """
    Parses the login.defs file for lifetime parameters.
    """
    print(f"Parsing login.defs file: {file_path}")
    parsed_data = {
        'login_defs_file': file_path
    }

    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                
                # Ignore comments and empty lines
                if not line or line.startswith('#'):
                    continue
                
                match = LOGIN_DEFS_RE.match(line)
                if match:
                    key, value = match.groups()
                    if key in LOGIN_DEFS_KEYS:
                        # Store the raw value. Analyzer will handle conversion.
                        parsed_data[key] = value
                        
    except FileNotFoundError:
        print(f"Warning: login.defs file not found at: {file_path}")
        parsed_data['login_defs_file'] = 'Not Found'
    except IOError as e:
        print(f"Error: Could not read login.defs file: {e}")
        parsed_data['login_defs_file'] = f"Error: {e}"

    return parsed_data

# --- Test block ---
if __name__ == "__main__":
    """
    Test harness for running the parser functions directly.
    This allows us to validate parsing logic in isolation.
    
    To run:
    1. cd into the 'password_auditor' directory
    2. run `python3 policy_parser.py`
    """
    
    # We are in password_auditor/, sample/ is a sibling dir
    SAMPLE_LOGIN_DEFS = './sample/login.defs'
    SAMPLE_PAM_DEBIAN = './sample/common-password'
    SAMPLE_PAM_RHEL = './sample/system-auth'
    
    print("--- Running Parser Test Harness ---")
    
    print(f"\n[Testing parse_login_defs with {SAMPLE_LOGIN_DEFS}]")
    login_defs_data = parse_login_defs(SAMPLE_LOGIN_DEFS)
    print(f"Result:\n{login_defs_data}")

    print(f"\n[Testing parse_pam_file with Debian Sample: {SAMPLE_PAM_DEBIAN}]")
    pam_debian_data = parse_pam_file(SAMPLE_PAM_DEBIAN)
    print(f"Result:\n{pam_debian_data}")

    print(f"\n[Testing parse_pam_file with RHEL Sample: {SAMPLE_PAM_RHEL}]")
    pam_rhel_data = parse_pam_file(SAMPLE_PAM_RHEL)
    print(f"Result:\n{pam_rhel_data}")

    print("\n--- Test Harness Complete ---")