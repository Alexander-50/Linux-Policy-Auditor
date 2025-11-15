"""
Password Policy Analyzer

This module takes the raw, parsed policy dictionary and:
1. Normalizes the values (applies defaults, converts credits)
2. Analyzes the normalized policy against security rules
3. Builds a list of findings and recommendations
"""

def _get_finding(parameter, value, status, recommendation):
    """Helper to format a finding dictionary."""
    return {
        "parameter": parameter,
        "value": str(value), # Store all values as strings for consistent reporting
        "status": status,
        "recommendation": recommendation
    }

def _normalize_policy(raw_policy):
    """
    Converts raw string values from the parser into a clean dictionary
    of integers and booleans, applying defaultaas.
    """
    # Start with defaults
    policy = {
        # pwquality
        "minlen": 8,  # Default if not set
        "dcredit": 0, # 0 = not enforced
        "ucredit": 0, # 0 = not enforced
        "lcredit": 0, # 0 = not enforced
        "ocredit": 0, # 0 = not enforced
        "enforce_for_root": False,
        
        # pam_unix
        "remember": 0, # 0 = not enforced
        
        # login.defs
        "PASS_MAX_DAYS": 99999,
        "PASS_MIN_DAYS": 0,
        "PASS_WARN_AGE": 7
    }

    # Helper to safely convert to int
    def to_int(s, default=0):
        try:
            return int(s)
        except (ValueError, TypeError):
            return default

    # Overwrite defaults with parsed values
    
    # pwquality
    if raw_policy.get('pwquality_module_found'):
        policy['minlen'] = to_int(raw_policy.get('minlen'), policy['minlen'])
        policy['dcredit'] = to_int(raw_policy.get('dcredit'), policy['dcredit'])
        policy['ucredit'] = to_int(raw_policy.get('ucredit'), policy['ucredit'])
        policy['lcredit'] = to_int(raw_policy.get('lcredit'), policy['lcredit'])
        policy['ocredit'] = to_int(raw_policy.get('ocredit'), policy['ocredit'])
        
        # 'enforce_for_root' is a boolean flag, its presence means True
        if 'enforce_for_root' in raw_policy:
            policy['enforce_for_root'] = True

    # pam_unix
    if raw_policy.get('unix_module_found'):
        policy['remember'] = to_int(raw_policy.get('remember'), policy['remember'])

    # login.defs
    policy['PASS_MAX_DAYS'] = to_int(raw_policy.get('PASS_MAX_DAYS'), policy['PASS_MAX_DAYS'])
    policy['PASS_MIN_DAYS'] = to_int(raw_policy.get('PASS_MIN_DAYS'), policy['PASS_MIN_DAYS'])
    policy['PASS_WARN_AGE'] = to_int(raw_policy.get('PASS_WARN_AGE'), policy['PASS_WARN_AGE'])
    
    return policy

def _audit_policy(policy, raw_policy):
    """
    Applies CIS-inspired logic to the normalized policy.
    Returns a list of finding dictionaries.
    """
    findings = []
    
    # --- 1. Audit pwquality (Complexity) ---
    if not raw_policy.get('pwquality_module_found'):
        findings.append(_get_finding("Complexity", "pam_pwquality.so not found", "Weak", "Install and configure pam_pwquality.so to enforce password complexity."))
        # If module is missing, don't run other pwquality checks
    else:
        # minlen
        ml = policy['minlen']
        if ml < 12:
            findings.append(_get_finding("minlen", ml, "Weak", "Set minlen=14 or greater for brute-force resistance."))
        elif ml < 14:
            findings.append(_get_finding("minlen", ml, "Moderate", "Set minlen=14 or greater for strong security."))
        else:
            findings.append(_get_finding("minlen", ml, "Secure", "Password length is set to a strong value (>= 14)."))

        # dcredit (digits)
        dc = policy['dcredit']
        if dc >= 0:
            findings.append(_get_finding("dcredit", dc, "Weak", "Set dcredit=-1 to require at least one digit."))
        else:
            findings.append(_get_finding("dcredit", dc, "Secure", "Password digit requirement is enforced."))

        # ucredit (uppercase)
        uc = policy['ucredit']
        if uc >= 0:
            findings.append(_get_finding("ucredit", uc, "Weak", "Set ucredit=-1 to require at least one uppercase letter."))
        else:
            findings.append(_get_finding("ucredit", uc, "Secure", "Password uppercase requirement is enforced."))
            
        # lcredit (lowercase)
        lc = policy['lcredit']
        if lc >= 0:
            findings.append(_get_finding("lcredit", lc, "Weak", "Set lcredit=-1 to require at least one lowercase letter."))
        else:
            findings.append(_get_finding("lcredit", lc, "Secure", "Password lowercase requirement is enforced."))
            
        # ocredit (special chars)
        oc = policy['ocredit']
        if oc >= 0:
            findings.append(_get_finding("ocredit", oc, "Weak", "Set ocredit=-1 to require at least one special character."))
        else:
            findings.append(_get_finding("ocredit", oc, "Secure", "Password special character requirement is enforced."))

        # enforce_for_root
        efr = policy['enforce_for_root']
        if not efr:
            findings.append(_get_finding("enforce_for_root", efr, "Weak", "Add enforce_for_root to the pam_pwquality line to enforce policy for the root user."))
        else:
            findings.append(_get_finding("enforce_for_root", efr, "Secure", "Password policy is enforced for root user."))

    # --- 2. Audit pam_unix (History) ---
    if not raw_policy.get('unix_module_found'):
        findings.append(_get_finding("History", "pam_unix.so not found", "Weak", "Could not check password history. pam_unix.so not found."))
    else:
        rem = policy['remember']
        if rem < 5:
            findings.append(_get_finding("remember", rem, "Weak", "Set remember=5 or greater to prevent reuse of last 5 passwords."))
        else:
            findings.append(_get_finding("remember", rem, "Secure", "Password history is set to a strong value (>= 5)."))

    # --- 3. Audit login.defs (Lifetime) ---
    # PASS_MAX_DAYS
    max_d = policy['PASS_MAX_DAYS']
    if max_d > 90:
        findings.append(_get_finding("PASS_MAX_DAYS", max_d, "Weak", "Set PASS_MAX_DAYS=90 or less to force regular password rotation."))
    else:
        findings.append(_get_finding("PASS_MAX_DAYS", max_d, "Secure", "Password maximum lifetime is enforced (<= 90 days)."))
        
    # PASS_MIN_DAYS
    min_d = policy['PASS_MIN_DAYS']
    if min_d < 1:
        findings.append(_get_finding("PASS_MIN_DAYS", min_d, "Weak", "Set PASS_MIN_DAYS=1 or greater to prevent immediate password changes."))
    else:
        findings.append(_get_finding("PASS_MIN_DAYS", min_d, "Secure", "Password minimum lifetime is enforced (>= 1 day)."))

    return findings

def analyze_policy(raw_policy):
    """
    Main analysis function.
    
    Takes raw config dict from parser.py.
    Returns a final "results" object.
    """
    print("Analyzing policy...")
    
    # 1. Normalize Policy
    normalized_policy = _normalize_policy(raw_policy)
    
    # 2. Run Audit Engine
    findings = _audit_policy(normalized_policy, raw_policy)
    
    # 3. Build Results
    results = {
        "findings": findings,
        "normalized_policy": normalized_policy,
        "raw_policy": raw_policy
    }
    
    print("Analysis complete.")
    return results

# --- Test block ---
if __name__ == "__main__":
    """
    Test harness for running the analyzer functions directly.
    
    To run:
    1. cd into the 'password_auditor' directory
    2. run `python3 policy_analyzer.py`
    """
    
    print("--- Running Analyzer Test Harness ---")
    
    # This mock data is what we expect from parser.py
    MOCK_RAW_POLICY = {
        'pam_file': './sample/common-password',
        'pwquality_module_found': True,
        'unix_module_found': True,
        'remember': '5',
        'retry': '3',
        'minlen': '12',
        'ucredit': '-1',
        'dcredit': '-1',
        'ocredit': '-1',
        # 'lcredit' is missing on purpose to test defaults
        'login_defs_file': './sample/login.defs',
        'PASS_MAX_DAYS': '90',
        'PASS_MIN_DAYS': '1',
        'PASS_WARN_AGE': '7'
    }
    
    print(f"\n[Testing analyze_policy with MOCK_RAW_POLICY]")
    
    results = analyze_policy(MOCK_RAW_POLICY)
    
    # Pretty-print the results
    import json
    print(json.dumps(results, indent=2))
    
    # --- Test a weak policy ---
    MOCK_WEAK_POLICY = {
        'pam_file': './sample/system-auth',
        'pwquality_module_found': True,
        'unix_module_found': True,
        'retry': '3',
        'remember': '3',
        # minlen, ucredit, dcredit, etc. are all missing
        'login_defs_file': 'Not Found',
        'PASS_MAX_DAYS': '99999'
    }
    
    print(f"\n[Testing analyze_policy with MOCK_WEAK_POLICY]")
    
    results_weak = analyze_policy(MOCK_WEAK_POLICY)
    print(json.dumps(results_weak, indent=2))
    
    print("\n--- Test Harness Complete ---")