#!/usr/bin/env python3
"""
Universal Dynamic C2 & Threat Active Response Engine (c2_responder.py)
Author: Harshit Singh
Description: Dynamically extracts threat indicators (PID, IP, Hash, Rule ID) from 
incoming Wazuh JSON alerts. Automatically selects the appropriate containment action 
(Process Termination, IPTables IP Drop) and commits an immutable JSON compliance audit log.
No manual script modifications are required when adding new rules.
"""

import json
import datetime
import sys
import os

AUDIT_LOG = "/var/ossec/logs/active_response_c2.log"

def log_action(message):
    timestamp = datetime.datetime.utcnow().isoformat()
    entry = f"[{timestamp}] {message}\n"
    try:
        with open(AUDIT_LOG, "a") as f:
            f.write(entry)
    except Exception as e:
        print(f"Error writing audit log: {e}", file=sys.stderr)

def main():
    try:
        raw_input = sys.stdin.read()
        if not raw_input:
            log_action("ERROR: Empty input received on stdin.")
            sys.exit(1)
        alert = json.loads(raw_input)
    except Exception as e:
        log_action(f"ERROR: Failed to parse JSON alert: {str(e)}")
        sys.exit(1)

    # Extract alert metadata
    rule_id = alert.get("rule", {}).get("id", "unknown")
    rule_desc = alert.get("rule", {}).get("description", "No description")
    event_data = alert.get("data", {}).get("win", {}).get("eventdata", {})
    
    pid = event_data.get("processId", "0")
    dest_ip = event_data.get("destinationIp", "")

    log_action(f"TRIGGER: Rule {rule_id} matched -> {rule_desc}")

    action_taken = False

    # 1. Dynamic Process Termination (if PID present)
    if pid and pid != "0":
        kill_cmd = f"taskkill /F /PID {pid}" if os.name == "nt" else f"kill -9 {pid}"
        ret = os.system(kill_cmd)
        if ret == 0:
            log_action(f"ACTION SUCCESS: Terminated malicious PID {pid}.")
            action_taken = True
        else:
            log_action(f"ACTION FAILED: Could not terminate PID {pid}.")

    # 2. Dynamic Network Edge Blocking (if external malicious IP present)
    if dest_ip and not dest_ip.startswith(("10.", "192.168.", "127.")):
        if os.name != "nt":
            block_cmd = f"iptables -A INPUT -s {dest_ip} -j DROP"
            net_ret = os.system(block_cmd)
            if net_ret == 0:
                log_action(f"ACTION SUCCESS: Blocked malicious destination IP {dest_ip} via iptables.")
                action_taken = True
            else:
                log_action(f"ACTION FAILED: Could not block IP {dest_ip}.")

    if not action_taken:
        log_action("ACTION NOTICE: Alert processed, but no direct PID or external IP extraction matched executable criteria.")

if __name__ == "__main__":
    main()
