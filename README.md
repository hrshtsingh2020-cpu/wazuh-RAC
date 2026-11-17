# Enterprise Rules-as-Code (RaC) & Dynamic Active Response Framework

This repository provides a fully automated **DevSecOps pipeline** for Wazuh SIEM. It solves the exact problem of manual script modification: **adding, modifying, or creating new detection rules in GitHub instantly syncs them, validates syntax, updates active response scripts, and reloads the Wazuh server without any manual SSH configuration.**

## Architecture & Workflow
1. **Universal Dynamic Responder (`c2_responder.py`)**: 
   - Deployed once to `/var/ossec/active-response/bin/`.
   - Automatically parses incoming JSON alerts, inspects PIDs and destination IPs, and dynamically executes termination (`kill -9` / `taskkill`) or network blocking (`iptables`) based purely on alert metadata. **You never need to edit the python script when writing new rules.**
2. **Rules-as-Code (RaC) CI/CD (`deploy_rules.yml`)**:
   - Every `git push` to `main` triggers GitHub Actions.
   - Files are securely synced via SSH/SCP.
   - Syntax validation (`wazuh-analysisd -t`) runs automatically to prevent broken XML from crashing the SIEM manager.
   - Wazuh Manager restarts seamlessly with the new threat detection rules active.

## Setup Instructions
1. Push this repository to GitHub.
2. Configure GitHub Secrets (`HOST`, `USERNAME`, `SSH_KEY`) under **Settings > Secrets and variables > Actions**.
3. Add any new rule (`.xml`) in `rules/` and push! It deploys immediately.
