#!/bin/bash

set -x
# Script to automate security audits and server hardening on Linux servers

# Global Variables
REPORT_FILE="/var/log/security_audit_report.txt"
CUSTOM_CHECKS_FILE="/etc/custom_security_checks.conf"
ALERT_EMAIL="admin@example.com"

# Function: Initialize Report
init_report() {
    echo "Security Audit and Hardening Report - $(date)" > $REPORT_FILE
    echo "----------------------------------------" >> $REPORT_FILE
}

# Function: User and Group Audits
audit_users_groups() {
    echo "1. User and Group Audits" >> $REPORT_FILE
    echo "Listing all users and groups:" >> $REPORT_FILE
    cat /etc/passwd >> $REPORT_FILE
    cat /etc/group >> $REPORT_FILE

    echo "Checking for non-standard users with UID 0:" >> $REPORT_FILE
    awk -F: '($3 == 0) {print}' /etc/passwd >> $REPORT_FILE

    echo "Checking for users without passwords or with weak passwords:" >> $REPORT_FILE
    awk -F: '($2 == "" || length($2) < 8) {print $1}' /etc/shadow >> $REPORT_FILE
}

# Function: File and Directory Permissions
audit_file_permissions() {
    echo "2. File and Directory Permissions" >> $REPORT_FILE
    echo "Scanning for world-writable files and directories:" >> $REPORT_FILE
    find / -perm -002 -type f -exec ls -l {} \; >> $REPORT_FILE

    echo "Checking .ssh directories for secure permissions:" >> $REPORT_FILE
    find /home -type d -name ".ssh" -exec ls -ld {} \; >> $REPORT_FILE

    echo "Checking for files with SUID/SGID bits set:" >> $REPORT_FILE
    find / -perm /6000 -type f -exec ls -l {} \; >> $REPORT_FILE
}

# Function: Service Audits
audit_services() {
    echo "3. Service Audits" >> $REPORT_FILE
    echo "Listing all running services:" >> $REPORT_FILE
    systemctl list-units --type=service >> $REPORT_FILE

    echo "Checking for unauthorized services:" >> $REPORT_FILE
    # Add specific checks for unauthorized services here

    echo "Checking for services listening on non-standard/insecure ports:" >> $REPORT_FILE
    netstat -tulnp | grep -E '(:23|:25|:110)' >> $REPORT_FILE  # Example for Telnet, SMTP, and POP3
}

# Function: Firewall and Network Security
audit_firewall_network() {
    echo "4. Firewall and Network Security" >> $REPORT_FILE
    echo "Checking firewall status:" >> $REPORT_FILE
    ufw status verbose >> $REPORT_FILE || iptables -L >> $REPORT_FILE

    echo "Reporting open ports and their associated services:" >> $REPORT_FILE
    netstat -tulnp >> $REPORT_FILE

    echo "Checking for IP forwarding or insecure network configurations:" >> $REPORT_FILE
    sysctl net.ipv4.ip_forward >> $REPORT_FILE
    sysctl net.ipv6.conf.all.forwarding >> $REPORT_FILE
}

# Function: IP and Network Configuration Checks
audit_ip_configuration() {
    echo "5. IP and Network Configuration Checks" >> $REPORT_FILE
    echo "Listing IP addresses and determining public/private status:" >> $REPORT_FILE
    ip addr show >> $REPORT_FILE
    # Add custom logic to determine public/private IP status
}

# Function: Security Updates and Patching
check_security_updates() {
    echo "6. Security Updates and Patching" >> $REPORT_FILE
    echo "Checking for available security updates:" >> $REPORT_FILE
    apt-get update -y && apt-get upgrade -s | grep -i security >> $REPORT_FILE
}

# Function: Log Monitoring
monitor_logs() {
    echo "7. Log Monitoring" >> $REPORT_FILE
    echo "Checking for suspicious log entries:" >> $REPORT_FILE
    grep -i "failed" /var/log/auth.log | tail -n 10 >> $REPORT_FILE
}

# Function: Server Hardening
harden_server() {
    echo "8. Server Hardening" >> $REPORT_FILE

    # SSH Configuration Hardening
    echo "Disabling password-based login for root and enabling SSH key authentication:" >> $REPORT_FILE
    sed -i 's/PermitRootLogin yes/PermitRootLogin no/' /etc/ssh/sshd_config
    sed -i 's/#PasswordAuthentication yes/PasswordAuthentication no/' /etc/ssh/sshd_config
    systemctl restart sshd

    # Disable IPv6 if not needed
    echo "Disabling IPv6:" >> $REPORT_FILE
    echo "net.ipv6.conf.all.disable_ipv6 = 1" >> /etc/sysctl.conf
    echo "net.ipv6.conf.default.disable_ipv6 = 1" >> /etc/sysctl.conf
    sysctl -p

    # Set GRUB password
    echo "Setting GRUB password:" >> $REPORT_FILE
    grub-mkpasswd-pbkdf2 >> $REPORT_FILE  # Requires manual input for password

    # Firewall Configuration
    echo "Configuring firewall:" >> $REPORT_FILE
    ufw allow 22/tcp
    ufw enable
    ufw default deny incoming
    ufw default allow outgoing
}

# Function: Custom Security Checks
custom_security_checks() {
    echo "9. Custom Security Checks" >> $REPORT_FILE
    if [ -f "$CUSTOM_CHECKS_FILE" ]; then
        bash "$CUSTOM_CHECKS_FILE" >> $REPORT_FILE
    else
        echo "No custom checks defined." >> $REPORT_FILE
    fi
}

# Function: Reporting and Alerting
report_and_alert() {
    echo "10. Reporting and Alerting" >> $REPORT_FILE
    echo "Summary report generated at $REPORT_FILE" | mail -s "Security Audit Report" $ALERT_EMAIL
}

# Main Function
main() {
    init_report
    audit_users_groups
    audit_file_permissions
    audit_services
    audit_firewall_network
    audit_ip_configuration
    check_security_updates
    monitor_logs
    harden_server
    custom_security_checks
    report_and_alert
}

# Execute the main function
main

