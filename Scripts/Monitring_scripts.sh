#!/bin/bash



set -x

# Function to display top 10 cpu and memory-consuming applications

  top -bn1 | grep -v "CPU(s)" | head -n 10
# Function to display network statistics
   netstat -s | grep -E "packets|bytes"
   ifconfig | grep -E "RX bytes|TX bytes"


# Funtion to display disk usage
 df -h | awk '{if  ($5 >= "80%") print $1, $2, $3, $4, $5}'


# Function to display system load and CPU usage
        top -bn1 | grep "CPU(s)" | head -n 1


# Function to display memory usage
 free -h

 # Function to display process monitoring
 ps -aux | head -n 10

# Function to display service status
systemctl status sshd nginx iptables
