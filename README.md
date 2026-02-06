# Nagios Check Updates

A Nagios monitoring plugin to check for available system updates on RHEL/CentOS and Debian/Ubuntu systems.

# Usage
`./check_updates.sh -w [Update WARNING] -c [Update CRITITAL] -s [Security Updates CRITICAL]`

Defaults are -c 10 -w 5 -s 1

## Features

- ✅ Detects available package updates
- ✅ Separates security updates from regular updates
- ✅ Supports RHEL 9+ (DNF) and Debian/Ubuntu (APT)
- ✅ Auto-detection of Linux distribution
- ✅ Performance data (perfdata) for graphing
- ✅ Fully commented code
- ✅ Compatible with Nagios/Icinga

## Supported Systems

- RHEL 9+ (using DNF)
- CentOS 9+
- Debian 10+
- Ubuntu 18.04+
- Any system with DNF or APT package manager

## Quick Start

### Installation

1. Copy the script to your Nagios plugins directory:
```bash
sudo cp check_updates.sh /usr/local/nagios/scripts/
# sudo chmod +x /usr/local/nagios/scripts/check_updates.sh -> schript is executable by default
sudo chown nagios:nagios /usr/local/nagios/scripts/check_updates.sh
