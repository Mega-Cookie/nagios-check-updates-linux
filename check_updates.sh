#! /usr/bin/env bash

#########################################################################################################
#                                                                                                       #
#  Nagios Check Updates Plugin                                                                          #
#  Version: 1.0                                                                                         #
#                                                                                                       #
#  Forked from https://github.com/MesseFREEZE/nagios-check-updates-linux                                #
#  Description: Check for available system updates on RHEL and Debian                                   #
#                                                                                                       #
#  Usage: ./check_updates.sh -w [Update WARNING] -c [Update CRITITAL] -s [Security Updates CRITICAL]    #
#  Exit codes: 0=OK, 1=WARNING, 2=CRITICAL, 3=UNKNOWN                                                   #
#                                                                                                       #
#########################################################################################################

# Strict error handling
set -o pipefail

################################################################################
# Configuration Section
################################################################################

# Thresholds for updates defaults
WARNING_THRESHOLD=5      # Alert if more than 5 updates
CRITICAL_THRESHOLD=10    # Critical if more than 10 updates
SECURITY_CRITICAL=1      # Critical if any security updates
# Set thresholds for updates
while getopts w:c:s: OPTNAME; do
	case "$OPTNAME" in
	    w)  WARNING_THRESHOLD="$OPTARG";;
        c)  CRITICAL_THRESHOLD="$OPTARG";;
        s)  SECURITY_CRITICAL="$OPTARG";;
        *)  echo "Usage: ./check_updates.sh -w [Update WARNING] -c [Update CRITITAL] -s [Security Updates CRITICAL]"
            exit 2
    esac
done

################################################################################
# Function: Detect Linux Distribution
# Returns: "rhel" or "debian" or "unknown"
################################################################################
detect_distro() {
    # Check for common distribution identifiers
    if [ -f /etc/redhat-release ] || [ -f /etc/os-release ]; then
        if grep -qi "rhel\|centos\|fedora" /etc/os-release 2>/dev/null || [ -f /etc/redhat-release ]; then
            echo "rhel"
            return
        fi
    fi

    if [ -f /etc/debian_version ] || grep -qi "debian\|ubuntu" /etc/os-release 2>/dev/null; then
        echo "debian"
        return
    fi

    echo "unknown"
}

################################################################################
# Function: Check RHEL/CentOS Updates (using DNF)
# Returns: updates count and security updates count
################################################################################
check_rhel_updates() {
    # Check if dnf is available
    status="OK"
    if ! command -v dnf &> /dev/null; then
        status="UNKNOWN"
        security="0"
        updates="0"
        securitylist="None"
        updateslist="None"
        export status
        export updates
        export security
        export securitylist
        export updateslist
        return
    fi

    # Count security updates specifically
    # --security flag limits to security updates only
    securitylist=$(dnf check-update --security --refresh -q 2>/dev/null | grep -v '^$' | tail -n +1)
    if [ "$securitylist" != "" ]; then
        security=$(echo "$securitylist" | wc -l)
    else
        security=0
    fi

    # Count total available updates
    # grep -v '^$' filters out empty lines
    updateslist=$(dnf check-update --refresh -q 2>/dev/null | grep -v '^$' | tail -n +1)
    if [ "$updateslist" != "" ]; then
        updates=$(echo "$updateslist" | wc -l)
    else
        updates=0
    fi

    # Return results
    export status
    export updates
    export security
    if [[ "$updateslist" == "$securitylist" ]]; then
        updateslist="None"
    fi
    if [[ "$security" == 0 ]]; then
        securitylist="None"
    fi
    export securitylist
    export updateslist
}

################################################################################
# Function: Check Debian/Ubuntu Updates (using APT)
# Returns: updates count and security updates count
################################################################################
check_debian_updates() {
    # Check if apt is available
    status="OK"
    if ! command -v apt &> /dev/null; then
        status="UNKNOWN"
        security="0"
        updates="0"
        securitylist="None"
        updateslist="None"
        export status
        export updates
        export security
        export securitylist
        export updateslist
        return
    fi

    # Get security updates specifically
    # apt list --upgradable | grep -i security filters security updates
    # This requires checking the changelog or using apt-get update && apt-get --dry-run upgrade
    # Fallback: count security package sources
    securitylist=$(apt list --upgradable 2>/dev/null | grep security | cut -d "/" -f 1)
    if [ "$securitylist" != "" ]; then
        security=$(echo "$securitylist" | wc -l)
    else
        security=0
    fi

    # Get all available updates (full count)
    # apt list --upgradable returns format: pkg/distro version [upgrade-version]
    # We grep for upgradable and exclude header
    updateslist=$(apt list --upgradable 2>/dev/null | grep upgradable | cut -d "/" -f 1)
    if [ "$updateslist" != "" ]; then
        updates=$(echo "$updateslist" | wc -l)
    else
        updates=0
    fi

    # Alternative: use apt show for each package (more accurate but slower)
    # For performance, we use the grep method above

    # Return results
    export status
    export updates
    export security
    if [[ "$updateslist" == "$securitylist" ]]; then
        updateslist="None"
    fi
    if [[ "$security" == 0 ]]; then
        securitylist="None"
    fi
    export securitylist
    export updateslist
}

################################################################################
# Function: Generate Nagios Output
# Parameters: status, updates_count, security_count
# Format: MESSAGE | perfdata
################################################################################
generate_output() {
    status=$1
    updates=$2
    security=$3

    # Build main message
    if [ "$status" != "unknown" ]; then
        message="Updates available: $updates"
    else
        message="Unknown Distro"
    fi

    # Add security info if present
    if [ "$security" -gt 0 ]; then
        message="$message ($security security)"
    fi

    # Build perfdata (format: label=value;warn;crit;min;max)
    # updates metric: warning at >5, critical at >10
    # security metric: critical at >1
    perfdata="updates=$updates;${WARNING_THRESHOLD};${CRITICAL_THRESHOLD};0;"
    perfdata="$perfdata security=$security;${SECURITY_CRITICAL};${SECURITY_CRITICAL};0;"

    # Output in Nagios format: MESSAGE | PERFDATA
    echo "$message | $perfdata"
}

################################################################################
# Function: Determine Exit Code
# Parameters: updates_count, security_count
# Returns: 0 (OK), 1 (WARNING), 2 (CRITICAL)
################################################################################
determine_exit_code() {
    updates=$1
    security=$2

    # Critical: if any security updates exist
    if [ "$security" -ge "$SECURITY_CRITICAL" ]; then
        return 2
    fi

    # Critical: if too many updates
    if [ "$updates" -ge "$CRITICAL_THRESHOLD" ]; then
        return 2
    fi

    # Warning: if moderate number of updates
    if [ "$updates" -ge "$WARNING_THRESHOLD" ]; then
        return 1
    fi

    # OK: system is up to date
    return 0
}

################################################################################
# Main Script
################################################################################

# Determine which check to run
if [ "$(detect_distro)" = "rhel" ]; then
    # Run RHEL check
    check_rhel_updates


elif [ "$(detect_distro)" = "debian" ]; then
    # Run Debian check
    check_debian_updates
else
    # Unknown distribution
    echo "UNKNOWN - Cannot detect distribution or unsupported OS"
    exit 3
fi

# Check if we got valid results
if [ "$status" != "OK" ]; then
    echo "UNKNOWN - Failed to check updates"
    exit 3
fi

if [ -f /var/run/reboot-required ]; then
    echo "For some updates to take effect a reboot is required!"
    exit 2
else
    # Generate Nagios output
    generate_output "$(detect_distro)" "$updates" "$security"
    echo "Available Security Update:"
    echo "$securitylist"
    echo "Available Normal Updates:"
    echo "$updateslist"

    # Determine and exit with appropriate code
    determine_exit_code "$updates" "$security"
    exit $?
fi