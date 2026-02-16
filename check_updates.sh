#! /usr/bin/env bash
#################################################################################
#                                                                               #
#   Nagios Check Updates Plugin                                                 #
#   Version: 1.0                                                                #
#                                                                               #
#   Forked from https://github.com/MesseFREEZE/nagios-check-updates-linux       #
#   Description: Check for available system updates on RHEL and Debian          #
#                                                                               #
#   Usage: ./check_updates.sh                                                   #
#                                   -w [Update WARNING]                         #
#                                   -c [Update CRITITAL]                        #
#                                   -s [Security Updates CRITICAL]              #
#                                   -t [TESTCASES [OK, WARN, CRIT, CRITSEC]]    #
#                                   -h Print this help text                     #
#                                                                               #
#         Exit codes: 0=OK, 1=WARNING, 2=CRITICAL, 3=UNKNOWN                    #
#                                                                               #
#################################################################################

# Strict error handling
set -o pipefail

################################################################################
# Configuration Section
################################################################################
# Print Help
help() {
    echo "Usage: ./check_updates.sh 
                                    -w [Update WARNING]
                                    -c [Update CRITITAL]
                                    -s [Security Updates CRITICAL]
                                    -t [TESTCASES [OK, WARN, CRIT, CRITSEC]]
            
          Exit codes: 0=OK, 1=WARNING, 2=CRITICAL, 3=UNKNOWN"
}


# Thresholds for updates defaults
WARNING_THRESHOLD=5      # Alert if more than 5 updates
CRITICAL_THRESHOLD=10    # Critical if more than 10 updates
SECURITY_CRITICAL=1      # Critical if any security updates
TESTING="false"
# Set thresholds for updates
while getopts w:c:s:t:h OPTNAME; do
	case "$OPTNAME" in
	    w)  WARNING_THRESHOLD="$OPTARG";;
        c)  CRITICAL_THRESHOLD="$OPTARG";;
        s)  SECURITY_CRITICAL="$OPTARG";;
        t)  TESTING="$OPTARG";;
        h)  help;;
        *)  help
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
# Function: Check Debian/Ubuntu Updates (using APT) or RHEL Updates (using DNF)
# Returns: updates count and security updates count
################################################################################
check_updates() {
    # Check if dnf or apt is available
    status="OK"
    if ! command -v dnf &> /dev/null && ! command -v apt &> /dev/null; then
        status="UNKNOWN"
        security="0"
        updates="0"
        securitylist="None"
        non_securitylist="None"
        export status
        export updates
        export security
        export securitylist
        export non_securitylist
        return
    fi

    # apt list --upgradable returns format: pkg/distro version [upgrade-version]
    # We grep for upgradable and strip everything except the package name
    if [ "$(detect_distro)" = "debian" ]; then
        securitylist=$(apt list --upgradable 2>/dev/null | grep security | cut -d "/" -f 1)
        updateslist=$(apt list --upgradable 2>/dev/null | grep upgradable | cut -d "/" -f 1)
    elif [ "$(detect_distro)" = "rhel" ]; then
        securitylist=$(dnf check-update --security --refresh -q 2>/dev/null | grep -v '^$' | tail -n +1 | cut -d " " -f 1)
        updateslist=$(dnf check-update --refresh -q 2>/dev/null | grep -v '^$' | tail -n +1 | cut -d " " -f 1)
    fi
    
    # Count available updates
    if [ "$securitylist" != "" ]; then
        security=$(echo "$securitylist" | wc -l)
    else
        security=0
    fi
    if [ "$updateslist" != "" ]; then
        updates=$(echo "$updateslist" | wc -l)
    else
        updates=0
    fi

    if [[ "$updateslist" == "$securitylist" ]]; then
        non_securitylist="None"
    else
        non_securitylist=$(awk 'NR==FNR {seen[$0]=1; next} !seen[$0]' <(echo "$securitylist") <(echo "$updateslist"))

    fi
    if [[ "$security" == 0 ]]; then
        securitylist="None"
    fi

    # Return results
    export status
    export updates
    export security
    export securitylist
    export non_securitylist
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
    # updates metric: warning at >=5, critical at >=10
    # security metric: critical at >=1
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

    # OK: system is up to date
    state=0

    # Critical: if any security updates exist
    if [ "$security" -ge "$SECURITY_CRITICAL" ]; then
        state=2
    fi

    # Critical: if too many updates
    if [ "$updates" -ge "$CRITICAL_THRESHOLD" ]; then
        state=2
    elif [ "$updates" -ge "$WARNING_THRESHOLD" ]; then
        state=1
    fi

    echo "$state"
}

################################################################################
# Test
################################################################################
istest() {
    test=$1
    if [ "$test" != "false" ]; then
        if [ "$test" == "OK" ]; then
            updates=0
            security=0
            non_securitylist="OK TEST PASSED"
            securitylist="NONE"
        elif [ "$test" == "WARN" ]; then
            updates=5
            security=0
            non_securitylist="WARN TEST PASSED"
            securitylist="NONE"
        elif [ "$test" == "CRIT" ]; then
            updates=20
            security=0
            non_securitylist="CRIT TEST PASSED"
            securitylist="NONE"
        elif [ "$test" == "CRITSEC" ]; then
            updates=1
            security=1
            non_securitylist="NONE"
            securitylist="CRITSEC TEST PASSED"
        fi
        export updates
        export security
        export securitylist
        export non_securitylist
    fi
}

################################################################################
# Reboot Check
################################################################################
check_reboot() {
    distro=$1
    reboot=0
    if [ "$distro" == "debian" ]; then
        if [ -f /var/run/reboot-required ]; then
            reboot=1 
        fi
    elif [ "$distro" == "rhel" ]; then
        if [[ "$(dnf needs-restarting -q)" ]]; then
            reboot=1
        fi
    else
        echo "Could not determine OS Derivate!"
        exit 2
    fi
    echo "$reboot"
}

################################################################################
# Main Script
################################################################################
# Run Check
check_updates
# Check if we got valid results
if [ "$status" != "OK" ]; then
    echo "UNKNOWN - Failed to check updates"
    exit 3
fi
istest "$TESTING"

if [ "$(check_reboot "$(detect_distro)")" == 1 ]; then
    echo "For some updates to take effect a reboot is required!"
    exit 2
else
    # Generate Nagios output
    generate_output "$(detect_distro)" "$updates" "$security"
    # Add long plugin output
    echo "Available Security Update:"
    echo "$securitylist"
    echo "Available Normal Updates:"
    echo "$non_securitylist"

    # Determine and exit with appropriate code
    state=$(determine_exit_code "$updates" "$security")
    exit "$state"
fi