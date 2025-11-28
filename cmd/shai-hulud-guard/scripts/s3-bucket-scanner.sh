#!/usr/bin/env bash
set -e
set -o pipefail
set -o noclobber
set -o nounset

# SHAI_HULUD_SCANNER_SAFE - This file is part of the Shai-Hulud scanner itself
# Files containing this marker will be excluded from malware detection scans

# Detect Bash version for compatibility
BASH_MAJOR_VERSION="${BASH_VERSINFO[0]}"

# Enable features based on Bash version
if [[ ${BASH_MAJOR_VERSION} -ge 4 ]]; then
	shopt -s lastpipe 2>/dev/null || true
fi

# Set paths, load helper functions etc
PROJECT_ROOT=${PROJECT_ROOT:-$(cd "$(dirname "${BASH_SOURCE[0]}")/" && pwd)}

# The logging level - if set to 0, nothing will be logged to the terminal
export LOG_LEVEL=${LOG_LEVEL:-3}

# Colours etc used for display and general awesomeness
export RED='\033[1;31m'
export DARK_GREEN='\033[0;32m'
export GREEN='\033[1;32m'
export BLUE='\033[1;34m'
export YELLOW='\033[1;33m'
export ORANGE='\033[0;33m'
export NC='\033[0m' # No Color, reset back to normal
if [[ $TERM != "dumb" ]]; then
	# tput is only happy on an proper terminal
	BOLD=$(tput bold)
	UNDERLINE=$(tput smul)
	OFFUNDERLINE=$(tput rmul)
	NORMAL=$(tput sgr0)
else
	BOLD=
	UNDERLINE=
	OFFUNDERLINE=
	NORMAL=
fi
export BOLD
export UNDERLINE
export OFFUNDERLINE
export NORMAL

accessKey=""
secretKey=""
protocol="https"
host=""
port="9000"
bucket=""
path=""
alias="scanner"
useToast=Y
workArea="/tmp/sh_s3_scanner"

usage() {
	echo "Usage: $0 ACCESS_KEY SECRET_KEY URL REGION PATH"
	echo "       This will recursively scan S3 storage looking for any evidence of Shai-Hulud infection"
	echo "       The 'mc' and 'jq' command dependencies are mandatory"
	echo "       Examples:"
	echo "           sudo $0 -v -a1234 -s5678"
	echo
	echo "Options:"
	echo "       -a <access key>"
	echo "              ${BOLD}Mandatory${NORMAL} - Set your access key"
	echo "       -b <bucket name>"
	echo "              Set the bucket"
	echo "       -c "
	echo "              Rebuild compromise cache, if it exists"
	echo "       -h <host>"
	echo "              Set the host"
	echo "       --help"
	echo "              This information"
	echo "       -p <protocol>"
	echo "              Set the protocol"
	echo "       -P <port>"
	echo "              Set the port (default: '${port}')"
	echo "       -path <path>"
	echo "              Set the path within the bucket"
	echo "       -s <secret key>"
	echo "              ${BOLD}Mandatory${NORMAL} - Set your secret key"
	echo "       -v, -vv"
	echo "              Displays additional information when running. 'vv' increases logging even further"
}

# Echos a message if it is appropriate to the log level
# Param 1 - The intended logging level
# Values:
#   1 - An error
#   2 - A warning
#   3 - Information
#   4 - Debug
#   5 - Trace
# Param 2 - The message to display
log() {
	local level="$1"
	shift
	local message="$*"
	if [[ "$level" -le ${LOG_LEVEL} ]]; then
		case "$level" in
			1)
				echo -e "[${RED}ERROR${NC}  ] ${message}"
				;;
			2)
				echo -e "[${ORANGE}WARN${NC}   ] ${message}"
				;;
			3)
				echo -e "[${BLUE}INFO${NC}   ] ${message}"
				;;
			4)
				echo -e "[${GREEN}DEBUG${NC}  ] ${message}"
				;;
			5)
				echo -e "[${DARK_GREEN}TRACE${NC}  ] ${message}"
				;;
			*)
				echo "Unknown logging option '$level', message '${message}'"
				exit 3
				;;
		esac
	fi
}

# Put a message into standard out and pop-up a notification the user (if that facility is available)
# A slightly different thing to logging, useful for "Done!" and "Crashed!" etc
# 1 - The notification level
#   Values:
#     1 - Failure
#     2 - Success
#     3 - Other
# 2 - The message
# 3 - Use notification, if available
function notify() {
	case "$1" in
		1)
			full_message="[${RED}FAILURE${NC}] $2"
			icon=/usr/share/icons/breeze-dark/emblems/22/emblem-error.svg
			;;
		2)
			full_message="[${DARK_GREEN}SUCCESS${NC}] $2"
			icon=/usr/share/icons/breeze-dark/emblems/22/emblem-success.svg
			;;
		3)
			full_message="[${BLUE}OTHER${NC}  ] $2"
			icon=/usr/share/icons/breeze-dark/emblems/22/emblem-information.svg
			;;
		*)
			echo "Unknown notify option '$1', message '$2' from '$(caller)'"
			exit 1
			;;
	esac

	echo -e "${full_message}"

	local use_toast=${3:-""}
	# TODO What are the Windows and MacOS equivs, if any?
	if [[ -n ${use_toast} ]] && hash notify-send 2>/dev/null; then
		notify-send "$2" -a "Shai-Hulud S3 Scanner" -i "${icon}"
		printf '\a'
	fi
}

print_banner() {
	local term_width=80
	if command -v tput >/dev/null 2>&1; then
		term_width=$(tput cols 2>/dev/null || echo 80)
	elif [[ -n "${COLUMNS:-}" ]]; then
		term_width="$COLUMNS"
	fi

	echo ""
	if [[ "$term_width" -ge 180 ]]; then
		cat "${PROJECT_ROOT}/resources/sworm_180.txt"
		echo -e "\n                                                            Supply Chain Malware Detection Scanner for Real Computers 🐧\n"
	else
		cat "${PROJECT_ROOT}/resources/sworm_72.txt"
		echo -e "\n      Supply Chain Malware Detection Scanner for Real Computers 🐧"
	fi
}

reportMCError() {
	local message cause json="$1"
	message=$(echo "${json}" | jq -r .error.message)
	cause=$(echo "${json}" | jq -r .error.cause.message)
	log 1 "Raw JSON:"
	echo "${json}" | jq
	log 1 "Message: ${message}"
	log 1 "Caused by: ${cause}"
	notify 1 "Scanning failed, see above" ${useToast}
	exit 1
}

getS3Folder() {
	local exitCode path="$1" objectKey objectType jsonLines
	log 3 "Fecthing content list from '${bucket}/${path}'"

	set +e
	jsonLines=$(mc --json ls "${alias}/${bucket}/${path}/")
	exitCode=$?
	set -e

	if [[ ${exitCode} -ne 0 ]]; then
		reportMCError "${jsonLines}"
	else
		if [[ -z "${jsonLines}" ]]; then
			log 4 "Nothing found in '${bucket}/${path}'"
		else
			# Process based on Bash version
			if [[ ${BASH_MAJOR_VERSION} -ge 4 ]]; then
				# Bash 4+: use lastpipe for better performance
				echo "${jsonLines}" | while IFS= read -r line; do
					[[ -z $line ]] && continue
					objectKey=$(echo "${line}" | jq -r .key)
					objectType=$(echo "${line}" | jq -r .type)
					if [[ "${objectType}" == "folder" ]]; then
						getS3Folder "${path}/${objectKey:0:-1}"
					elif [[ "${objectType}" == "file" ]]; then
						getS3File "${path}/${objectKey}"
					else
						log 2 "Unknown object type '${objectType}'"
					fi
				done
			else
				# Bash 3.2: use subshell
				echo "${jsonLines}" | {
					while IFS= read -r line; do
						[[ -z $line ]] && continue
						objectKey=$(echo "${line}" | jq -r .key)
						objectType=$(echo "${line}" | jq -r .type)
						if [[ "${objectType}" == "folder" ]]; then
							# Remove trailing slash (Bash 3.2 compatible)
							objectKey="${objectKey%/}"
							getS3Folder "${path}/${objectKey}"
						elif [[ "${objectType}" == "file" ]]; then
							getS3File "${path}/${objectKey}"
						else
							log 2 "Unknown object type '${objectType}'"
						fi
					done
				}
			fi
		fi
	fi
}

getS3File() {
	local filePath="$1" fileName
	log 3 "Downloading '${bucket}/${filePath}' to '${workArea}'"
	mc get "${alias}/${bucket}/${filePath}" "${workArea}"
}

OPTIONS=a:b:h:p:P:s:vV
LONGOPTS=help,path:

# Use ! and PIPESTATUS to get exit code with errexit set
#  - Temporarily store output to be able to check for errors
#  - Activate quoting/enhanced mode (e.g. by writing out “--options”)
#  - Pass arguments only via   -- "$@"   to separate them correctly
! PARSED=$(getopt --options=$OPTIONS --longoptions=$LONGOPTS --name "$0" -- "$@")
if [[ ${PIPESTATUS[0]} -ne 0 ]]; then
	# Return value is non-zero, ergo getopt has complained about wrong arguments to stdout
	usage
	exit 2
fi

# Read getopt’s output this way to handle the quoting right:
eval set -- "${PARSED}"

while true; do
	case "$1" in
		-a)
			accessKey=$2
			shift
			;;
		-b)
			bucket=$2
			shift
			;;
		-h)
			host=$2
			shift
			;;
		--help)
			usage
			exit
			;;
		-p)
			protocol=$2
			shift
			;;
		-P)
			port=$2
			shift
			;;
		--path)
			path=$2
			if [[ ${2:0:1} == "/" ]]; then
				path=${2:1}
			else
				path=$2
			fi
			if [[ ${2: -1} == "/" ]]; then
				path=${path:0:-1}
			fi
			shift
			;;
		-s)
			secretKey=$2
			shift
			;;
		-v)
			if [[ ${LOG_LEVEL} -gt 4 ]]; then
				log 1 "Cannot increase logging further"
			else
				export LOG_LEVEL=$((LOG_LEVEL+1))
			fi
			;;
		--)
			break
			;;
		*)
			notify 1 "Programming error in '$0', unknown option, '$1'." "${use_toast}"
			exit 3
			;;
	esac
	shift
done

failing=
if ! which mc > /dev/null; then
	log 1 "'mc' command is missing'"
	failing=Y
fi
if ! which jq > /dev/null; then
	log 1 "'jq' command is missing'"
	failing=Y
fi
if [[ -z ${accessKey} ]]; then
	log 1 "Access key is not set"
	failing=Y
fi
if [[ -z ${secretKey} ]]; then
	log 1 "Secret key is not set"
	failing=Y
fi
if [[ -z ${protocol} ]]; then
	log 1 "Protocol is not set"
	failing=Y
fi
if [[ -z ${host} ]]; then
	log 1 "Host is not set"
	failing=Y
fi
if [[ -z ${bucket} ]]; then
	log 1 "Bucket is not set"
	failing=Y
fi
if [[ -z ${path} ]]; then
	log 1 "Path is not set"
	failing=Y
fi

if [[ -n ${failing} ]]; then
	notify 1 "Validation failures" ${useToast}
  log 1 "See above. Run './s3-bucket-scanner.sh -h' for help"
	exit 1
fi

print_banner

log 2 "Run this S3 scanner for bucket '${bucket}', path '${path}', on '${protocol}://${host}:${port}'"
set +e
read -r -t 15 -p "Are you sure? [y/N] " response
set -e
if [[ $? -gt 128 ]] ; then
	response="timeout"
	echo
else
	# Convert to lowercase (Bash version compatible)
	if [[ ${BASH_MAJOR_VERSION} -ge 4 ]]; then
		response=${response,,}
	else
		response=$(echo "$response" | tr '[:upper:]' '[:lower:]')
	fi
fi
# Use case statement for pattern matching (Bash 3.2 compatible)
case "$response" in
	yes|y)
		;;
	*)
		notify 1 "Execution was not confirmed, aborting" ${useToast}
		exit 1
		;;
esac

log 5 "Adding '${alias}' alias"
mc alias set "${alias}" "${protocol}://${host}:${port}" "${accessKey}" "${secretKey}" > /dev/null

rm -rf "${workArea}"
mkdir -p "${workArea}"

getS3Folder "${path}"

log 3 "Running scan...."
"${PROJECT_ROOT}"/scripts/Check-ShaiHulud-Dynamic.sh -r "${workArea}" -m "full" -o "${PROJECT_ROOT}/ShaiHulud-S3-Scan-Report.txt" -B -F

log 5 "Removing '${alias}' alias"
mc alias remove "${alias}" > /dev/null

notify 2 "Scanning complete" ${useToast}
