#!/usr/bin/env bash
set -euo pipefail

# SHAI_HULUD_SCANNER_SAFE - This file is part of the Shai-Hulud scanner itself
# Files containing this marker will be excluded from malware detection scans

# Track if we've encountered an error - stop checkpointing after first error
SCAN_ERROR=0

# Track all background process groups for cleanup
BG_PIDS=()

# Flag to prevent double cleanup
CLEANUP_DONE=0

# Cleanup function to kill all background processes
cleanup() {
  # Prevent double cleanup
  [[ $CLEANUP_DONE -eq 1 ]] && return
  CLEANUP_DONE=1
  
  local exit_code=$?
  echo "" >&2
  echo "[*] Cleaning up background processes..." >&2
  
  # Kill all tracked background processes and their children
  if [[ ${#BG_PIDS[@]} -gt 0 ]]; then
    for pid in "${BG_PIDS[@]}"; do
      if kill -0 "$pid" 2>/dev/null; then
        # Kill the process group (negative PID kills the group)
        kill -TERM "-$pid" 2>/dev/null || true
        # Give it a moment to terminate gracefully
        sleep 0.1
        # Force kill if still running
        kill -KILL "-$pid" 2>/dev/null || true
      fi
    done
  fi
  
  # Also find and kill any orphaned xargs processes from this script
  pkill -P $$ 2>/dev/null || true
  
  # Clean up any temp files
  rm -f /tmp/shai-hulud-* 2>/dev/null || true
  
  exit "$exit_code"
}

# Trap errors and set error flag
trap 'SCAN_ERROR=1' ERR

# Trap exit and signals to ensure cleanup
trap cleanup EXIT INT TERM QUIT HUP

ROOTS=("$HOME")
SCAN_MODE="full"
REPORT_PATH=""  # Will be set after parsing arguments

# Wide ASCII Art Banner (for terminals >= 180 chars)
BANNER_WIDE='
     .:--.------:--:--:--:---:--:--:--:---:--:--:=-:------.--:--:---:--:--:------:--.--:--:---:--:--:------:--:--:------:--:--:------:--:--:---:--:--.=--------:=-:--:---:=-:--..
     .=##:##+*#++##=##=##=*#*+##=##=##+##*=##=##=##++#*+##:##+*#=###=##+##-##*+#*+##-##+*#+*##=##=##-*#**#*=##=##+##++##=##-##=*#+*##-##=##=##*+##+##:##+*#+*##-##+##=*##+##=##:.

                   ...:---:... .:::..   .:::.     ..::::..     :::..                    .:::.     :::....:::..   ..:::. .:::.     ..::..    .:::.  .:::::::....
                  ..*@@@@@@@+. -@@@..   :%@@-     .@@@@@:.     @@@=.                    .@@@-     @@@=..-@@@:.   .=@@%. .%@@*     .#@@+.    .#@@:. .@@@@@@@@@%-.
                  .+@@#. ..=-. -@@@:.   :%@@-    .+@@#@@%.     @@@=.                    .@@@-     @@@=..-@@@:.    =@@%. .%@@*     .#@@+.    .#@@:. .@@%:..:+@@@%:
                  .*@@%:...    -@@@:....:%@@-    .@@#.#@@+.    @@@=.                    .@@@-.....@@@=. -@@@:.    =@@%. .%@@*     .#@@+.    .#@@:. .@@%:   ..#@@*
                  .:%@@@@%+... -@@@@@@@@@@@@-  ..#@@-.-@@@.    @@@=.                    .@@@@@@@@@@@@=. -@@@:.    =@@%. .%@@*     .#@@+.    .#@@:. .@@%:     =@@%
                     .+%@@@@#. -@@@%####%@@@-  .=@@#  .*@@%..  @@@=.      -#####=.      .@@@%#####@@@=. -@@@:.    =@@%. .%@@*     .#@@+.    .#@@:. .@@%:     -@@%
                        .=@@@= -@@@:.   :%@@-  :%@@@@@@@@@@=.  @@@=.      =@@@@@*.      .@@@-     @@@=..-@@@:.   .=@@%. .%@@*     .*@@*.    .%@@:. .@@%:     #@@*
                  .=:....:@@@- -@@@..   :%@@- .*@@#=====*@@%.. @@@=.                    .@@@-     @@@=...@@@#....-@@@+. .%@@*......=@@@-....*@@%.  .@@%:...-%@@@:
                  .%@@@@@@@@=. -@@@..   :%@@- -@@@:     .#@@*. @@@=.                    .@@@-     @@@=.  .#@@@@@@@@@=.  .%@@@@@@@%..+@@@@@@@@@%..  .@@@@@@@@@@*.
                   .:=**+-:.   .-=-..   .-=-. :=-:.      .-=-. -=-..                    .-=-.     -=-..   ..-+**+-:..   .:-------:.  .:-+**=:..    .-------:.

       ....... ...... .. ...... .. ...... .. ...... .... ...... .. ... .. .. ... .. .. ... .. ...... .... ...... .. ...... .. ...... .. ...... ........... ...... .. .. ... .. ..
       +++-++-++:++==+=-++-++-++-=++=++:++-++-++=-++-++:++==+==++.++-++-+++-++-++:++==+=-++:++=++==++-++-++-=+==++-++-++-++=-++-++:++-=+==++:++-++-++=-++-++:++==+==++:++-++-=++.
....................................................................................................................................................................................
--------------------------------::::::-------------::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::...........................................................
---------------------------------:::::------------:::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::..:..........................................................
----------------------------------:::::-----------:::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::...............................................................
----------------------------------::::------------:-::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::............................................................
----------------------------------:::-------------::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::...:........................................................
-------------------------------:::----------------::::::::::::::::::::::::::::::::-::::::::::::::::::::::::::::::::::::.............................................................
--------------------------------------------------:::::::::::::::::::::::::::::::*#+-:::::::::::::::::::::::::::::::::..............................................................
---------------------------------------------------:::::::::::::::::::::::::::::*#%*+=:::::::::::::::::::::::::::::::::.............................................................
-------------------------------------------------:-:::::::::::::::::::::::::::*#%%#*++*-:::::::::::::::::::::::::::::::..:..........................................................
-------------------------------------------------:::::::::::::::::::::::::::::#+##+++=*+-:::::::::::::::::::::::::::::::::..........................................................
---------------------------------------------------::::::::::::::::::::::::::###%%##*+:=*=:::::::::::::::::::::::::::::::..:........................................................
-------------------------------------------------::::::::::::::::::::-::::=*+=#%%%***+=:**+=::::::::::::::::::::::::::::..:.........................................................
-------------------------------------------------::::::::::::::::::::::-=*#==%%#%%%#+=**:-+-=:::::::::::::::::::::::::::..:.........................................................
-------------------------------------------------:-:::::::::::::::::::::-=-*####%###*#=+#=:*=-=::::::::::::::::::::::::::.:.:.......................................................
-------------------------------------------------:::::::::::::::::::::::=*###*#@%*#**%#+:-::-*---:::::::::::::::::::::::::::::......................................................
-------------------------------------------------::--:::::::::::::::::-*#*****%%#**+--%#=::.:==+====+===--:.::::::::::::..::::......................................................
------------------------------------------------:::::::::::::::::::::-*****++##*-:::.-%*=-++++++++=++==+++++=-:::::::::::::.::......................................................
-------------------------------------------:-:--:::-:::::::::::::::::=*=::::+#+--*###**+++*#******#*++**++=======--::..:::..........................................................
---------------------------------------------:-::::::::::::::::::::::==::::-###%%%#***##**#%#*##########**++**+===----:..::.........................................................
------------------------------------------:--::::::::::::::::::::::::::::=#%*%####*###%%%%%%%%%%%%%%%########*+==++++===:..::.......................................................
---------------------------------------:-:-::::::::::::::::::::::::::::+%%%*#%###%##%%%@@%%%%%%%%%%%%%%%%%####****+====---:.::::..................................::.::::::.::::..::
-----------------------------------------::::::::::::::::::::::::::::+###%%%#%%##%%%%@@%%%#########%#%#%%%%%%%%%#*++++====-:...:.............................:.::::::::::::::::--==-
-------------------------------------:---:-:-::::::::::::::::::::::-#%%%#%%%##%%%%@%%%##########**######%%%%#%%%###*#*++==---:.::.:....:.......:----::::.....:::::::::::::-======++=
--------------------------------------:::::::::::::::::::::::::::*#####%%%%%%%%@@%%#####**####**###**#**#*#####%%%%##*+=====---..............-==+++=-:::::::-------===========++++++
----------------::---------------::::::::::::::::::::::::::::::-*######%%%%@@@%%%####%#**##*###*###**+***++**###%%%##**++====---:::.......:==++*++---:---------=====+==+++++==+++++=
::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::-*#%%%##%%%%%%%%%%#*###%**##*#%#*###*+++++==+**##*#%%%%##**++===---:-------==++****++==--============++======+++*****+
----------:::::::::::::::::------------:---:::::::::::-------+*##%%%##%%%@@%%%%#***#%%##%######***+=+++++*###*++**#%%%%%#*++=----::-======++*******+++=-=======++=+++++====+++++++*+
==========------------------------------================--==+*####%%%#%%%%%%#%%#***#%###%######***+****#****+++=+++*#%%%##**+==----:-++++++**********+=-----====+=++++==+=====+++++=
+++++===-----------------=======+++++++++++++++++++++======**######%%%%%%#####%#***#%##%%##%%#*#***+*##*#*+++++====++#%%%%##*====----:+++++++++*++++++===++=--=++++++++++++++++++++=
=++++++++++++++++==--------====+++++++++++++++++++++++++++#**######%@@%%%#*###%%##*#%%%%%##%%####*+*####****++++====+*%%%%###*+=--=--:-=+++++++**************+==++++++++++++++++++++
++++++=======---------------=====+++++++++++++++++++====+*#**#####%%@@%%%%####%%####%%%%%#%%%##%#*#######*****+===--=+#%%%%%##*+++++=--:++++++++*******+++++++===+==+++++++++++++++=
++====------============+===============+++++++++++====++*#**#%###%%@%%%%%%%###%%#%##%%%%%%%%%%%#####%###***+++=====-=*%%%%%%###*++==--:-++===+++++++++++++===========+++++++++===+=
-----------====================================++++++++*##%####%%%%%%%%%###%%##%%%#%%%%%%%%%%%%%%%%%%%###****++=======+#%%%%%%%#**+===-:::=+++++++++++++++==========+++++++++++++++=
=+++++++++++****++==------=================+==++++++++**#%%%%###%@%%%#%%%%###%%#%%%%%%%@%@@%%%%%%%%%%%%#*#***+++=++===+*%%%%%%%###*++=--::-====+++++++++++++++++++++++++++==========
+++++++++===----:-------======++++===+++++++++++++**+*#*#%%%%%%%%@%%%###%%%%##%%%%%%%%%%@@@%%%@%%%%%%%%###***++==+++===*%%%%#%%%%##**+=-::-++++++++++++++++++++++++++++++++++++++++=
=======-------===============+++++++++++++++++++++*++#%###%%%%%@@%%%%%%###%%%%%###%%%#%%@@%%%%@%%%%%%%%%###****++=+++==+#%%%%##%%%%##*++-:-*++++++++++++++++====+++++++=========+++=
----=========================++++++++++++++++++++*++*#%%###%%%%@%%%%#%%%%%###%%%*#%#########%%@%%%%%%%%%###***++==+*+==+#%%%%%%##%@%%#*+=--+********++++++++++++++++++++++++++=====-
*******+=====+++++++++++++++++++++*****+++++++++++***#%%%###%%%%%%%%#####%%%%###*#####*******#%%%%%%%%%%%#******+++*++==*%%%%%%%%%%%%%#*+=-*#****************************+=======+++
*+++++++++++++***++++++++*+****+++++****+++******+***#%%%%%%%%%%@@%%%#############*************#%%%%%%%%%###****+++**===+#%%%%%%%%%%%%%#+=-###*#**************+**********+====*****+
******************++++++++++++++++++++++**********#####%%%@@@@%%%%%%%%###*****++++**************+**#%%%%%%##*********==++**#%%%%%%%%%%%*+==#*############***#########*****##*######*
******################***++====++++++++++++++****#%%%####%%@@@%%%%###%%%####***++********#######*#**%%%%%%%%%######**++++**+***###%%##*+==***********##############################*
#####################*****+=====+=+++++********###%%%%%##%%%%%%%%%%#***#####**+====++********#*******%%%%%%%%#####******++*##***+++++===+*******###################################*
####*****++++++++++==============+++++++*******%%%%%%@%%%%%%%%%%%%%###**++++++=======+++**************#%%%%%%##########%#++***********************#################################*
*+++****+++++++++++++++++++++++++++++++++***#*#%%%%%%%%%%%%%%%%%%%%%%%##**++===========++***************%%%%%%%%%%%%%%%%%*=****#**#***********#####################################*
**********************************************#%%%%%%%%@%%%@%%%%%###***+++=---=++=======++****************%%%#**#%%%#%%%#*=***##########**********############################%%%%%*
####################**********************#####%%%%%%%%%%%%%%%%%%%##**+++==--==+=========+****************+*####***#%###%#=*###########**##*****############################%######*
#######################*****************#####%%%%%%%%%%%%%%%%%%%%%%##***+++=+============+**************++++++#%###***###+=*##############**#******################################*
###################*******************#####%%%%%%%%%%######%%%%%%%#####**+==========+====+***********************####**++=+#####********************###############################*
#****###################*******#****#*####%%%%%%%%%%%#############****++==============-==+****###*#*#*######**#*****##****####*******************##################################*

                                          Supply Chain Malware Detection Scanner for macOS
'

# Narrow ASCII Art Banner (for terminals < 180 chars)
BANNER_NARROW='
   ___  _  _   _   ___      _  _ _   _ _    _   _ ___
  / __|| || | /_\ |_ _| ___| || | | | | |  | | | |   \
  \__ \| __ |/ _ \ | | |___| __ | |_| | |__| |_| | |) |
  |___/|_||_/_/ \_\___|    |_||_|\___/|____|\___/|___/
  .......................................................
  ---------------::-----::::::::::::::::::::::::::::::::..............
  -----------------------:::::::::::::=+:::::::::::::::.................
  -----------------------::::::::::::%#*+-::::::::::::::.................
  ----------------------::::::::::=+*#%#*+:=-::::::::::::::..............
  ----------------------:::::::::-***%*=+*:-===---::::::::...............
  -------------------:::::::::::::+#####%%%%%%%#%##**+==-::...........:.
  ------------------::::::::::::+#%%%%%%%########%#%#**+=-:::....:--::--+
  -------:::::::::::::::::::::=###%%@%##%*####*+*+*##%#*+=--:::-+*+--=+++
  --=----:-------------------+#%%#%%%%*###*###+****++*%%#+=---=++***+=+++
  +++++++==---==++++++++++++*###%%%##%###%#%##+##*++==+%%#*=---+++**+++++
  ==-----==========++++++++*##%%%%%%#%#%%%%%%%#%#**+==-#%%##+=--++++++=+=
  +++++++=---=====++=+++++*#%%%%%#%%%%%%%%@%%%%%##*+=+=+%%%%#+=:=++++====
  -============+++++++++**%#%%@%%%%#%%#####%@%%%%#**=++=%%%%%%*==**+++===
  ++++++++++++*+++**+*****#%%%%%%######******%%%%##*+++=*%%%%%#++*#**+=**
  ###########**==++++***#%##%%%%##%##++***####*%%%%%#**+**+***+=****#####
  ***+++++++++++++++***%%%%%%%%%%#*+=====+******#%%%%%%%#*####*****######
  #########*********###%%%%%%%%%#*+==+====+*******##**%##*######***######
  ########*********##%%%%%##%####*+=======+**********##*+*#*********#####

            Supply Chain Malware Detection Scanner
'

# Function to print banner based on terminal width
print_banner() {
  local term_width=80
  if command -v tput >/dev/null 2>&1; then
    term_width=$(tput cols 2>/dev/null || echo 80)
  elif [[ -n "${COLUMNS:-}" ]]; then
    term_width="$COLUMNS"
  fi

  echo ""
  if [[ "$term_width" -ge 180 ]]; then
    echo -e "\033[33m${BANNER_WIDE}\033[0m"
  else
    echo -e "\033[33m${BANNER_NARROW}\033[0m"
  fi
}

usage() {
  cat <<'EOF'
Usage: Check-ShaiHulud-Dynamic-macOS.sh [options]
  -r, --roots "path1,path2"   Comma-separated root paths to scan (default: $HOME)
  -m, --mode  quick|full      Scan mode (default: quick)
  -o, --report FILE           Report output path (default: /tmp/ShaiHulud-Scan-Report-<mode>-<timestamp>.txt)
  -h, --help                  Show this help
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    -r|--roots) IFS=',' read -r -a ROOTS <<<"$2"; shift 2;;
    -m|--mode) SCAN_MODE="$(echo "$2" | tr '[:upper:]' '[:lower:]')"; shift 2;;
    -o|--report) REPORT_PATH="$2"; shift 2;;
    -h|--help) usage; exit 0;;
    *) ROOTS+=("$1"); shift;;
  esac
done

if [[ "$SCAN_MODE" != "quick" && "$SCAN_MODE" != "full" ]]; then
  echo "Invalid mode: $SCAN_MODE (use quick or full)" >&2
  exit 1
fi

# Set default report path with timestamp and scan mode if not specified
if [[ -z "$REPORT_PATH" ]]; then
  TIMESTAMP="$(date +%Y%m%d-%H%M%S)"
  REPORT_PATH="${TMPDIR:-/tmp}/ShaiHulud-Scan-Report-${SCAN_MODE}-${TIMESTAMP}.txt"
fi

SCRIPT_DIR="$(cd -- "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CACHE_DIR="${TMPDIR:-/tmp}/shai-hulud-scanner-cache"
CACHE_FILE="$CACHE_DIR/compromised-packages-cache.txt"
CACHE_TTL=86400  # 24 hours in seconds
CHECKPOINT_FILE="$CACHE_DIR/checkpoint.txt"

# Create cache directory
mkdir -p "$CACHE_DIR"

PACKAGE_FEED_URLS=(
  "https://raw.githubusercontent.com/Cobenian/shai-hulud-detect/refs/heads/main/compromised-packages.txt"
)

MALICIOUS_FILES=(
  "shai-hulud.js" "shai_hulud.js"
  "shai-hulud-workflow.yml" "shai_hulud_workflow.yml"
  "shai-hulud.yml" "shai_hulud.yml"
  "setup_bun.js" "bun_environment.js" "discussion.yaml"
  "truffleSecrets.json" "actionsSecrets.json"
)

SUSPICIOUS_BRANCH_PATTERNS=("shai-hulud" "shai_hulud" "SHA1HULUD")
SUSPICIOUS_WORKFLOW_PATTERNS=("self-hosted" "SHA1HULUD" "shai-hulud" "shai_hulud" "webhook.site" "bb8ca5f6-4175-45d2-b042-fc9ebb8170b7")
CLOUD_CREDENTIAL_PATHS=(".aws/credentials" ".aws/config" ".azure/" ".npmrc" ".env")
SUSPICIOUS_HOOK_PATTERNS=("curl " "wget " "node -e" "eval(" "base64" "webhook" "exfil" "/tmp/" "\\temp\\" "powershell" "cmd /c")
SUSPICIOUS_NAMES=("bundle.js" "setup_bun.js" "bun_environment.js" "shai-hulud.js" "shai_hulud.js")

# Hash checking functions (compatible with bash 3.2)
check_mal_sha256() {
  local hash="$1"
  case "$hash" in
    "46faab8ab153fae6e80e7cca38eab363075bb524edd79e42269217a083628f09")
      echo "Shai-Hulud bundle.js payload"
      return 0
      ;;
    "b74caeaa75e077c99f7d44f46daaf9796a3be43ecf24f2a1fd381844669da777")
      echo "Shai-Hulud malicious file"
      return 0
      ;;
    "dc67467a39b70d1cd4c1f7f7a459b35058163592f4a9e8fb4dffcbba98ef210c")
      echo "Shai-Hulud malicious file"
      return 0
      ;;
    "4b2399646573bb737c4969563303d8ee2e9ddbd1b271f1ca9e35ea78062538db")
      echo "Shai-Hulud malicious file"
      return 0
      ;;
    *)
      return 1
      ;;
  esac
}

check_mal_sha1() {
  local hash="$1"
  case "$hash" in
    "d1829b4708126dcc7bea7437c04d1f10eacd4a16")
      echo "setup_bun.js (Shai-Hulud 2.0)"
      return 0
      ;;
    "d60ec97eea19fffb4809bc35b91033b52490ca11")
      echo "bun_environment.js (Shai-Hulud 2.0)"
      return 0
      ;;
    "3d7570d14d34b0ba137d502f042b27b0f37a59fa")
      echo "bun_environment.js variant (Shai-Hulud 2.0)"
      return 0
      ;;
    *)
      return 1
      ;;
  esac
}

FINDING_LIST=()

# Cache helper functions
get_cache_file() {
  local cache_name="$1"
  echo "$CACHE_DIR/${cache_name}.cache"
}

is_cache_valid() {
  local cache_file="$1"
  [[ ! -f "$cache_file" ]] && return 1
  local now=$(date +%s)
  local mtime=$(stat -f %m "$cache_file" 2>/dev/null || echo 0)
  local age=$(( now - mtime ))
  [[ $age -lt $CACHE_TTL ]]
}

save_to_cache() {
  local cache_name="$1"
  local cache_file="$(get_cache_file "$cache_name")"
  cat > "$cache_file"
}

load_from_cache() {
  local cache_name="$1"
  local cache_file="$(get_cache_file "$cache_name")"
  if is_cache_valid "$cache_file"; then
    echo "[CACHE] Loading cached results for: $cache_name" >&2
    cat "$cache_file"
    return 0
  fi
  return 1
}

save_checkpoint() {
  local step="$1"
  # Don't save checkpoints if we've encountered an error
  if [[ $SCAN_ERROR -eq 1 ]]; then
    echo "[WARNING] Not saving checkpoint due to previous error" >&2
    return 1
  fi
  echo "$step|$(date +%s)" > "$CHECKPOINT_FILE"
}

get_last_checkpoint() {
  [[ -f "$CHECKPOINT_FILE" ]] && cat "$CHECKPOINT_FILE" | cut -d'|' -f1 || echo ""
}

clear_checkpoint() {
  rm -f "$CHECKPOINT_FILE"
}

should_skip_step() {
  local step="$1"
  local last_checkpoint="$(get_last_checkpoint)"
  [[ -n "$last_checkpoint" ]] || return 1
  
  # Define step order
  local steps=("packages" "node_modules_find" "node_modules_scan" "npm_cache" "malicious_files" "git" "workflows" "credentials" "runners" "hooks" "hashes" "migration" "trufflehog" "env_patterns")
  
  local current_idx=-1
  local checkpoint_idx=-1
  for i in "${!steps[@]}"; do
    [[ "${steps[$i]}" == "$step" ]] && current_idx=$i
    [[ "${steps[$i]}" == "$last_checkpoint" ]] && checkpoint_idx=$i
  done
  
  [[ $current_idx -ge 0 && $checkpoint_idx -ge 0 && $current_idx -le $checkpoint_idx ]]
}

log_section() { echo; echo "---- $1 ----"; }
add_finding() {
  local type="$1" indicator="$2" location="$3"
  FINDING_LIST+=("$type|$indicator|$location")
  # Append to report immediately
  echo "Type: $type | Indicator: $indicator | Location: $location" >> "$REPORT_PATH"
}

trim() {
  local s="$1"
  s="${s#"${s%%[![:space:]]*}"}"
  s="${s%"${s##*[![:space:]]}"}"
  printf '%s' "$s"
}

escape_regex() {
  local s="$1"
  s="${s//\\/\\\\}"; s="${s//\./\\.}"; s="${s//\*/\\*}"; s="${s//\+/\\+}"
  s="${s//\?/\\?}"; s="${s//\^/\\^}"; s="${s//\$/\\$}"; s="${s//\[/\\[}"
  s="${s//\]/\\]}"; s="${s//\(/\\(}"; s="${s//\)/\\)}"; s="${s//\{/\\{}"
  s="${s//\}/\\}}"; s="${s//\|/\\|}"; s="${s//\//\\/}"
  s="${s//:/[:_-]}"
  printf '%s' "$s"
}

COMP_UNSCOPED=()
COMP_SCOPED=()
COMP_SCOPES=()
COMPROMISED_REGEX=""

# Helper functions for checking compromised packages (bash 3.2 compatible)
is_compromised_unscoped() {
  local pkg="$1"
  local item
  if [ ${#COMP_UNSCOPED[@]} -eq 0 ]; then
    return 1
  fi
  for item in "${COMP_UNSCOPED[@]}"; do
    if [ "$item" = "$pkg" ]; then
      return 0
    fi
  done
  return 1
}

is_compromised_scoped() {
  local scope="$1"
  local name="$2"
  local key="$scope|$name"
  local item
  if [ ${#COMP_SCOPED[@]} -eq 0 ]; then
    return 1
  fi
  for item in "${COMP_SCOPED[@]}"; do
    if [ "$item" = "$key" ]; then
      return 0
    fi
  done
  return 1
}

has_compromised_scope() {
  local scope="$1"
  local item
  if [ ${#COMP_SCOPES[@]} -eq 0 ]; then
    return 1
  fi
  for item in "${COMP_SCOPES[@]}"; do
    if [ "$item" = "$scope" ]; then
      return 0
    fi
  done
  return 1
}

load_compromised_packages() {
  if should_skip_step "packages"; then
    echo "[RESUME] Skipping packages load (already completed)"
    # Restore from cache
    local pkg_cache="$(get_cache_file "packages")"
    if [[ -f "$pkg_cache" ]]; then
      while IFS= read -r line; do
        local token="$line"
        if [[ "$token" == @*/* ]]; then
          local scope="${token%%/*}"
          local name="${token#*/}"
          COMP_SCOPED+=("$scope|$name")
          COMP_SCOPES+=("$scope")
        else
          COMP_UNSCOPED+=("$token")
        fi
      done < "$pkg_cache"
      echo "[*] Restored $(( ${#COMP_UNSCOPED[@]} + ${#COMP_SCOPED[@]} )) packages from cache"
      return
    fi
  fi
  
  local loaded=0
  local tmpfile
  tmpfile="$(mktemp)"
  for url in "${PACKAGE_FEED_URLS[@]}"; do
    echo "[*] Fetching compromised package list from: $url"
    if curl -fsSL --max-time 30 "$url" >>"$tmpfile"; then
      loaded=1
    else
      echo "[!] Failed to fetch $url" >&2
    fi
  done

  if [[ $loaded -eq 0 && -f "$CACHE_FILE" ]]; then
    echo "[*] Using cached compromised package snapshot: $CACHE_FILE"
    cat "$CACHE_FILE" >"$tmpfile"
  fi

  if [[ ! -s "$tmpfile" ]]; then
    rm -f "$tmpfile"
    return
  fi

  >"$CACHE_FILE"
  while IFS= read -r line || [[ -n "$line" ]]; do
    line="${line%%#*}"
    line="$(trim "$line")"
    [[ -z "$line" ]] && continue
    local token="${line%%[ ,;|]*}"
    token="$(trim "$token")"
    [[ -z "$token" ]] && continue
    echo "$token" >>"$CACHE_FILE"
    if [[ "$token" == @*/* ]]; then
      local scope="${token%%/*}"
      local name="${token#*/}"
      local key="$scope|$name"
      # Add to scoped list if not already present
      local found=0
      local item
      if [ ${#COMP_SCOPED[@]} -gt 0 ]; then
        for item in "${COMP_SCOPED[@]}"; do
          if [ "$item" = "$key" ]; then
            found=1
            break
          fi
        done
      fi
      if [ $found -eq 0 ]; then
        COMP_SCOPED+=("$key")
      fi
      # Add to scopes list if not already present
      found=0
      if [ ${#COMP_SCOPES[@]} -gt 0 ]; then
        for item in "${COMP_SCOPES[@]}"; do
          if [ "$item" = "$scope" ]; then
            found=1
            break
          fi
        done
      fi
      if [ $found -eq 0 ]; then
        COMP_SCOPES+=("$scope")
      fi
    else
      # Add to unscoped list if not already present
      local found=0
      local item
      if [ ${#COMP_UNSCOPED[@]} -gt 0 ]; then
        for item in "${COMP_UNSCOPED[@]}"; do
          if [ "$item" = "$token" ]; then
            found=1
            break
          fi
        done
      fi
      if [ $found -eq 0 ]; then
        COMP_UNSCOPED+=("$token")
      fi
    fi
  done <"$tmpfile"
  rm -f "$tmpfile"

  local patterns=()
  local pkg
  if [ ${#COMP_UNSCOPED[@]} -gt 0 ]; then
    for pkg in "${COMP_UNSCOPED[@]}"; do
      patterns+=("$(escape_regex "$pkg")")
    done
  fi
  local key
  if [ ${#COMP_SCOPED[@]} -gt 0 ]; then
    for key in "${COMP_SCOPED[@]}"; do
      local scope="${key%%|*}"; local name="${key#*|}"
      patterns+=("$(escape_regex "$scope/$name")")
    done
  fi
  if [[ ${#patterns[@]} -gt 0 ]]; then
    COMPROMISED_REGEX="(${patterns[*]// /|})"
  fi
  echo "[*] Total unique compromised package identifiers loaded: $(( ${#COMP_UNSCOPED[@]} + ${#COMP_SCOPED[@]} ))"
  
  # Save to cache
  cat "$CACHE_FILE" | save_to_cache "packages"
  save_checkpoint "packages"
}

find_node_modules() {
  local mode="$1"; shift
  
  # Try cache first
  if load_from_cache "node_modules_dirs_${mode}"; then
    return 0
  fi
  
  local -a dirs=()
  for root in "$@"; do
    [[ -d "$root" ]] || { echo "[!] Root path not found: $root" >&2; continue; }
    if [[ "$mode" == "quick" ]]; then
      # Quick mode: Use find but limit depth to improve performance
      # Search common project directories with reasonable depth
      while IFS= read -r -d '' d; do 
        dirs+=("$d")
      done < <(find "$root" -maxdepth 5 -type d -name node_modules -print0 2>/dev/null)
    else
      # Full mode: Deep recursive search with no depth limit
      while IFS= read -r -d '' d; do dirs+=("$d"); done < <(find "$root" -type d -name node_modules -print0 2>/dev/null)
    fi
  done
  
  # Only output if we found directories
  if [[ ${#dirs[@]} -gt 0 ]]; then
    printf '%s\n' "${dirs[@]}" | sort -u | tee >(save_to_cache "node_modules_dirs_${mode}")
  fi
}

scan_node_modules() {
  local nm_dirs=("$@")
  local total=${#nm_dirs[@]}
  
  echo "[*] Scanning $total node_modules directories in parallel..."
  
  local tmpfile_results="$(mktemp)"
  local tmpfile_count="$(mktemp)"
  local tmpfile_unscoped="$(mktemp)"
  local tmpfile_scoped="$(mktemp)"
  local tmpfile_scopes="$(mktemp)"
  
  # Write package lists to temp files for workers to read
  printf '%s\n' "${COMP_UNSCOPED[@]}" > "$tmpfile_unscoped"
  printf '%s\n' "${COMP_SCOPED[@]}" > "$tmpfile_scoped"
  printf '%s\n' "${COMP_SCOPES[@]}" > "$tmpfile_scopes"
  
  # Process directories in parallel with progress using helper
  printf '%s\n' "${nm_dirs[@]}" | \
    parallel_with_progress "Scanning node_modules" "$total" 10 "bash -c '
      check_node_modules_dir \"\$1\" \"'$tmpfile_unscoped'\" \"'$tmpfile_scoped'\" \"'$tmpfile_scopes'\"
    ' _" "$tmpfile_results" "$tmpfile_count"
  
  rm -f "$tmpfile_unscoped" "$tmpfile_scoped" "$tmpfile_scopes" "$tmpfile_count"
  
  # Process results
  local found=0
  while IFS='|' read -r type desc location; do
    [[ -z "$type" ]] && continue
    ((found++))
    add_finding "$type" "$desc" "$location"
    echo "    [!] FOUND: $desc at $location"
  done < "$tmpfile_results"
  
  rm -f "$tmpfile_results"
  echo "[*] Scanned $total node_modules directories (found $found compromised packages)"
}

scan_npm_cache() {
  local cache_path="$1"
  [[ -n "$cache_path" && -d "$cache_path" ]] || { echo "[*] npm cache path not detected."; return; }
  [[ -z "$COMPROMISED_REGEX" ]] && return
  echo "[*] Scanning npm cache at: $cache_path"
  echo "[*] Searching for compromised packages in cache (parallel mode)..."
  
  local num_cores
  num_cores=$(sysctl -n hw.ncpu 2>/dev/null || echo 4)
  local parallel_jobs=$((num_cores * 2))
  
  local tmpfile_results="$(mktemp)"
  local tmpfile_count="$(mktemp)"
  local tmpfile_regex="$(mktemp)"
  echo "$COMPROMISED_REGEX" > "$tmpfile_regex"
  
  # Count total directories first
  local total_dirs
  total_dirs=$(find "$cache_path" -type d -print 2>/dev/null | wc -l | tr -d ' ')
  echo "[*] Scanning $total_dirs npm cache directories..."
  
  # Parallel scan with progress using helper
  find "$cache_path" -type d -print 2>/dev/null | \
    parallel_with_progress "Scanning npm cache" "$total_dirs" auto "bash -c '
      dir=\"\$1\"
      regex=\"$COMPROMISED_REGEX\"
      if [[ \"\$dir\" =~ \$regex ]]; then
        echo \"npm-cache|\${BASH_REMATCH[0]}|\$dir\"
      fi
    ' _" "$tmpfile_results" "$tmpfile_count"
  
  rm -f "$tmpfile_regex"
  
  # Process results
  local checked=0
  while IFS='|' read -r type desc location; do
    [[ -z "$type" ]] && continue
    ((checked++))
    add_finding "$type" "$desc" "$location"
    echo "    [!] FOUND in cache: $desc"
  done < "$tmpfile_results"
  
  local total_scanned
  total_scanned=$(wc -l < "$tmpfile_count" 2>/dev/null | tr -d ' ')
  rm -f "$tmpfile_results" "$tmpfile_count"
  echo "[*] Scanned $total_scanned npm cache directories (found $checked compromised packages)"
}

scan_malicious_files() {
  local mode="$1"; shift
  local roots=("$@")
  local files_checked=0
  echo "[*] Searching for ${#MALICIOUS_FILES[@]} known malicious file patterns..."
  for root in "${roots[@]}"; do
    [[ -d "$root" ]] || continue
    if [[ "$mode" == "quick" ]]; then
      for f in "${MALICIOUS_FILES[@]}"; do
        ((files_checked++))
        [[ -f "$root/$f" ]] && { add_finding "file-artifact" "$f" "$root/$f"; echo "    [!] FOUND: $f at $root"; }
        if [[ -d "$root/.github/workflows" && -f "$root/.github/workflows/$f" ]]; then
          add_finding "file-artifact" "$f" "$root/.github/workflows/$f"
          echo "    [!] FOUND: $f at $root/.github/workflows"
        fi
      done
    else
      while IFS= read -r -d '' fpath; do
        ((files_checked++))
        add_finding "file-artifact" "$(basename "$fpath")" "$fpath"
        echo "    [!] FOUND: $(basename "$fpath") at $(dirname "$fpath")"
      done < <(find "$root" -type f \( $(printf -- '-name %q -o ' "${MALICIOUS_FILES[@]}") -false \) -print0 2>/dev/null)
    fi
  done
  echo "[*] Scanned for malicious files (checked $files_checked locations)"
}

scan_git() {
  local mode="$1"; shift
  local roots=("$@")
  local repos_checked=0
  echo "[*] Searching for git repositories and analyzing branches/remotes..."
  
  local num_cores
  num_cores=$(sysctl -n hw.ncpu 2>/dev/null || echo 4)
  local parallel_jobs=$((num_cores * 2))
  
  for root in "${roots[@]}"; do
    [[ -d "$root" ]] || continue
    if [[ "$mode" == "quick" ]]; then
      local candidates=()
      [[ -d "$root/.git" ]] && candidates+=("$root/.git")
      local count=0
      for sub in "$root"/*; do
        [[ -d "$sub/.git" ]] && candidates+=("$sub/.git")
        ((count++)); [[ $count -ge 20 ]] && break
      done
      for gitdir in "${candidates[@]}"; do
        ((repos_checked++))
        local repo
        repo="$(dirname "$gitdir")"
        branches=$(git -C "$repo" branch -a 2>/dev/null || true)
        remotes=$(git -C "$repo" remote -v 2>/dev/null || true)
        for b in $branches; do
          for pat in "${SUSPICIOUS_BRANCH_PATTERNS[@]}"; do
            if [[ "$b" == *"$pat"* ]]; then
              add_finding "git-branch" "Branch: $b" "$repo"
            fi
          done
        done
        if [[ "$remotes" == *"Shai-Hulud"* ]]; then
          add_finding "git-remote" "Remote contains 'Shai-Hulud'" "$repo"
        fi
      done
    else
      local tmpfile_results="$(mktemp)"
      local tmpfile_count="$(mktemp)"
      
      # Count total git repos first
      local total_repos
      total_repos=$(find "$root" -type d -name .git -print 2>/dev/null | wc -l | tr -d ' ')
      echo "[*] Scanning $total_repos git repositories in parallel (using $parallel_jobs workers)..."
      
      # Parallel git repo scanning with progress using helper
      find "$root" -type d -name .git -print 2>/dev/null | \
        parallel_with_progress "Checking git repos" "$total_repos" 10 "check_git_repo" "$tmpfile_results" "$tmpfile_count"
      
      # Process results
      local found=0
      while IFS='|' read -r type desc location; do
        [[ -z "$type" ]] && continue
        ((found++))
        add_finding "$type" "$desc" "$location"
        echo "    [!] FOUND: $desc at $location"
      done < "$tmpfile_results"
      
      repos_checked=$(wc -l < "$tmpfile_count" 2>/dev/null | tr -d ' ')
      rm -f "$tmpfile_results" "$tmpfile_count"
    fi
  done
  echo "[*] Analyzed $repos_checked git repositories"
}

scan_workflows() {
  local roots=("$@")
  echo "[*] Searching for GitHub Actions workflow files..."
  
  local num_cores
  num_cores=$(sysctl -n hw.ncpu 2>/dev/null || echo 4)
  local parallel_jobs=$((num_cores * 2))
  
  local tmpfile_results="$(mktemp)"
  local tmpfile_patterns="$(mktemp)"
  local tmpfile_count="$(mktemp)"
  printf '%s\n' "${SUSPICIOUS_WORKFLOW_PATTERNS[@]}" > "$tmpfile_patterns"
  
  # Count total workflow files first
  local total_workflows=0
  for root in "${roots[@]}"; do
    [[ -d "$root" ]] || continue
    total_workflows=$((total_workflows + $(find "$root" -type d -path "*/.github/workflows" -exec find {} -maxdepth 1 -type f \( -name "*.yml" -o -name "*.yaml" \) -print \; 2>/dev/null | wc -l | tr -d ' ')))
  done
  echo "[*] Scanning $total_workflows workflow files in parallel (using $parallel_jobs workers)..."
  
  for root in "${roots[@]}"; do
    [[ -d "$root" ]] || continue
    
    # Find all workflow files and scan in parallel with progress using helper
    find "$root" -type d -path "*/.github/workflows" -exec find {} -maxdepth 1 -type f \( -name "*.yml" -o -name "*.yaml" \) -print \; 2>/dev/null | \
      parallel_with_progress "Scanning workflows" "$total_workflows" 10 "bash -c 'check_workflow_file \"\$1\" \"$tmpfile_patterns\"' _" "$tmpfile_results" "$tmpfile_count"
  done
  
  rm -f "$tmpfile_patterns"
  
  # Process results
  local found=0
  while IFS='|' read -r type desc location; do
    [[ -z "$type" ]] && continue
    ((found++))
    add_finding "$type" "$desc" "$location"
    echo "    [!] SUSPICIOUS workflow: $location"
  done < "$tmpfile_results"
  
  local scanned
  scanned=$(wc -l < "$tmpfile_count" 2>/dev/null | tr -d ' ')
  rm -f "$tmpfile_results" "$tmpfile_count"
  echo "[*] Scanned $scanned workflow files (found $found suspicious workflows)"
}

scan_credentials() {
  local mode="$1"; shift
  local roots=("$@")
  local found=0
  
  # Count total credential paths to check
  local total_creds=$((${#roots[@]} * ${#CLOUD_CREDENTIAL_PATHS[@]}))
  echo "[*] Checking for exposed cloud credentials and .env files..."
  echo "[*] Scanning ${#CLOUD_CREDENTIAL_PATHS[@]} credential paths across ${#roots[@]} root(s)"
  
  local checked=0
  for root in "${roots[@]}"; do
    [[ -d "$root" ]] || continue
    for cred in "${CLOUD_CREDENTIAL_PATHS[@]}"; do
      ((checked++))
      if (( checked % 5 == 0 )) || (( checked == total_creds )); then
        printf "\r[*] Checking credentials: %d/%d paths..." "$checked" "$total_creds" >&2
      fi
      local path="$root/$cred"
      if [[ -e "$path" ]]; then
        add_finding "credential-file" "$cred" "$path"
        ((found++))
      fi
    done
  done
  printf "\n" >&2
  
  if [[ "$mode" == "full" ]]; then
    local tmpfile_results="$(mktemp)"
    local tmpfile_count="$(mktemp)"
    
    # Count total .env files
    local total_env=0
    for root in "${roots[@]}"; do
      [[ -d "$root" ]] || continue
      total_env=$((total_env + $(find "$root" -type f -name ".env*" ! -path "*/node_modules/*" -print 2>/dev/null | wc -l | tr -d ' ')))
    done
    
    if [[ $total_env -gt 0 ]]; then
      echo "[*] Found $total_env .env files to check"
      
      for root in "${roots[@]}"; do
        [[ -d "$root" ]] || continue
        find "$root" -type f -name ".env*" ! -path "*/node_modules/*" -print 2>/dev/null | \
          parallel_with_progress "Checking .env files" "$total_env" auto "echo" "$tmpfile_results" "$tmpfile_count"
      done
      
      while IFS= read -r envfile; do
        [[ -n "$envfile" ]] || continue
        add_finding "credential-file" ".env file" "$envfile"
        ((found++))
      done < "$tmpfile_results"
      
      rm -f "$tmpfile_results" "$tmpfile_count"
    fi
  else
    for root in "${roots[@]}"; do
      [[ -d "$root" ]] || continue
      if [[ -f "$root/.env" ]]; then
        add_finding "credential-file" ".env file" "$root/.env"
        ((found++))
      fi
    done
  fi
  
  echo "[*] Found $found credential files"
}

scan_runners() {
  local roots=("$@")
  local tmpfile="$(mktemp)" || { echo "[ERROR] Failed to create temp file" >&2; return 1; }
  local checked=0
  for root in "${roots[@]}"; do
    [[ -d "$root" ]] || continue
    find "$root" -type d \( -name "actions-runner" -o -name "_work" -o -name "*runner*" \) -print0 2>/dev/null > "$tmpfile" || true
    while IFS= read -r -d '' dir; do
      ((checked++))
      local runner="$dir/.runner"
      if [[ -f "$runner" ]]; then
        if grep -q "SHA1HULUD" "$runner" 2>/dev/null; then
          add_finding "malicious-runner" "Malicious self-hosted runner 'SHA1HULUD'" "$dir"
          echo "    [!] CRITICAL: Malicious runner at $dir"
        else
          add_finding "runner-installation" "Self-hosted runner installation (verify legitimacy)" "$dir"
        fi
      fi
    done < "$tmpfile"
  done
  rm -f "$tmpfile"
  echo "[*] Checked $checked runner directories"
}

scan_hooks() {
  local mode="$1"; shift
  local roots=("$@")
  local total_checked=0
  echo "[*] Analyzing package.json files for suspicious npm lifecycle hooks..."
  echo "[*] Checking: preinstall, postinstall, install, prepare hooks"
  
  for root in "${roots[@]}"; do
    [[ -d "$root" ]] || continue
    if [[ "$mode" == "quick" ]]; then
      local pkg="$root/package.json"
      if [[ -f "$pkg" ]]; then
        echo "[*] Checking: $pkg"
        ((total_checked++))
        while IFS='|' read -r hook pat content; do
          [[ -z "$hook" ]] && continue
          add_finding "postinstall-hook" "Suspicious $hook: $pat" "$pkg"
          echo "    [!] FOUND: Suspicious $hook in $(basename "$(dirname "$pkg")")"
          printf '    Hook content: %s\n' "$content"
        done <<<"$(python3 - "$pkg" "${SUSPICIOUS_HOOK_PATTERNS[@]}" 2>/dev/null <<'PY'
import json, sys
pkg = sys.argv[1]
pats = sys.argv[2:]
try:
    data = json.load(open(pkg, "r", encoding="utf-8"))
except Exception:
    sys.exit(0)
scripts = data.get("scripts") or {}
for hook in ("postinstall","preinstall","install","prepare"):
    val = scripts.get(hook)
    if not isinstance(val, str):
        continue
    for pat in pats:
        if pat in val:
            print(f"{hook}|{pat}|{val}")
            sys.exit(0)
PY
)"
      fi
    else
      # Parallel processing for full mode
      local tmpfile_results="$(mktemp)"
      local tmpfile_count="$(mktemp)"
      local tmpfile_patterns="$(mktemp)"
      printf '%s\n' "${SUSPICIOUS_HOOK_PATTERNS[@]}" > "$tmpfile_patterns"
      
      # Count total package.json files first
      local total_hooks
      total_hooks=$(find "$root" -type f -name "package.json" ! -path "*/node_modules/*/node_modules/*" -print 2>/dev/null | wc -l | tr -d ' ')
      echo "[*] Scanning $total_hooks package.json files in parallel..."
      
      # Use parallel_with_progress helper
      find "$root" -type f -name "package.json" ! -path "*/node_modules/*/node_modules/*" -print 2>/dev/null | \
        parallel_with_progress "Checking package hooks" "$total_hooks" auto "check_package_hooks \"\$1\" \"$tmpfile_patterns\"" "$tmpfile_results" "$tmpfile_count"
      
      rm -f "$tmpfile_patterns"
      
      local scanned_count=$(wc -l < "$tmpfile_count" 2>/dev/null | tr -d ' ')
      
      # Process results
      local found=0
      while IFS='|' read -r hook pat content pkg; do
        [[ -z "$hook" ]] && continue
        ((found++))
        add_finding "postinstall-hook" "Suspicious $hook: $pat" "$pkg"
        echo "    [!] FOUND: Suspicious $hook in $(basename "$(dirname "$pkg")")"
        printf '    Hook content: %s\n' "$content"
      done < "$tmpfile_results"
      
      total_checked=$scanned_count
      rm -f "$tmpfile_results" "$tmpfile_count"
      echo "[*] Checked $scanned_count package.json files for suspicious hooks (found $found suspicious hooks)"
      unset SUSPICIOUS_HOOK_PATTERNS_STR
    fi
  done
  echo "[*] Checked $total_checked package.json files for suspicious hooks"
}

# Worker function for parallel node_modules checking
check_node_modules_dir() {
  local nm="$1"
  local unscoped_file="$2"
  local scoped_file="$3"
  local scopes_file="$4"
  
  [[ -d "$nm" ]] || return 0
  
  # Check each package in this node_modules directory
  find "$nm" -mindepth 1 -maxdepth 1 -type d -print0 2>/dev/null | while IFS= read -r -d '' child; do
    local name
    name="$(basename "$child")"
    
    if [[ "$name" == @* ]]; then
      # Scoped package - check if scope is in our list
      if grep -Fxq "$name" "$scopes_file" 2>/dev/null; then
        # Check each package under this scope
        find "$child" -mindepth 1 -maxdepth 1 -type d -print0 2>/dev/null | while IFS= read -r -d '' pkgdir; do
          local pkgname
          pkgname="$(basename "$pkgdir")"
          local key="$name|$pkgname"
          if grep -Fxq "$key" "$scoped_file" 2>/dev/null; then
            echo "node_modules|$name/$pkgname|$pkgdir"
          fi
        done
      fi
    else
      # Unscoped package
      if grep -Fxq "$name" "$unscoped_file" 2>/dev/null; then
        echo "node_modules|$name|$child"
      fi
    fi
  done
}
export -f check_node_modules_dir

# Worker function for parallel hash checking
check_file_hash() {
  local file="$1"
  
  # Skip files that are part of the scanner itself
  if head -n 10 "$file" 2>/dev/null | grep -q "SHAI_HULUD_SCANNER_SAFE"; then
    return 0
  fi
  
  local sha256
  sha256=$(shasum -a 256 "$file" 2>/dev/null | awk '{print $1}')
  local desc
  if desc=$(check_mal_sha256 "$sha256"); then
    echo "malware-hash|SHA256 match: $desc|$file"
    return 0
  fi
  
  local sha1
  sha1=$(shasum -a 1 "$file" 2>/dev/null | awk '{print $1}')
  if desc=$(check_mal_sha1 "$sha1"); then
    echo "malware-hash|SHA1 match: $desc|$file"
  fi
}

# Worker function for parallel git repository checking
check_git_repo() {
  local gitdir="$1"
  local repo
  repo="$(dirname "$gitdir")"
  local branches
  branches=$(git -C "$repo" branch -a 2>/dev/null || true)
  local remotes
  remotes=$(git -C "$repo" remote -v 2>/dev/null || true)
  
  for b in $branches; do
    for pat in shai-hulud shai_hulud SHA1HULUD; do
      if [[ "$b" == *"$pat"* ]]; then
        echo "git-branch|Branch: $b|$repo"
        return 0
      fi
    done
  done
  
  if [[ "$remotes" == *"Shai-Hulud"* ]]; then
    echo "git-remote|Remote contains 'Shai-Hulud'|$repo"
  fi
}

# Worker function for parallel workflow checking
check_workflow_file() {
  local wf="$1"
  local patterns_file="$2"
  local base
  base="$(basename "$wf")"
  
  if [[ "$base" =~ ^formatter_[0-9]+\.yml$ ]]; then
    echo "workflow-pattern|Suspicious workflow name: $base|$wf"
  fi
  
  local content
  content="$(cat "$wf" 2>/dev/null || true)"
  while IFS= read -r pat; do
    [[ -z "$pat" ]] && continue
    if [[ "$content" == *"$pat"* ]]; then
      echo "workflow-content|Workflow contains: $pat|$wf"
      return 0
    fi
  done < "$patterns_file"
}

# Worker function for parallel npm cache checking  
check_npm_cache_dir() {
  local dir="$1"
  local regex="$2"
  if [[ "$dir" =~ $regex ]]; then
    echo "npm-cache|${BASH_REMATCH[0]}|$dir"
  fi
}

# Worker function for parallel package.json hooks checking
check_package_hooks() {
  local pkg="$1"
  local patterns_file="$2"
  python3 - "$pkg" "$patterns_file" 2>/dev/null <<'PY'
import json, sys, pathlib
pkg = pathlib.Path(sys.argv[1])
patterns_file = sys.argv[2]
with open(patterns_file, "r") as f:
    pats = [line.strip() for line in f if line.strip()]
try:
    data = json.load(open(pkg, "r", encoding="utf-8"))
except Exception:
    sys.exit(0)
scripts = data.get("scripts") or {}
for hook in ("postinstall","preinstall","install","prepare"):
    val = scripts.get(hook)
    if not isinstance(val, str):
        continue
    for pat in pats:
        if pat in val:
            print(f"{hook}|{pat}|{val}|{pkg}")
            sys.exit(0)
PY
}

export -f check_file_hash check_mal_sha256 check_mal_sha1 check_package_hooks
export -f check_git_repo check_workflow_file check_npm_cache_dir

# Parallel processing helper with progress tracking and pv support
# Processes stdin (newline-separated items), shows progress, executes worker in parallel
# Usage: parallel_with_progress <description> <total_count> <update_freq> <worker_function> <tmpfile_results> <tmpfile_count>
parallel_with_progress() {
  local description="$1"
  local total_count="$2"
  local update_freq="$3"
  local worker_function="$4"
  local tmpfile_results="$5"
  local tmpfile_count="$6"
  
  local num_cores
  num_cores=$(sysctl -n hw.ncpu 2>/dev/null || echo 4)
  local parallel_jobs=$((num_cores * 2))
  
  # Use core count as update frequency if passed as 'auto'
  if [[ "$update_freq" == "auto" ]]; then
    update_freq=$num_cores
  fi
  
  # Check if pv is available for better progress display (check common locations for sudo compatibility)
  local pv_cmd=""
  if command -v pv >/dev/null 2>&1; then
    pv_cmd="pv"
  elif [[ -x /opt/homebrew/bin/pv ]]; then
    pv_cmd="/opt/homebrew/bin/pv"
  elif [[ -x /usr/local/bin/pv ]]; then
    pv_cmd="/usr/local/bin/pv"
  fi
  
  if [[ -n "$pv_cmd" ]] && [[ $total_count -gt 0 ]]; then
    # Use pv for clean progress bars with ETA
    "$pv_cmd" -l -s "$total_count" -N "$description" 2>&2 | \
      xargs -n 1 -P "$parallel_jobs" -I {} bash -c "$worker_function"' "$@"' _ {} >> "$tmpfile_results" 2>/dev/null &
    local xargs_pid=$!
    BG_PIDS+=("$xargs_pid")
    wait "$xargs_pid" 2>/dev/null || true
  else
    # Fallback to manual progress tracking with while loop
    while IFS= read -r item; do
      local count
      count=$(wc -l < "$tmpfile_count" 2>/dev/null | tr -d ' ' || echo 0)
      if (( count % update_freq == 0 )) || (( count == total_count )); then
        printf "\r[*] %s: %d/%d..." "$description" "$count" "$total_count" 2>/dev/null >&2 || true
      fi
      printf '%s\0' "$item"
    done 2>/dev/null | \
      xargs -0 -n 1 -P "$parallel_jobs" bash -c '
        '"$worker_function"' "$1"
        echo "1" >> "'"$tmpfile_count"'"
      ' _ {} >> "$tmpfile_results" 2>/dev/null &
    local xargs_pid=$!
    BG_PIDS+=("$xargs_pid")
    wait "$xargs_pid" 2>/dev/null || true
    printf "\n" 2>/dev/null >&2 || true
  fi
}

scan_hashes() {
  local mode="$1"; shift
  local roots=("$@")
  
  local num_cores
  num_cores=$(sysctl -n hw.ncpu 2>/dev/null || echo 4)
  local parallel_jobs=$((num_cores * 2))
  
  echo "[*] Using $parallel_jobs parallel workers for hash scanning"
  
  local tmpfile_results="$(mktemp)"
  local tmpfile_count="$(mktemp)"
  
  for root in "${roots[@]}"; do
    [[ -d "$root" ]] || continue
    if [[ "$mode" == "quick" ]]; then
      # Count total files first
      local total_quick
      total_quick=$(find "$root" \( -path "*/node_modules/*/node_modules/*" -prune \) -o -type f \( $(printf -- '-name %q -o ' "${SUSPICIOUS_NAMES[@]}") -false \) -print 2>/dev/null | wc -l | tr -d ' ')
      echo "[*] Found $total_quick suspicious files to hash"
      
      find "$root" \( -path "*/node_modules/*/node_modules/*" -prune \) -o -type f \( $(printf -- '-name %q -o ' "${SUSPICIOUS_NAMES[@]}") -false \) -print 2>/dev/null | \
        parallel_with_progress "Hashing files" "$total_quick" auto "check_file_hash" "$tmpfile_results" "$tmpfile_count"
    else
      # Count total files first
      local total_full
      total_full=$(find "$root" \( -path "*/node_modules/*" -o -name "*.d.ts" \) -prune -false -o -type f \( -name "*.js" -o -name "*.ts" \) -print 2>/dev/null | wc -l | tr -d ' ')
      echo "[*] Found $total_full JS/TS files to hash"
      
      find "$root" \( -path "*/node_modules/*" -o -name "*.d.ts" \) -prune -false -o -type f \( -name "*.js" -o -name "*.ts" \) -print 2>/dev/null | \
        parallel_with_progress "Hashing files" "$total_full" auto "check_file_hash" "$tmpfile_results" "$tmpfile_count"
    fi
  done
  
  # Process results
  local found=0
  while IFS='|' read -r type desc location; do
    if [[ -n "$type" ]]; then
      add_finding "$type" "$desc" "$location"
      echo "    [!!!] MALWARE DETECTED: $location"
      ((found++))
    fi
  done < "$tmpfile_results"
  
  local total_files
  total_files=$(wc -l < "$tmpfile_count" 2>/dev/null | tr -d ' ')
  echo "[*] Hashed $total_files files for malware detection (found $found malicious files)"
  
  rm -f "$tmpfile_results" "$tmpfile_count"
}

scan_migration_suffix() {
  local roots=("$@")
  echo "[*] Checking for migration attack patterns..."
  
  local num_cores
  num_cores=$(sysctl -n hw.ncpu 2>/dev/null || echo 4)
  local parallel_jobs=$((num_cores * 2))
  
  local tmpfile_results="$(mktemp)"
  local checked=0
  
  for root in "${roots[@]}"; do
    [[ -d "$root" ]] || continue
    
    # Check git repos in parallel
    find "$root" -type d -name .git -print0 2>/dev/null | \
      xargs -0 -n 1 -P "$parallel_jobs" bash -c '
        gitdir="$1"
        repo="$(dirname "$gitdir")"
        remotes=$(git -C "$repo" remote -v 2>/dev/null || true)
        if echo "$remotes" | grep -qi "\-migration"; then
          echo "migration-attack|Remote URL contains '\''-migration'\''|$repo"
        fi
      ' _ {} >> "$tmpfile_results"
    
    # Check directories
    find "$root" -type d -name "*-migration" -print0 2>/dev/null | \
      xargs -0 -n 1 -P "$parallel_jobs" bash -c '
        dir="$1"
        echo "migration-attack|Directory ends with -migration|$dir"
      ' _ {} >> "$tmpfile_results"
  done
  
  # Process results
  while IFS='|' read -r type desc location; do
    [[ -z "$type" ]] && continue
    ((checked++))
    add_finding "$type" "$desc" "$location"
    echo "    [!] FOUND: $desc at $location"
  done < "$tmpfile_results"
  
  rm -f "$tmpfile_results"
  echo "[*] Checked for migration attacks (found $checked indicators)"
}

scan_trufflehog() {
  local mode="$1"; shift
  local roots=("$@")
  if command -v trufflehog >/dev/null 2>&1; then
    add_finding "trufflehog-installation" "TruffleHog in PATH" "$(command -v trufflehog)"
  fi
  if [[ "$mode" == "full" ]]; then
    for root in "${roots[@]}"; do
      [[ -d "$root" ]] || continue
      while IFS= read -r -d '' tf; do
        add_finding "trufflehog-installation" "TruffleHog binary" "$tf"
      done < <(find "$root" -type f -regex ".*trufflehog(\.exe)?$" -print0 2>/dev/null)
      while IFS= read -r -d '' pkg; do
        if grep -qi "trufflehog" "$pkg" 2>/dev/null; then
          add_finding "trufflehog-reference" "package.json references trufflehog" "$pkg"
        fi
      done < <(find "$root" -type f -name "package.json" ! -path "*/node_modules/*/node_modules/*" -print0 2>/dev/null)
    done
  fi
}

# Worker function for env pattern checking
check_env_patterns() {
  local file="$1"
  local known_iocs='webhook\.site|bb8ca5f6-4175-45d2-b042-fc9ebb8170b7'
  local sensitive_env='AWS_ACCESS_KEY|AWS_SECRET|GITHUB_TOKEN|NPM_TOKEN|GH_TOKEN|AZURE_'
  local generic_env='process\.env|os\.environ|\$env:'
  local exfil_funcs='fetch\s*\(|axios\.|http\.request|https\.request'
  local exfil_keywords='exfiltrat'
  
  local content
  content="$(cat "$file" 2>/dev/null || true)"
  [[ -z "$content" ]] && return 0
  
  # CRITICAL: Known Shai-Hulud IOCs
  if echo "$content" | grep -Eiq "$known_iocs"; then
    echo "malware-ioc|CRITICAL: Known Shai-Hulud IOC detected|$file"
    return 0
  fi
  
  # HIGH: Sensitive credentials + exfil patterns
  if echo "$content" | grep -Eiq "$sensitive_env"; then
    if echo "$content" | grep -Eiq "$exfil_funcs|$exfil_keywords"; then
      echo "credential-exfil|HIGH: Sensitive credential access + exfil pattern|$file"
      return 0
    fi
  fi
  
  # LOW: Generic env access + generic fetch
  if echo "$content" | grep -Eiq "$generic_env" && echo "$content" | grep -Eiq "$exfil_funcs"; then
    echo "env-access-low|LOW: Generic env access + network call (likely benign)|$file"
  fi
}

export -f check_env_patterns

scan_env_patterns() {
  local roots=("$@")
  local num_cores
  num_cores=$(sysctl -n hw.ncpu 2>/dev/null || echo 4)
  local parallel_jobs=$((num_cores * 2))
  
  local tmpfile_list="$(mktemp)" || { echo "[ERROR] Failed to create temp file" >&2; return 1; }
  local tmpfile_results="$(mktemp)"
  local tmpfile_count="$(mktemp)"
  local critical_count=0
  local high_count=0
  local low_count=0
  
  # Count total files to scan first
  local total_files=0
  for root in "${roots[@]}"; do
    [[ -d "$root" ]] || continue
    total_files=$((total_files + $(find "$root" \( -path "*/node_modules/*" -o -name "*.d.ts" \) -prune -false -o -type f \( -name "*.js" -o -name "*.ts" -o -name "*.py" -o -name "*.sh" -o -name "*.ps1" \) -print 2>/dev/null | wc -l | tr -d ' ')))
  done
  echo "[*] Scanning $total_files code files for env+exfil patterns (using $parallel_jobs workers)"
  
  for root in "${roots[@]}"; do
    [[ -d "$root" ]] || continue
    find "$root" \( -path "*/node_modules/*" -o -name "*.d.ts" \) -prune -false -o -type f \( -name "*.js" -o -name "*.ts" -o -name "*.py" -o -name "*.sh" -o -name "*.ps1" \) -print 2>/dev/null | \
      parallel_with_progress "Scanning for env patterns" "$total_files" auto "check_env_patterns" "$tmpfile_results" "$tmpfile_count"
  done
  
  # Process results
  local scanned=0
  while IFS='|' read -r type desc location; do
    [[ -z "$type" ]] && continue
    ((scanned++))
    add_finding "$type" "$desc" "$location"
    
    case "$type" in
      malware-ioc)
        echo "    [!!!] CRITICAL: Shai-Hulud IOC found: $location"
        ((critical_count++))
        ;;
      credential-exfil)
        echo "    [!!] HIGH: Credential exfil pattern: $location"
        ((high_count++))
        ;;
      env-access-low)
        ((low_count++))
        ;;
    esac
  done < "$tmpfile_results"
  
  local total_scanned
  total_scanned=$(wc -l < "$tmpfile_count" 2>/dev/null | tr -d ' ')
  rm -f "$tmpfile_list" "$tmpfile_results" "$tmpfile_count"
  
  echo "[*] Scanned $total_scanned code files for suspicious patterns (found $scanned issues)"
  if [[ $critical_count -gt 0 ]]; then
    echo "    [!!!] CRITICAL: $critical_count file(s) with known Shai-Hulud IOCs"
  fi
  if [[ $high_count -gt 0 ]]; then
    echo "    [!!] HIGH: $high_count file(s) with credential exfiltration patterns"
  fi
  if [[ $low_count -gt 0 ]]; then
    echo "    [·] LOW: $low_count file(s) with generic env access (logged in report)"
  fi
}

main() {
  local start_ts
  start_ts=$(date +%s)

  # Initialize report file immediately
  {
    echo "Shai-Hulud Dynamic Detection Report"
    echo "Timestamp: $(date -u "+%Y-%m-%d %H:%M:%SZ")"
    echo "Scan Mode: $(echo "$SCAN_MODE" | tr '[:lower:]' '[:upper:]')"
    echo "Paths Scanned: ${ROOTS[*]}"
    echo "Status: SCAN IN PROGRESS"
    echo ""
    echo "=== FINDINGS ==="
    echo ""
  } > "$REPORT_PATH"
  echo "[*] Report initialized at: $REPORT_PATH"

  print_banner
  echo ""
  echo "============================================"
  echo " Shai-Hulud Dynamic Detection (macOS)"
  echo "============================================"
  echo "[*] Scan Mode: $(echo "$SCAN_MODE" | tr '[:lower:]' '[:upper:]')"
  echo ""

  # Check for resume
  local last_checkpoint="$(get_last_checkpoint)"
  if [[ -n "$last_checkpoint" ]]; then
    echo ""
    echo "[RESUME] Detected previous incomplete scan, resuming from checkpoint: $last_checkpoint"
    echo "[RESUME] Cache TTL: ${CACHE_TTL}s (5 minutes)"
    echo ""
  fi

  log_section "Loading compromised package lists"
  load_compromised_packages
  if [[ ${#COMP_UNSCOPED[@]} -eq 0 && ${#COMP_SCOPED[@]} -eq 0 ]]; then
    echo "[!] No compromised packages loaded. Package-based checks will be limited."
  fi

  log_section "Finding node_modules directories"
  if should_skip_step "node_modules_find"; then
    local cache_file="$(get_cache_file "node_modules_dirs_${SCAN_MODE}")"
    if [[ -f "$cache_file" && -s "$cache_file" ]]; then
      echo "[RESUME] Loading cached node_modules directories"
      NM_DIRS=()
      while IFS= read -r line; do
        NM_DIRS+=("$line")
      done < "$cache_file"
    else
      echo "[WARNING] Cache file missing or empty, re-scanning" >&2
      NM_DIRS=()
      while IFS= read -r line; do
        NM_DIRS+=("$line")
      done < <(find_node_modules "$SCAN_MODE" "${ROOTS[@]}")
      save_checkpoint "node_modules_find"
    fi
  else
    NM_DIRS=()
    while IFS= read -r line; do
      NM_DIRS+=("$line")
    done < <(find_node_modules "$SCAN_MODE" "${ROOTS[@]}")
    save_checkpoint "node_modules_find"
  fi
  echo "[*] Found ${#NM_DIRS[@]} node_modules directories."

  local npm_cache=""
  if [[ "$SCAN_MODE" == "full" ]]; then
    if npm_cmd=$(command -v npm 2>/dev/null); then
      npm_cache="$(npm config get cache 2>/dev/null || true)"
    fi
    [[ -z "$npm_cache" ]] && npm_cache="$HOME/.npm"
  fi

  log_section "Scanning for malicious packages in node_modules"
  if ! should_skip_step "node_modules_scan"; then
    if [[ ${#NM_DIRS[@]} -gt 0 && ( ${#COMP_UNSCOPED[@]} -gt 0 || ${#COMP_SCOPED[@]} -gt 0 ) ]]; then
      if scan_node_modules "${NM_DIRS[@]}"; then
        save_checkpoint "node_modules_scan"
      else
        echo "[ERROR] node_modules scan failed" >&2
      fi
    else
      echo "[-] Skipping node_modules package scan (no packages or dirs)."
      save_checkpoint "node_modules_scan"
    fi
  else
    echo "[RESUME] Skipping node_modules scan (already completed)"
  fi

  if [[ "$SCAN_MODE" == "full" ]]; then
    log_section "Scanning npm cache for compromised packages"
    if ! should_skip_step "npm_cache"; then
      if [[ -n "$npm_cache" ]]; then
        if scan_npm_cache "$npm_cache"; then
          save_checkpoint "npm_cache"
        else
          echo "[ERROR] npm cache scan failed" >&2
        fi
      else
        echo "[-] Skipping npm cache scan (no cache path)."
        save_checkpoint "npm_cache"
      fi
    else
      echo "[RESUME] Skipping npm cache scan (already completed)"
    fi
  else
    echo "[Quick] Skipping npm cache scan (use --mode full)"
  fi

  log_section "Scanning for known Shai-Hulud artifact files"
  if ! should_skip_step "malicious_files"; then
    if scan_malicious_files "$SCAN_MODE" "${ROOTS[@]}"; then
      save_checkpoint "malicious_files"
    else
      echo "[ERROR] malicious files scan failed" >&2
    fi
  else
    echo "[RESUME] Skipping malicious files scan (already completed)"
  fi

  log_section "Scanning for suspicious git branches and remotes"
  if ! should_skip_step "git"; then
    if scan_git "$SCAN_MODE" "${ROOTS[@]}"; then
      save_checkpoint "git"
    else
      echo "[ERROR] git scan failed" >&2
    fi
  else
    echo "[RESUME] Skipping git scan (already completed)"
  fi

  log_section "Scanning GitHub Actions workflows"
  if ! should_skip_step "workflows"; then
    if scan_workflows "${ROOTS[@]}"; then
      save_checkpoint "workflows"
    else
      echo "[ERROR] workflows scan failed" >&2
    fi
  else
    echo "[RESUME] Skipping workflows scan (already completed)"
  fi

  log_section "Checking cloud credential files"
  if ! should_skip_step "credentials"; then
    if scan_credentials "$SCAN_MODE" "${ROOTS[@]}"; then
      save_checkpoint "credentials"
    else
      echo "[ERROR] credentials check failed" >&2
    fi
  else
    echo "[RESUME] Skipping credentials check (already completed)"
  fi

  if [[ "$SCAN_MODE" == "full" ]]; then
    log_section "Checking for self-hosted runners"
    if ! should_skip_step "runners"; then
      if scan_runners "${ROOTS[@]}"; then
        save_checkpoint "runners"
      else
        echo "[ERROR] runners check failed" >&2
      fi
    else
      echo "[RESUME] Skipping runners check (already completed)"
    fi
  else
    echo "[Quick] Skipping self-hosted runner scan (use --mode full)"
  fi

  log_section "Scanning npm lifecycle hooks"
  if ! should_skip_step "hooks"; then
    if scan_hooks "$SCAN_MODE" "${ROOTS[@]}"; then
      save_checkpoint "hooks"
    else
      echo "[ERROR] hooks scan failed" >&2
    fi
  else
    echo "[RESUME] Skipping hooks scan (already completed)"
  fi

  log_section "Hash-based malware detection"
  if ! should_skip_step "hashes"; then
    if scan_hashes "$SCAN_MODE" "${ROOTS[@]}"; then
      save_checkpoint "hashes"
    else
      echo "[ERROR] hash detection failed" >&2
    fi
  else
    echo "[RESUME] Skipping hash detection (already completed)"
  fi

  if [[ "$SCAN_MODE" == "full" ]]; then
    log_section "Checking for migration suffix attack"
    if ! should_skip_step "migration"; then
      if scan_migration_suffix "${ROOTS[@]}"; then
        save_checkpoint "migration"
      else
        echo "[ERROR] migration check failed" >&2
      fi
    else
      echo "[RESUME] Skipping migration check (already completed)"
    fi
  else
    echo "[Quick] Skipping migration suffix scan (use --mode full)"
  fi

  log_section "Checking for TruffleHog installation"
  if ! should_skip_step "trufflehog"; then
    if scan_trufflehog "$SCAN_MODE" "${ROOTS[@]}"; then
      save_checkpoint "trufflehog"
    else
      echo "[ERROR] TruffleHog check failed" >&2
    fi
  else
    echo "[RESUME] Skipping TruffleHog check (already completed)"
  fi

  if [[ "$SCAN_MODE" == "full" ]]; then
    log_section "Scanning for suspicious env+exfil patterns"
    if ! should_skip_step "env_patterns"; then
      if scan_env_patterns "${ROOTS[@]}"; then
        save_checkpoint "env_patterns"
      else
        echo "[ERROR] env patterns scan failed" >&2
      fi
    else
      echo "[RESUME] Skipping env patterns scan (already completed)"
    fi
  else
    echo "[Quick] Skipping env+exfil pattern scan (use --mode full)"
  fi

  # Mark scan as complete
  save_checkpoint "scan_complete"

  local end_ts
  end_ts=$(date +%s)
  local duration=$(( end_ts - start_ts ))

  log_section "Summary"
  echo "[*] Scan completed in ${duration}s ($(echo "$SCAN_MODE" | tr '[:lower:]' '[:upper:]') mode)"
  if [[ ${#FINDING_LIST[@]} -eq 0 ]]; then
    echo "[OK] No indicators of Shai-Hulud compromise were found in the scanned locations."
  else
    echo "[!!!] POTENTIAL INDICATORS OF COMPROMISE FOUND: ${#FINDING_LIST[@]} item(s)"
    for f in "${FINDING_LIST[@]}"; do
      IFS='|' read -r t ind loc <<<"$f"
      printf "%-18s %-40s %s\n" "$t" "$ind" "$loc"
    done
  fi

  echo ""
  echo "[*] Updating final report summary: $REPORT_PATH"
  # Update report with final summary
  {
    echo ""
    echo "=== SCAN SUMMARY ==="
    echo ""
    echo "Status: COMPLETED SUCCESSFULLY"
    echo "Scan Duration: ${duration}s"
    echo "Compromised packages loaded: $(( ${#COMP_UNSCOPED[@]} + ${#COMP_SCOPED[@]} ))"
    echo "Total indicators found: ${#FINDING_LIST[@]}"
    echo ""
    if [[ ${#FINDING_LIST[@]} -eq 0 ]]; then
      echo "No indicators of compromise found in scanned locations."
    else
      echo "Review findings above for details."
      echo ""
      echo "=== FINDINGS BY CATEGORY ==="
      echo ""
      
      # Categorize findings
      local critical_findings=()
      local high_findings=()
      local medium_findings=()
      local low_findings=()
      
      for f in "${FINDING_LIST[@]}"; do
        IFS='|' read -r t ind loc <<<"$f"
        if [[ "$ind" == "CRITICAL:"* ]] || [[ "$t" == "malware-hash" ]] || [[ "$t" == "malware-ioc" ]]; then
          critical_findings+=("$loc")
        elif [[ "$ind" == "HIGH:"* ]] || [[ "$t" == "credential-exfil" ]]; then
          high_findings+=("$loc")
        elif [[ "$ind" == "LOW:"* ]] || [[ "$t" == "env-access-low" ]]; then
          low_findings+=("$loc")
        else
          medium_findings+=("$loc")
        fi
      done
      
      if [[ ${#critical_findings[@]} -gt 0 ]]; then
        echo "CRITICAL FINDINGS (${#critical_findings[@]}):"
        printf '%s\n' "${critical_findings[@]}" | sort -u
        echo ""
      fi
      
      if [[ ${#high_findings[@]} -gt 0 ]]; then
        echo "HIGH SEVERITY FINDINGS (${#high_findings[@]}):"
        printf '%s\n' "${high_findings[@]}" | sort -u
        echo ""
      fi
      
      if [[ ${#medium_findings[@]} -gt 0 ]]; then
        echo "MEDIUM/SUSPICIOUS FINDINGS (${#medium_findings[@]}):"
        printf '%s\n' "${medium_findings[@]}" | sort -u
        echo ""
      fi
      
      if [[ ${#low_findings[@]} -gt 0 ]]; then
        echo "LOW SEVERITY / INFORMATIONAL (${#low_findings[@]}):"
        printf '%s\n' "${low_findings[@]}" | sort -u
        echo ""
      fi
    fi
  } >> "$REPORT_PATH"
  echo "[*] Report finalized successfully."
  
  # Clear checkpoint on successful completion
  clear_checkpoint
  echo "[*] Checkpoint cleared - scan completed successfully"
  
  echo ""
  echo "============================================"
  echo " ✓ SCAN COMPLETED SUCCESSFULLY"
  echo "============================================"
  if [[ ${#FINDING_LIST[@]} -eq 0 ]]; then
    echo -e "\033[32m[✓] No threats detected - system appears clean\033[0m"
  else
    echo -e "\033[31m[!] ${#FINDING_LIST[@]} potential indicators found - review report\033[0m"
  fi
  echo "[*] Full report available at: $REPORT_PATH"
  echo "[*] Cache directory: $CACHE_DIR (TTL: ${CACHE_TTL}s)"
  echo "============================================"
  echo ""
}

main "$@"
