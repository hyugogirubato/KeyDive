#!/system/bin/sh

# ==UserScript==
# @name         mkshrc
# @namespace    https://github.com/hyugogirubato/KeyDive
# @version      0.1
# @description  null
# @author       hyugogirubato
# @match        Android
# ==/UserScript==


# Set hostname based on device serial number
export HOSTNAME=$(getprop ro.boot.serialno)

# Determine if the script is running as root
export USER=$(id -u -n)
export LOGNAME=$USER

frida="${TMPDIR:-/data/local/tmp}/frida-server"
if [ ! -f "$frida" ]; then
  version='16.2.1'
  url="https://github.com/frida/frida/releases/download/$version/frida-server-$version-android-arm.xz"
  # TODO: detect binary abi
fi


# Define and check the existence of BusyBox
busybox="${TMPDIR:-/data/local/tmp}/busybox"
if [ ! -f "$busybox" ]; then
  url='https://busybox.net/downloads/binaries/1.26.2-defconfig-multiarch'
  abi=$(getprop ro.product.cpu.abi)
  binary=$(echo "$abi" | grep -q 'arm' && echo 'busybox-armv6l' || echo 'busybox-x86_64')
  echo "Downloading BusyBox binary for $abi from $url/$binary"
  curl -o "$busybox" "$url/$binary" || {
    echo "ERROR: Failed to download BusyBox binary: $busybox"
    return 1
  }
fi

# Ensure BusyBox binary is executable
chown shell:shell "$busybox"
chmod +x "$busybox"

# Alias all available BusyBox functions if not already in PATH
for func in $( $busybox --list ); do
  if ! which "$func" >/dev/null 2>&1 && [ "$func" != 'man' ]; then
    alias "$func"="$busybox $func" 2>/dev/null
  fi
done

# Enhance shell commands with color support if available
if ls --color=auto > /dev/null 2>&1; then
  alias ls='ls --color=auto'
  alias grep='grep --color=auto'
  alias fgrep='fgrep --color=auto'
  alias egrep='egrep --color=auto'
  alias logcat='logcat -v color'
  alias ip='ip -c'
fi

# Define commonly used aliases
alias ll='ls -alF'
alias la='ls -A'
alias l='ls -CF'
alias ipa='ip a'
alias rm='rm -rf'

# Define a function to display a directory tree
tree() {
  local path=${1:-.}
  find "$path" -print | sort | sed 's;[^/]*/;|---;g;s;---|; |;g'
}

# Simulate 'man' command using help option for commands
man() {
  if [ -z "$1" ]; then
    echo "What manual page do you want?"
    echo "For example, try 'man ls'."
    return 1
  else
    "$1" --help
  fi
}

# Define a sudo-like function
sudo() {
  if [ "$(id -u)" -eq 0 ]; then
    $*
  elif which su >/dev/null 2>&1; then
    su -c "$*"
  else
    echo 'ERROR: su binary not found'
    return 127
  fi
}