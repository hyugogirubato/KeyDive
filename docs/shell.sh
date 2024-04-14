# Env
export PATH='/sbin:/system/sbin:/product/bin:/apex/com.android.runtime/bin:/system/bin:/system/xbin:/odm/bin:/vendor/bin:/vendor/xbin'

# Path
export TMP='/data/local/tmp/'
export APP='/data/data'
export LOCAL='/storage/emulated/0'
export WIFI='/data/misc/wifi'

# Color
alias ls='ls --color=auto'
alias grep='grep --color=auto'
alias fgrep='fgrep --color=auto'
alias egrep='egrep --color=auto'
alias logcat='logcat -v color'
alias ip='ip -c'

# Custom
alias ll='ls -alF'
alias la='ls -A'

alias l='ls -CF'
alias ipa='ip a'
alias rm='rm -rf'

# Extra
tree() {
  path=${1:-.}
  find ${path} -print | sort | sed 's;[^/]*/;|---;g;s;---|; |;g'
}

man() {
  ${1} --help
}

clear
