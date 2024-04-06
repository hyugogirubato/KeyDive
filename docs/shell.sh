
alias ls='ls --color=auto'
alias grep='grep --color=auto'
alias fgrep='fgrep --color=auto'
alias egrep='egrep --color=auto'
alias logcat='logcat -v color'

alias ll='ls -alF'
alias la='ls -A'
alias l='ls -CF'
alias ipa='ip -c a'
alias rm='rm -rf'

tree() {
  path=${1:-.}
  find ${path} -print | sort | sed 's;[^/]*/;|---;g;s;---|; |;g'
}

clear
