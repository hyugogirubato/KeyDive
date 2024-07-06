from keydive.vendor import Vendor

NATIVE_C_API = {
    # STDIO
    'fclose', 'fflush', 'fgetc', 'fgetpos', 'fgets', 'fopen', 'fprintf', 'fputc', 'fputs', 'fread', 'freopen',
    'fscanf', 'fseek', 'fsetpos', 'ftell', 'fwrite', 'getc', 'getchar', 'gets', 'perror', 'printf', 'putc',
    'putchar', 'puts', 'remove', 'rename', 'rewind', 'scanf', 'setbuf', 'setvbuf', 'sprintf', 'sscanf', 'tmpfile',
    'tmpnam', 'ungetc', 'vfprintf', 'vprintf', 'vsprintf', 'fileno', 'feof', 'ferror',
    # STDLIB
    'abort', 'abs', 'atexit', 'atof', 'atoi', 'atol', 'bsearch', 'calloc', 'div', 'exit', 'free', 'getenv', 'labs',
    'ldiv', 'malloc', 'mblen', 'mbstowcs', 'mbtowc', 'qsort', 'rand', 'realloc', 'srand', 'strtod', 'strtol',
    'strtoul', 'system', 'wcstombs', 'wctomb',
    # STRING
    'memchr', 'memcmp', 'memcpy', 'memmove', 'memset', 'strcat', 'strchr', 'strcmp', 'strcoll', 'strcpy', 'strcspn',
    'strerror', 'strlen', 'strncat', 'strncmp', 'strncpy', 'strpbrk', 'strrchr', 'strspn', 'strstr', 'strtok',
    'strxfrm', 'strncasecmp',
    # MATH
    'acos', 'asin', 'atan', 'atan2', 'cos', 'cosh', 'exp', 'fabs', 'floor', 'fmod', 'frexp', 'ldexp', 'log',
    'log10', 'modf', 'pow', 'sin', 'sinh', 'sqrt', 'tan', 'tanh',
    # CTYPE
    'isalnum', 'isalpha', 'iscntrl', 'isdigit', 'isgraph', 'islower', 'isprint', 'ispunct', 'isspace', 'isupper',
    'isxdigit', 'tolower', 'toupper',
    # TIME
    'asctime', 'clock', 'ctime', 'difftime', 'gmtime', 'localtime', 'mktime', 'strftime', 'time',
    # UNISTD
    'access', 'alarm', 'chdir', 'chown', 'close', 'dup', 'dup2', 'execle', 'execv', 'execve', 'execvp', 'fork',
    'fpathconf', 'getcwd', 'getegid', 'geteuid', 'getgid', 'getgroups', 'getlogin', 'getopt', 'getpgid', 'getpgrp',
    'getpid', 'getppid', 'getuid', 'isatty', 'lseek', 'pathconf', 'pause', 'pipe', 'read', 'rmdir', 'setgid',
    'setpgid', 'setsid', 'setuid', 'sleep', 'sysconf', 'tcgetpgrp', 'tcsetpgrp', 'ttyname', 'ttyname_r', 'write',
    'fsync', 'unlink', 'syscall', 'getpagesize',
    # FCNTL
    'creat', 'fcntl', 'open',
    # SYS_TYPE
    'fd_set', 'FD_CLR', 'FD_ISSET', 'FD_SET', 'FD_ZERO',
    # SYS_STAT
    'chmod', 'fchmod', 'fstat', 'mkdir', 'mkfifo', 'stat', 'umask',
    # SYS_TIME
    'gettimeofday', 'select', 'settimeofday',
    # SIGNAL
    'signal', 'raise', 'kill', 'sigaction', 'sigaddset', 'sigdelset', 'sigemptyset', 'sigfillset', 'sigismember',
    'sigpending', 'sigprocmask', 'sigsuspend', 'alarm', 'pause',
    # SETJMP
    'longjmp', 'setjmp',
    # ERRNO
    'errno', 'strerror', 'perror',
    # ASSERT
    'assert',
    # LOCAL
    'localeconv', 'setlocale',
    # WCHAR
    'btowc', 'fgetwc', 'fgetws', 'fputwc', 'fputws', 'fwide', 'fwprintf', 'fwscanf', 'getwc', 'getwchar', 'mbrlen',
    'mbrtowc', 'mbsinit', 'mbsrtowcs', 'putwc', 'putwchar', 'swprintf', 'swscanf', 'ungetwc', 'vfwprintf',
    'vfwscanf', 'vwprintf', 'vwscanf', 'wcrtomb', 'wcscat', 'wcschr', 'wcscmp', 'wcscoll', 'wcscpy', 'wcscspn',
    'wcsftime', 'wcslen', 'wcsncat', 'wcsncmp', 'wcsncpy', 'wcspbrk', 'wcsrchr', 'wcsrtombs', 'wcsspn', 'wcsstr',
    'wcstod', 'wcstok', 'wcstol', 'wcstombs', 'wcstoul', 'wcsxfrm', 'wctob', 'wmemchr', 'wmemcmp', 'wmemcpy',
    'wmemmove', 'wmemset', 'wprintf', 'wscanf',
    # WCTYPE
    'iswalnum', 'iswalpha', 'iswcntrl', 'iswdigit', 'iswgraph', 'iswlower', 'iswprint', 'iswpunct', 'iswspace',
    'iswupper', 'iswxdigit', 'towlower', 'towupper', 'iswctype', 'wctype',
    # STDDEF
    'NULL', 'offsetof', 'ptrdiff_t', 'size_t', 'wchar_t',
    # STDARG
    'va_arg', 'va_end', 'va_start',
    # DLFCN
    'dlclose', 'dlerror', 'dlopen', 'dlsym',
    # DIRENT
    'closedir', 'opendir', 'readdir',
    # SYS_SENDFILE
    'sendfile',
    # SYS_MMAN
    'mmap', 'mprotect', 'munmap',
    # SYS_UTSNAME
    'uname',
    # LINK
    'dladdr'
}

OEM_CRYPTO_API = {
    # Mapping of function names across different API levels (obfuscated names may vary).
    'rnmsglvj', 'polorucp', 'kqzqahjq', 'pldrclfq', 'kgaitijd', 'cwkfcplc', 'crhqcdet', 'ulns', 'dnvffnze', 'ygjiljer',
    'qbjxtubz', 'qkfrcjtw', 'rbhjspoh', 'zgtjmxko', 'igrqajte', 'ofskesua', 'qllcoacg', 'pukctkiv', 'ehmduqyt'
    # Add more as needed for different versions.
}

CDM_VENDOR_API = {
    'mediaserver': {
        Vendor(11, '1.0', 'libwvdrmengine.so')
    },
    'mediadrmserver': {
        Vendor(11, '1.0', 'libwvdrmengine.so')
    },
    'android.hardware.drm@1.0-service.widevine': {
        Vendor(13, '5.1.0', 'libwvhidl.so')
    },
    'android.hardware.drm@1.1-service.widevine': {
        Vendor(14, '14.0.0', 'libwvhidl.so')
    },
    'android.hardware.drm@1.2-service.widevine': {
        Vendor(15, '15.0.0', 'libwvhidl.so')
    },
    'android.hardware.drm@1.3-service.widevine': {
        Vendor(16, '16.0.0', 'libwvhidl.so')
    },
    'android.hardware.drm@1.4-service.widevine': {
        Vendor(16, '16.1.0', 'libwvhidl.so')
    },
    'android.hardware.drm-service.widevine': {
        Vendor(17, '17.0.0', 'libwvaidl.so'),
        Vendor(18, '18.0.0', 'android.hardware.drm-service.widevine')
    }
}

# https://developers.google.com/widevine
CDM_FUNCTION_API = {
    'UsePrivacyMode',
    'GetCdmClientPropertySet',
    'PrepareKeyRequest',
    'getOemcryptoDeviceId'
}
