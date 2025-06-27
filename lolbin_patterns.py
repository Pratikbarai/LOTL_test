# lolbin_patterns.py
LOLBIN_PATTERNS = {
    'AddinUtil.exe': [
        r'-AddinRoot:\.'
    ],
    'ms-appinstaller': [
        r'ms-appinstaller://\?source=https?://'
    ],
    'aspnet_compiler.exe': [
        r'-v none -p .* -f .* -u'
    ],
    'at.exe': [
        r'/interactive /every:.* cmd /c',
        r'\d{2}:\d{2}.*cmd /c'
    ],
    'ATBroker.exe': [
        r'/start malware'
    ],
    'bash.exe': [
        r'-c "cmd /c',
        r'-c "socat tcp-connect:',
        r"-c 'cat .* > /dev/tcp/"
    ],
    'bitsadmin.exe': [
        r'/create .* /addfile .*https?://',
        r'/SetNotifyCmdLine .*:cmd\.exe',
        r'/RESUME .* /complete'
    ],
    'certoc.exe': [
        r'-LoadDLL ',
        r'-GetCACAPS https?://'
    ],
    'CertReq.exe': [
        r'-Post -config https?://'
    ],
    'certutil.exe': [
        r'-urlcache -f https?://',
        r'-verifyctl -f https?://',
        r'-URL https?://',
        r'-encode ',
        r'-decode(hex)? '
    ],
    'cipher.exe': [
        r'/w:'
    ],
    'cmd.exe': [
        r'/c echo regsvr32\.exe.*scrobj\.dll',
        r'- < \S+:',
        r'type \\\\\.*\\.*\\.* >'
    ],
    'cmdkey.exe': [
        r'/list'
    ],
    'cmdl32.exe': [
        r'/vpn /lan'
    ],
    'cmstp.exe': [
        r'/ni /s (https?://|\\\\.*\\.*)'
    ],
    # Continue for all binaries in your raw file...
    # Patterns truncated for brevity - include all from your file
}

WHITELIST_PATTERNS = {
    'certutil.exe': [
        r'-dump$',
        r'-viewstore$',
        r'-ping$',
        r'-store$'
    ],
    'rundll32.exe': [
        r'Control_RunDLL \w+\.cpl$',
        r'Shell32\.dll,Control_RunDLL$'
    ]
}

MITRE_MAPPING = {
    'certutil.exe': ['T1140', 'T1105'],
    'rundll32.exe': ['T1218.011'],
    'mshta.exe': ['T1218.005'],
    'bitsadmin.exe': ['T1197'],
    'regsvr32.exe': ['T1218.010'],
    # Add mappings for all binaries
}