# lolbin_detector.py
import re
from collections import defaultdict
from datetime import datetime
import logging

class LOLBinDetector:
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.patterns = self._load_lolbin_patterns()
        self.whitelist = self._load_whitelist_patterns()
        # Renamed method and attributes
        self.malicious_combined = self._compile_patterns(self.patterns)
        self.whitelist_combined = self._compile_patterns(self.whitelist)
        self.last_command_line = ""
        self.severity_map = self._create_severity_map()
        self.cache = {}  # Initialize cache
        self.cache_size = 1000  # Set cache size
    def _load_lolbin_patterns(self):
        """Load optimized patterns from the raw commands"""
        LOLBIN_PATTERNS={
            # AddinUtil.exe patterns
            'AddinUtil.exe': [
                r'-AddinRoot:\.?\\?',
                r'-PipelineStoreDir:[^\s]+',
                r'-HostView:[^\s]+',
                r'-Addin:[^\s]+\.dll'
            ],
            
            # AppInstaller.exe patterns
            'appInstaller.exe': [
                r'ms-appinstaller:\?source=https?://[^\s]+\.exe',
                r'ms-appinstaller:\?source=https?://[^\s]+\.dll',
                r'ms-appinstaller:\?source=https?://[^\s]+\.bat',
                r'ms-appinstaller:\?source=https?://[^\s]+\.cmd',
                r'ms-appinstaller:\?source=https?://[^\s]+\.ps1',
                r'ms-appinstaller:\?source=https?://[^\s]+\.js',
                r'ms-appinstaller:\?source=https?://[^\s]+\.vbs',
                r'ms-appinstaller:\?source=https?://[^\s%]*%2[eE][xX][eE]'
            ],
            
            # aspnet_compiler.exe patterns
            'aspnet_compiler.exe': [
                r'-p\s+[cC]:\\users\\[^\s]+\\desktop\\[^\s]+',
                r'-p\s+[^\s]*\\(temp|downloads|public)\\[^\s]+',
                r'-u.*-f',
                r'-v\s+none\s+-p\s+[^\s]+',
                r'-f\s+[cC]:\\users\\[^\s]+\\desktop\\[^\s]+',
                r'-p\s+(?!.*inetpub).*'
            ],
            
            # at.exe patterns
            'at.exe': [
                r'\d{1,2}:\d{2}\s+/interactive\s+/every:[^\s]+\s+cmd\s+/c\s+[^\s]+',
                r'/every:[a-z,]+.*(cmd|powershell|wscript|cscript)\s+/c\s+[^\s]+'
            ],
            
            # atbroker.exe patterns
            'atbroker.exe': [
                r'/start\s+[^\s]+'
            ],
            
            # bash.exe patterns
            'bash.exe': [
                r'-c\s+"?cmd\s+/c\s+[^\s]+',
                r'-c\s+"?socat\s+tcp-connect:[\d.]+:\d+\s+exec:\w+',
                r'-c\s+[\'"]?cat\s+[^\s]+\s+>\s+/dev/tcp/\d{1,3}(?:\.\d{1,3}){3}/\d+'
            ],
            
            # bitsadmin.exe patterns
            'bitsadmin.exe': [
                r'/addfile\s+\d+\s+(https?|ftp)://[^\s]+\s+[^\s]+',
                r'/addfile\s+\d+\s+c:\\windows\\system32\\[^\s]+\s+[^\s]+',
                r'/SetNotifyCmdLine\s+\d+\s+[^\s]+:(exe|cmd|ps1)\s+NULL',
                r'/SetNotifyCmdLine\s+\d+\s+[^\s]+\.(exe|cmd|bat|ps1)\s+NULL',
                r'/create\s+\d+\s+.*(/addfile|/SetNotifyCmdLine|/resume|/complete|/reset)',
                r'/reset\s*$',
                r'/resume\s+\d+\s+.*(/SetNotifyCmdLine|/complete)',
                r'/create\s+\d+\s*&\s*bitsadmin'
            ],
            
            # certoc.exe patterns
            'certoc.exe': [
                r'-LoadDLL\s+c:\\windows\\temp\\[^\s]+\.dll',
                r'-GetCACAPS\s+https?://[^\s]+\.ps1'
            ],
            
            # certreq.exe patterns
            'certreq.exe': [
                r'-Post\s+-config\s+https?://[^\s]+\s+[cC]:\\windows\\temp\\[^\s]+',
                r'-Post\s+-config\s+https?://[^\s]+'
            ],
            
            # certutil.exe patterns
            'certutil.exe': [
                r'-urlcache\s+-f\s+https?://[^\s]+\s+[^\s]+',
                r'-verifyctl\s+-f\s+https?://[^\s]+',
                r'-URL\s+https?://[^\s]+',
                r'-urlcache\s+-f\s+https?://[^\s]+\s+[^\s]+:[^\s]+',
                r'-encode\s+[^\s]+\s+[^\s]+\.base64',
                r'-decode\s+[^\s]+\.base64\s+[^\s]+\.(exe|dll|ps1|bat|cmd)',
                r'-decodehex\s+[^\s]+\.hex\s+[^\s]+\.(exe|dll|ps1|bat|cmd)'
            ],
            
            # cipher.exe patterns
            'cipher.exe': [
                r'/w:\s*[cC]:\\windows\\temp\\[^\s]+'
            ],
            
            # cmd.exe patterns
            'cmd.exe': [
                r'/c\s+echo\s+regsvr32\.exe\s+\^/s\s+\^/u\s+\^/i:https?://[^\s]+\s+\^scrobj\.dll\s+>\s+\S+:payload\.bat',
                r'-\s*<\s*\S+:payload\.bat',
                r'set\s+comspec\s*=\s*[^&]+\.exe\s*&\s*cscript\s+[^\s"]*manage-bde\.wsf',
                r'copy\s+[^\s"]+evil\.exe\s+[^\s"]+manage-bde\.exe\s*&\s*cd\s+[^\s"]+\s*&\s*cscript(\.exe)?\s+[^\s"]*manage-bde\.wsf',
                r'Pester\.bat\s+(?:/help|\?|-\?|/\?)\s*"?\$null;\s*cmd\s*/c\s+[^\s"]+\.exe"?',
                r'Pester\.bat\s*;\s*[^\s"]+\.exe',
                r'rmdir\s+%temp%\\lolbin\s+/s\s+/q\s+2>nul\s+&\s+mkdir\s+"%temp%\\lolbin\\Windows Media Player"\s+&\s+copy\s+C:\\Windows\\System32\\calc\.exe\s+"%temp%\\lolbin\\Windows Media Player\\wmpnscfg\.exe"\s+>nul\s+&&\s+cmd\s+/V\s+/C\s+"set\s+"ProgramW6432=%temp%\\lolbin"\s+&&\s+unregmp2\.exe\s+/HideWMP"'
            ],
            
            # type.exe patterns
            'type.exe': [
                r'type\s+\\\\[^\s]+\\[cC]\$\\windows\\temp\\[^\s]+\s*>\s*[cC]:\\windows\\temp\\[^\s]+',
                r'type\s+[cC]:\\windows\\temp\\[^\s]+\s*>\s+\\\\[^\s]+\\[cC]\$\\windows\\temp\\[^\s]+'
            ],
            
            # cmdkey.exe patterns
            'cmdkey.exe': [
                r'/list'
            ],
            
            # cmdl32.exe patterns
            'cmdl32.exe': [
                r'/vpn\s+/lan\s+%cd%\\config'
            ],
            
            # cmstp.exe patterns
            'cmstp.exe': [
                r'/ni\s+/s\s+[cC]:\\windows\\temp\\[^\s]+\.inf',
                r'/ni\s+/s\s+https?://[^\s]+\.inf'
            ],
            
            # colorcpl.exe patterns
            'colorcpl.exe': [
                r'\S+\.(exe|dll|inf|ocx)'
            ],
            
            # ComputerDefaults.exe patterns
            'ComputerDefaults.exe': [
                r'\.(exe|dll|bat|cmd|ps1)\b',  # Focus on extension abuse
                r'https?://\S+\.(scr|pif|jar)'
            ],
            
            # ConfigSecurityPolicy.exe patterns
            'ConfigSecurityPolicy.exe': [
                r'[cC]:\\Windows\\Temp\\[^\s]+',
                r'https?://[^\s]+'
            ],
            
            # conhost.exe patterns
            'conhost.exe': [
                r'--headless\s+cmd\s+/c\s+[cC]:\\windows\\system32\\[^\s]+',
                r'cmd\s+/c\s+[cC]:\\windows\\system32\\[^\s]+'
            ],
            
            # control.exe patterns
            'control.exe': [
                r'[cC]:\\Windows\\Temp\\[^\s]+:\w+\.dll',
                r'[cC]:\\Windows\\Temp\\[^\s]+\.cpl'
            ],
            
            # csc.exe patterns
            'csc.exe': [
                r'-out:[^\s]+\.exe\s+[^\s]+\.cs',
                r'-target:library\s+[^\s]+\.cs'
            ],
            
            # cscript.exe patterns
            'cscript.exe': [
                r'//e:vbscript\s+[cC]:\\Windows\\Temp\\[^\s]+:\w+\.vbs',
                r'pubprn\.vbs\s+\d{1,3}(\.\d{1,3}){3}\s+script:https?:\/\/[^\s"]+\.sct',
                r'cscript(\.exe)?\s+[^\s"]*manage-bde\.wsf',
                r'%SystemDrive%\\BypassDir\\cscript\s+//nologo\s+[^\s"]*winrm\.vbs\s+get\s+wmicimv2/Win32_Process\?Handle=\d+\s+-format:pretty'
            ],
            
            # CustomShellHost.exe patterns
            'CustomShellHost.exe': [
                r'.*'
            ],
            
            # DataSvcUtil.exe patterns
            'DataSvcUtil.exe': [
                r'/out:[cC]:\\Windows\\Temp\\[^\s]+',
                r'/uri:https?://[^\s]+'
            ],
            
            # desktopimgdownldr.exe patterns
            'desktopimgdownldr.exe': [
                r'/lockscreenurl:https?://[^\s]+',
                r'/eventName:desktopimgdownldr'
            ],
            
            # DeviceCredentialDeployment.exe patterns
            'DeviceCredentialDeployment.exe': [
                r'.*'
            ],
            
            # diantz.exe patterns
            'diantz.exe': [
                r'C:\\Windows\\Temp\\[^\s]+\.exe\s+C:\\Windows\\Temp\\[^\s]+:\w+\.cab',
                r'\\\\[^\s]+\\C\$\\Windows\\Temp\\[^\s]+\.exe\s+C:\\Windows\\Temp\\[^\s]+(:[^\s]+\.cab)?',
                r'/f\s+[^\s]+\.ddf'
            ],
            
            # diskshadow.exe patterns
            'diskshadow.exe': [
                r'/s\s+[^\s]+\.txt',
                r'diskshadow>\s*exec\s+[^\s]+\.exe'
            ],
            
            # dnscmd.exe patterns
            'dnscmd.exe': [
                r'/serverlevelplugindll\s+\\\\[^\s]+\\C\$\\Windows\\Temp\\[^\s]+\.dll'
            ],
            
            # esentutl.exe patterns
            'esentutl.exe': [
                r'/y\s+C:\\Windows\\Temp\\[^\s]+\.(exe|vbs)\s+/d\s+C:\\Windows\\Temp\\[^\s]+',
                r'/y\s+/vss\s+c:\\windows\\ntds\\ntds\.dit\s+/d\s+C:\\Windows\\Temp\\[^\s]+\.dit',
                r'/y\s+\\\\[^\s]+\\C\$\\Windows\\Temp\\[^\s]+\.(exe|vbs)\s+/d\s+C:\\Windows\\Temp\\[^\s]+',
                r'/y\s+\\\\[^\s]+\\C\$\\Windows\\Temp\\[^\s]+\.source\.exe\s+/d\s+\\\\[^\s]+\\C\$\\Windows\\Temp\\[^\s]+\.dest\.exe\s+/o'
            ],
            
            # eventvwr.exe patterns
            'eventvwr.exe': [
                r'^eventvwr\.exe$',
                r'ysoserial\.exe.*cmd\s+/c\s+c:\\windows\\system32\\calc\.exe.*eventvwr\.exe'
            ],
            
            # expand.exe patterns
            'expand.exe': [
                r'\\\\[^\s]+\\C\$\\Windows\\Temp\\[^\s]+\.bat\s+C:\\Windows\\Temp\\[^\s]+\.bat',
                r'C:\\Windows\\Temp\\[^\s]+\.source\.ext\s+C:\\Windows\\Temp\\[^\s]+\.dest\.ext',
                r'\\\\[^\s]+\\C\$\\Windows\\Temp\\[^\s]+\.bat\s+C:\\Windows\\Temp\\[^\s]+:[^\s]+\.bat'
            ],
            
            # explorer.exe patterns
            'explorer.exe': [
                r'/root,"?C:\\Windows\\Temp\\[^\s]+\.exe"?',
                r'^explorer\.exe\s+C:\\Windows\\Temp\\[^\s]+\.exe$'
            ],
            
            # Extexport.exe patterns
            'Extexport.exe': [
                r'C:\\Windows\\Temp\\[^\s]+(\s+\w+){1,2}'
            ],
            
            # extrac32.exe patterns
            'extrac32.exe': [
                r'C:\\Windows\\Temp\\[^\s]+\.cab\s+C:\\Windows\\Temp\\[^\s]+:[^\s]+',
                r'/[Yy]\s+/[Cc]\s+\\\\[^\s]+\\C\$\\Windows\\Temp\\[^\s]+\s+C:\\Windows\\Temp\\[^\s]+',
                r'/[Cc]\s+C:\\Windows\\Temp\\[^\s]+\s+C:\\Windows\\Temp\\[^\s]+'
            ],
            
            # findstr.exe patterns
            'findstr.exe': [
                r'/V\s+/L\s+\w+\s+C:\\Windows\\Temp\\[^\s]+\s+>\s+C:\\Windows\\Temp\\[^\s]+:[^\s]+',
                r'/S\s+/I\s+cpassword\s+\\\\sysvol\\policies\\\*\.xml',
                r'/V\s+/L\s+\w+\s+\\\\[^\s]+\\C\$\\Windows\\Temp\\[^\s]+\s+>\s+C:\\Windows\\Temp\\[^\s]+'
            ],
            
            # finger.exe patterns
            'finger.exe': [
                r'finger\s+\S+\s+\|\s+more\s+\+\d+\s+\|\s+cmd'
            ],
            
            # fltMC.exe patterns
            'fltMC.exe': [
                r'unload\s+\w+'
            ],
            
            # forfiles.exe patterns
            'forfiles.exe': [
                r'/p\s+c:\\windows\\system32\s+/m\s+\w+\.exe\s+/c\s+"cmd\s+/c\s+c:\\windows\\system32\\calc\.exe"',
                r'/p\s+c:\\windows\\system32\s+/m\s+\w+\.exe\s+/c\s+"C:\\Windows\\Temp\\[^\s]+:[^\s]+"'
            ],
            
            # fsutil.exe patterns
            'fsutil.exe': [
                r'file\s+setZeroData\s+offset=\d+\s+length=\d+\s+C:\\Windows\\Temp\\[^\s]+',
                r'usn\s+deletejournal\s+/d\s+c:',
                r'trace\s+decode'
            ],
            
            # ftp.exe patterns
            'ftp.exe': [
                r'echo\s+!cmd\s+/c\s+c:\\windows\\system32\\calc\.exe\s+>\s+ftpcommands\.txt\s+&&\s+ftp\s+-s:ftpcommands\.txt',
                r'cmd\.exe\s+/c\s+"@echo\s+open\s+[^\s]+\s+\d+>ftp\.txt.*ftp\s+-s:ftp\.txt\s+-v"'
            ],
            
            # Gpscript.exe patterns
            'Gpscript.exe': [
                r'/logon',
                r'/startup'
            ],
            
            # hh.exe patterns
            'hh.exe': [
                r'https?://[^\s]+\.bat',
                r'C:\\Windows\\Temp\\[^\s]+\.exe',
                r'https?://[^\s]+\.chm'
            ],
            
            # IMEWDBLD.exe patterns
            'IMEWDBLD.exe': [
                r'https?://[^\s]+'
            ],
            
            # ie4uinit.exe patterns
            'ie4uinit.exe': [
                r'-BaseSettings'
            ],
            
            # iediagcmd.exe patterns
            'iediagcmd.exe': [
                r'/out:C:\\Windows\\Temp\\[^\s]+\.cab'
            ],
            
            # ieexec.exe patterns
            'ieexec.exe': [
                r'https?://[^\s]+\.exe'
            ],
            
            # ilasm.exe patterns
            'ilasm.exe': [
                r'C:\\Windows\\Temp\\[^\s]+\.txt\s+/exe',
                r'C:\\Windows\\Temp\\[^\s]+\.txt\s+/dll'
            ],
            
            # InfDefaultInstall.exe patterns
            'InfDefaultInstall.exe': [
                r'[^\s]+\.inf'
            ],
            
            # InstallUtil.exe patterns
            'InstallUtil.exe': [
                r'/logfile=\s+/LogToConsole=false\s+/U\s+[^\s]+\.dll',
                r'https?://[^\s]+\.ext'
            ],
            
            # jsc.exe patterns
            'jsc.exe': [
                r'[^\s]+\.js',
                r'/t:library\s+[^\s]+\.js'
            ],
            
            # ldifde.exe patterns
            'ldifde.exe': [
                r'-i\s+-f\s+[^\s]+\.ldf'
            ],
            
            # makecab.exe patterns
            'makecab.exe': [
                r'C:\\Windows\\Temp\\[^\s]+\.exe\s+C:\\Windows\\Temp\\[^\s]+:[^\s]+\.cab',
                r'\\\\[^\s]+\\C\$\\Windows\\Temp\\[^\s]+\.exe\s+C:\\Windows\\Temp\\[^\s]+(:[^\s]+\.cab)?',
                r'/F\s+[^\s]+\.ddf'
            ],
            
            # mavinject.exe patterns
            'mavinject.exe': [
                r'\d+\s+/INJECTRUNNING\s+C:\\Windows\\Temp\\[^\s]+\.dll',
                r'\d+\s+/INJECTRUNNING\s+C:\\Windows\\Temp\\[^\s]+:[^\s]+\.dll'
            ],
            
            # microsoft.workflow.compiler.exe patterns
            'microsoft.workflow.compiler.exe': [
                r'[^\s]+\s+[^\s]+\.log'
            ],
            
            # mmc.exe patterns
            'mmc.exe': [
                r'-Embedding\s+C:\\Windows\\Temp\\[^\s]+\.msc',
                r'gpedit\.msc'
            ],
            
            # mpcmdrun.exe patterns
            'mpcmdrun.exe': [
                r'-DownloadFile\s+-url\s+https?://[^\s]+\s+-path\s+C:\\Windows\\Temp\\[^\s]+',
                r'-DownloadFile\s+-url\s+https?://[^\s]+\s+-path\s+C:\\Users\\Public\\Downloads\\[^\s]+',
                r'-DownloadFile\s+-url\s+https?://[^\s]+\s+-path\s+C:\\Windows\\Temp\\[^\s]+:[^\s]+',
                r'copy\s+".*?MpCmdRun\.exe"\s+C:\\Users\\Public\\Downloads\\MP\.exe\s+&&\s+chdir\s+".*?"\s+&&\s+".*?MP\.exe"\s+-DownloadFile\s+-url\s+https?://[^\s]+\s+-path\s+C:\\Users\\Public\\Downloads\\[^\s]+'
            ],
            
            # msbuild.exe patterns
            'msbuild.exe': [
                r'[^\s]+\.xml',
                r'[^\s]+\.csproj',
                r'/logger:TargetLogger,C:\\Windows\\Temp\\[^\s]+\.dll;MyParameters,[^\s]+',
                r'[^\s]+\.proj',
                r'@file\.rsp'
            ],
            
            # msconfig.exe patterns
            'msconfig.exe': [
                r'-5'
            ],
            
            # msdt.exe patterns
            'msdt.exe': [
                r'-path\s+C:\\WINDOWS\\diagnostics\\index\\PCWDiagnostic\.xml\s+-af\s+C:\\Windows\\Temp\\[^\s]+\.xml\s+/skip\s+TRUE',
                r'/id\s+PCWDiagnostic\s+/skip\s+force\s+/param\s+".*?\$\([^\)]+\)\.exe"'
            ],
            
            # msedge.exe patterns
            'msedge.exe': [
                r'https?://[^\s]+\.exe\.txt',
                r'--headless\s+--enable-logging\s+--disable-gpu\s+--dump-dom\s+"https?://[^\s]+\.base64\.html"\s+>\s+[^\s]+\.b64',
                r'--disable-gpu-sandbox\s+--gpu-launcher="cmd\s+/c\s+c:\\windows\\system32\\[^\s]+\.exe\s+&&"'
            ],
            
            # mshta.exe patterns
            'mshta.exe': [
                r'[^\s]+\.hta',
                r'vbscript:Close\(Execute\("GetObject\("+"script:https?://[^\s]+\.sct"\)\)\)',
                r'javascript:a=GetObject\("script:https?://[^\s]+\.sct"\)\.Exec\(\);close\(\);',
                r'C:\\Windows\\Temp\\[^\s]+:[^\s]+\.hta',
                r'https?://[^\s]+\.ext'
            ],
            
            # msiexec.exe patterns
            'msiexec.exe': [
                r'/quiet\s+/i\s+[^\s]+\.msi',
                r'/q\s+/i\s+https?://[^\s]+\.ext',
                r'/[yz]\s+C:\\Windows\\Temp\\[^\s]+\.dll',
                r'/i\s+C:\\Windows\\Temp\\[^\s]+\.msi\s+TRANSFORMS="https?://[^\s]+\.mst"\s+/qb'
            ],
            
            # netsh.exe patterns
            'netsh.exe': [
                r'add\s+helper\s+C:\\Windows\\Temp\\[^\s]+\.dll'
            ],
            
            # ngen.exe patterns
            'ngen.exe': [
                r'https?://[^\s]+\.ext'
            ],
            
            # odbcconf.exe patterns
            'odbcconf.exe': [
                r'/a\s+\{REGSVR\s+C:\\Windows\\Temp\\[^\s]+\.dll\}',
                r'INSTALLDRIVER\s+"[^|]+\|Driver=C:\\Windows\\Temp\\[^\s]+\.dll\|[^"]+"',
                r'configsysdsn\s+"[^"]+"\s+"DSN=[^"]+"',
                r'-f\s+[^\s]+\.rsp'
            ],
            
            # offlinescannershell.exe patterns
            'offlinescannershell.exe': [
                r'.*'
            ],
            
            # onedrivestandaloneupdater.exe patterns
            'onedrivestandaloneupdater.exe': [
                r'.*'
            ],
            
            # pcalua.exe patterns
            'pcalua.exe': [
                r'-a\s+[^\s]+\.exe',
                r'-a\s+\\\\[^\s]+\\C\$\\Windows\\Temp\\[^\s]+\.dll',
                r'-a\s+C:\\Windows\\Temp\\[^\s]+\.cpl\s+-c\s+Java'
            ],
            
            # pcwrun.exe patterns
            'pcwrun.exe': [
                r'C:\\Windows\\Temp\\[^\s]+\.exe',
                r'/\.\./\.\./\$\([^\)]+\)\.exe'
            ],
            
            # pktmon.exe patterns
            'pktmon.exe': [
                r'start\s+--etw',
                r'filter\s+add\s+-p\s+445'
            ],
            
            # pnputil.exe patterns
            'pnputil.exe': [
                r'-i\s+-a\s+C:\\Windows\\Temp\\[^\s]+\.inf'
            ],
            
            # presentationhost.exe patterns
            'presentationhost.exe': [
                r'C:\\Windows\\Temp\\[^\s]+\.xbap',
                r'https?://[^\s]+'
            ],
            
            # print.exe patterns
            'print.exe': [
                r'/D:C:\\Windows\\Temp\\[^\s]+:[^\s]+\s+C:\\Windows\\Temp\\[^\s]+',
                r'/D:C:\\Windows\\Temp\\[^\s]+\.exe\s+C:\\Windows\\Temp\\[^\s]+\.exe',
                r'/D:C:\\Windows\\Temp\\[^\s]+\.exe\s+\\\\[^\s]+\\C\$\\Windows\\Temp\\[^\s]+\.exe'
            ],
            
            # printbrm.exe patterns
            'printbrm.exe': [
                r'-b\s+-d\s+\\\\[^\s]+\\C\$\\Windows\\Temp\\[^\s]+\\?\s+-f\s+C:\\Windows\\Temp\\[^\s]+\.zip',
                r'-r\s+-f\s+C:\\Windows\\Temp\\[^\s]+:[^\s]+\.zip\s+-d\s+C:\\Windows\\Temp\\[^\s]+'
            ],
            
            # provlaunch.exe patterns
            'provlaunch.exe': [
                r'LOLBin'
            ],
            
            # psr.exe patterns
            'psr.exe': [
                r'/start\s+/output\s+C:\\Windows\\Temp\\[^\s]+\.zip\s+/sc\s+\d+\s+/gui\s+\d+'
            ],
            
            # rasautou.exe patterns
            'rasautou.exe': [
                r'-d\s+[^\s]+\.dll\s+-p\s+[^\s]+\s+-a\s+[^\s]+\s+-e\s+[^\s]+'
            ],
            
            # rdrleakdiag.exe patterns
            'rdrleakdiag.exe': [
                r'/p\s+\d+\s+/o\s+C:\\Windows\\Temp\\[^\s]+\s+/fullmemdmp\s+/wait\s+\d+',
                r'/p\s+\d+\s+/o\s+C:\\Windows\\Temp\\[^\s]+\s+/fullmemdmp\s+/snap'
            ],
            
            # reg.exe patterns
            'reg.exe': [
                r'export\s+HKLM\\[^\s]+\s+C:\\Windows\\Temp\\[^\s]+:[^\s]+\.reg',
                r'save\s+HKLM\\SECURITY\s+C:\\Windows\\Temp\\[^\s]+\.bak\s+&&\s+reg\s+save\s+HKLM\\SYSTEM\s+C:\\Windows\\Temp\\[^\s]+\.bak\s+&&\s+reg\s+save\s+HKLM\\SAM\s+C:\\Windows\\Temp\\[^\s]+\.bak'
            ],
            
            # regasm.exe patterns
            'regasm.exe': [
                r'[^\s]+\.dll',
                r'/U\s+[^\s]+\.dll'
            ],
            
            # regedit.exe patterns
            'regedit.exe': [
                r'/E\s+C:\\Windows\\Temp\\[^\s]+:[^\s]+\.reg\s+HKEY_CURRENT_USER\\[^\s]+',
                r'C:\\Windows\\Temp\\[^\s]+:[^\s]+\.reg'
            ],
            
            # regini.exe patterns
            'regini.exe': [
                r'[^\s]+:[^\s]+\.ini'
            ],
            
            # register-cimprovider patterns
            'register-cimprovider': [
                r'-path\s+C:\\Windows\\Temp\\[^\s]+\.dll'
            ],
            
            # regsvcs.exe patterns
            'regsvcs.exe': [
                r'[^\s]+\.dll'
            ],
            
            # regsvr32.exe patterns
            'regsvr32.exe': [
                r'/s\s+/n\s+/u\s+/i:https?://[^\s]+\.sct\s+scrobj\.dll',
                r'/s\s+/u\s+/i:[^\s]+\.sct\s+scrobj\.dll'
            ],
            
            # replace.exe patterns
            'replace.exe': [
                r'C:\\Windows\\Temp\\[^\s]+\.cab\s+C:\\Windows\\Temp\\[^\s]+\\?\s+/A',
                r'\\\\[^\s]+\\C\$\\Windows\\Temp\\[^\s]+\.exe\s+C:\\Windows\\Temp\\[^\s]+\\?\s+/A'
            ],
            
            # rpcping.exe patterns
            'rpcping.exe': [
                r'-s\s+\d{1,3}(?:\.\d{1,3}){3}\s+-e\s+\d+\s+-a\s+\w+\s+-u\s+\w+',
                r'/s\s+\d{1,3}(?:\.\d{1,3}){3}\s+/e\s+\d+\s+/a\s+\w+\s+/u\s+\w+'
            ],
            
            # rundll32.exe patterns
            'rundll32.exe': [
                r'javascript:.*script:https?://',
                r',ShOpenVerbApplication\s+https?://',
                r',InstallScreenSaver\s+\S+\.scr',
                r',RegisterOCX\s+\S+\.(dll|exe)',
                r'dfshim\.dll,ShOpenVerbApplication\s+https?://[^\s]+',
                r'[^\s]+,\w+',
                r'\\\\[^\s]+\\C\$\\Windows\\Temp\\[^\s]+,\w+',
                r'javascript:"\\\.\.\\mshtml,RunHTMLApplication\s+";.*GetObject\("script:https?://[^\s]+\.ext"\)',
                r'-sta\s+{[0-9a-fA-F\-]+}',
                r'"[^\s]+:[^\s]+\.dll",\w+',
                r'advpack\.dll,LaunchINFSection\s+[^\s,]+,DefaultInstall_SingleUser,1,',
                r'advpack\.dll,LaunchINFSection\s+[^\s,]+,,1,',
                r'advpack\.dll,RegisterOCX\s+[^\s]+',
                r'advpack\.dll,\s*RegisterOCX\s+cmd\s+/c\s+c:\\windows\\system32\\[^\s]+',
                r'desk\.cpl,InstallScreenSaver\s+(\\\\[^\s]+|[cC]:\\[^\s]+\.scr)',
                r'dfshim\.dll,ShOpenVerbApplication\s+https?://[^\s]+',
                r'ieadvpack\.dll,LaunchINFSection\s+[^\s,]+,DefaultInstall_SingleUser,1,',
                r'ieadvpack\.dll,LaunchINFSection\s+[^\s,]+,,1,',
                r'ieadvpack\.dll,RegisterOCX\s+[^\s]+',
                r'ieadvpack\.dll,\s*RegisterOCX\s+cmd\s+/c\s+c:\\windows\\system32\\[^\s]+',
                r'ieframe\.dll,OpenURL\s+[^\s]+\.url',
                r'mshtml\.dll,PrintHTML\s+[^\s]+\.hta',
                r'pcwutl\.dll,LaunchApplication\s+[^\s]+\.exe',
                r'scrobj\.dll,GenerateTypeLib\s+https?://[^\s]+',
                r'setupapi\.dll,InstallHinfSection\s+DefaultInstall\s+128\s+[^\s]+\.inf',
                r'shdocvw\.dll,OpenURL\s+[^\s]+\.url',
                r'shell32\.dll,Control_RunDLL\s+[^\s]+\.dll',
                r'shell32\.dll,ShellExec_RunDLL\s+[^\s]+\.exe',
                r'SHELL32\.DLL,ShellExec_RunDLL\s+[^\s]+\.exe(\s+/[^\s]+)*',
                r'shell32\.dll,#44\s+[^\s]+\.dll',
                r'shimgvw\.dll,ImageView_Fullscreen\s+https?://[^\s]+',
                r'syssetup\.dll,SetupInfObjectInstallAction\s+DefaultInstall\s+128\s+[^\s]+\.inf',
                r'url\.dll,OpenURL\s+[^\s]+\.hta',
                r'url\.dll,OpenURL\s+[^\s]+\.url',
                r'url\.dll,OpenURL\s+file://\^?[C]:/\^?W[^"]+',
                r'url\.dll,FileProtocolHandler\s+[^\s]+\.exe',
                r'url\.dll,FileProtocolHandler\s+file:///[^\s]+\.hta',
                r'zipfldr\.dll,RouteTheCall\s+[^\s]+\.exe',
                r'zipfldr\.dll,RouteTheCall\s+file://\^?C:/\^?W[^"]+',
                r'comsvcs\.dll\s+MiniDump\s+{[^\s]+}\s+[^\s]+\.bin\s+full'
            ],
            
            # runexehelper.exe patterns
            'runexehelper.exe': [
                r'C:\\Windows\\Temp\\[^\s]+\.exe'
            ],
            
            # runonce.exe patterns
            'runonce.exe': [
                r'/AlternateShellStartup'
            ],
            
            # runscripthelper.exe patterns
            'runscripthelper.exe': [
                r'surfacecheck\s+\\\\\?\\C:\\Windows\\Temp\\[^\s]+\.txt\s+C:\\Windows\\Temp\\[^\s]+'
            ],
            
            # sc.exe patterns
            'sc.exe': [
                r'create\s+[^\s]+\s+binPath="\\"c:\\ADS\\[^\s]+:[^\s]+\.exe\\".*"',
                r'config\s+{[^}]+}\s+binPath="\\"c:\\ADS\\[^\s]+:[^\s]+\.exe\\".*"\s+&\s+sc\s+start\s+{[^}]+}'
            ],
            
            # schtasks.exe patterns
            'schtasks.exe': [
                r'/create\s+/sc\s+minute\s+/mo\s+\d+\s+/tn\s+".*?"\s+/tr\s+"cmd\s+/c\s+c:\\windows\\system32\\[^\s]+"',
                r'/create\s+/s\s+[^\s]+\s+/tn\s+".*?"\s+/tr\s+"cmd\s+/c\s+c:\\windows\\system32\\[^\s]+"\s+/sc\s+daily'
            ],
            
            # scriptrunner.exe patterns
            'scriptrunner.exe': [
                r'-appvscript\s+[^\s]+\.exe',
                r'-appvscript\s+\\\\[^\s]+\\C\$\\Windows\\Temp\\[^\s]+\.cmd'
            ],
            
            # setres.exe patterns
            'setres.exe': [
                r'-w\s+\d+\s+-h\s+\d+'
            ],
            
            # settingsynchost.exe patterns
            'settingsynchost.exe': [
                r'-LoadAndRunDiagScript\s+[^\s]+\.exe',
                r'-LoadAndRunDiagScriptNoCab\s+[^\s]+\.bat'
            ],
            
            # sftp patterns
            'sftp': [
                r'-o\s+ProxyCommand="cmd\s+/c\s+c:\\windows\\system32\\[^\s]+"'
            ],
            
            # ssh patterns
            'ssh': [
                r'localhost\s+"cmd\s+/c\s+c:\\windows\\system32\\[^\s]+"',
                r'-o\s+ProxyCommand="cmd\s+/c\s+c:\\windows\\system32\\[^\s]+"\s+\.'
            ],
            
            # stordiag.exe patterns
            'stordiag.exe': [
                r'.*'
            ],
            
            # syncappvpublishingserver.exe patterns
            'syncappvpublishingserver.exe': [
                r'"n;\(New-Object\s+Net\.WebClient\)\.DownloadString\(\'https?://[^\']+\.ps1\'\)\s+\|\s+IEX"'
            ],
            
            # tar.exe patterns
            'tar.exe': [
                r'-cf\s+[^\s]+:[^\s]+\s+C:\\Windows\\Temp\\[^\s]+',
                r'-xf\s+[^\s]+:[^\s]+',
                r'-xf\s+\\\\[^\s]+\\C\$\\Windows\\Temp\\[^\s]+\.tar'
            ],
            
            # ttdinject.exe patterns
            'ttdinject.exe': [
                r'/ClientParams\s+"7\s+tmp\.run\s+0\s+0\s+0\s+0\s+0\s+0\s+0\s+0\s+0\s+0"\s+/Launch\s+"[^\s]+"',
                r'/ClientScenario\s+TTDRecorder\s+/ddload\s+\d+\s+/ClientParams\s+"7\s+tmp\.run\s+0\s+0\s+0\s+0\s+0\s+0\s+0\s+0\s+0\s+0"\s+/launch\s+"[^\s]+"'
            ],
            
            # tttracer.exe patterns
            'tttracer.exe': [
                r'C:\\Windows\\Temp\\[^\s]+\.exe',
                r'-dumpFull\s+-attach\s+\d+'
            ],
            
            # vbc.exe patterns
            'vbc.exe': [
                r'/target:exe\s+C:\\Windows\\Temp\\[^\s]+\.vb',
                r'-reference:Microsoft\.VisualBasic\.dll\s+C:\\Windows\\Temp\\[^\s]+\.vb'
            ],
            
            # verclsid.exe patterns
            'verclsid.exe': [
                r'/S\s+/C\s+{[^}]+}'
            ],
            
            # wab.exe patterns
            'wab.exe': [
                r'.*'
            ],
            
            # wbadmin.exe patterns
            'wbadmin.exe': [
                r'start\s+backup\s+-backupTarget:C:\\Windows\\Temp\\[^\s]+\s+-include:C:\\Windows\\NTDS\\NTDS\.dit,C:\\Windows\\System32\\config\\SYSTEM\s+-quiet',
                r'start\s+recovery\s+-version:\s+-recoverytarget:C:\\Windows\\Temp\\[^\s]+\s+-itemtype:file\s+-items:C:\\Windows\\NTDS\\NTDS\.dit,C:\\Windows\\System32\\config\\SYSTEM\s+-notRestoreAcl\s+-quiet'
            ],
            
            # wbemtest.exe patterns
            'wbemtest.exe': [
                r'.*'
            ],
            
            # winget.exe patterns
            'winget.exe': [
                r'install\s+--manifest\s+[^\s]+\.yml',
                r'install\s+--accept-package-agreements\s+-s\s+msstore\s+[^{}\s]+',
                r'install\s+--accept-package-agreements\s+-s\s+msstore\s+{[^}]+}'
            ],
            
            # wlrmdr.exe patterns
            'wlrmdr.exe': [
                r'-s\s+\d+\s+-f\s+\d+\s+-t\s+_\s+-m\s+_\s+-a\s+\d+\s+-u\s+[^\s]+\.exe'
            ],
            
            # wmic.exe patterns
            'wmic.exe': [
                r'process\s+call\s+create\s+"C:\\Windows\\Temp\\[^\s]+:program\.exe"',
                r'process\s+call\s+create\s+"cmd\s+/c\s+c:\\windows\\system32\\calc\.exe"',
                r'/node:"\d{1,3}(?:\.\d{1,3}){3}"\s+process\s+call\s+create\s+"cmd\s+/c\s+c:\\windows\\system32\\calc\.exe"',
                r'process\s+get\s+brief\s+/format:"https?://[^\s"]+\.xsl"',
                r'process\s+get\s+brief\s+/format:"\\\\servername\\C\$\\Windows\\Temp\\[^\s"]+\.xsl"',
                r'datafile\s+where\s+"Name=\'C:\\\\windows\\\\system32\\\\calc\.exe\'"\s+call\s+Copy\s+"C:\\\\users\\\\public\\\\calc\.exe"'
            ],
            
            # workfolders patterns
            'workfolders': [
                r'.*'
            ],
            
            # wscript.exe patterns
            'wscript.exe': [
                r'//e:vbscript\s+[^\s]+:script\.vbs',
                r'echo\s+GetObject\("script:https://[^\s"]+"\)\s+>\s+C:\\Windows\\Temp\\[^\s]+:hi\.js\s+&&\s+wscript\.exe\s+C:\\Windows\\Temp\\[^\s]+:hi\.js'
            ],
            
            # wsreset.exe patterns
            'wsreset.exe': [
                r'.*'
            ],
            
            # wuauclt.exe patterns
            'wuauclt.exe': [
                r'/UpdateDeploymentProvider\s+C:\\Windows\\Temp\\[^\s]+\.dll\s+/RunHandlerComServer'
            ],
            
            # xwizard.exe patterns
            'xwizard.exe': [
                r'RunWizard\s+{[0-9a-fA-F-]+}',
                r'RunWizard\s+/taero\s+/u\s+{[0-9a-fA-F-]+}',
                r'RunWizard\s+{[0-9a-fA-F-]+}\s+/zhttps?://[^\s"]+\.ext'
            ],
            
            # msedge_proxy.exe patterns
            'msedge_proxy.exe': [
                r'https?://[^\s"]+\.zip',
                r'--disable-gpu-sandbox\s+--gpu-launcher="?cmd\s+/c\s+[^\s"]+'
            ],
            
            # msedgewebview2.exe patterns
            'msedgewebview2.exe': [
                r'--no-sandbox\s+--browser-subprocess-path="?[^"\s]+\.exe"?',
                r'--utility-cmd-prefix="?cmd\s+/c\s+[^\s"]+"?',
                r'--disable-gpu-sandbox\s+--gpu-launcher="?cmd\s+/c\s+[^\s"]+"?',
                r'--no-sandbox\s+--renderer-cmd-prefix="?cmd\s+/c\s+[^\s"]+"?'
            ],
            
            # wt.exe patterns
            'wt.exe': [
                r'cmd\s+/c\s+c:\\windows\\system32\\[^\s"]+'
            ],
            
            # AccCheckConsole.exe patterns
            'AccCheckConsole.exe': [
                r'-window\s+".+?"\s+C:\\Windows\\Temp\\[^\s"]+\.dll'
            ],
            
            # adplus.exe patterns
            'adplus.exe': [
                r'-hang\s+-pn\s+[^\s]+\.exe\s+-o\s+C:\\Windows\\Temp\\[^\s]+(\s+-quiet)?',
                r'-c\s+[^\s]+\.xml',
                r'-crash\s+-o\s+"?C:\\Windows\\Temp\\[^\s"]+"?\s+-sc\s+[^\s]+\.exe'
            ],
            
            # AgentExecutor.exe patterns
            'AgentExecutor.exe': [
                r'-powershell\s+"C:\\Windows\\Temp\\[^\s"]+\.ps1"\s+"C:\\Windows\\Temp\\[^\s"]+\.log"\s+"C:\\Windows\\Temp\\[^\s"]+\.log"\s+"C:\\Windows\\Temp\\[^\s"]+\.log"\s+\d+\s+"(C:\\Windows\\SysWOW64\\WindowsPowerShell\\v1\.0|C:\\Windows\\Temp\\[^\s"]+)"\s+0\s+1'
            ],
            
            # appcert.exe patterns
            'appcert.exe': [
                r'test\s+-apptype\s+desktop\s+-setuppath\s+C:\\Windows\\Temp\\[^\s"]+\.exe\s+-reportoutputpath\s+C:\\Windows\\Temp\\[^\s"]+\.xml',
                r'test\s+-apptype\s+desktop\s+-setuppath\s+C:\\Windows\\Temp\\[^\s"]+\.msi\s+-setupcommandline\s+/q\s+-reportoutputpath\s+C:\\Windows\\Temp\\[^\s"]+\.xml'
            ],
            
            # AppVLP.exe patterns
            'AppVLP.exe': [
                r'\\\\[^\s]+\\C\$\\Windows\\Temp\\[^\s"]+\.bat',
                r'powershell\.exe\s+-c\s+"\$e=New-Object\s+-ComObject\s+shell\.application;\$e\.ShellExecute\(\'[^\']+\.exe\',\'\',\s*\'\',\s*\'open\',\s*1\)"'
            ],
            
            # bginfo.exe patterns
            'bginfo.exe': [
                r'[^\s"]+\.bgi\s+/popup\s+/nolicprompt'
            ],
            
            # cdb.exe patterns
            'cdb.exe': [
                r'-cf\s+[^\s"]+\.wds\s+-o\s+[^\s"]+\.exe',
                r'-pd\s+-pn\s+{[^\s}]+}',
                r'\.shell\s+cmd\s+/c\s+c:\\windows\\system32\\[^\s"]+\.exe',
                r'-c\s+[^\s"]+\.txt\s+"cmd\s+/c\s+c:\\windows\\system32\\[^\s"]+\.exe"'
            ],
            
            # coregen.exe patterns
            'coregen.exe': [
                r'/L\s+C:\\Windows\\Temp\\[^\s"]+\.dll\s+[^\s"]+',
                r'[^\s"]+'
            ],
            
            # createdump.exe patterns
            'createdump.exe': [
                r'-n\s+-f\s+[^\s"]+\.dmp\s+\d+'
            ],
            
            # csi.exe patterns
            'csi.exe': [
                r'[^\s"]+\.cs'
            ],
            
            # DefaultPack.exe patterns
            'DefaultPack.exe': [
                r'/C:"cmd\s+/c\s+c:\\windows\\system32\\[^\s"]+\.exe"'
            ],
            
            # devinit.exe patterns
            'devinit.exe': [
                r'run\s+-t\s+msi-install\s+-i\s+https?://[^\s"]+\.msi'
            ],
            
            # devtoolslauncher.exe patterns
            'devtoolslauncher.exe': [
                r'LaunchForDeploy\s+C:\\Windows\\Temp\\[^\s"]+\.exe\s+".+?"\s+[^\s"]+',
                r'LaunchForDebug\s+C:\\Windows\\Temp\\[^\s"]+\.exe\s+".+?"\s+[^\s"]+'
            ],
            
            # dnx.exe patterns
            'dnx.exe': [
                r'C:\\Windows\\Temp\\[^\s"]+'
            ],
            
            # dotnet.exe patterns
            'dotnet.exe': [
                r'[^\s"]+\.dll',
                r'msbuild\s+[^\s"]+\.csproj',
                r'fsi'
            ],
            
            # dsdbutil.exe patterns
            'dsdbutil.exe': [
                r'"activate instance ntds"\s+"snapshot"\s+"create"\s+"quit"\s+"quit"',
                r'"activate instance ntds"\s+"snapshot"\s+"mount\s+{[0-9a-fA-F-]+}"\s+"quit"\s+"quit"',
                r'"activate instance ntds"\s+"snapshot"\s+"delete\s+{[0-9a-fA-F-]+}"\s+"quit"\s+"quit"',
                r'"activate instance ntds"\s+"snapshot"\s+"create"\s+"list all"\s+"mount\s+\d+"\s+"quit"\s+"quit"',
                r'"activate instance ntds"\s+"snapshot"\s+"list all"\s+"delete\s+\d+"\s+"quit"\s+"quit"'
            ],
            
            # dump64.exe patterns
            'dump64.exe': [
                r'\d+\s+[^\s"]+\.dmp'
            ],
            
            # DumpMinitool.exe patterns
            'DumpMinitool.exe': [
                r'--file\s+C:\\Windows\\Temp\\[^\s"]+\.\w+\s+--processId\s+\d+\s+--dumpType\s+Full'
            ],
            
            # Dxcap.exe patterns
            'Dxcap.exe': [
                r'-c\s+C:\\Windows\\Temp\\[^\s"]+\.exe'
            ],
            
            # ECMangen.exe patterns
            'ECMangen.exe': [
                r'https?://[^\s"]+'
            ],
            
            # Excel.exe patterns
            'Excel.exe': [
                r'https?://[^\s"]+'
            ],
            
            # fsi.exe patterns
            'fsi.exe': [
                r'[^\s"]+\.fsscript',
                r'$'
            ],
            
            # fsianycpu.exe patterns
            'fsianycpu.exe': [
                r'[^\s"]+\.fsscript',
                r'$'
            ],
            
            # Mftrace.exe patterns
            'Mftrace.exe': [
                r'[^\s"]+\.exe'
            ],
            
            # Microsoft.NodejsTools.PressAnyKey.exe patterns
            'Microsoft.NodejsTools.PressAnyKey.exe': [
                r'normal\s+\d+\s+[^\s"]+\.exe'
            ],
            
            # MSAccess.exe patterns
            'MSAccess.exe': [
                r'https?://[^\s"]+'
            ],
            
            # msdeploy.exe patterns
            'msdeploy.exe': [
                r'-verb:sync\s+-source:RunCommand\s+-dest:runCommand="C:\\Windows\\Temp\\[^\s"]+\.bat"',
                r'-verb:sync\s+-source:filePath=C:\\Windows\\Temp\\[^\s"]+\.\w+\s+-dest:filePath=C:\\Windows\\Temp\\[^\s"]+\.\w+'
            ],
            
            # MsoHtmEd.exe patterns
            'MsoHtmEd.exe': [
                r'https?://[^\s"]+'
            ],
            
            # mspub.exe patterns
            'mspub.exe': [
                r'https?://[^\s"]+'
            ],
            
            # msxsl.exe patterns
            'msxsl.exe': [
                r'[^\s"]+\.xml\s+[^\s"]+\.xsl',
                r'https?://[^\s"]+\.xml\s+https?://[^\s"]+\.xsl',
                r'https?://[^\s"]+\.xml\s+https?://[^\s"]+\.xsl\s+-o\s+[^\s"]+',
                r'https?://[^\s"]+\.xml\s+https?://[^\s"]+\.xsl\s+-o\s+[^\s"]+:[^\s"]+'
            ],
            
            # ntdsutil.exe patterns
            'ntdsutil.exe': [
                r'"ac i ntds"\s+"ifm"\s+"create full c:\\\\?"\s+q\s+q'
            ],
            
            # OpenConsole.exe patterns
            'OpenConsole.exe': [
                r'[^\s"]+\.exe'
            ],
            
            # Powerpnt.exe patterns
            'Powerpnt.exe': [
                r'https?://[^\s"]+'
            ],
            
            # procdump.exe patterns
            'procdump.exe': [
                r'-md\s+[^\s"]+\.dll\s+[^\s"]+'
            ],
            
            # ProtocolHandler.exe patterns
            'ProtocolHandler.exe': [
                r'https?://[^\s"]+'
            ],
            
            # rcsi.exe patterns
            'rcsi.exe': [
                r'[^\s"]+\.csx'
            ],
            
            # Remote.exe patterns
            'Remote.exe': [
                r'/s\s+\\\\?[^\s"]+\\[^\s"]+\\[^\s"]+\.exe\s+[^\s"]+',
                r'/s\s+[^\s"]+\.exe\s+[^\s"]+'
            ],
            
            # sqldumper.exe patterns
            'sqldumper.exe': [
                r'\d+\s+\d+\s+0x[0-9a-fA-F:]+'
            ],
            
            # Sqlps.exe patterns
            'Sqlps.exe': [
                r'-noprofile'
            ],
            
            # SQLToolsPS.exe patterns
            'SQLToolsPS.exe': [
                r'-noprofile\s+-command\s+Start-Process\s+[^\s"]+\.exe'
            ],
            
            # squirrel.exe patterns
            'squirrel.exe': [
                r'--download\s+https?://[^\s"]+',
                r'--update\s+https?://[^\s"]+',
                r'--updateRollback=https?://[^\s"]+'
            ],
            
            # te.exe patterns
            'te.exe': [
                r'[^\s"]+\.wsc',
                r'[^\s"]+\.dll'
            ],
            
            # teams.exe patterns
            'teams.exe': [
                r'--disable-gpu-sandbox\s+--gpu-launcher="cmd\s+/c\s+c:\\windows\\system32\\calc\.exe\s+&&?"'
            ],
            
            # TestWindowRemoteAgent.exe patterns
            'TestWindowRemoteAgent.exe': [
                r'start\s+-h\s+[a-zA-Z0-9+/=.-]+\.example\.com\s+-p\s+\d+'
            ],
            
            # Tracker.exe patterns
            'Tracker.exe': [
                r'/d\s+[^\s"]+\.dll\s+/c\s+C:\\Windows\\[^\s"]+\.exe'
            ],
            
            # Update.exe patterns
            'Update.exe': [
                r'--download\s+https?://[^\s"]+',
                r'--update\s*=\s*https?://[^\s"]+',
                r'--update\s*=\s*\\\\?[^\s"]+\\[^\s"]+',
                r'--updateRollback\s*=\s*https?://[^\s"]+',
                r'--updateRollback\s*=\s*\\\\?[^\s"]+\\[^\s"]+',
                r'--processStart\s+[^\s"]+\.exe\s+--process-start-args\s+"[^"]+"',
                r'--createShortcut\s*=\s*[^\s"]+\.exe\s+-l=Startup',
                r'--removeShortcut\s*=\s*[^\s"]+\.exe-l=Startup'
            ],
            
            # VSDiagnostics.exe patterns
            'VSDiagnostics.exe': [
                r'start\s+\d+\s+/launch:[^\s"]+\.exe',
                r'start\s+\d+\s+/launch:[^\s"]+\.exe\s+/launchArgs:"[^"]+"'
            ],
            
            # VSIISExeLauncher.exe patterns
            'VSIISExeLauncher.exe': [
                r'-p\s+[^\s"]+\.exe\s+-a\s+"[^"]+"'
            ],
            
            # Visio.exe patterns
            'Visio.exe': [
                r'https?://[^\s"]+'
            ],
            
            # VisualUiaVerifyNative.exe patterns
            'VisualUiaVerifyNative.exe': [
                r'.*'
            ],
            
            # VSLaunchBrowser.exe patterns
            'VSLaunchBrowser.exe': [
                r'\.exe\s+https?://[^\s"]+',
                r'\.exe\s+C:\\Windows\\Temp\\[^\s"]+\.exe',
                r'\.exe\s+\\\\[^\s"]+\\[^\s"]+'
            ],
            
            # vshadow.exe patterns
            'vshadow.exe': [
                r'-nw\s+-exec=[^\s"]+\.exe\s+C:'
            ],
            
            # Vsjitdebugger.exe patterns
            'Vsjitdebugger.exe': [
                r'[^\s"]+\.exe'
            ],
            
            # WFMFormat.exe patterns
            'WFMFormat.exe': [
                r'.*'
            ],
            
            # wfc.exe patterns
            'wfc.exe': [
                r'C:\\Windows\\Temp\\[^\s"]+\.xoml'
            ],
            
            # WinProj.exe patterns
            'WinProj.exe': [
                r'https?://[^\s"]+'
            ],
            
            # winword.exe patterns
            'winword.exe': [
                r'https?://[^\s"]+'
            ],
            
            # wsl.exe patterns
            'wsl.exe': [
                r'-e\s+/mnt/c/Windows/System32/[^\s"]+\.exe',
                r'-u\s+root\s+-e\s+cat\s+/etc/shadow',
                r'--exec\s+bash\s+-c\s+"cmd\s+/c\s+c:\\windows\\system32\\[^\s"]+\.exe"',
                r'--exec\s+bash\s+-c\s+\'cat\s+<\s+/dev/tcp/\d{1,3}(?:\.\d{1,3}){3}/\d{1,5}\s+>\s+[^\s\']+\''
            ],
            
            # xbootmgrsleep.exe patterns
            'xbootmgrsleep.exe': [
                r'\d+\s+"cmd\s+/c\s+c:\\windows\\system32\\[^\s"]+\.exe"'
            ],
            
            # devtunnel.exe patterns
            'devtunnel.exe': [
                r'host\s+-p\s+\d{1,5}'
            ],
            
            # vsls-agent.exe patterns
            'vsls-agent.exe': [
                r'--agentExtensionPath\s+C:\\Windows\\Temp\\[^\s"]+\.dll'
            ],
            
            # vstest.console.exe patterns
            'vstest.console.exe': [
                r'[^\s"]+\.dll'
            ],
            
            # winfile.exe patterns
            'winfile.exe': [
                r'[^\s"]+\.exe'
            ],
            
            # xsd.exe patterns
            'xsd.exe': [
                r'https?://[^\s"]+'
            ],
            
            # powershell.exe patterns
            'powershell.exe': [
                r'-ep\s+bypass\s+-command\s+"set-location.+?LoadAssemblyFromPath.+?\.dll;?\[Program\]::Fun\(\)"',
                r'-ep\s+bypass\s+-command\s+"set-location.+?RegSnapin.+?\.dll;?\[Program\.Class\]::Main\(\)"',
                r'-ep\s+bypass\s+-command\s+"[^"]*RegSnapin\s+[^\s"]+\.dll\s*;?\s*\[.*?\]::Main\(\)',
                r'import-module\s+[^\s"]*UtilityFunctions\.ps1'
                r"-EncodedCommand\s+[A-Za-z0-9+/=]{20,}",
                r"-enc\s+[A-Za-z0-9+/=]{20,}",
                r"-e\s+[A-Za-z0-9+/=]{20,}"

            ],
            
            # Launch-VsDevShell.ps1 patterns
            'Launch-VsDevShell.ps1': [
                r'-VsWherePath\s+C:\\Windows\\Temp\\[^\s"]+\.exe',
                r'-VsInstallationPath\s+".*file\.exe.*"'
            ],
            
            # SyncAppvPublishingServer.vbs patterns
            'SyncAppvPublishingServer.vbs': [
                r'"[^"]*DownloadString\(\s*\'https?:\/\/[^\s\']+\.ps1\'\s*\)\s*\|\s*IEX'
            ],
            
            # winrm patterns
            'winrm': [
                r'winrm\s+invoke\s+Create\s+wmicimv2/Win32_Process\s+\@{CommandLine\s*=\s*"cmd\s*/c\s+[^\s"]+\.exe"}',
                r'winrm\s+invoke\s+Create\s+wmicimv2/Win32_Service\s+\@{[^}]*PathName\s*=\s*"cmd\s*/c\s+[^\s"]+\.exe"}.*?StartService'
            ],
            
            # pubprn.vbs patterns
            'pubprn.vbs': [
                r'127\.0\.0\.1\s+script:https?:\/\/[^\s"]+\.sct'
            ],
            
            # Pester.bat patterns
            'Pester.bat': [
                r'\$null;\s*cmd\s*/c\s+[^\s"]+\.exe',
                r';\s*[^\s"]+\.exe'
            ]
       }
        return LOLBIN_PATTERNS

    def _load_whitelist_patterns(self):
        """Common legitimate uses to exclude"""
        WHITELIST_PATTERNS= {
           'certutil.exe': [
                r'-dump$',
                r'-viewstore$',
                r'-ping\s+',
                r'-verifyctl\s+-f\s+http://crl\.microsoft\.com',
                r'-urlcache\s+-split\s+http://ctldl\.windowsupdate\.com'
            ],
            'rundll32.exe': [
                r'Control_RunDLL\s+\w+\.cpl',
                r'Shell32\.dll,Control_RunDLL',
                r'ThemeUI\.dll,OpenThemeData'
            ],
            'powershell.exe': [
                r'-Command\s+Get-Process',
                r'-Command\s+Get-Service',
                r'-ExecutionPolicy\s+Restricted',
                r'-File\s+[A-Za-z]:\\Program\sFiles\\'
            ],
            'bitsadmin.exe': [
                r'/transfer\s+WindowsUpdate',
                r'/create\s+WindowsUpdate',
                r'/addfile\s+http://windowsupdate\.com'
            ],
            'msiexec.exe': [
                r'/i\s+[A-Za-z]:\\Program\sFiles\\',
                r'/package\s+[A-Za-z]:\\Program\sFiles\\',
                r'/quiet\s+/i\s+http://windowsupdate\.com'
            ],
            'wmic.exe': [
                r'process\s+get\s+name',
                r'os\s+get\s+caption',
                r'/node:localhost\s+process\s+list\s+brief'
            ],
            'msbuild.exe': [
                r'/t:Restore',
                r'/t:Rebuild',
                r'/p:Configuration=Release'
            ],
            'wsl.exe': [
                r'--install',
                r'-d\s+Ubuntu',
                r'exec\s+/usr/bin/apt'
            ]
        }
        return WHITELIST_PATTERNS

    def _compile_patterns(self, patterns_dict):
        """Compile single combined regex per binary for O(1) matching"""
        combined = {}
        for binary, patterns in patterns_dict.items():
            try:
                combined_pattern = "|".join(f"({p})" for p in patterns)
                combined[binary.lower()] = re.compile(combined_pattern, re.IGNORECASE)
            except re.error as e:
                self.logger.error(f"Invalid pattern for {binary}: {str(e)}")
        return combined


    def detect(self, process_name, command_line):
        """Ultra-fast detection with O(1) complexity per binary"""
        binary = process_name.lower()
        cache_key = f"{binary}:{command_line[:100]}"
        
        if cache_key in self.cache:
            return self.cache[cache_key]
            
        result = self._perform_detection(binary, command_line)
        
        if len(self.cache) >= self.cache_size:
            self.cache.pop(next(iter(self.cache)))
        self.cache[cache_key] = result
        return result

    def _create_severity_map(self):
        """Determine severity rating based on binary's potential for abuse.
        
        Args:
            binary (str): Name of the binary being checked (lowercase)
            
        Returns:
            str: Severity rating ('critical', 'high', 'medium', 'low')
        """
        severity_map = {
            
            "AddinUtil.exe": "medium",         # .NET execution, proxy technique
            "AppInstaller.exe": "high",        # Used for downloading executable payloads
            "Aspnet_Compiler.exe": "medium",   # Bypasses application whitelisting
            "At.exe": "high",                  # Scheduled task execution
            "Atbroker.exe": "high",            # Executes arbitrary EXEs
            "Bash.exe": "medium",              # Indirect/obfuscated command execution
            "Bitsadmin.exe": "high",           # Download, alternate data streams, proxy exec
            "CertOC.exe": "high",              # DLL execution + download
            "CertReq.exe": "medium",           # Used for data transfer (exfil/infil)
            "Certutil.exe": "high", 
            "Cipher.exe": "high",              # Data destruction (T1485)
            "Cmd.exe": "high",                 # Core LOLBin for download, exfil, NTFS abuse
            "Cmdkey.exe": "high",              # Credentials access (T1078)
            "Cmdl32.exe": "high",              # File download
            "Cmstp.exe": "high",               # INF-based AWL bypass + remote execution
            "Colorcpl.exe": "medium",          # Legitimate disguise (T1036.005)
            "ComputerDefaults.exe": "high",    # UAC bypass (T1548.002)
            "ConfigSecurityPolicy.exe": "high",# Exfil and download via web service
            "Conhost.exe": "medium",           # Executes other shells
            "Control.exe": "high",             # DLL execution (T1218.002)
            "Csc.exe": "medium",
            "Cscript.exe": "high",                  # WSH + ADS abuse
            "CustomShellHost.exe": "medium",        # Proxy execution
            "DataSvcUtil.exe": "high",              # Upload/exfil
            "Desktopimgdownldr.exe": "high",        # Ingress tool transfer
            "DeviceCredentialDeployment.exe": "high",  # Hide artifacts
            "Dfsvc.exe": "high",                    # Remote ClickOnce bypass
            "Diantz.exe": "high",                   # Download, compression + ADS
            "Diskshadow.exe": "high",               # NTDS dump + cmd exec
            "Dnscmd.exe": "medium",                 # DLL injection for service
            "Esentutl.exe": "high",                 # NTDS + download + ADS
            "Eventvwr.exe": "high",                 # UAC bypass
            "Expand.exe": "medium",                 # Download + ADS (less abused)
            "Explorer.exe": "medium",               # EXE execution (normal use too)
            "Extexport.exe": "medium",              # DLL execution
            "Extrac32.exe": "high",                 # Compression + download + ADS
            "Findstr.exe": "medium",                # Text tools, possible ADS abuse
            "Finger.exe": "medium",                 # Simple download, rare use
            "FltMC.exe": "high",                    # Tool tampering
            "Forfiles.exe": "medium",               # Indirect EXE exec + ADS
            "Fsutil.exe": "high",                   # Data destruction + system abuse
            "Ftp.exe": "medium",                    # Legit but abusable for download
            "Gpscript.exe": "medium",               # CMD execution via system tool
            "Hh.exe": "high",                       # GUI+remote EXE exec
            "IMEWDBLD.exe": "high",                 # INetCache download
            "Ie4uinit.exe": "medium",               # INF abuse, rare
            "iediagcmd.exe": "medium",
            "Ieexec.exe": "high",                  # Remote EXE execution + transfer
            "Ilasm.exe": "medium",                 # Compilation (low abuse frequency)
            "Infdefaultinstall.exe": "medium",     # INF execution
            "Installutil.exe": "high",             # DLL/EXE execution + AWL bypass
            "Jsc.exe": "medium",                   # JS compiler
            "Ldifde.exe": "medium",                # Download (infiltration)
            "Makecab.exe": "high",                 # Compression + ADS + masquerade
            "Mavinject.exe": "high",               # DLL injection + ADS
            "Microsoft.Workflow.Compiler.exe": "medium", # Used for XOML execution
            "Mmc.exe": "high",                     # DLL UAC bypass + GUI download
            "MpCmdRun.exe": "medium",              # ADS and file transfers (AV tool abuse)
            "Msbuild.exe": "high",                 # C# AWL bypass + DLL/XSL/CMD execution
            "Msconfig.exe": "medium",              # Normal tool but abusable for CMD
            "Msdt.exe": "high",                    # MSI/CMD AWL bypass + GUI tricks
            "Msedge.exe": "medium",
             "Mshta.exe": "high",                  # Remote execution, HTA abuse, ADS
            "Msiexec.exe": "high",                # MSI/DLL remote execution
            "Netsh.exe": "high",                  # DLL helper execution, C2 tunneling
            "Ngen.exe": "medium",                 # Download (can assist staging)
            "Odbcconf.exe": "high",               # DLL execution abuse
            "OfflineScannerShell.exe": "medium",  # Can proxy DLLs
            "OneDriveStandaloneUpdater.exe": "medium",  # Download abuse
            "Pcalua.exe": "medium",               # EXE/DLL launch, less frequent abuse
            "Pcwrun.exe": "medium",               # Indirect execution
            "Pktmon.exe": "medium",               # Recon + packet sniffing
            "Pnputil.exe": "high",                # Persistence via driver INF
            "Presentationhost.exe": "high",       # XBAP execution + download
            "Print.exe": "medium",                # ADS manipulation
            "PrintBrm.exe": "high",               # Compression + ADS + staging
            "Provlaunch.exe": "medium",           # Indirect execution
            "Psr.exe": "medium",                  # Screen capture
            "Rasautou.exe": "high",               # DLL execution
            "rdrleakdiag.exe": "high",                        "Reg.exe": "high",                    # Credential access + ADS abuse
            "Regasm.exe": "high",                 # DLL execution + AWL bypass
            "Regedit.exe": "medium",              # ADS, but also common admin tool
            "Regini.exe": "medium",               # ADS abuse (niche)
            "Register-cimprovider.exe": "medium", # DLL proxy execution
            "Regsvcs.exe": "high",                # Same abuse as Regasm (AWL bypass)
            "Regsvr32.exe": "high",               # Remote SCT execution, AWL bypass
            "Replace.exe": "medium",              # File replacement (download/copy)
            "Rpcping.exe": "high",                # Credential access via forced auth
            "Rundll32.exe": "high",               # Classic DLL execution, JScript, ADS
            "Runexehelper.exe": "medium",         # System EXE launcher
            "Runonce.exe": "medium",              # Execution at login (persistable)
            "Runscripthelper.exe": "high",        # PowerShell execution
            "Sc.exe": "medium",                       # Legit binary but can proxy execution
            "Schtasks.exe": "high",               # Scheduled task execution
            "Scriptrunner.exe": "high",           # Remote EXE execution
            "Setres.exe": "medium",               # System binary execution
            "SettingSyncHost.exe": "medium",      # CMD/EXE execution
            "Sftp.exe": "medium",                 # File transfer via cmd
            "ssh.exe": "medium",                  # Remote shell access
            "Stordiag.exe": "medium",             # Executes other EXEs
            "SyncAppvPublishingServer.exe": "high",  # PowerShell execution
            "Tar.exe": "medium",                  # ADS + compression
            "Ttdinject.exe": "high",              # EXE execution + injection potential
            "Tttracer.exe": "high",               # EXE + dumping (NTDS/creds)
            "Unregmp2.exe": "medium",             # Indirect execution
            "vbc.exe": "medium",                  # .NET compiler abuse
            "Verclsid.exe": "medium",             # COM proxy execution
            "Wab.exe": "high",                    # DLL execution
            "wbadmin.exe": "high",                # NTDS backup/dump abuse
            "wbemtest.exe": "medium",             # WMI GUI and command exec
            "winget.exe": "high",                 # Download + execution + AWL bypass
            "Wlrmdr.exe": "medium" , 
            "Wmic.exe": "high",                   # ADS, remote XSL, copy/download abuse
            "WorkFolders.exe": "medium",          # Proxy EXE execution
            "Wscript.exe": "high",                # ADS + WSH script execution
            "Wsreset.exe": "high",                # UAC bypass
            "wuauclt.exe": "high",                # DLL execution
            "Xwizard.exe": "high",                # COM execution + download
            "msedge_proxy.exe": "medium",         # CMD + download via Edge
            "msedgewebview2.exe": "medium",       # Electron execution path
            "wt.exe": "medium",                   # CMD launcher, Windows Terminal abuse
            # DLLs (LOLLibs)
            "Advpack.dll": "high",                # AWL bypass + DLL/INF exec
            "Desk.cpl": "high",                   # Control panel CPL + remote exec
            "Dfshim.dll": "high",                 # Remote ClickOnce AWL bypass
            "Ieadvpack.dll": "high",              # AWL bypass + INF execution
            "Ieframe.dll": "medium",              # URL execution, less direct
            "Mshtml.dll": "high",                 # HTA rendering/execution
            "Pcwutl.dll": "medium",               # Proxy execution
            "Scrobj.dll": "high",                 # Download + COM scripting
            "Setupapi.dll": "high",               # INF execution + AWL bypass
            "Shdocvw.dll": "medium",              # Legacy URL handler
            "Shell32.dll": "high",                    # Execution of EXE/CMD/DLL via rundll32
            
            "Shimgvw.dll": "medium",               # Download only (INetCache)
            "Syssetup.dll": "high",                # INF execution + AWL bypass
            "Url.dll": "high",                     # HTA/URL/EXE execution
            "Zipfldr.dll": "medium",               # EXE execution via rundll32
            "Comsvcs.dll": "high",                 # LSASS memory dumping

            # Other Microsoft-signed binaries
            "AccCheckConsole.exe": "high",         # DLL (.NET) execution + AWL bypass
            "adplus.exe": "high",                  # LSASS dump + EXE exec
            "AgentExecutor.exe": "high",           # Executes PowerShell + EXE
            "AppCert.exe": "high",                 # MSI and EXE execution
            "Appvlp.exe": "medium",                # CMD/EXE exec via App-V (less abused)
            "Bginfo.exe": "high",                  # Remote/WSH exec + AWL bypass
            "Cdb.exe": "high",                     # Shellcode, CMD execution
            "coregen.exe": "high",                 # DLL execution + process injection
            "Createdump.exe": "high",              # Memory/credential dump
            "csi.exe": "medium",                   # CSharp execution
            "DefaultPack.EXE": "medium",           # CMD execution (low abuse)
            "Devinit.exe": "high",                  # MSI/remote execution
             "Devtoolslauncher.exe": "medium",      # CMD execution (less common)
            "dnx.exe": "medium",                   # CSharp execution
            "Dotnet.exe": "high",                  # DLL + scripting + AWL bypass
            "dsdbutil.exe": "high",                # NTDS dump
            "dtutil.exe": "medium",                # Copy/data staging
            "Dump64.exe": "high",                  # LSASS dump
            "DumpMinitool.exe": "high",            # LSASS dump
            "Dxcap.exe": "medium",                 # EXE execution
            "ECMangen.exe": "medium",              # Download (staging)
            "Excel.exe": "medium",                 # Download abuse (used in macro chains)
            "Fsi.exe": "high",                     # F# scripting AWL bypass
            "FsiAnyCpu.exe": "high",               # Same as above
            "Mftrace.exe": "medium",               # Proxy EXE launcher
            "Microsoft.NodejsTools.PressAnyKey.exe": "medium",  # Custom EXE exec
            "MSAccess.exe": "medium",              # Download via Office abuse
            "Msdeploy.exe": "high",                # CMD exec + download + AWL bypass
            "MsoHtmEd.exe": "medium",               # Download, niche abuse
             "Mspub.exe": "medium",                # Office-based download vector
            "msxsl.exe": "high",                  # XSL exec, ADS, remote abuse, AWL bypass
            "ntdsutil.exe": "high",               # NTDS dump tool
            "OpenConsole.exe": "medium",          # Indirect EXE execution
            "Powerpnt.exe": "medium",             # PowerPoint download vector
            "Procdump.exe": "high",               # DLL injection, dump tool
            "ProtocolHandler.exe": "medium",      # Download, less abused
            "rcsi.exe": "high",                   # AWL bypass via CSharp
            "Remote.exe": "high",                 # Remote EXE + AWL bypass
            "Sqldumper.exe": "high",              # LSASS/credential dump
            "Sqlps.exe": "high",                  # PowerShell via SQL
            "SQLToolsPS.exe": "high",             # PowerShell abuse
            "Squirrel.exe": "high",               # AWL bypass via Nuget + remote execution
            "te.exe": "medium",                   # Custom format WSH/DLL execution
            "Teams.exe": "medium",                 # Electron app execution abuse (Node.js)
            "TestWindowRemoteAgent.exe": "high",       # Exfiltration capability
            "Tracker.exe": "high",                     # DLL execution + AWL bypass
            "Update.exe": "high",                      # Download, persistence, indicator removal
            "VSDiagnostics.exe": "medium",             # EXE/CMD execution
            "VSIISExeLauncher.exe": "medium",          # EXE launcher
            "Visio.exe": "medium",                     # Download (Office vector)
            "VisualUiaVerifyNative.exe": "medium",     # .NET AWL bypass
            "VSLaunchBrowser.exe": "high",             # EXE/remote launch + download
            "Vshadow.exe": "medium",                   # EXE execution, less abused
            "vsjitdebugger.exe": "medium",             # EXE launch
            "WFMFormat.exe": "medium",                 # .NET EXE launch
            "Wfc.exe": "high",                         # XOML AWL bypass
            "WinProj.exe": "medium",                   # Office-based download
            "Winword.exe": "medium",                   # Macro/download vector
            "Wsl.exe": "high",                         # Remote EXE/CMD + download
            "XBootMgrSleep.exe": "medium",             # CMD execution, niche
            "devtunnel.exe": "medium",                  # Download, tunnel staging
            "vsls-agent.exe": "high",             # DLL execution
            "vstest.console.exe": "high",         # AWL bypass with DLLs
            "winfile.exe": "medium",              # Indirect EXE execution
            "xsd.exe": "medium",                  # Downloads (less abused)

            # Scripts (T1216)
            "CL_LoadAssembly.ps1": "high",        # .NET DLL execution
            "CL_Mutexverifiers.ps1": "high",      # PowerShell proxy
            "CL_Invocation.ps1": "high",          # CMD execution
            "Launch-VsDevShell.ps1": "medium",    # Developer shell, EXE exec
            "Manage-bde.wsf": "medium",           # EXE execution via WSF
            "Pubprn.vbs": "high",                 # SCT/COM execution via VBScript
            "Syncappvpublishingserver.vbs": "high",  # PowerShell proxy via VBS
            "UtilityFunctions.ps1": "high",       # .NET DLL execution
            "winrm.vbs": "high",                  # CMD/remote + XSL abuse (AWL bypass)
            "Pester.bat": "medium",                # EXE execution via Batch
            
            
            # Medium - Can be dangerous but requires more specific conditions
            'at.exe': 'medium',
            'forfiles.exe': 'medium',
            'findstr.exe': 'medium',
            'makecab.exe': 'medium',
            'expand.exe': 'medium',
            'extrac32.exe': 'medium',
            'replace.exe': 'medium',
            'ftp.exe': 'medium',
            'finger.exe': 'medium',
            'type.exe': 'medium',
            'esentutl.exe': 'medium',
            'diskshadow.exe': 'medium',
            'vssadmin.exe': 'medium',
            'wbadmin.exe': 'medium',
            
            # Low - Less commonly abused or requires very specific scenarios
            'control.exe': 'low',
            'hh.exe': 'low',
            'explorer.exe': 'low',
            'notepad.exe': 'low',
            'calc.exe': 'low',
            'mspaint.exe': 'low',
            'wordpad.exe': 'low',
            'winword.exe': 'low',
            'excel.exe': 'low',
            'powerpnt.exe': 'low',
            
            # Office-related binaries
            'msohtmled.exe': 'medium',
            'winproj.exe': 'medium',
            'visio.exe': 'medium',
            
            # Development tools
            'csc.exe': 'high',
            'vbc.exe': 'high',
            'ilasm.exe': 'high',
            'jsc.exe': 'high',
            'dotnet.exe': 'high',
            
            # Debugging tools
            'cdb.exe': 'high',
            'windbg.exe': 'high',
            'procdump.exe': 'high',
        }
        
        return 'critical'
            
        return severity_map.get(binary, 'medium')
    

    def _perform_detection(self, binary, command_line):
        """Core detection logic with combined pattern matching"""
        # Check whitelist
        if binary == "openconsole.exe":
            return None
        if binary in self.whitelist_combined:
            if self.whitelist_combined[binary].search(command_line):
                return None

        # Check for known malicious patterns
        if binary in self.malicious_combined:
            match = self.malicious_combined[binary].search(command_line)
            if match:
                # Find which exact pattern matched using group indexing
                matched_pattern = next(
                    (p for i, p in enumerate(self.patterns[binary]) if match.group(i + 1)),
                    None
                )
                base_severity = self.severity_map.get(binary, 'high')
                if binary in ('msedge.exe', 'msedgewebview2.exe', 'teams.exe') and '--gpu-launcher' in command_line:
                    final_severity = 'critical'
                else:
                    final_severity = base_severity

                return {
                    'detected': True,
                    'binary': binary,
                    'matched_pattern': matched_pattern,
                    'severity': final_severity,
                    'timestamp': datetime.now().isoformat()
                }

        # If no match
        return None

    def flush_cache(self):
        self.cache.clear()