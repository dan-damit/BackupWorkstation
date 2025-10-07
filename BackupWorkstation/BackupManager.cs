using Microsoft.Data.Sqlite;
using Microsoft.Win32;
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;
using System.Windows;
using static BackupWorkstation.DecryptorMethods;


namespace BackupWorkstation
{
    [SupportedOSPlatform("windows")]
    public class BackupManager
    {
        // Events
        public event Action<int, int, string>? ProgressChanged;

        // Fields
        private int _filesCopied;
        private int _totalFiles;

        // --- Win32 API for network share connection ---
        [DllImport("mpr.dll")]
        private static extern int WNetAddConnection2(ref NETRESOURCE netResource, string password, string username, int flags);

        [StructLayout(LayoutKind.Sequential)]
        private struct NETRESOURCE
        {
            public int dwScope;
            public int dwType;
            public int dwDisplayType;
            public int dwUsage;
            public string lpLocalName;
            public string lpRemoteName;
            public string lpComment;
            public string lpProvider;
        }

        // --- Check if a file can be opened exclusively (i.e., not locked) ---
        private bool TryOpenExclusive(string path)
        {
            try
            {
                using var fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.None);
                return true;
            }
            catch (Exception ex)
            {
                Logger.Log($"🔒 File locked or inaccessible: {path} - {ex.Message}");
                return false;
            }
        }

        // --- Check and wait for file to be unlocked ---
        private bool EnsureUnlocked(string path, int maxAttempts = 5, int delayMs = 500)
        {
            if (!File.Exists(path))
            {
                Logger.Log($"ℹ File not present (skipping lock check): {path}");
                return true;
            }

            for (int attempt = 1; attempt <= maxAttempts; attempt++)
            {
                if (TryOpenExclusive(path))
                {
                    Logger.Log($"✔ Exclusive access obtained for: {path}");
                    return true;
                }

                Logger.Log($"⏳ Waiting for file unlock ({attempt}/{maxAttempts}): {path}");
                Thread.Sleep(delayMs);
            }

            Logger.Log($"❌ Could not obtain exclusive access to: {path} after {maxAttempts} attempts.");
            return false;
        }

        // --- Main backup method ---
        public async Task RunBackupAsync(string sourceUser, string backupRoot)
        {
            // Always have a logger target, even if backupRoot is inaccessible
            string tempLogPath = Path.Combine(Path.GetTempPath(), "BackupWorkstation_startup_log.txt");
            Logger.Init(tempLogPath);

            // Manifest initialization
            ManifestWriter.Append("manifest_initialized", backupRoot);
            ManifestWriter.Append("source_user_final", sourceUser);
            ManifestWriter.Append("source_sid", CurrentUserInfo.GetUserSid());

            var normalizedRoot = NormalizePath(backupRoot);
            var parentPath = GetParentPath(normalizedRoot);

            // Preflight against the parent (since the final folder may not exist yet)
            // If inaccessible, prompt for credentials and attempt connection
            if (!TestPathAccess(parentPath))
            {
                Logger.Log($"⚠ Cannot access '{parentPath}'. Prompting for credentials...");
                var creds = PromptForCredentials(parentPath);
                if (creds.HasValue)
                {
                    if (!ConnectToShare(parentPath, creds.Value.user, creds.Value.pass))
                    {
                        Logger.Log("❌ Could not connect to network share with provided credentials. Backup aborted.");
                        return;
                    }
                    Logger.Log("🔑 Network share connected successfully.");
                }
                else
                {
                    Logger.Log("❌ Backup cancelled — no credentials provided.");
                    return;
                }
            }

            // Preflight DPAPI readiness check
            // This is crucial for decrypting browser passwords
            Logger.Log("🔐 Preflight: DPAPI readiness check...");
            bool dpapiOk = DpapiDiagnostics.CheckDpapiReadiness(out string dpapiMsg);
            Logger.Log(dpapiMsg);

            // Optional manifest logging
            ManifestWriter.Append("dpapi_readiness", dpapiOk ? "ok" : "warning");
            ManifestWriter.Append("dpapi_message", dpapiMsg);

            // Ensure the final target directory exists (create if missing; OK if it already exists)
            if (!EnsureTargetRootReady(normalizedRoot))
                return;

            // Now that we have a valid target, re-init logger to write there
            string? userProfile = ResolveUserProfilePath(sourceUser);
            if (userProfile == null)
            {
                Logger.Log($"❌ Could not find a profile folder for '{sourceUser}'. Backup aborted.");
                return;
            }

            string backupPath = Path.Combine(backupRoot, sourceUser);
            string appDataPath = Path.Combine(backupPath, "appdata");

            Directory.CreateDirectory(backupPath);
            Directory.CreateDirectory(appDataPath);

            Logger.Init(Path.Combine(backupPath, "backup_log.txt"));

            // 🔹 Kill processes before backup
            TerminateProcesses();

            // --- ensure Login Data files are unlocked before proceeding ---
            string loginDataChrome = Path.Combine(userProfile, "AppData", "Local", "Google", "Chrome", "User Data", "Default", "Login Data");
            string loginDataEdge = Path.Combine(userProfile, "AppData", "Local", "Microsoft", "Edge", "User Data", "Default", "Login Data");

            // Wait for exclusive access to critical DBs (chrome required; edge optional)
            if (!EnsureUnlocked(loginDataChrome))
            {
                Logger.Log("❌ Aborting backup: Chrome Login Data locked. Consider stopping Chrome and re-running backup.");
                return;
            }

            bool edgeUnlocked = EnsureUnlocked(loginDataEdge);
            if (!edgeUnlocked)
            {
                Logger.Log("⚠ Edge Login Data locked or not present. Edge password export will be skipped.");
            }

            // 🔹 Collect tech info (after locks verified)
            CollectTechInfo(Path.Combine(backupPath, @"OTHER\tech info.txt"));

            // --- PRESCAN: Pre-scan all files to get a global total (unchanged) ---
            var profileDirs = new[]
            {
                "Contacts", "Desktop", "Documents", "Downloads", "Favorites",
                "Links", "Music", "Pictures", "Saved Games", "Searches", "Videos"
            };

            var appDataDirs = new Dictionary<string, string>
            {
                { @"appdata\local\dymo", Path.Combine(appDataPath, @"local\dymo") },
                { @"appdata\local\google", Path.Combine(appDataPath, @"local\google") },
                { @"appdata\local\google\chrome\user data\default", Path.Combine(appDataPath, @"local\google\chrome\user data\default") },
                { @"appdata\local\mozilla", Path.Combine(appDataPath, @"local\mozilla") },
                { @"appdata\local\microsoft\outlook", Path.Combine(appDataPath, @"local\microsoft\outlook") },
                { @"appdata\roaming\mozilla", Path.Combine(appDataPath, @"roaming\mozilla") },
                { @"appdata\roaming\microsoft\signatures", Path.Combine(appDataPath, @"roaming\microsoft\signatures") },
                { @"appdata\local\Microsoft\Edge\User Data", Path.Combine(appDataPath, @"local\Microsoft\Edge\User Data") },
                { @"appdata\local\Microsoft\Edge\User Data\Default", Path.Combine(appDataPath, @"local\Microsoft\Edge\User Data\Default") }
            };

            var extraAppDataDirs = new Dictionary<string, string>
            {
                { @"appdata\roaming\align", Path.Combine(appDataPath, @"roaming\align") },
                { @"appdata\roaming\DYMO Stamps", Path.Combine(appDataPath, @"roaming\DYMO Stamps") },
                { @"appdata\roaming\microsoft\spelling", Path.Combine(appDataPath, @"roaming\microsoft\spelling") },
                { @"appdata\roaming\microsoft\stationary", Path.Combine(appDataPath, @"roaming\microsoft\stationary") },
                { @"appdata\roaming\microsoft\sticky notes", Path.Combine(appDataPath, @"roaming\microsoft\sticky notes") },
                { @"appdata\roaming\Venga5", Path.Combine(appDataPath, @"roaming\Venga5") },
                { @"appdata\roaming\Spark", Path.Combine(appDataPath, @"roaming\Spark") },
                { @"appdata\local\packages\Microsoft.MicrosoftEdge_8wekyb3d8bbwe\AC\MicrosoftEdge\User\Default\Favorites",
                  Path.Combine(appDataPath, @"local\packages\Microsoft.MicrosoftEdge_8wekyb3d8bbwe\AC\MicrosoftEdge\User\Default\Favorites") }
            };

            var extraDirs = new Dictionary<string, string>
            {
                { @"C:\Program Files\Dexis\FlashDir", Path.Combine(backupPath, @"OTHER\Program Files\Dexis\FlashDir") },
                { @"C:\Program Files (x86)\Dexis\FlashDir", Path.Combine(backupPath, @"OTHER\Program Files (x86)\Dexis\FlashDir") },
                { @"C:\Dexis\FlashDir", Path.Combine(backupPath, @"OTHER\Dexis\FlashDir") },
                { @"C:\ProgramData\Dexis\FlashDir", Path.Combine(backupPath, @"OTHER\ProgramData\Dexis\FlashDir") },
                { @"C:\Program Files (x86)\Cadent", Path.Combine(backupPath, @"OTHER\Program Files (x86)\Cadent") },
                { @"C:\Program Files\ISIP\iCATVision", Path.Combine(backupPath, @"OTHER\ISIP\iCATVision") },
                { @"C:\Program Files\Align", Path.Combine(backupPath, @"OTHER\Program Files\Align") },
                { @"C:\Program Files (x86)\Align", Path.Combine(backupPath, @"OTHER\Program Files (x86)\Align") },
                { @"C:\Users\Public\Documents", Path.Combine(backupPath, @"OTHER\Public") }
            };

            // Merge extra AppData into main set
            foreach (var kvp in extraAppDataDirs)
                appDataDirs[kvp.Key] = kvp.Value;

            // 1 Pre‑scan all files to get a global total
            _filesCopied = 0;
            _totalFiles = CountAllFiles(userProfile, profileDirs, appDataDirs, extraDirs);

            Logger.Log($"📊 Found {_totalFiles} files to back up.");

            // 2 Export browser passwords
            Logger.Log("🔐 Exporting browser passwords (early-phase)...");
            await DecryptorMethods.ExportBrowserPasswordsAsync("Chrome", backupPath);
            if (edgeUnlocked)
            {
                await DecryptorMethods.ExportBrowserPasswordsAsync("Edge", backupPath);
            }
            else
            {
                Logger.Log("⚠ Skipped Edge password export due to locked/missing Login Data.");
            }

            // 3 Copy profile directories
            foreach (var dir in profileDirs)
            {
                string source = Path.Combine(userProfile, dir);
                string destination = Path.Combine(backupPath, dir);
                await CopyIfExistsAsync(source, destination);
            }

            // 4 Copy AppData directories
            foreach (var kvp in appDataDirs)
            {
                string source = Path.Combine(userProfile, kvp.Key);
                string destination = kvp.Value;
                await CopyIfExistsAsync(source, destination);
            }

            // 5 Copy extra program/public dirs
            foreach (var kvp in extraDirs)
            {
                await CopyIfExistsAsync(kvp.Key, kvp.Value);
            }

            // 6 Export HKCU hive
            ExportHKCU(backupPath);

            Logger.Log("✅ Backup complete.");
            ProgressChanged?.Invoke(_totalFiles, _totalFiles, "Backup Complete");
        }

        // --- Current user info helpers ---
        public static class CurrentUserInfo
        {
            public static string GetUserPrincipal()
            {
                try { return WindowsIdentity.GetCurrent()?.Name ?? Environment.UserName; }
                catch { return Environment.UserName; }
            }

            public static string GetUserSid()
            {
                try
                {
                    var id = WindowsIdentity.GetCurrent()?.User;
                    return id?.Value ?? string.Empty;
                }
                catch { return string.Empty; }
            }
        }

        // --- Test if path is accessible ---
        private bool TestPathAccess(string path)
        {
            try
            {
                if (Directory.Exists(path))
                {
                    Directory.GetDirectories(path);
                    return true;
                }
                return false;
            }
            catch (IOException ex) when (ex.Message.Contains("user name or password", StringComparison.OrdinalIgnoreCase))
            {
                return false;
            }
            catch (UnauthorizedAccessException)
            {
                return false;
            }
        }

        // --- Helpers for UNC path handling ---
        private static string NormalizePath(string path)
        {
            return path.TrimEnd('\\', '/');
        }

        // Get parent directory of a given path
        private static string GetParentPath(string path)
        {
            var normalized = NormalizePath(path);
            // Path.GetDirectoryName handles both UNC and local (returns \\Server\Share for \\Server\Share\Folder)
            return Path.GetDirectoryName(normalized) ?? normalized;
        }

        // Ensure target root directory exists and is writable
        private bool EnsureTargetRootReady(string targetRoot)
        {
            var normalized = NormalizePath(targetRoot);
            var parent = GetParentPath(normalized);

            // 1) Ensure we can access the parent (prompt/connect if needed happens in caller)
            if (!TestPathAccess(parent))
            {
                Logger.Log($"❌ Cannot access parent directory '{parent}'.");
                return false;
            }

            // 2) Create target if missing; no-op if it already exists
            try
            {
                Directory.CreateDirectory(normalized);
                Logger.Log($"📁 Target directory ready: '{normalized}'");
                return true;
            }
            catch (Exception ex)
            {
                Logger.Log($"❌ Failed to create target directory '{normalized}': {ex.Message}");
                return false;
            }
        }

        // --- Simple WPF credential prompt  ---
        private (string user, string pass)? PromptForCredentials(string sharePath)
        {
            var dialog = new CredentialPromptWindow(sharePath)
            {
                Owner = Application.Current.MainWindow
            };

            if (dialog.ShowDialog() == true)
            {
                return (dialog.Username, dialog.Password);
            }
            return null;
        }

        // --- Connect to network share ---
        private bool ConnectToShare(string sharePath, string username, string password)
        {
            var nr = new NETRESOURCE
            {
                dwType = 1, // RESOURCETYPE_DISK
                lpRemoteName = sharePath
            };

            int result = WNetAddConnection2(ref nr, password, username, 0);
            return result == 0;
        }

        // Count all files in specified directories for progress tracking
        private int CountAllFiles(
            string userProfile,
            string[] profileDirs,
            Dictionary<string, string> appDataDirs,
            Dictionary<string, string> extraDirs)
        {
            int count = 0;

            // Profile dirs
            foreach (var dir in profileDirs)
            {
                string source = Path.Combine(userProfile, dir);
                count += CountDirFiles(source);
            }

            // AppData dirs
            foreach (var kvp in appDataDirs)
            {
                string source = Path.Combine(userProfile, kvp.Key);
                count += CountDirFiles(source);
            }

            // Extra absolute dirs
            foreach (var kvp in extraDirs)
            {
                string source = kvp.Key;
                count += CountDirFiles(source);
            }

            return count;
        }

        private int CountDirFiles(string source)
        {
            if (Directory.Exists(source) && !IsReparsePoint(source))
            {
                try
                {
                    return Directory.GetFiles(source, "*", SearchOption.AllDirectories).Length;
                }
                catch (Exception ex)
                {
                    Logger.Log($"⚠ Skipped '{source}' during file count: {ex.Message}");
                }
            }
            else if (IsReparsePoint(source))
            {
                Logger.Log($"⚠ Skipped reparse point '{source}' during file count.");
            }
            return 0;
        }

        // Helper to copy directories if they exist
        private async Task CopyIfExistsAsync(string source, string destination)
        {
            if (Directory.Exists(source))
            {
                await Task.Run(() => CopyDirectory(source, destination));
                Logger.Log($"✔ Copied '{source}'");
            }
            else
            {
                Logger.Log($"⚠ Skipped '{source}' (not found)");
            }
        }

        // Core directory copy logic with progress updates
        private void CopyDirectory(string sourceDir, string destDir)
        {
            if (IsReparsePoint(sourceDir))
            {
                Logger.Log($"⚠ Skipped reparse point '{sourceDir}' during copy.");
                return;
            }

            try
            {
                Directory.CreateDirectory(destDir);
            }
            catch (IOException ex)
            {
                Logger.Log($"❌ Failed to create backup directory: {ex.Message}");
                return;
            }

            string[] allFiles;
            try
            {
                allFiles = Directory.GetFiles(sourceDir, "*", SearchOption.AllDirectories);
            }
            catch (Exception ex)
            {
                Logger.Log($"⚠ Failed to enumerate files in '{sourceDir}': {ex.Message}");
                return;
            }

            foreach (var file in allFiles)
            {
                var relativePath = file.Substring(sourceDir.Length + 1);
                var destFile = Path.Combine(destDir, relativePath);

                var dirName = Path.GetDirectoryName(destFile);
                if (!string.IsNullOrEmpty(dirName))
                {
                    try
                    {
                        Directory.CreateDirectory(dirName);
                    }
                    catch (Exception ex)
                    {
                        Logger.Log($"⚠ Failed to create directory '{dirName}': {ex.Message}");
                        continue;
                    }
                }

                try
                {
                    File.Copy(file, destFile, true);
                    _filesCopied++;
                    Logger.Log($"Copied file: {relativePath}");
                    ProgressChanged?.Invoke(_filesCopied, _totalFiles, $"Copying file: {relativePath}");
                }
                catch (Exception ex)
                {
                    Logger.Log($"⚠ Failed to copy '{relativePath}': {ex.Message}");
                }
            }
        }

        // Resolve user profile path from username
        private string? ResolveUserProfilePath(string inputUser)
        {
            string userPart = inputUser.Contains("\\")
                ? inputUser.Split('\\')[1]
                : inputUser;

            string basePath = Path.Combine(@"C:\Users", userPart);

            if (Directory.Exists(basePath))
                return basePath;

            var matches = Directory.GetDirectories(@"C:\Users", userPart + ".*");
            if (matches.Length > 0)
                return matches[0];

            return null;
        }

        // Check if a directory is a reparse point (symlink/junction)
        private bool IsReparsePoint(string path)
        {
            try
            {
                var attr = File.GetAttributes(path);
                return (attr & FileAttributes.ReparsePoint) != 0;
            }
            catch
            {
                return false; // If we can't read attributes, treat it as non-reparse
            }
        }

        // Collect technical info for troubleshooting
        private void CollectTechInfo(string outputPath)
        {
            Directory.CreateDirectory(Path.GetDirectoryName(outputPath)!);
            using var writer = new StreamWriter(outputPath, append: true);

            writer.WriteLine(DateTime.Now.ToString("F"));
            writer.WriteLine("-------------------");
            writer.WriteLine("NETWORK DRIVES");
            writer.WriteLine("-------------------");
            writer.WriteLine(RunCommand("net", "use"));
            writer.WriteLine("-------------------");
            writer.WriteLine("PRINTERS");
            writer.WriteLine("-------------------");
            try
            {
                writer.WriteLine(RunCommand(
                    "powershell",
                    "-NoProfile -ExecutionPolicy Bypass -Command \"Get-Printer | Format-Table -AutoSize\""
                ));
            }
            catch (Exception ex)
            {
                Logger.Log($"⚠ Failed to collect printer info: {ex.Message}");
            }
            writer.WriteLine("-------------------");
            writer.WriteLine("IP AND NETWORK INFORMATION");
            writer.WriteLine("-------------------");
            writer.WriteLine(RunCommand("ipconfig", "/all"));
            writer.WriteLine("-------------------");
            writer.WriteLine("SHARED RESOURCE INFO");
            writer.WriteLine("-------------------");
            writer.WriteLine(RunCommand("net", "share"));
        }

        // Helper to run a command and capture output
        private string RunCommand(string fileName, string args)
        {
            try
            {
                var psi = new ProcessStartInfo(fileName, args)
                {
                    RedirectStandardOutput = true,
                    UseShellExecute = false,
                    CreateNoWindow = true
                };
                using var proc = Process.Start(psi);
                return proc?.StandardOutput.ReadToEnd() ?? "";
            }
            catch (Win32Exception ex) when (ex.NativeErrorCode == 2)
            {
                Logger.Log($"⚠ Command '{fileName}' not found on this system.");
                return "";
            }
            catch (Exception ex)
            {
                Logger.Log($"⚠ Failed to run '{fileName} {args}': {ex.Message}");
                return "";
            }
        }

        // Terminate known processes that may lock files
        private void TerminateProcesses()
        {
            string[] targets = { "chrome", "msedge", "firefox", "OUTLOOK", "StikyNot" }; // adjust to real names on host
            foreach (var name in targets)
            {
                var procs = Process.GetProcessesByName(name);
                if (procs.Length == 0) continue;
                Logger.Log($"🛑 Terminating {procs.Length} process(es) named: {name}");
                foreach (var proc in procs)
                {
                    try
                    {
                        if (!proc.HasExited)
                        {
                            try { proc.CloseMainWindow(); } catch { /* ignore */ }
                            if (!proc.WaitForExit(3000))
                            {
                                proc.Kill();
                                proc.WaitForExit(5000);
                            }
                        }
                        Logger.Log($"✔ Terminated process: {name} (pid {proc.Id})");
                    }
                    catch (Exception ex)
                    {
                        Logger.Log($"⚠ Failed to terminate {name} (pid {proc.Id}): {ex.Message}");
                    }
                }
            }

            // extra safety: small pause then re-check and log remaining processes of interest
            Thread.Sleep(500);
            foreach (var name in targets)
            {
                var remaining = Process.GetProcessesByName(name);
                if (remaining.Length > 0)
                    Logger.Log($"⚠ Still {remaining.Length} process(es) named {name} remain after termination attempts.");
            }
        }

        // Export selected HKCU registry keys to .reg files
        private void ExportHKCU(string backupPath)
        {
            var targets = new Dictionary<string, string>
            {
                { "Console", "HKCU\\Console" },
                { "File Explorer", "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer" },
                { "Printers", "HKCU\\Software\\Microsoft\\Windows NT\\CurrentVersion\\PrinterPorts" },
                { "NetworkDrives", "HKCU\\Network" },
                { "MountedDevices", "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\MountPoints2" },
                { "UserAssist", "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\UserAssist" },
                { "RunOnce", "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce" },
                { "Run", "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run" },
                { "OutlookProfiles", "HKCU\\Software\\Microsoft\\Office" },
                { "StickyNotes", "HKCU\\Software\\Microsoft\\Sticky Notes" },
                { "FileExts", "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\FileExts" },
                { "RecentDocs", "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\RecentDocs" },
                { "Theme", "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Themes" },
                { "AppEvents", "HKCU\\AppEvents" },
                { "Colors", "HKCU\\Software\\Microsoft\\Windows\\DWM" },
                { "KeyboardLayout", "HKCU\\Keyboard Layout" },
                { "Environment", "HKCU\\Environment" },
                { "Taskbar", "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Taskband" },
                { "Edge", "HKCU\\Software\\Microsoft\\Edge" },
                { "Chrome", "HKCU\\Software\\Google\\Chrome" },
                { "RDP", "HKCU\\Software\\Microsoft\\Terminal Server Client" }
            };

            // ensure RegKeys folder exists
            string regFolder = Path.Combine(backupPath, "RegKeys");
            Directory.CreateDirectory(regFolder);

            foreach (var kvp in targets)
            {
                try
                {
                    string subKeyPath = kvp.Value.Substring("HKCU\\".Length);
                    using var key = Registry.CurrentUser.OpenSubKey(subKeyPath);
                    if (key == null || (key.GetValueNames().Length == 0 && key.GetSubKeyNames().Length == 0))
                    {
                        Logger.Log($"⚠ Skipping {kvp.Key} — key not found or empty: {kvp.Value}");
                        continue;
                    }

                    // sanitize filename to avoid characters invalid for file names
                    string safeName = string.Join("_", kvp.Key.Split(Path.GetInvalidFileNameChars()));
                    string regFile = Path.Combine(regFolder, $"{safeName}.reg");
                    var psi = new ProcessStartInfo("reg.exe", $"export \"{kvp.Value}\" \"{regFile}\" /y")
                    {
                        UseShellExecute = false,
                        CreateNoWindow = true
                    };

                    using var proc = Process.Start(psi);
                    if (proc != null)
                    {
                        proc.WaitForExit();
                        if (proc.ExitCode == 0)
                            Logger.Log($"✅ Exported {kvp.Key} to: {regFile}");
                        else
                            Logger.Log($"⚠ reg.exe exited with code {proc.ExitCode} — {kvp.Key} export may have failed.");
                    }
                    else
                    {
                        Logger.Log($"❌ Failed to start reg.exe for {kvp.Key} — process was null.");
                    }
                }
                catch (Exception ex)
                {
                    Logger.Log($"❌ Exception while exporting {kvp.Key}: {ex.Message}");
                }
            }
        }
    }
}