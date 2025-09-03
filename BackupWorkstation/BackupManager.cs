using System;
using System.Collections.Generic;
using System.IO;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Threading.Tasks;
using System.Windows;

namespace BackupWorkstation
{
    [SupportedOSPlatform("windows")]
    public class BackupManager
    {
        // Events
        public event Action<string>? LogMessage;
        public event Action<int, int, string>? ProgressChanged;

        // Fields
        private int _filesCopied;
        private int _totalFiles;

        // --- NEW: Win32 API for network share connection ---
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

        // Main backup method
        public async Task RunBackupAsync(string sourceUser, string backupRoot)
        {
            // Always have a logger target, even if backupRoot is inaccessible
            string tempLogPath = Path.Combine(Path.GetTempPath(), "BackupWorkstation_startup_log.txt");
            Logger.Init(tempLogPath);

            // --- Preflight UNC path access check ---
            if (!TestPathAccess(backupRoot))
            {
                Log($"⚠ Cannot access '{backupRoot}'. Prompting for credentials...");
                var creds = PromptForCredentials(backupRoot);
                if (creds.HasValue)
                {
                    if (!ConnectToShare(backupRoot, creds.Value.user, creds.Value.pass))
                    {
                        Log("❌ Could not connect to network share with provided credentials. Backup aborted.");
                        return;
                    }
                    else
                    {
                        Log("🔑 Network share connected successfully.");
                    }
                }
                else
                {
                    Log("❌ Backup cancelled — no credentials provided.");
                    return;
                }
            }

            string? userProfile = ResolveUserProfilePath(sourceUser);

            if (userProfile == null)
            {
                Log($"❌ Could not find a profile folder for '{sourceUser}'. Backup aborted.");
                return;
            }

            string backupPath = Path.Combine(backupRoot, sourceUser);
            string appDataPath = Path.Combine(backupPath, "appdata");

            Directory.CreateDirectory(backupPath);
            Directory.CreateDirectory(appDataPath);

            Logger.Init(Path.Combine(backupPath, "backup_log.txt"));

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

            // 1️ Pre‑scan all files to get a global total
            _filesCopied = 0;
            _totalFiles = CountAllFiles(userProfile, profileDirs, appDataDirs);

            Log($"📊 Found {_totalFiles} files to back up.");

            // 2️ Copy profile directories
            foreach (var dir in profileDirs)
            {
                string source = Path.Combine(userProfile, dir);
                string destination = Path.Combine(backupPath, dir);
                await CopyIfExistsAsync(source, destination);
            }

            // 3️ Copy AppData directories
            foreach (var kvp in appDataDirs)
            {
                string source = Path.Combine(userProfile, kvp.Key);
                string destination = kvp.Value;
                await CopyIfExistsAsync(source, destination);
            }

            Logger.Log("✅ Backup complete.");
            ProgressChanged?.Invoke(_totalFiles, _totalFiles, "Backup Complete");
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
        private int CountAllFiles(string userProfile, string[] profileDirs, Dictionary<string, string> appDataDirs)
        {
            int count = 0;

            foreach (var dir in profileDirs)
            {
                string source = Path.Combine(userProfile, dir);
                if (Directory.Exists(source) && !IsReparsePoint(source))
                {
                    try
                    {
                        count += Directory.GetFiles(source, "*", SearchOption.AllDirectories).Length;
                    }
                    catch (Exception ex)
                    {
                        Log($"⚠ Skipped '{source}' during file count: {ex.Message}");
                    }
                }
                else if (IsReparsePoint(source))
                {
                    Log($"⚠ Skipped reparse point '{source}' during file count.");
                }
            }

            foreach (var kvp in appDataDirs)
            {
                string source = Path.Combine(userProfile, kvp.Key);
                if (Directory.Exists(source) && !IsReparsePoint(source))
                {
                    try
                    {
                        count += Directory.GetFiles(source, "*", SearchOption.AllDirectories).Length;
                    }
                    catch (Exception ex)
                    {
                        Log($"⚠ Skipped '{source}' during file count: {ex.Message}");
                    }
                }
                else if (IsReparsePoint(source))
                {
                    Log($"⚠ Skipped reparse point '{source}' during file count.");
                }
            }

            return count;
        }

        // Helper to copy directories if they exist
        private async Task CopyIfExistsAsync(string source, string destination)
        {
            if (Directory.Exists(source))
            {
                await Task.Run(() => CopyDirectory(source, destination));
                Log($"✔ Copied '{source}'");
            }
            else
            {
                Log($"⚠ Skipped '{source}' (not found)");
            }
        }

        // Core directory copy logic with progress updates
        private void CopyDirectory(string sourceDir, string destDir)
        {
            if (IsReparsePoint(sourceDir))
            {
                Log($"⚠ Skipped reparse point '{sourceDir}' during copy.");
                return;
            }

            try
            {
                Directory.CreateDirectory(destDir);
            }
            catch (IOException ex)
            {
                Log($"❌ Failed to create backup directory: {ex.Message}");
                return;
            }

            string[] allFiles;
            try
            {
                allFiles = Directory.GetFiles(sourceDir, "*", SearchOption.AllDirectories);
            }
            catch (Exception ex)
            {
                Log($"⚠ Failed to enumerate files in '{sourceDir}': {ex.Message}");
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
                        Log($"⚠ Failed to create directory '{dirName}': {ex.Message}");
                        continue;
                    }
                }

                try
                {
                    File.Copy(file, destFile, true);
                    _filesCopied++;
                    Log($"Copied file: {relativePath}");
                    ProgressChanged?.Invoke(_filesCopied, _totalFiles, $"Copying file: {relativePath}");
                }
                catch (Exception ex)
                {
                    Log($"⚠ Failed to copy '{relativePath}': {ex.Message}");
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

        // --- Secure password input for console ---
        private string ReadPassword()
        {
            var pass = string.Empty;
            ConsoleKey key;
            do
            {
                var keyInfo = Console.ReadKey(intercept: true);
                key = keyInfo.Key;

                if (key == ConsoleKey.Backspace && pass.Length > 0)
                {
                    pass = pass.Substring(0, pass.Length - 1);
                    Console.Write("\b \b"); // erase last char
                }
                else if (!char.IsControl(keyInfo.KeyChar))
                {
                    pass += keyInfo.KeyChar;
                    Console.Write("*");
                }
            }
            while (key != ConsoleKey.Enter);

            Console.WriteLine();
            return pass;
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

        // Logging helper
        private void Log(string message)
        {
            Logger.Log(message);
            LogMessage?.Invoke(message);
        }
    }
}