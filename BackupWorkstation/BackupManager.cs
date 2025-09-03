using System;
using System.Collections.Generic;
using System.IO;
using System.Runtime.Versioning;
using System.Threading.Tasks;

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

        // Main backup method
        public async Task RunBackupAsync(string sourceUser, string backupRoot)
        {
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

        // Helper to count all files in specified directories
        private int CountAllFiles(string userProfile, string[] profileDirs, Dictionary<string, string> appDataDirs)
        {
            int count = 0;

            foreach (var dir in profileDirs)
            {
                string source = Path.Combine(userProfile, dir);
                if (Directory.Exists(source))
                    count += Directory.GetFiles(source, "*", SearchOption.AllDirectories).Length;
            }

            foreach (var kvp in appDataDirs)
            {
                string source = Path.Combine(userProfile, kvp.Key);
                if (Directory.Exists(source))
                    count += Directory.GetFiles(source, "*", SearchOption.AllDirectories).Length;
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
            Directory.CreateDirectory(destDir);

            var allFiles = Directory.GetFiles(sourceDir, "*", SearchOption.AllDirectories);

            foreach (var file in allFiles)
            {
                var relativePath = file.Substring(sourceDir.Length + 1);
                var destFile = Path.Combine(destDir, relativePath);

                var dirName = Path.GetDirectoryName(destFile);
                if (!string.IsNullOrEmpty(dirName))
                    Directory.CreateDirectory(dirName);

                try
                {
                    File.Copy(file, destFile, true);
                    _filesCopied++;
                    Log($"Copied file: {relativePath}");

                    // Global per‑file progress update
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

        // Logging helper
        private void Log(string message)
        {
            Logger.Log(message);
            LogMessage?.Invoke(message);
        }
    }
}