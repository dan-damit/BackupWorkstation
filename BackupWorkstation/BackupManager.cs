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
using System.Text;
using System.Text.Json;
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

        // --- Main backup method ---
        public async Task RunBackupAsync(string sourceUser, string backupRoot)
        {
            // Always have a logger target, even if backupRoot is inaccessible
            string tempLogPath = Path.Combine(Path.GetTempPath(), "BackupWorkstation_startup_log.txt");
            Logger.Init(tempLogPath);

            var normalizedRoot = NormalizePath(backupRoot);
            var parentPath = GetParentPath(normalizedRoot);

            // Preflight against the parent (since the final folder may not exist yet)
            if (!TestPathAccess(parentPath))
            {
                Log($"⚠ Cannot access '{parentPath}'. Prompting for credentials...");
                var creds = PromptForCredentials(parentPath);
                if (creds.HasValue)
                {
                    if (!ConnectToShare(parentPath, creds.Value.user, creds.Value.pass))
                    {
                        Log("❌ Could not connect to network share with provided credentials. Backup aborted.");
                        return;
                    }
                    Log("🔑 Network share connected successfully.");
                }
                else
                {
                    Log("❌ Backup cancelled — no credentials provided.");
                    return;
                }
            }

            // Ensure the final target directory exists (create if missing; OK if it already exists)
            if (!EnsureTargetRootReady(normalizedRoot))
                return;

            // Now that we have a valid target, re-init logger to write there
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

            // 🔹 Kill processes before backup
            TerminateProcesses();

            // 🔹 Collect tech info
            CollectTechInfo(Path.Combine(backupPath, @"OTHER\tech info.txt"));

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

            // 1️ Pre‑scan all files to get a global total
            _filesCopied = 0;
            _totalFiles = CountAllFiles(userProfile, profileDirs, appDataDirs, extraDirs);

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

            // 4️ Copy extra program/public dirs
            foreach (var kvp in extraDirs)
            {
                await CopyIfExistsAsync(kvp.Key, kvp.Value);
            }

            // 5️ Export browser passwords and HKCU hive
            await ExportBrowserPasswordsAsync("Chrome", backupPath);
            await ExportBrowserPasswordsAsync("Edge", backupPath);
            ExportHKCU(backupPath);

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

        // --- Browser password export helpers ---
        public async Task ExportBrowserPasswordsAsync(string browserName, string backupPath)
        {
            string basePath = browserName switch
            {
                "Chrome" => Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), @"Google\Chrome\User Data"),
                "Edge" => Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), @"Microsoft\Edge\User Data"),
                _ => throw new ArgumentException("Unsupported browser")
            };

            string loginDataPath = Path.Combine(basePath, @"Default\Login Data");
            string localStatePath = Path.Combine(basePath, "Local State");
            string outputCsv = Path.Combine(backupPath, $"{browserName}Passwords.csv");

            if (!File.Exists(loginDataPath) || !File.Exists(localStatePath))
            {
                Logger.Log($"⚠ {browserName} password files not found at expected paths.");
                return;
            }

            string tempDb = Path.Combine(Path.GetTempPath(), $"{browserName}_LoginData_{Guid.NewGuid():N}.db");
            byte[]? aesKey = null;

            try
            {
                aesKey = await GetDecryptedKeyAsync(localStatePath);
                Logger.Log($"Export: obtained AES key len={(aesKey?.Length ?? 0)}");

                if (aesKey == null || aesKey.Length != 32)
                {
                    Logger.Log($"❌ {browserName} AES key invalid length: {(aesKey?.Length ?? 0)}; expected 32 bytes.");
                    return;
                }

                File.Copy(loginDataPath, tempDb, true);
                if (!File.Exists(tempDb))
                {
                    Logger.Log($"❌ Failed to copy Login Data to temp DB: {tempDb}");
                    return;
                }

                Logger.Log($"Export: opened temp DB at {tempDb}");

                using var conn = new SqliteConnection($"Data Source={tempDb};Mode=ReadOnly;Cache=Shared");
                conn.Open();

                using var cmd = new SqliteCommand("SELECT origin_url, username_value, password_value FROM logins", conn);
                using var reader = cmd.ExecuteReader();

                using var writer = new StreamWriter(outputCsv, false, Encoding.UTF8);
                writer.WriteLine("URL,Username,Password");

                int exported = 0;
                int failed = 0;

                // Reader loop per line
                int decryptedCount = 0;
                int writtenCount = 0;
                int failedDecryptCount = 0;

                while (reader.Read())
                {
                    string url = reader.IsDBNull(0) ? string.Empty : reader.GetString(0);
                    string username = reader.IsDBNull(1) ? string.Empty : reader.GetString(1);
                    byte[] encryptedPassword = reader.IsDBNull(2) ? Array.Empty<byte>() : (byte[])reader["password_value"];

                    // Use exhaustive variant tester (keeps all keys local)
                    var diag = TryExhaustiveDecrypt(encryptedPassword, aesKey!, url);

                    string password;
                    if (diag.Success)
                    {
                        decryptedCount++;
                        // diag.PlainText may be empty for blank passwords
                        password = diag.PlainText ?? string.Empty;
                    }
                    else
                    {
                        failedDecryptCount++;
                        password = "[UNABLE TO DECRYPT]";
                        Logger.Log($"❌ Decryption failed for {url}: {diag.Error} | Iv:{diag.IvHex} Tag:{diag.TagHex} Ct:{diag.CtHexSample}");
                    }

                    try
                    {
                        writer.WriteLine($"{CsvEscape(url)},{CsvEscape(username)},{CsvEscape(password)}");
                        writtenCount++;
                    }
                    catch (Exception rowEx)
                    {
                        Logger.Log($"⚠ Failed writing CSV row for {url}: {rowEx.Message}");
                    }
                }

                Logger.Log($"🔐 Export summary: decrypted={decryptedCount} failedDecrypts={failedDecryptCount} rowsWritten={writtenCount}");

                writer.Flush();
                Logger.Log($"🔐 Exported {exported} {browserName} password entries to: {outputCsv} (failed: {failed})");
            }
            catch (Exception ex)
            {
                Logger.Log($"❌ Failed to export {browserName} passwords: {ex.Message}");
            }
            finally
            {
                // clear sensitive key material
                if (aesKey != null)
                {
                    Array.Clear(aesKey, 0, aesKey.Length);
                }

                // Ensure all handles released before attempting delete
                try
                {
                    GC.Collect();
                    GC.WaitForPendingFinalizers();
                    Thread.Sleep(100);

                    if (File.Exists(tempDb))
                    {
                        // retry delete in a small loop if locked
                        for (int i = 0; i < 3; i++)
                        {
                            try
                            {
                                File.Delete(tempDb);
                                Logger.Log($"Cleanup: deleted temp DB {tempDb}");
                                break;
                            }
                            catch (IOException)
                            {
                                Thread.Sleep(100);
                            }
                        }
                    }
                }
                catch (Exception ex)
                {
                    Logger.Log($"Cleanup: failed to delete temp DB {tempDb}: {ex.Message}");
                }
            }
        }

        private static string CsvEscape(string s)
        {
            if (s == null) return "\"\"";
            string escaped = s.Replace("\"", "\"\"");
            return $"\"{escaped}\"";
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
                Log($"❌ Cannot access parent directory '{parent}'.");
                return false;
            }

            // 2) Create target if missing; no-op if it already exists
            try
            {
                Directory.CreateDirectory(normalized);
                Log($"📁 Target directory ready: '{normalized}'");
                return true;
            }
            catch (Exception ex)
            {
                Log($"❌ Failed to create target directory '{normalized}': {ex.Message}");
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
                    Log($"⚠ Skipped '{source}' during file count: {ex.Message}");
                }
            }
            else if (IsReparsePoint(source))
            {
                Log($"⚠ Skipped reparse point '{source}' during file count.");
            }
            return 0;
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
                Log($"⚠ Failed to collect printer info: {ex.Message}");
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
                Log($"⚠ Command '{fileName}' not found on this system.");
                return "";
            }
            catch (Exception ex)
            {
                Log($"⚠ Failed to run '{fileName} {args}': {ex.Message}");
                return "";
            }
        }

        // Terminate known processes that may lock files
        private void TerminateProcesses()
        {
            string[] targets = {
        "firefox", "chrome", "outlook", "StikyNot",
        "MicrosoftEdge", "MicrosoftEdgeCP"
        };
            foreach (var name in targets)
            {
                foreach (var proc in Process.GetProcessesByName(name))
                {
                    try
                    {
                        proc.Kill();
                        Log($"🛑 Terminated process: {name}.exe");
                    }
                    catch (Exception ex)
                    {
                        Log($"⚠ Failed to terminate {name}.exe: {ex.Message}");
                    }
                }
            }
        }

        // Decrypt Chrome/Edge password using AES-GCM
        private async Task<byte[]?> GetDecryptedKeyAsync(string localStatePath)
        {
            try
            {
                using var stream = File.OpenRead(localStatePath);
                using var doc = await JsonDocument.ParseAsync(stream);

                if (!doc.RootElement.TryGetProperty("os_crypt", out var osCrypt) ||
                    !osCrypt.TryGetProperty("encrypted_key", out var encryptedKeyElem))
                {
                    Logger.Log($"GetDecryptedKey: missing os_crypt/encrypted_key in {localStatePath}");
                    return null;
                }

                string encryptedKeyBase64 = encryptedKeyElem.GetString() ?? string.Empty;
                if (string.IsNullOrWhiteSpace(encryptedKeyBase64))
                {
                    Logger.Log("GetDecryptedKey: encrypted_key was empty");
                    return null;
                }

                byte[] encryptedKey;
                try
                {
                    encryptedKey = Convert.FromBase64String(encryptedKeyBase64);
                }
                catch (FormatException fex)
                {
                    Logger.Log($"GetDecryptedKey: base64 decode failed: {fex.Message}");
                    return null;
                }

                const string dpapiPrefix = "DPAPI";
                var prefixBytes = Encoding.ASCII.GetBytes(dpapiPrefix);
                if (encryptedKey.Length <= prefixBytes.Length ||
                    !encryptedKey.Take(prefixBytes.Length).SequenceEqual(prefixBytes))
                {
                    Logger.Log("GetDecryptedKey: encrypted_key does not start with expected DPAPI prefix");
                    return null;
                }

                byte[] dpapiBlob = encryptedKey.Skip(prefixBytes.Length).ToArray();
                Logger.Log($"GetDecryptedKey: dpapi blob len={dpapiBlob.Length}");

                byte[]? unprotected;
                try
                {
                    unprotected = ProtectedData.Unprotect(dpapiBlob, null, DataProtectionScope.CurrentUser);
                }
                catch (Exception ex)
                {
                    Logger.Log($"GetDecryptedKey: ProtectedData.Unprotect failed: {ex.Message}");
                    return null;
                }
                finally
                {
                    Array.Clear(dpapiBlob, 0, dpapiBlob.Length);
                }

                if (unprotected == null)
                {
                    Logger.Log("GetDecryptedKey: unprotected is null");
                    return null;
                }

                if (unprotected.Length != 32)
                {
                    Logger.Log($"GetDecryptedKey: unexpected key length={unprotected.Length}; Chrome expects 32 bytes. Aborting.");
                    Array.Clear(unprotected, 0, unprotected.Length);
                    return null;
                }

                string sample = BitConverter.ToString(unprotected, 0, Math.Min(8, unprotected.Length)).Replace("-", "");
                Logger.Log($"GetDecryptedKey: success key len={unprotected.Length} sample={sample}");
                return unprotected;
            }
            catch (Exception ex)
            {
                Logger.Log($"GetDecryptedKey: unexpected error: {ex.Message}");
                return null;
            }
        }

        // --- Decrypt result structure for diagnostics ---
        public class ChromeDecryptResult
        {
            public bool Success { get; set; }
            public string? PlainText { get; set; }
            public string? Error { get; set; }
            public string? IvHex { get; set; }
            public string? TagHex { get; set; }
            public string? CtHexSample { get; set; }
        }

        // Decrypt Chrome/Edge password blob using AES-GCM
        // Call: TryExhaustiveDecrypt(blob, aesKey, origin)
        public ChromeDecryptResult TryExhaustiveDecrypt(byte[] blob, byte[] aesKey, string origin = "")
        {
            static string Hex(byte[]? b, int n = 12) => b == null || b.Length == 0 ? "<empty>" : BitConverter.ToString(b.Take(n).ToArray()).Replace("-", "");
            if (blob == null || blob.Length == 0) return new ChromeDecryptResult { Success = false, Error = "blob len=0" };

            // IV is expected 12 bytes for Chrome; keep 16 as a defensive candidate but 12 is primary
            int[] ivCandidates = { 12, 16 };
            int[] tagCandidates = { 16 }; // Chrome uses 16-byte GCM tag; keep single candidate to avoid noisy attempts
            bool[] tagPositionsTrailing = { true, false }; // true => tag at end, false => tag after IV

            // AAD options: null (none), 3-byte ascii prefix if present, first 3 bytes, empty, first 4 bytes
            byte[] prefix = blob.Length >= 3 ? Encoding.ASCII.GetBytes(Encoding.ASCII.GetString(blob, 0, 3)) : Array.Empty<byte>();
            var aadOptions = new List<byte[]?>() { null, prefix, blob.Take(3).ToArray(), Array.Empty<byte>(), blob.Take(4).ToArray() };

            for (int ivLenIdx = 0; ivLenIdx < ivCandidates.Length; ivLenIdx++)
                for (int tagLenIdx = 0; tagLenIdx < tagCandidates.Length; tagLenIdx++)
                    for (int tagPosIdx = 0; tagPosIdx < tagPositionsTrailing.Length; tagPosIdx++)
                    {
                        int ivLen = ivCandidates[ivLenIdx];
                        int tagLen = tagCandidates[tagLenIdx];
                        bool tagTrailing = tagPositionsTrailing[tagPosIdx];

                        // minimal sanity length check
                        if (blob.Length < ivLen + tagLen + 1) continue;

                        // offset = 3 if blob starts with ASCII 'v' (version prefix), else 0
                        int offset = (blob.Length >= 3 && blob[0] == (byte)'v') ? 3 : 0;

                        // defensive: ensure we won't slice past blob bounds
                        if (offset + ivLen > blob.Length) continue;

                        byte[] iv = blob.Skip(offset).Take(ivLen).ToArray();
                        byte[] tag;
                        byte[] ciphertext;

                        if (tagTrailing)
                        {
                            if (blob.Length < tagLen) continue;
                            tag = blob.Skip(blob.Length - tagLen).Take(tagLen).ToArray();
                            int ctStart = offset + ivLen;
                            int ctLen = Math.Max(0, blob.Length - ctStart - tagLen);
                            ciphertext = blob.Skip(ctStart).Take(ctLen).ToArray();
                        }
                        else
                        {
                            // tag immediately after IV
                            if (offset + ivLen + tagLen > blob.Length) continue;
                            tag = blob.Skip(offset + ivLen).Take(tagLen).ToArray();
                            ciphertext = blob.Skip(offset + ivLen + tagLen).Take(Math.Max(0, blob.Length - (offset + ivLen + tagLen))).ToArray();
                        }

                        foreach (var aad in aadOptions)
                        {
                            ReadOnlySpan<byte> aadSpan = aad is null ? ReadOnlySpan<byte>.Empty : aad.AsSpan();

                            try
                            {
                                if (ciphertext.Length == 0)
                                {
                                    Logger.Log($"EXH: origin={origin} ivLen={ivLen} tagLen={tagLen} tagTrailing={tagTrailing} aad={(aad == null ? "<none>" : Hex(aad, 8))} => EMPTY_PLAINTEXT");
                                    Logger.Log($"→ FullBlob: {BitConverter.ToString(blob)}");
                                    Logger.Log($"→ IV: {BitConverter.ToString(iv)}");
                                    Logger.Log($"→ CT: {BitConverter.ToString(ciphertext)}");
                                    Logger.Log($"→ TAG: {BitConverter.ToString(tag)}");
                                    return new ChromeDecryptResult { Success = true, PlainText = string.Empty, IvHex = Hex(iv), TagHex = Hex(tag), CtHexSample = Hex(ciphertext) };
                                }

                                // Replace this line:
                                // using var aesGcm = new AesGcm(aesKey);
                                // With this line (specifying the required tag size, which for Chrome/Edge is 16 bytes):
                                using var aesGcm = new AesGcm(aesKey, 16);
                                byte[] plaintext = new byte[ciphertext.Length];
                                aesGcm.Decrypt(iv, ciphertext, tag, plaintext, aadSpan);
                                string pt = Encoding.UTF8.GetString(plaintext);

                                Logger.Log($"EXH: origin={origin} SUCCESS ivLen={ivLen} tagLen={tagLen} tagTrailing={tagTrailing} aad={(aad == null ? "<none>" : Hex(aad, 8))} ptSample=\"{(pt.Length > 64 ? pt.Substring(0, 64) : pt)}\"");
                                Logger.Log($"→ FullBlob: {BitConverter.ToString(blob)}");
                                Logger.Log($"→ IV: {BitConverter.ToString(iv)}");
                                Logger.Log($"→ CT: {BitConverter.ToString(ciphertext)}");
                                Logger.Log($"→ TAG: {BitConverter.ToString(tag)}");

                                return new ChromeDecryptResult { Success = true, PlainText = pt, IvHex = Hex(iv), TagHex = Hex(tag), CtHexSample = Hex(ciphertext) };
                            }
                            catch (Exception ex)
                            {
                                // Detailed failure logging including full IV, CT and TAG for later analysis
                                Logger.Log($"EXH FAIL: origin={origin} ivLen={ivLen} tagLen={tagLen} tagTrailing={tagTrailing} aad={(aad == null ? "<none>" : Hex(aad, 8))}");
                                Logger.Log($"→ FullBlob: {BitConverter.ToString(blob)}");
                                Logger.Log($"→ IV: {BitConverter.ToString(iv)}");
                                Logger.Log($"→ CT: {BitConverter.ToString(ciphertext)}");
                                Logger.Log($"→ TAG: {BitConverter.ToString(tag)}");
                                Logger.Log($"→ Error: {ex.Message}");
                            }
                        }
                    }

            return new ChromeDecryptResult { Success = false, Error = "exhaustive variants failed" };
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
                        Log($"⚠ Skipping {kvp.Key} — key not found or empty: {kvp.Value}");
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
                            Log($"✅ Exported {kvp.Key} to: {regFile}");
                        else
                            Log($"⚠ reg.exe exited with code {proc.ExitCode} — {kvp.Key} export may have failed.");
                    }
                    else
                    {
                        Log($"❌ Failed to start reg.exe for {kvp.Key} — process was null.");
                    }
                }
                catch (Exception ex)
                {
                    Log($"❌ Exception while exporting {kvp.Key}: {ex.Message}");
                }
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