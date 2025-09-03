using BackupWorkstation;
using System;
using System.IO;
using System.Threading.Tasks;

namespace BackupWorkstation
{
    public class BackupManager
    {
        public event Action<string>? LogMessage;
        public event Action<int, int, string>? ProgressChanged;

        public async Task RunBackupAsync(string sourceUser, string backupRoot)
        {
            string userProfile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
            string backupPath = Path.Combine(backupRoot, sourceUser);
            string logPath = Path.Combine(backupPath, "backup_log.txt");

            Directory.CreateDirectory(backupPath);
            Logger.Init(logPath);


            var directories = new[] { "Documents", "Pictures", "Downloads", "Desktop" };
            int total = directories.Length;
            int current = 0;

            foreach (var dir in directories)
            {
                current++;
                string source = Path.Combine(userProfile, dir);
                string destination = Path.Combine(backupPath, dir);

                ProgressChanged?.Invoke(current, total, $"Copying: {dir}");

                if (Directory.Exists(source))
                {
                    await Task.Run(() => CopyDirectory(source, destination));
                    Log($"✔ Copied '{dir}'");
                }
                else
                {
                    Log($"⚠ Skipped '{dir}' (not found)");
                }
            }

            Log("✅ Backup complete.");
            ProgressChanged?.Invoke(total, total, "Backup Complete");
        }

        private void CopyDirectory(string sourceDir, string destDir)
        {
            Directory.CreateDirectory(destDir);
            foreach (var file in Directory.GetFiles(sourceDir, "*", SearchOption.AllDirectories))
            {
                var relativePath = file.Substring(sourceDir.Length + 1);
                var destFile = Path.Combine(destDir, relativePath);
                Directory.CreateDirectory(Path.GetDirectoryName(destFile)!);
                File.Copy(file, destFile, true);
                Log($"Copied file: {relativePath}");
            }
        }

        private void Log(string message)
        {
            Logger.Log(message);
            LogMessage?.Invoke(message);
        }
    }
}