using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace BackupWorkstation
{
    // --- Manifest writer for auditability ---
    public static class ManifestWriter
    {
        static readonly object _lock = new();
        static string? _manifestPath;

        public static void Initialize(string backupRootPath)
        {
            _manifestPath = Path.Combine(backupRootPath, "backup_manifest.txt");
        }

        public static void Append(string key, string value)
        {
            if (string.IsNullOrEmpty(_manifestPath))
                throw new InvalidOperationException("ManifestWriter not initialized. Call Initialize(...) first.");

            lock (_lock)
            {
                File.AppendAllText(_manifestPath, $"{DateTime.UtcNow:O}\t{key}\t{value}{Environment.NewLine}");
            }
        }
    }
}
