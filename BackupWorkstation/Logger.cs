using System;
using System.IO;
using System.Threading.Tasks;
using System.Windows;

namespace BackupWorkstation
{
    public static class Logger
    {
        private static string _logFilePath = string.Empty;

        public static void Init(string logFilePath)
        {
            _logFilePath = logFilePath;
            Directory.CreateDirectory(Path.GetDirectoryName(logFilePath)!);
            File.WriteAllText(_logFilePath, $"Backup started: {DateTime.Now}\n");
        }

        public static void Log(string message)
        {
            string line = $"[{DateTime.Now:HH:mm:ss}] {message}";
            File.AppendAllText(_logFilePath, line + Environment.NewLine);
        }
    }
}