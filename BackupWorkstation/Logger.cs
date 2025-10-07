using System;
using System.IO;
using System.Runtime.Versioning;
using System.Threading.Tasks;
using System.Windows;

namespace BackupWorkstation
{
    [SupportedOSPlatform("windows")]
    public static class Logger
    {
        // Fields
        private static string _logFilePath = string.Empty;
        public static event Action<string>? LogMessageReceived;

        // Initialization log file
        public static void Init(string logFilePath)
        {
            _logFilePath = logFilePath;
            Directory.CreateDirectory(Path.GetDirectoryName(logFilePath)!);
            File.WriteAllText(_logFilePath, $"Backup started: {DateTime.Now}\n");
        }

        // Log a message with timestamp
        public static void Log(string message)
        {
            string line = $"[{DateTime.Now:HH:mm:ss}] {message}";
            File.AppendAllText(_logFilePath, line + Environment.NewLine);

            Application.Current.Dispatcher.Invoke(() =>
            {
                LogMessageReceived?.Invoke(line);
            });
        }
    }
}