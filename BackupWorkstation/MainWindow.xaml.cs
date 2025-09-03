using BackupWorkstation;
using System;
using System.Collections.ObjectModel;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Threading;
using Microsoft.WindowsAPICodePack.Dialogs;

namespace BackupWorkstation
{
    public partial class MainWindow : Window
    {
        private ObservableCollection<string> _logEntries = new ObservableCollection<string>();
        private BackupManager _backupManager;

        public MainWindow()
        {
            InitializeComponent();
            lstLog.ItemsSource = _logEntries;

            _backupManager = new BackupManager();
            _backupManager.LogMessage += OnLogMessage;
            _backupManager.ProgressChanged += OnProgressChanged;
        }

        private void Browse_Click(object sender, RoutedEventArgs e)
        {
            var dlg = new CommonOpenFileDialog
            {
                IsFolderPicker = true,
                Title = "Select Backup Destination"
            };

            if (dlg.ShowDialog() == CommonFileDialogResult.Ok)
            {
                txtBackupPath.Text = dlg.FileName;
            }
        }

        private async void StartBackup_Click(object sender, RoutedEventArgs e)
        {
            if (string.IsNullOrWhiteSpace(txtBackupPath.Text) || string.IsNullOrWhiteSpace(txtUsername.Text))
            {
                MessageBox.Show("Please enter both backup path and username.");
                return;
            }

            _logEntries.Clear();
            progressBar.Value = 0;

            await _backupManager.RunBackupAsync(txtUsername.Text, txtBackupPath.Text);
        }

        private void OnLogMessage(string message)
        {
            Dispatcher.Invoke(() =>
            {
                _logEntries.Add(message);
                lstLog.ScrollIntoView(message);
            });
        }

        private void OnProgressChanged(int current, int total, string status)
        {
            Dispatcher.Invoke(() =>
            {
                progressBar.Value = (double)current / total * 100;
                Title = $"Workstation Backup Tool - {status}";
            });
        }
        private void Close_Click(object sender, RoutedEventArgs e)
        {
            Close();
        }
    }
}