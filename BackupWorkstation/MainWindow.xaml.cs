using BackupWorkstation;
using Microsoft.WindowsAPICodePack.Dialogs;
using System;
using System.Collections.ObjectModel;
using System.Runtime.Versioning;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using System.Windows.Threading;
using static BackupWorkstation.BackupManager;
using static BackupWorkstation.Logger;

namespace BackupWorkstation
{
    [SupportedOSPlatform("windows")]
    public partial class MainWindow : Window
    {
        // Fields
        private ObservableCollection<string> _logEntries = new ObservableCollection<string>();
        private BackupManager _backupManager;
        private bool _sourceUserEditedByUser;
        private string? _autoSeedSourceUser;
        private string? _backupRoot;

        // Constructor
        public MainWindow()
        {
            InitializeComponent();
            lstLog.ItemsSource = _logEntries;

            Logger.LogMessageReceived += OnLogMessage;
            _backupManager = new BackupManager();
            _backupManager.ProgressChanged += OnProgressChanged;
        }

        // Enable window dragging from the title bar area
        private void TitleBar_MouseDown(object sender, MouseButtonEventArgs e)
        {
            // Allow dragging the window when the left mouse button is held down
            if (e.ChangedButton == MouseButton.Left)
            {
                DragMove();
            }
        }

        // Browse for backup destination folder
        private void btnBrowse_Click(object sender, RoutedEventArgs e)
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

        // On window load, populate current user info
        private void Window_Loaded(object sender, RoutedEventArgs e)
        {
            _backupRoot = txtBackupPath.Text;
            ManifestWriter.Initialize(_backupRoot);

            _autoSeedSourceUser = CurrentUserInfo.GetUserPrincipal();
            txtUsername.Text = _autoSeedSourceUser;

            txtUsername.TextChanged += TxtUsername_TextChanged;
            btnResetSourceUser.Click += BtnResetSourceUser_Click;
        }

        // Track if user has modified the source username
        private void TxtUsername_TextChanged(object sender, TextChangedEventArgs e)
        {
            // If the current text differs from the auto-seed, mark as edited.
            _sourceUserEditedByUser = !string.Equals(txtUsername.Text, _autoSeedSourceUser, StringComparison.Ordinal);
        }

        // Reset the source username to the auto-detected value
        private void BtnResetSourceUser_Click(object sender, RoutedEventArgs e)
        {
            txtUsername.Text = _autoSeedSourceUser;
            _sourceUserEditedByUser = false;
            ManifestWriter.Append("source_user_reset", _autoSeedSourceUser);
        }

        // Start the backup process
        private async void btnStartBackup_Click(object sender, RoutedEventArgs e)
        {
            if (string.IsNullOrWhiteSpace(txtBackupPath.Text) || string.IsNullOrWhiteSpace(txtUsername.Text))
            {
                MessageBox.Show("Please enter both backup path and username.");
                return;
            }

            // UI preflight
            btnStartBackup.IsEnabled = false;
            this.Cursor = Cursors.Wait;
            _logEntries.Clear();
            progressBar.Value = 0;

            try
            {
                // Run backup (optionally pass a cancellation token later)
                await _backupManager.RunBackupAsync(txtUsername.Text, txtBackupPath.Text);
            }
            catch (Exception ex)
            {
                MessageBox.Show("Backup failed: " + ex.Message);
            }
            finally
            {
                // restore UI
                btnStartBackup.IsEnabled = true;
                this.Cursor = Cursors.Arrow;
            }
        }

        // Update log messages in the UI
        private void OnLogMessage(string message)
        {
            _logEntries.Add(message);
            if (lstLog.Items.Count > 0)
            {
                lstLog.ScrollIntoView(lstLog.Items[lstLog.Items.Count - 1]);
            }
        }

        // Update progress bar and window title
        private void OnProgressChanged(int current, int total, string status)
        {
            Dispatcher.Invoke(() =>
            {
                progressBar.Value = (double)current / total * 100;
                Title = $"Workstation Backup Tool - {status}";
            });
        }

        // Close the application
        private void Close_Click(object sender, RoutedEventArgs e)
        {
            Close();
        }
    }
}