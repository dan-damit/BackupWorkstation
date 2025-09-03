using System.Windows;
using System.Windows.Controls;
using System.Windows.Forms;
using System.Windows.Input;

namespace BackupWorkstation;
    public partial class CredentialPromptWindow : Window
    {
        public string Username => UsernameBox.Text;
        public string Password => PasswordBox.Password;
    
        public CredentialPromptWindow(string sharePath)
        {
            InitializeComponent();
            Title = $"Credentials for {sharePath}";
        }
    
        private void Ok_Click(object sender, RoutedEventArgs e)
        {
            DialogResult = true;
            Close();
        }  

        private void Cancel_Click(object sender, RoutedEventArgs e)
        {
            DialogResult = false;
            Close();
        }

        private void TitleBar_MouseDown(object sender, MouseButtonEventArgs e)
        {
            if (e.ChangedButton == MouseButton.Left)
                DragMove();
        }
    }