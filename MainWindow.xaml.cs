using System;
using System.IO;
using System.Net.Http;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using System.Windows;
using System.Diagnostics;

namespace RepoCop
{
    public partial class MainWindow : Window
    {
        public MainWindow()
        {
            InitializeComponent();
        }

        // Window Dragging (Custom Title Bar)
        private void Window_MouseLeftButtonDown(object sender, System.Windows.Input.MouseButtonEventArgs e)
        {
            if (e.ButtonState == System.Windows.Input.MouseButtonState.Pressed)
                this.DragMove();
        }

        // Minimize Button Click
        private void MinimizeButton_Click(object sender, RoutedEventArgs e)
        {
            this.WindowState = WindowState.Minimized;
        }

        // Maximize Button Click
        private void MaximizeButton_Click(object sender, RoutedEventArgs e)
        {
            if (this.WindowState == WindowState.Maximized)
                this.WindowState = WindowState.Normal;
            else
                this.WindowState = WindowState.Maximized;
        }

        // Close Button Click
        private void CloseButton_Click(object sender, RoutedEventArgs e)
        {
            Application.Current.Shutdown();
        }

        // Focus and Lost Focus for the Repo URL TextBox
        private void RepoUrlTextBox_GotFocus(object sender, RoutedEventArgs e)
        {
            if (RepoUrlTextBox.Text == "Enter GitHub Repo URL")
            {
                RepoUrlTextBox.Text = "";
                RepoUrlTextBox.Foreground = System.Windows.Media.Brushes.White;
            }
        }

        private void RepoUrlTextBox_LostFocus(object sender, RoutedEventArgs e)
        {
            if (string.IsNullOrEmpty(RepoUrlTextBox.Text))
            {
                RepoUrlTextBox.Text = "Enter GitHub Repo URL";
                RepoUrlTextBox.Foreground = System.Windows.Media.Brushes.Gray;
            }
        }

        // Clone Repo and Scan Button
        private async void CloneRepoButton_Click(object sender, RoutedEventArgs e)
        {
            string repoUrl = RepoUrlTextBox.Text;
            ResultsTextBox.Text = "Cloning and scanning repository...\n";

            if (Uri.IsWellFormedUriString(repoUrl, UriKind.Absolute))
            {
                string clonePath = await CloneRepo(repoUrl);

                if (Directory.Exists(clonePath))
                {
                    ResultsTextBox.AppendText($"Repo cloned to: {clonePath}\n");

                    // Start scanning the cloned repo
                    string result = ScanRepoForMaliciousCode(clonePath);

                    // Display results
                    ResultsTextBox.AppendText(result);
                }
                else
                {
                    ResultsTextBox.AppendText("Error: Unable to clone repo.\n");
                }
            }
            else
            {
                ResultsTextBox.AppendText("Invalid GitHub Repo URL.\n");
            }
        }

        // Clone the GitHub repository to a local directory
        private async Task<string> CloneRepo(string repoUrl)
        {
            string localRepoPath = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments), "RepoCop", Guid.NewGuid().ToString());
            Directory.CreateDirectory(localRepoPath);

            try
            {
                // Use Git to clone the repo (ensure Git is installed)
                ProcessStartInfo gitProcess = new ProcessStartInfo("git", $"clone {repoUrl} {localRepoPath}")
                {
                    RedirectStandardOutput = true,
                    RedirectStandardError = true,
                    UseShellExecute = false
                };

                Process process = Process.Start(gitProcess);
                await process.WaitForExitAsync();

                return localRepoPath;
            }
            catch (Exception ex)
            {
                ResultsTextBox.AppendText($"Error cloning repo: {ex.Message}\n");
                return string.Empty;
            }
        }

        // Scan the cloned repo for malicious code (Reverse Shells, Backdoors, Malware)
        private string ScanRepoForMaliciousCode(string repoPath)
        {
            string[] maliciousPatterns = new string[]
            {
                // Reverse Shell Patterns
                @"nc\s*-\s*e\s*[^ ]+\s*[^ ]+", // Reverse shell via netcat
                @"powershell\s*-nop\s*-w\s*no.*-enc", // PowerShell reverse shell
                @"bash\s*-i\s*>\s*&\s*\d{1,3}(\.\d{1,3}){3}:\d{1,5}", // Bash reverse shell
                @"bash\s*-c\s*""\s*nc\s*-e\s*[^ ]+\s*[^ ]+""", // Netcat reverse shell
                @"Invoke-WebRequest\s*\([^\)]+\)\s*|Invoke-Expression\s*\([^\)]+", // PowerShell web requests
                @"System\.Diagnostics\.Process\.Start\s*\([^\)]*\)", // Process.Start usage

                // Backdoor Indicators
                @"wget\s+[^\s]+",  // wget to fetch files
                @"curl\s+[^\s]+",  // curl to fetch files
                @"HttpWebRequest\s*\(",  // HttpWebRequest usage
                @"WebClient\s*\.",  // WebClient usage
                @"HttpClient\s*\.",  // HttpClient usage
                @"File\.WriteAllBytes", // File write operations
                @"FileStream\s*\(", // FileStream
                @"File\.Delete", // File delete functions
                @"Process\.Start", // Process manipulation
                @"(reverse|backdoor|payload|shell|malware)",  // General malicious terms
            };

            string result = "Scanning Results:\n";
            bool foundMaliciousCode = false;

            foreach (string filePath in Directory.GetFiles(repoPath, "*.*", SearchOption.AllDirectories))
            {
                // Scan only code files (for example, .js, .py, .cs, etc.)
                if (filePath.EndsWith(".cs") || filePath.EndsWith(".js") || filePath.EndsWith(".sh") || filePath.EndsWith(".py"))
                {
                    string fileContent = File.ReadAllText(filePath);

                    foreach (string pattern in maliciousPatterns)
                    {
                        if (Regex.IsMatch(fileContent, pattern, RegexOptions.IgnoreCase))
                        {
                            foundMaliciousCode = true;
                            result += $"- Malicious code detected in {filePath} (Pattern: {pattern})\n";
                        }
                    }
                }
            }

            if (!foundMaliciousCode)
            {
                result += "No malicious code detected.\n";
            }

            return result;
        }
    }
}
