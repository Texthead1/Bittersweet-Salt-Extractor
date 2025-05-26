using System;
using System.Drawing;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using System.Windows.Forms;

namespace Bittersweet
{
    public partial class Form1 : Form
    {
        private CancellationTokenSource cts;

        public const int SALT_LENGTH = 0x35;
        private static readonly byte[] saltHash = new byte[]
        {
            0x73, 0x5D, 0x9A, 0xB9, 0x4E, 0xCA, 0x74, 0xD8, 0xE2, 0x50, 0x67, 0xF5, 0x8C, 0x4C, 0xCA, 0x6B,
            0x8E, 0x92, 0x6F, 0x39, 0xC8, 0x8E, 0x36, 0xB9, 0x33, 0xF9, 0xF0, 0x9D, 0x6D, 0x95, 0x32, 0x60
        };

        private static readonly long[] offsets = new long[]
        {
            0x00000000,             // salt.txt
            0x0AC24A6C,             // ssa pc usa
            0x0BEBA11C,             // ssa pc usa
            0x0D9590C8,             // ssa jp wii
            0x0B407354,             // ssa brazil wii
            0x00D396D4,             // sg build 6
            0x0000000101C5DB04,     // ssf wii
            0x0AACC6B8,             // stt wii
            0x0BBED868,             // sscr wii
            0x62CBA430,             // sscr wii
            0x00013E48              // spyrolibrary
        };

        public Form1()
        {
            InitializeComponent();
        }

        private void PCUSAToolStripMenuItem_Click(object sender, EventArgs e)
        {
            OpenFile(offsets[1], offsets[2]);
        }

        private void spyroNoDaiboukenToolStripMenuItem_Click(object sender, EventArgs e)
        {
            OpenFile(offsets[3]);
        }

        private void wiiBrazilRVZToolStripMenuItem_Click(object sender, EventArgs e)
        {
            OpenFile(offsets[4]);
        }

        private void july102012AlphaRVTHToolStripMenuItem_Click(object sender, EventArgs e)
        {
            OpenFile(offsets[5]);
        }

        private void SFWiiToolStripMenuItem_Click(object sender, EventArgs e)
        {
            OpenFile(offsets[6]);
        }

        private void TTWiiRVZToolStripMenuItem_Click(object sender, EventArgs e)
        {
            OpenFile(offsets[7]);
        }

        private void SSCRWiiToolStripMenuItem_Click(object sender, EventArgs e)
        {
            OpenFile(offsets[8], offsets[9]);
        }

        private void spyroLibrarydllToolStripMenuItem_Click(object sender, EventArgs e)
        {
            OpenFile(offsets[10]);
        }

        private async void otherAutoToolStripMenuItem_Click(object sender, EventArgs e)
        {
            using (OpenFileDialog openFileDialog = new OpenFileDialog())
            {
                openFileDialog.Filter = "All Files|*.*";
                if (openFileDialog.ShowDialog() != DialogResult.OK) return;

                cts?.Cancel();
                cts = new CancellationTokenSource();

                FileInfo info = new FileInfo(openFileDialog.FileName);
                if (info.Length < SALT_LENGTH)
                {
                    consoleLabel.Text = "File size is too small for salt";
                    consoleLabel.ForeColor = Color.Red;
                    return;
                }

                using (FileStream fs = new FileStream(openFileDialog.FileName, FileMode.Open, FileAccess.Read))
                {
                    byte[] buffer = new byte[SALT_LENGTH];
                    foreach (long offset in offsets)
                    {
                        fs.Seek(offset, SeekOrigin.Begin);
                        fs.Read(buffer, 0, SALT_LENGTH);

                        if (SHA256.Create().ComputeHash(buffer).SequenceEqual(saltHash))
                        {
                            consoleLabel.Invoke((MethodInvoker)(() =>
                            {
                                consoleLabel.Text = $"Salt found successfully";
                                consoleLabel.ForeColor = Color.Green;
                                SaveFile(buffer);
                            }));
                            return;
                        }
                    }
                }
                DialogResult dialogResult = MessageBox.Show("Salt could not be found at a known offset. Would you like to do a progressive scan of the file?\n(Note: this can take a couple of minutes, depending on file size)", "Bittersweet", MessageBoxButtons.YesNo);
                if (dialogResult != DialogResult.Yes) return;
                long max = info.Length - SALT_LENGTH;
                progressBar1.Value = 0;
                progressBar1.Maximum = 100;

                consoleLabel.Text = "Searching...";
                consoleLabel.ForeColor = Color.Blue;

                IProgress<int> progress = new Progress<int>(x => progressBar1.Value = x);

                await Task.Run(() =>
                {
                    using (FileStream fs = new FileStream(openFileDialog.FileName, FileMode.Open, FileAccess.Read))
                    {
                        byte[] buffer = new byte[SALT_LENGTH];
                        for (long i = 0; i <= max; i++)
                        {
                            if (cts.Token.IsCancellationRequested) return;

                            fs.Seek(i, SeekOrigin.Begin);
                            fs.Read(buffer, 0, SALT_LENGTH);

                            if (SHA256.Create().ComputeHash(buffer).SequenceEqual(saltHash))
                            {
                                consoleLabel.Invoke((MethodInvoker)(() =>
                                {
                                    progress.Report(100);
                                    consoleLabel.Text = $"Salt found successfully";
                                    consoleLabel.ForeColor = Color.Green;
                                    SaveFile(buffer);
                                }));
                                return;
                            }

                            if (i % 10000 == 0)
                            {
                                int percentage = (int)(i * 100 / (max - SALT_LENGTH));
                                progress.Report(percentage);
                            }
                        }
                        progress.Report(100);
                        consoleLabel.Invoke((MethodInvoker)(() =>
                        {
                            consoleLabel.Text = "Salt could not be found";
                            consoleLabel.ForeColor = Color.Red;
                        }));
                    }
                }, cts.Token);
            }
        }

        private void OpenFile(params long[] offsets)
        {
            using (OpenFileDialog openFileDialog = new OpenFileDialog())
            {
                openFileDialog.Filter = "All Files|*.*";
                if (openFileDialog.ShowDialog() != DialogResult.OK) return;
                
                cts?.Cancel();
                cts = new CancellationTokenSource();
                
                long maxOffset = offsets.Max();

                FileInfo info = new FileInfo(openFileDialog.FileName);
                if (info.Length < maxOffset + SALT_LENGTH)
                {
                    consoleLabel.Text = "File size is too small for salt";
                    consoleLabel.ForeColor = Color.Red;
                    return;
                }

                foreach (long offset in offsets)
                {
                    byte[] buffer = new byte[SALT_LENGTH];
                    using (FileStream fs = new FileStream(openFileDialog.FileName, FileMode.Open, FileAccess.Read))
                    {
                        {
                            fs.Seek(offset, SeekOrigin.Begin);
                            fs.Read(buffer, 0, SALT_LENGTH);
                        }

                        Console.WriteLine(Encoding.UTF8.GetString(buffer));

                        if (SHA256.Create().ComputeHash(buffer).SequenceEqual(saltHash))
                        {
                            consoleLabel.Text = "Salt found successfully";
                            consoleLabel.ForeColor = Color.Green;
                            SaveFile(buffer);
                            return;
                        }
                    }
                }
                consoleLabel.Text = "Could not retrieve salt from file\nWas the correct file given?";
                consoleLabel.ForeColor = Color.Red;
            }
        }

        private void SaveFile(byte[] salt)
        {
            SaveFileDialog saveFileDialog = new SaveFileDialog();
            saveFileDialog.InitialDirectory = AppDomain.CurrentDomain.BaseDirectory;
            saveFileDialog.FileName = "salt.txt";
            saveFileDialog.Filter = "Text Files (*.txt)|*.txt|All Files (*.*)|*.*";

            if (saveFileDialog.ShowDialog() != DialogResult.OK) return;

            File.WriteAllBytes(saveFileDialog.FileName, salt);
        }
    }
}
