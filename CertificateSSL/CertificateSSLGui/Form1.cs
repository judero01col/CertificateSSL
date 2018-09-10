using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.Drawing;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Windows.Forms;
using CertificateSSLClass;
using CERTENROLLLib;
using System.IO;

namespace CertificateSSLGui
{
    public partial class Form1 : Form
    {
        CertificateSSL oCertificateSSL = new CertificateSSL("SHA512", "Witech", "Witech Usa Inc CA", 1000);

        public Form1()
        {
            InitializeComponent();
        }

        private void button1_Click(object sender, EventArgs e)
        {
            string Key = oCertificateSSL.Export();
            File.WriteAllText("PrivateKey.Key", Key);
        }

        private void button2_Click(object sender, EventArgs e)
        {
            StreamReader Reader = File.OpenText("PrivateKey.Key");
            string Key  = Reader.ReadToEnd();
            oCertificateSSL.Import(Key);
        }

        private void button3_Click(object sender, EventArgs e)
        {
            oCertificateSSL.GenSelfSignedCert();
        }

        private void button4_Click(object sender, EventArgs e)
        {
            oCertificateSSL.GenSelfSignedCert("Novo", "JURGEN-HP");
        }
    }
}
