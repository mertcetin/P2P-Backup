/*  
 *  Secure Messenger Client v1.0
 * 
 *  Created by: Mert Cetin & Tolga Eren
 *  
 *  Date: 28/03/2008
 * 
 */

//#define _SHOWMSG

using System;

using System.IO;
using System.Windows.Forms;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Security.Cryptography;
using System.Collections;
using System.Collections.Generic;

namespace p2p
{
	public class SecureMsgClient : System.Windows.Forms.Form
    {
       // public static int kemalLength = 395;
        public byte[] data;
        public RSACryptoServiceProvider rsa;
        public RSACryptoServiceProvider rsaserver;
        public RSACryptoServiceProvider rsapeer;
        public RSAParameters myrsap;
        public int myport;
        public client senderClient;
        public int m_peerCount = 0;
        public List<file> filelist;
        public SHA1CryptoServiceProvider cryptoTransformSHA1;
        public string hash;
        public List<byte[]> partsFromOthers = new List<byte[]>();
        public List<SharedData> secretsFromOthers = new List<SharedData>();
        public int enoughParts = 0;
        public byte[] perFileKey;
        public const int MAX_SOCKETS = 50;
        public string reconstructedFileName;

        private System.Windows.Forms.Label label3;
        private System.Windows.Forms.Label label2;
        private System.Windows.Forms.Button buttonDisconnect;
        private System.Windows.Forms.TextBox textBoxIP;
        private System.Windows.Forms.Label label5;
        private System.Windows.Forms.Button buttonConnect;
        private System.Windows.Forms.TextBox textBoxPort;
        private System.Windows.Forms.RichTextBox richTextRxMessage;
        private System.Windows.Forms.Label label4;
        private System.Windows.Forms.TextBox textBoxConnectStatus;
        private System.Windows.Forms.RichTextBox richTextTxMessage;
        private System.Windows.Forms.Button buttonSendMessage;
        private System.Windows.Forms.Button buttonClose;

        IAsyncResult m_result;
        public AsyncCallback m_pfnCallBack;
        public Socket m_clientSocket;
        public Socket m_mainSocket;
        public Socket[] m_peerSockets = new Socket[MAX_SOCKETS];
        public AsyncCallback pfnWorkerCallBack;

        private TextBox tb_encSent;
        private Label label8;
        private Label label9;
        private TextBox tb_aesKey;
        private TextBox tb_encRecv;
        private Label label10;
        private Label label11;
        private TextBox tb_currentMode;
        private TextBox tb_IV;
        private TabControl tabControl1;
        private TabPage tabPage1;
        private TabPage tabPage2;
        private TextBox tb_encKey;
        private Label label12;
        private GroupBox groupBox3;
        private TextBox tb_RsaPublicKey;
        private Label label6;
        private Label label7;
        private TextBox tb_RsaPublicKeyExpo;
        private Label label13;
        private Label label14;
        private GroupBox groupBox1;
        private Label label1;
        private Button backup_button;
        private Button btn_recover;
        private TextBox tb_clientListenPort;
        private TextBox tb_filename;
        private TextBox tb_recoverName;
        private TextBox sharedKeyBox;

        public struct client
        {
            public string ip;
            public string port;
            public string publicKey;
            public byte[] sessionkey;
            public string ticket;
        };

        public struct file
        {
            public string fileid;
            public string filesize;
            public string filename;
            public byte[] filedata;

        }
        public class SocketPacket
        {
            public System.Net.Sockets.Socket m_currentSocket;
            public byte[] dataBuffer = new byte[65536 * 16];
        }
        public SecureMsgClient()
        {
            //
            // The InitializeComponent() call is required for Windows Forms designer support.
            //
            InitializeComponent();
            SecureMsgClient.CheckForIllegalCrossThreadCalls = false;
            rsa = new RSACryptoServiceProvider(2048);
            rsapeer = new RSACryptoServiceProvider(2048);
            RSAParameters myrsap = rsa.ExportParameters(false);
            myport = 7000;
            filelist = new List<file>();
            cryptoTransformSHA1 = new SHA1CryptoServiceProvider();
            
                        
            textBoxIP.Text = GetIP();
        }

        [STAThread]
        public static void Main(string[] args)
        {
            Application.Run(new SecureMsgClient());
        }

        #region Windows Forms Designer generated code
        /// <summary>
        /// This method is required for Windows Forms designer support.
        /// Do not change the method contents inside the source code editor. The Forms designer might
        /// not be able to load this method if it was changed manually.
        /// </summary>
        private void InitializeComponent()
        {
            this.buttonClose = new System.Windows.Forms.Button();
            this.buttonSendMessage = new System.Windows.Forms.Button();
            this.richTextTxMessage = new System.Windows.Forms.RichTextBox();
            this.textBoxConnectStatus = new System.Windows.Forms.TextBox();
            this.label4 = new System.Windows.Forms.Label();
            this.richTextRxMessage = new System.Windows.Forms.RichTextBox();
            this.textBoxPort = new System.Windows.Forms.TextBox();
            this.buttonConnect = new System.Windows.Forms.Button();
            this.label5 = new System.Windows.Forms.Label();
            this.textBoxIP = new System.Windows.Forms.TextBox();
            this.buttonDisconnect = new System.Windows.Forms.Button();
            this.label2 = new System.Windows.Forms.Label();
            this.label3 = new System.Windows.Forms.Label();
            this.tb_encSent = new System.Windows.Forms.TextBox();
            this.label8 = new System.Windows.Forms.Label();
            this.label9 = new System.Windows.Forms.Label();
            this.tb_aesKey = new System.Windows.Forms.TextBox();
            this.tb_encRecv = new System.Windows.Forms.TextBox();
            this.label10 = new System.Windows.Forms.Label();
            this.sharedKeyBox = new System.Windows.Forms.TextBox();
            this.label11 = new System.Windows.Forms.Label();
            this.tb_currentMode = new System.Windows.Forms.TextBox();
            this.tb_IV = new System.Windows.Forms.TextBox();
            this.tabControl1 = new System.Windows.Forms.TabControl();
            this.tabPage1 = new System.Windows.Forms.TabPage();
            this.tb_recoverName = new System.Windows.Forms.TextBox();
            this.tb_filename = new System.Windows.Forms.TextBox();
            this.tb_clientListenPort = new System.Windows.Forms.TextBox();
            this.btn_recover = new System.Windows.Forms.Button();
            this.backup_button = new System.Windows.Forms.Button();
            this.label1 = new System.Windows.Forms.Label();
            this.groupBox1 = new System.Windows.Forms.GroupBox();
            this.label13 = new System.Windows.Forms.Label();
            this.groupBox3 = new System.Windows.Forms.GroupBox();
            this.tb_RsaPublicKey = new System.Windows.Forms.TextBox();
            this.label6 = new System.Windows.Forms.Label();
            this.label7 = new System.Windows.Forms.Label();
            this.tb_RsaPublicKeyExpo = new System.Windows.Forms.TextBox();
            this.tabPage2 = new System.Windows.Forms.TabPage();
            this.label14 = new System.Windows.Forms.Label();
            this.tb_encKey = new System.Windows.Forms.TextBox();
            this.label12 = new System.Windows.Forms.Label();
            this.tabControl1.SuspendLayout();
            this.tabPage1.SuspendLayout();
            this.groupBox1.SuspendLayout();
            this.groupBox3.SuspendLayout();
            this.tabPage2.SuspendLayout();
            this.SuspendLayout();
            // 
            // buttonClose
            // 
            this.buttonClose.Location = new System.Drawing.Point(451, 127);
            this.buttonClose.Name = "buttonClose";
            this.buttonClose.Size = new System.Drawing.Size(127, 24);
            this.buttonClose.TabIndex = 11;
            this.buttonClose.Text = "Close";
            this.buttonClose.Click += new System.EventHandler(this.ButtonCloseClick);
            // 
            // buttonSendMessage
            // 
            this.buttonSendMessage.Location = new System.Drawing.Point(9, 127);
            this.buttonSendMessage.Name = "buttonSendMessage";
            this.buttonSendMessage.Size = new System.Drawing.Size(269, 24);
            this.buttonSendMessage.TabIndex = 14;
            this.buttonSendMessage.Text = "Send Message";
            this.buttonSendMessage.Click += new System.EventHandler(this.ButtonSendMessageClick);
            // 
            // richTextTxMessage
            // 
            this.richTextTxMessage.Location = new System.Drawing.Point(9, 25);
            this.richTextTxMessage.Name = "richTextTxMessage";
            this.richTextTxMessage.Size = new System.Drawing.Size(269, 96);
            this.richTextTxMessage.TabIndex = 2;
            this.richTextTxMessage.Text = "";
            // 
            // textBoxConnectStatus
            // 
            this.textBoxConnectStatus.BackColor = System.Drawing.SystemColors.Control;
            this.textBoxConnectStatus.BorderStyle = System.Windows.Forms.BorderStyle.None;
            this.textBoxConnectStatus.ForeColor = System.Drawing.SystemColors.HotTrack;
            this.textBoxConnectStatus.Location = new System.Drawing.Point(467, 86);
            this.textBoxConnectStatus.Name = "textBoxConnectStatus";
            this.textBoxConnectStatus.ReadOnly = true;
            this.textBoxConnectStatus.Size = new System.Drawing.Size(97, 13);
            this.textBoxConnectStatus.TabIndex = 10;
            this.textBoxConnectStatus.Text = "Not Connected";
            // 
            // label4
            // 
            this.label4.Location = new System.Drawing.Point(6, 6);
            this.label4.Name = "label4";
            this.label4.Size = new System.Drawing.Size(120, 16);
            this.label4.TabIndex = 9;
            this.label4.Text = "Message To Server:";
            // 
            // richTextRxMessage
            // 
            this.richTextRxMessage.BackColor = System.Drawing.SystemColors.InactiveCaption;
            this.richTextRxMessage.ForeColor = System.Drawing.SystemColors.InactiveCaptionText;
            this.richTextRxMessage.Location = new System.Drawing.Point(307, 25);
            this.richTextRxMessage.Name = "richTextRxMessage";
            this.richTextRxMessage.ReadOnly = true;
            this.richTextRxMessage.Size = new System.Drawing.Size(271, 96);
            this.richTextRxMessage.TabIndex = 1;
            this.richTextRxMessage.Text = "";
            // 
            // textBoxPort
            // 
            this.textBoxPort.Location = new System.Drawing.Point(94, 51);
            this.textBoxPort.Name = "textBoxPort";
            this.textBoxPort.Size = new System.Drawing.Size(48, 20);
            this.textBoxPort.TabIndex = 6;
            this.textBoxPort.Text = "8000";
            // 
            // buttonConnect
            // 
            this.buttonConnect.BackColor = System.Drawing.SystemColors.HotTrack;
            this.buttonConnect.Font = new System.Drawing.Font("Tahoma", 8.25F, System.Drawing.FontStyle.Bold, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.buttonConnect.ForeColor = System.Drawing.Color.Yellow;
            this.buttonConnect.Location = new System.Drawing.Point(353, 23);
            this.buttonConnect.Name = "buttonConnect";
            this.buttonConnect.Size = new System.Drawing.Size(98, 48);
            this.buttonConnect.TabIndex = 7;
            this.buttonConnect.Text = "Connect To Server";
            this.buttonConnect.UseVisualStyleBackColor = false;
            this.buttonConnect.Click += new System.EventHandler(this.ButtonConnectClick);
            // 
            // label5
            // 
            this.label5.Location = new System.Drawing.Point(350, 86);
            this.label5.Name = "label5";
            this.label5.Size = new System.Drawing.Size(104, 16);
            this.label5.TabIndex = 13;
            this.label5.Text = "Connection Status:";
            // 
            // textBoxIP
            // 
            this.textBoxIP.Location = new System.Drawing.Point(94, 28);
            this.textBoxIP.Name = "textBoxIP";
            this.textBoxIP.Size = new System.Drawing.Size(152, 20);
            this.textBoxIP.TabIndex = 3;
            // 
            // buttonDisconnect
            // 
            this.buttonDisconnect.BackColor = System.Drawing.Color.Red;
            this.buttonDisconnect.Font = new System.Drawing.Font("Tahoma", 8.25F, System.Drawing.FontStyle.Bold, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.buttonDisconnect.ForeColor = System.Drawing.Color.Yellow;
            this.buttonDisconnect.Location = new System.Drawing.Point(467, 23);
            this.buttonDisconnect.Name = "buttonDisconnect";
            this.buttonDisconnect.Size = new System.Drawing.Size(97, 48);
            this.buttonDisconnect.TabIndex = 15;
            this.buttonDisconnect.Text = "Disconnet From Server";
            this.buttonDisconnect.UseVisualStyleBackColor = false;
            this.buttonDisconnect.Click += new System.EventHandler(this.ButtonDisconnectClick);
            // 
            // label2
            // 
            this.label2.Location = new System.Drawing.Point(4, 55);
            this.label2.Name = "label2";
            this.label2.Size = new System.Drawing.Size(64, 16);
            this.label2.TabIndex = 5;
            this.label2.Text = "Server Port:";
            // 
            // label3
            // 
            this.label3.Location = new System.Drawing.Point(304, 6);
            this.label3.Name = "label3";
            this.label3.Size = new System.Drawing.Size(192, 16);
            this.label3.TabIndex = 8;
            this.label3.Text = "Message From Server:";
            // 
            // tb_encSent
            // 
            this.tb_encSent.Font = new System.Drawing.Font("Courier New", 8.25F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, ((byte)(162)));
            this.tb_encSent.Location = new System.Drawing.Point(9, 253);
            this.tb_encSent.Multiline = true;
            this.tb_encSent.Name = "tb_encSent";
            this.tb_encSent.ReadOnly = true;
            this.tb_encSent.ScrollBars = System.Windows.Forms.ScrollBars.Vertical;
            this.tb_encSent.Size = new System.Drawing.Size(569, 53);
            this.tb_encSent.TabIndex = 27;
            // 
            // label8
            // 
            this.label8.AutoSize = true;
            this.label8.Location = new System.Drawing.Point(7, 236);
            this.label8.Name = "label8";
            this.label8.Size = new System.Drawing.Size(152, 13);
            this.label8.TabIndex = 26;
            this.label8.Text = "Last Sent Encrpyted Message:";
            // 
            // label9
            // 
            this.label9.AutoSize = true;
            this.label9.Location = new System.Drawing.Point(6, 156);
            this.label9.Name = "label9";
            this.label9.Size = new System.Drawing.Size(68, 13);
            this.label9.TabIndex = 25;
            this.label9.Text = "Session Key:";
            // 
            // tb_aesKey
            // 
            this.tb_aesKey.Font = new System.Drawing.Font("Courier New", 8.25F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, ((byte)(162)));
            this.tb_aesKey.HideSelection = false;
            this.tb_aesKey.Location = new System.Drawing.Point(7, 173);
            this.tb_aesKey.Name = "tb_aesKey";
            this.tb_aesKey.ReadOnly = true;
            this.tb_aesKey.Size = new System.Drawing.Size(341, 20);
            this.tb_aesKey.TabIndex = 24;
            // 
            // tb_encRecv
            // 
            this.tb_encRecv.Font = new System.Drawing.Font("Courier New", 8.25F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, ((byte)(162)));
            this.tb_encRecv.Location = new System.Drawing.Point(9, 326);
            this.tb_encRecv.Multiline = true;
            this.tb_encRecv.Name = "tb_encRecv";
            this.tb_encRecv.ReadOnly = true;
            this.tb_encRecv.ScrollBars = System.Windows.Forms.ScrollBars.Vertical;
            this.tb_encRecv.Size = new System.Drawing.Size(569, 54);
            this.tb_encRecv.TabIndex = 29;
            // 
            // label10
            // 
            this.label10.AutoSize = true;
            this.label10.Location = new System.Drawing.Point(7, 309);
            this.label10.Name = "label10";
            this.label10.Size = new System.Drawing.Size(177, 13);
            this.label10.TabIndex = 28;
            this.label10.Text = "Last Recieved Decrypted Message:";
            // 
            // sharedKeyBox
            // 
            this.sharedKeyBox.Font = new System.Drawing.Font("Courier New", 8.25F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, ((byte)(162)));
            this.sharedKeyBox.Location = new System.Drawing.Point(6, 35);
            this.sharedKeyBox.Name = "sharedKeyBox";
            this.sharedKeyBox.Size = new System.Drawing.Size(341, 20);
            this.sharedKeyBox.TabIndex = 30;
            this.sharedKeyBox.Text = "01 24 54 56 4A EB F4 E7 01 24 54 56 4A EB F4 E7";
            // 
            // label11
            // 
            this.label11.AutoSize = true;
            this.label11.Location = new System.Drawing.Point(376, 42);
            this.label11.Name = "label11";
            this.label11.Size = new System.Drawing.Size(74, 13);
            this.label11.TabIndex = 32;
            this.label11.Text = "Current Mode:";
            // 
            // tb_currentMode
            // 
            this.tb_currentMode.BackColor = System.Drawing.Color.DarkBlue;
            this.tb_currentMode.Font = new System.Drawing.Font("Calibri", 14F, System.Drawing.FontStyle.Bold, System.Drawing.GraphicsUnit.Point, ((byte)(162)));
            this.tb_currentMode.ForeColor = System.Drawing.Color.White;
            this.tb_currentMode.Location = new System.Drawing.Point(466, 28);
            this.tb_currentMode.Name = "tb_currentMode";
            this.tb_currentMode.ReadOnly = true;
            this.tb_currentMode.Size = new System.Drawing.Size(47, 30);
            this.tb_currentMode.TabIndex = 31;
            this.tb_currentMode.TextAlign = System.Windows.Forms.HorizontalAlignment.Center;
            // 
            // tb_IV
            // 
            this.tb_IV.Font = new System.Drawing.Font("Courier New", 8.25F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, ((byte)(162)));
            this.tb_IV.Location = new System.Drawing.Point(9, 213);
            this.tb_IV.Name = "tb_IV";
            this.tb_IV.ReadOnly = true;
            this.tb_IV.Size = new System.Drawing.Size(341, 20);
            this.tb_IV.TabIndex = 33;
            // 
            // tabControl1
            // 
            this.tabControl1.Controls.Add(this.tabPage1);
            this.tabControl1.Controls.Add(this.tabPage2);
            this.tabControl1.Location = new System.Drawing.Point(1, 12);
            this.tabControl1.Name = "tabControl1";
            this.tabControl1.SelectedIndex = 0;
            this.tabControl1.Size = new System.Drawing.Size(594, 645);
            this.tabControl1.TabIndex = 34;
            // 
            // tabPage1
            // 
            this.tabPage1.Controls.Add(this.tb_recoverName);
            this.tabPage1.Controls.Add(this.tb_filename);
            this.tabPage1.Controls.Add(this.tb_clientListenPort);
            this.tabPage1.Controls.Add(this.btn_recover);
            this.tabPage1.Controls.Add(this.backup_button);
            this.tabPage1.Controls.Add(this.label1);
            this.tabPage1.Controls.Add(this.groupBox1);
            this.tabPage1.Controls.Add(this.groupBox3);
            this.tabPage1.Controls.Add(this.textBoxIP);
            this.tabPage1.Controls.Add(this.label2);
            this.tabPage1.Controls.Add(this.textBoxPort);
            this.tabPage1.Controls.Add(this.buttonDisconnect);
            this.tabPage1.Controls.Add(this.buttonConnect);
            this.tabPage1.Controls.Add(this.label5);
            this.tabPage1.Controls.Add(this.textBoxConnectStatus);
            this.tabPage1.Location = new System.Drawing.Point(4, 22);
            this.tabPage1.Name = "tabPage1";
            this.tabPage1.Padding = new System.Windows.Forms.Padding(3);
            this.tabPage1.Size = new System.Drawing.Size(586, 619);
            this.tabPage1.TabIndex = 0;
            this.tabPage1.Text = "Settings";
            this.tabPage1.UseVisualStyleBackColor = true;
            // 
            // tb_recoverName
            // 
            this.tb_recoverName.Location = new System.Drawing.Point(306, 507);
            this.tb_recoverName.Name = "tb_recoverName";
            this.tb_recoverName.Size = new System.Drawing.Size(182, 20);
            this.tb_recoverName.TabIndex = 41;
            // 
            // tb_filename
            // 
            this.tb_filename.Location = new System.Drawing.Point(13, 509);
            this.tb_filename.Name = "tb_filename";
            this.tb_filename.Size = new System.Drawing.Size(182, 20);
            this.tb_filename.TabIndex = 40;
            // 
            // tb_clientListenPort
            // 
            this.tb_clientListenPort.Location = new System.Drawing.Point(94, 77);
            this.tb_clientListenPort.Name = "tb_clientListenPort";
            this.tb_clientListenPort.Size = new System.Drawing.Size(48, 20);
            this.tb_clientListenPort.TabIndex = 39;
            this.tb_clientListenPort.Text = "8001";
            // 
            // btn_recover
            // 
            this.btn_recover.Location = new System.Drawing.Point(306, 460);
            this.btn_recover.Name = "btn_recover";
            this.btn_recover.Size = new System.Drawing.Size(117, 41);
            this.btn_recover.TabIndex = 38;
            this.btn_recover.Text = "download this file";
            this.btn_recover.UseVisualStyleBackColor = true;
            this.btn_recover.Click += new System.EventHandler(this.btn_recover_Click);
            // 
            // backup_button
            // 
            this.backup_button.Location = new System.Drawing.Point(8, 460);
            this.backup_button.Name = "backup_button";
            this.backup_button.Size = new System.Drawing.Size(134, 42);
            this.backup_button.TabIndex = 37;
            this.backup_button.Text = "share this file";
            this.backup_button.UseVisualStyleBackColor = true;
            this.backup_button.Click += new System.EventHandler(this.backup_button_Click);
            // 
            // label1
            // 
            this.label1.AutoSize = true;
            this.label1.Location = new System.Drawing.Point(4, 35);
            this.label1.Name = "label1";
            this.label1.Size = new System.Drawing.Size(54, 13);
            this.label1.TabIndex = 36;
            this.label1.Text = "Server IP:";
            // 
            // groupBox1
            // 
            this.groupBox1.Controls.Add(this.label13);
            this.groupBox1.Controls.Add(this.tb_currentMode);
            this.groupBox1.Controls.Add(this.label11);
            this.groupBox1.Controls.Add(this.sharedKeyBox);
            this.groupBox1.Location = new System.Drawing.Point(7, 105);
            this.groupBox1.Name = "groupBox1";
            this.groupBox1.Size = new System.Drawing.Size(569, 78);
            this.groupBox1.TabIndex = 35;
            this.groupBox1.TabStop = false;
            this.groupBox1.Text = "AES";
            // 
            // label13
            // 
            this.label13.AutoSize = true;
            this.label13.Location = new System.Drawing.Point(6, 18);
            this.label13.Name = "label13";
            this.label13.Size = new System.Drawing.Size(101, 13);
            this.label13.TabIndex = 34;
            this.label13.Text = "A Priori Shared Key:";
            // 
            // groupBox3
            // 
            this.groupBox3.Controls.Add(this.tb_RsaPublicKey);
            this.groupBox3.Controls.Add(this.label6);
            this.groupBox3.Controls.Add(this.label7);
            this.groupBox3.Controls.Add(this.tb_RsaPublicKeyExpo);
            this.groupBox3.Location = new System.Drawing.Point(7, 206);
            this.groupBox3.Name = "groupBox3";
            this.groupBox3.Size = new System.Drawing.Size(569, 248);
            this.groupBox3.TabIndex = 33;
            this.groupBox3.TabStop = false;
            this.groupBox3.Text = "Server\'s Public Key";
            // 
            // tb_RsaPublicKey
            // 
            this.tb_RsaPublicKey.BackColor = System.Drawing.SystemColors.Control;
            this.tb_RsaPublicKey.Font = new System.Drawing.Font("Courier New", 8F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, ((byte)(162)));
            this.tb_RsaPublicKey.Location = new System.Drawing.Point(6, 36);
            this.tb_RsaPublicKey.Multiline = true;
            this.tb_RsaPublicKey.Name = "tb_RsaPublicKey";
            this.tb_RsaPublicKey.Size = new System.Drawing.Size(551, 152);
            this.tb_RsaPublicKey.TabIndex = 3;
            // 
            // label6
            // 
            this.label6.AutoSize = true;
            this.label6.Location = new System.Drawing.Point(6, 191);
            this.label6.Name = "label6";
            this.label6.Size = new System.Drawing.Size(55, 13);
            this.label6.TabIndex = 6;
            this.label6.Text = "Exponent:";
            // 
            // label7
            // 
            this.label7.AutoSize = true;
            this.label7.Location = new System.Drawing.Point(3, 20);
            this.label7.Name = "label7";
            this.label7.Size = new System.Drawing.Size(50, 13);
            this.label7.TabIndex = 4;
            this.label7.Text = "Modulus:";
            // 
            // tb_RsaPublicKeyExpo
            // 
            this.tb_RsaPublicKeyExpo.BackColor = System.Drawing.SystemColors.Control;
            this.tb_RsaPublicKeyExpo.Font = new System.Drawing.Font("Courier New", 8F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, ((byte)(162)));
            this.tb_RsaPublicKeyExpo.Location = new System.Drawing.Point(9, 208);
            this.tb_RsaPublicKeyExpo.Name = "tb_RsaPublicKeyExpo";
            this.tb_RsaPublicKeyExpo.Size = new System.Drawing.Size(250, 20);
            this.tb_RsaPublicKeyExpo.TabIndex = 5;
            // 
            // tabPage2
            // 
            this.tabPage2.Controls.Add(this.label14);
            this.tabPage2.Controls.Add(this.tb_encKey);
            this.tabPage2.Controls.Add(this.buttonClose);
            this.tabPage2.Controls.Add(this.label12);
            this.tabPage2.Controls.Add(this.label9);
            this.tabPage2.Controls.Add(this.tb_IV);
            this.tabPage2.Controls.Add(this.label4);
            this.tabPage2.Controls.Add(this.label3);
            this.tabPage2.Controls.Add(this.tb_aesKey);
            this.tabPage2.Controls.Add(this.label8);
            this.tabPage2.Controls.Add(this.tb_encSent);
            this.tabPage2.Controls.Add(this.label10);
            this.tabPage2.Controls.Add(this.tb_encRecv);
            this.tabPage2.Controls.Add(this.buttonSendMessage);
            this.tabPage2.Controls.Add(this.richTextTxMessage);
            this.tabPage2.Controls.Add(this.richTextRxMessage);
            this.tabPage2.Location = new System.Drawing.Point(4, 22);
            this.tabPage2.Name = "tabPage2";
            this.tabPage2.Padding = new System.Windows.Forms.Padding(3);
            this.tabPage2.Size = new System.Drawing.Size(586, 619);
            this.tabPage2.TabIndex = 1;
            this.tabPage2.Text = "Messages";
            this.tabPage2.UseVisualStyleBackColor = true;
            // 
            // label14
            // 
            this.label14.AutoSize = true;
            this.label14.Location = new System.Drawing.Point(7, 196);
            this.label14.Name = "label14";
            this.label14.Size = new System.Drawing.Size(57, 13);
            this.label14.TabIndex = 39;
            this.label14.Text = "Current IV:";
            // 
            // tb_encKey
            // 
            this.tb_encKey.Font = new System.Drawing.Font("Courier New", 8.25F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, ((byte)(162)));
            this.tb_encKey.HideSelection = false;
            this.tb_encKey.Location = new System.Drawing.Point(9, 399);
            this.tb_encKey.Multiline = true;
            this.tb_encKey.Name = "tb_encKey";
            this.tb_encKey.ReadOnly = true;
            this.tb_encKey.Size = new System.Drawing.Size(569, 107);
            this.tb_encKey.TabIndex = 38;
            // 
            // label12
            // 
            this.label12.AutoSize = true;
            this.label12.Location = new System.Drawing.Point(7, 383);
            this.label12.Name = "label12";
            this.label12.Size = new System.Drawing.Size(124, 13);
            this.label12.TabIndex = 37;
            this.label12.Text = "Session Key (Ciphertext):";
            // 
            // SecureMsgClient
            // 
            this.AutoScaleBaseSize = new System.Drawing.Size(5, 13);
            this.ClientSize = new System.Drawing.Size(591, 661);
            this.Controls.Add(this.tabControl1);
            this.FormBorderStyle = System.Windows.Forms.FormBorderStyle.FixedSingle;
            this.Name = "SecureMsgClient";
            this.Text = "Secure Messenger Client v1.0";
            this.tabControl1.ResumeLayout(false);
            this.tabPage1.ResumeLayout(false);
            this.tabPage1.PerformLayout();
            this.groupBox1.ResumeLayout(false);
            this.groupBox1.PerformLayout();
            this.groupBox3.ResumeLayout(false);
            this.groupBox3.PerformLayout();
            this.tabPage2.ResumeLayout(false);
            this.tabPage2.PerformLayout();
            this.ResumeLayout(false);

        }
        #endregion
     
        public void OnPeerConnect(IAsyncResult asyn)
        {
            try
            {
                // Here we complete/end the BeginAccept() asynchronous call
                // by calling EndAccept() - which returns the reference to
                // a new Socket object
                m_peerSockets[m_peerCount] = m_mainSocket.EndAccept(asyn);
                // Let the worker Socket do the further processing for the 
                // just connected client
                WaitForPeerData(m_peerSockets[m_peerCount]);
                // Now increment the client count
                ++m_peerCount;
                // Display this client connection as a status message on the GUI	
                String str = String.Format("Client # {0} connected", m_peerCount);


                // Since the main Socket is now free, it can go back and wait for
                // other clients who are attempting to connect
                m_mainSocket.BeginAccept(new AsyncCallback(OnPeerConnect), null);

                string a = "somebody connected: " + myport.ToString();
                //MessageBox.Show(a);


                // send the AES mode to the newly connected client
                //try
                //{
                //    string changeMode = "/chg";
                //    changeMode += Convert.ToInt32(cryptor.rijn.Mode);


                //    Object objData = changeMode;

                //    byte[] byData = System.Text.Encoding.ASCII.GetBytes(objData.ToString());

                //    for (int i = 0; i < m_clientCount; i++)
                //    {
                //        if (m_workerSocket[i] != null)
                //        {
                //            if (m_workerSocket[i].Connected)
                //            {
                //                m_workerSocket[i].Send(byData);
                //            }
                //        }
                //    }
                //}
                //catch (SocketException se)
                //{
                //    MessageBox.Show(se.Message);
                //}


            }
            catch (ObjectDisposedException)
            {
                System.Diagnostics.Debugger.Log(0, "1", "\n OnPeerConnection: Socket has been closed\n");
            }
            catch (SocketException se)
            {
                MessageBox.Show(se.Message);
            }

        }
        public void WaitForData()
        {
            try
            {
                if (m_pfnCallBack == null)
                {
                    m_pfnCallBack = new AsyncCallback(OnDataReceived);
                }
                SocketPacket theSocPkt = new SocketPacket();
                theSocPkt.m_currentSocket = m_clientSocket;
                // Start listening to the data asynchronously
                m_result = m_clientSocket.BeginReceive(theSocPkt.dataBuffer,
                                                        0, theSocPkt.dataBuffer.Length,
                                                        SocketFlags.None,
                                                        m_pfnCallBack,
                                                        theSocPkt);
            }
            catch (SocketException se)
            {
                MessageBox.Show(se.Message);
            }

        }
        public void WaitForPeerData(System.Net.Sockets.Socket soc)
        {
            try
            {
                if (pfnWorkerCallBack == null)
                {
                    // Specify the call back function which is to be 
                    // invoked when there is any write activity by the 
                    // connected client
                    pfnWorkerCallBack = new AsyncCallback(OnPeerDataReceived);
                }
                SocketPacket theSocPkt = new SocketPacket();
                theSocPkt.m_currentSocket = soc;

                // Start receiving any data written by the connected client
                // asynchronously
                soc.BeginReceive(theSocPkt.dataBuffer, 0,
                                   theSocPkt.dataBuffer.Length,
                                   SocketFlags.None,
                                   pfnWorkerCallBack,
                                   theSocPkt);
            }
            catch (SocketException se)
            {
                MessageBox.Show(se.Message);
            }

        }
        public void OnPeerDataReceived(IAsyncResult asyn)
        {
            try
            {
                SocketPacket socketData = (SocketPacket)asyn.AsyncState;

                int iRx = 0;
                // Complete the BeginReceive() asynchronous call by EndReceive() method
                // which will return the number of characters written to the stream 
                // by the client
                iRx = socketData.m_currentSocket.EndReceive(asyn);
                char[] chars = new char[iRx + 1];
                System.Text.Decoder d = System.Text.Encoding.Default.GetDecoder();
                int charLen = d.GetChars(socketData.dataBuffer,
                                         0, iRx, chars, 0);
                System.String szData = new System.String(chars);

                string incoming = szData.Substring(0, szData.Length - 1);


                if (incoming.StartsWith("/file"))
                {
                    MessageBox.Show("receiving file");
                    //recieved file
                    //file infile = new file();


                    string infilemsg = incoming.Substring(5);
                    cryptor.rijn.Key = senderClient.sessionkey;
                    string infilepart = cryptor.DecryptMessage(infilemsg);
                    string[] infilefields = infilepart.Split(' ');
                    //infile.fileid = infilefields[0];
                    //infile.filesize = infilefields[1];
                    string concat = infilefields[2]+" "+infilefields[3]+" "+infilefields[4];
                    byte[] bytefile = System.Text.Encoding.ASCII.GetBytes(concat);
                    //infile.filedata = bytefile;


                    string filename = infilefields[0];
                    //infile.filename = filename;

                    //filelist.Add(infile);
                    FileStream fStream = new FileStream(filename, FileMode.CreateNew);

                    BinaryWriter bw = new BinaryWriter(fStream);

                    bw.Write(bytefile);

                    bw.Close();

                    fStream.Close();



                }
                else if (incoming.StartsWith("/req"))
                {
                    //MessageBox.Show("Give me a halelujah");
                    //recieved share request

                    //receive tickets and import them to a arraylist.
                    mytickets tickets = new mytickets();

                    //List<client> clientlist = new List<client>();

                    tickets.DecodeFromString(incoming.Substring(4));

                    if ((!rsaserver.VerifyData(tickets.ticketlist[0].origFirst, new SHA1CryptoServiceProvider(), tickets.ticketlist[0].signFirst))
                            || (!rsaserver.VerifyData(tickets.ticketlist[0].origSecond, new SHA1CryptoServiceProvider(), tickets.ticketlist[0].signSecond)))
                    {
                        MessageBox.Show("AS is not authentic!");

                    }
                    else
                    {
                        ASCIIEncoding ByteConverter = new ASCIIEncoding();
                        string originalData = ByteConverter.GetString(tickets.ticketlist[0].origSecond);
                        string[] origfields = originalData.Split(' ');

                        if (!rsa.ToXmlString(false).Equals(origfields[2]))
                        {
                            MessageBox.Show("This ticket is not mine!");
                        }
                        else
                        {
                            string destData = ByteConverter.GetString(tickets.ticketlist[0].origFirst);
                            string[] destfields = destData.Split(' ');
                            senderClient = new client();
                            senderClient.ip = destfields[0];
                            senderClient.port = destfields[1];
                            senderClient.publicKey = destfields[2];
                            senderClient.ticket = incoming.Substring(4);
                            //WaitForPeerData(); // gerek var mý ?

                        }

                    }




                }
                else if (incoming.StartsWith("/key"))
                {
                    //recieved shared key

                    string[] KeyFields = incoming.Substring(4).Split(' ');
                    rsapeer.FromXmlString(senderClient.publicKey);



                    if (!rsapeer.VerifyData(ToByteArray(KeyFields[0]), new SHA1CryptoServiceProvider(), ToByteArray(KeyFields[1])))
                    {
                        MessageBox.Show("Key is not authenticated by valid sender!");

                    }
                    else
                    {
                        byte[] SessionKey = rsa.Decrypt(ToByteArray(KeyFields[0]), true);
                        senderClient.sessionkey = SessionKey;

                    }




                }
                else if (incoming.StartsWith("/sndreq"))
                {
                    //file'i oku
                    string[] fields = incoming.Substring(7).Split(' ');

                    //receive tickets and import them to a arraylist.
                    mytickets tickets = new mytickets();

                    //List<client> clientlist = new List<client>();

                    tickets.DecodeFromString(fields[0]);

                    if ((!rsaserver.VerifyData(tickets.ticketlist[0].origFirst, new SHA1CryptoServiceProvider(), tickets.ticketlist[0].signFirst))
                            || (!rsaserver.VerifyData(tickets.ticketlist[0].origSecond, new SHA1CryptoServiceProvider(), tickets.ticketlist[0].signSecond)))
                    {
                        MessageBox.Show("AS is not authentic!");

                    }
                    else
                    {

                        try
                        {

                            string fname = fields[1];
                            FileInfo fInfo = new FileInfo(fname);

                            long numBytes = fInfo.Length;

                            FileStream fStream = new FileStream(fname, FileMode.Open, FileAccess.Read);

                            BinaryReader br = new BinaryReader(fStream);

                            data = br.ReadBytes((int)numBytes);
                            br.Close();
                            fStream.Close();



                            MessageBox.Show("sending file piece back");
                            string functionID = "/pback";


                            string request = functionID + BytesToHex(data).Replace(" ", "");

                            //Object objData = request;

                            byte[] byData = System.Text.Encoding.ASCII.GetBytes(request);


                            //who to send?
                            Socket tempSoc;
                            //try
                            //{
                            string target = new ASCIIEncoding().GetString(tickets.ticketlist[0].origFirst);
                            string[] targetFields = target.Split(' ');
                            string ipStr = targetFields[0];
                            string portStr = targetFields[1];

                            UpdateControls(false);
                            // Create the socket instance
                            tempSoc = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);

                            // Cet the remote IP address
                            IPAddress ip = IPAddress.Parse(ipStr);
                            int iPortNo = System.Convert.ToInt16(portStr);
                            // Create the end point 
                            IPEndPoint ipEnd = new IPEndPoint(ip, iPortNo);
                            // Connect to the remote host

                            tempSoc.Connect(ipEnd);
                            if (tempSoc.Connected)
                            {

                                UpdateControls(true);
                                //Wait for data asynchronously 

                            }
                            //}
                            //catch (SocketException se)
                            //{
                            //  string str;
                            //str = "\nConnection failed, is the server running?\n" + se.Message;
                            //MessageBox.Show(str);
                            //UpdateControls(false);

                            //}



                            if (tempSoc != null)
                            {
                                tempSoc.Send(byData);
                            }
                        }
                        catch (SocketException se)
                        {
                            MessageBox.Show(se.Message);
                        }
                    }
                }
                else if (incoming.StartsWith("/pback"))
                {
                    string filePartMsg = incoming.Substring(6);
                    byte[] filePartb = ToByteArray(filePartMsg);

                    string bconcat = System.Text.Encoding.ASCII.GetString(filePartb);


                    string[] infilefields = bconcat.Split(' ');
                                        
                    byte[] tempPart = ToByteArray(infilefields[0]);


                    SharedData partOftheSecretThatWeAreTryingToAcquire = new SharedData();
                    partOftheSecretThatWeAreTryingToAcquire.xi = System.Convert.ToInt64(infilefields[1]);
                    partOftheSecretThatWeAreTryingToAcquire.yi = System.Convert.ToInt64(infilefields[2]);

                    secretsFromOthers.Add(partOftheSecretThatWeAreTryingToAcquire);
                    partsFromOthers.Add(tempPart);

                    if (partsFromOthers.Count >= enoughParts)
                    {
                        Reconstruct();
                    }
                }


                // Continue the waiting for data on the Socket
                WaitForPeerData(socketData.m_currentSocket);
            }
            catch (ObjectDisposedException)
            {
                System.Diagnostics.Debugger.Log(0, "1", "\nOnDataReceived: Socket has been closed\n");
            }
            catch (SocketException se)
            {
                MessageBox.Show(se.Message);
            }
        }
        public void OnDataReceived(IAsyncResult asyn)
        {
            try
            {
                SocketPacket theSockId = (SocketPacket)asyn.AsyncState;
                int iRx = theSockId.m_currentSocket.EndReceive(asyn);
                char[] chars = new char[iRx + 1];
                System.Text.Decoder d = System.Text.Encoding.Default.GetDecoder();
                int charLen = d.GetChars(theSockId.dataBuffer, 0, iRx, chars, 0);
                System.String szData = new System.String(chars);

                string incoming = szData.Substring(0, szData.Length - 1);

                if (incoming.StartsWith("/chg"))
                {
#if _SHOWMSG
                    MessageBox.Show("Mode Change Code recieved");
#endif

                    string mode = incoming.Substring(4, 1);
                    cryptor.rijn.Mode = (CipherMode)Convert.ToInt32(mode);
                    tb_currentMode.Text = cryptor.rijn.Mode.ToString();

                }
                else if (incoming.StartsWith("/sIV"))
                {
#if _SHOWMSG
                    MessageBox.Show("New IV recieved");
#endif

                    string iv = incoming.Substring(4);
                    cryptor.rijn.IV = ToByteArray(iv);
                    tb_IV.Text = BytesToHex(cryptor.rijn.IV);
                }
                else if (incoming.StartsWith("/rsaS"))
                {
#if _SHOWMSG
                    MessageBox.Show("RSA public key received");
#endif

                    string rsaKey = incoming.Substring(5);

                    rsaserver = new RSACryptoServiceProvider(2048);
                    rsaserver.FromXmlString(rsaKey);

                    RSAParameters rsap = rsaserver.ExportParameters(false);

                    tb_RsaPublicKey.Text = BytesToHex(rsap.Modulus);
                    tb_RsaPublicKeyExpo.Text = BytesToHex(rsap.Exponent);

                    // do not need begin
                    cryptor.rijn.GenerateKey();
                    tb_aesKey.Text = BytesToHex(cryptor.rijn.Key);
                    byte[] rsaEncData = rsaserver.Encrypt(cryptor.rijn.Key, true);
                    string encKeyHex = BytesToHex(rsaEncData).Replace(" ", "");
                    tb_encKey.Text = encKeyHex;
                    //do not need end

                    string newKeyMsg = "/rsaC" + GetIP() + " " + myport + " " + rsa.ToXmlString(false);

                    try
                    {

                        Object objData = newKeyMsg;
                        byte[] byData = System.Text.Encoding.ASCII.GetBytes(objData.ToString());
                        if (m_clientSocket != null)
                        {

                            m_clientSocket.Send(byData);

                        }
                    }
                    catch (SocketException se)
                    {
                        MessageBox.Show(se.Message);
                    }

                }
                else if (incoming.StartsWith("/tck"))
                {
                    //recieved tickets

                    //receive tickets and import them to a arraylist.
                    mytickets tickets = new mytickets();
                    List<client> clientlist = new List<client>();


                    tickets.DecodeFromString(incoming.Substring(4));
                    int dest_count = tickets.GetClientCount();
                    for (int i = 0; i < dest_count; i++)
                    {
                        if ((!rsaserver.VerifyData(tickets.ticketlist[i].origFirst, new SHA1CryptoServiceProvider(), tickets.ticketlist[i].signFirst))
                            || (!rsaserver.VerifyData(tickets.ticketlist[i].origSecond, new SHA1CryptoServiceProvider(), tickets.ticketlist[i].signSecond)))
                        {
                            MessageBox.Show("AS is not authentic!");

                        }
                        else
                        {
                            ASCIIEncoding ByteConverter = new ASCIIEncoding();
                            string originalData = ByteConverter.GetString(tickets.ticketlist[i].origFirst);
                            string[] origfields = originalData.Split(' ');

                            if (!rsa.ToXmlString(false).Equals(origfields[2]))
                            {
                                MessageBox.Show("This ticket is not mine!");
                            }
                            else
                            {
                                string destData = ByteConverter.GetString(tickets.ticketlist[i].origSecond);
                                string[] destfields = destData.Split(' ');
                                client tempclient = new client();
                                tempclient.ip = destfields[0];
                                tempclient.port = destfields[1];
                                tempclient.publicKey = destfields[2];
                                tempclient.ticket = tickets.ExportSingleTicket(i);
                                clientlist.Add(tempclient);
                            }

                        }

                    }

                    int numParts = dest_count - 1; //because the final part is the parity

                    int lengthofEachPart = (int)(data.Length / numParts) + 1;//pad the last one


                    //hash = BitConverter.ToString(cryptoTransformSHA1.ComputeHash()).Replace("-", "");



                    List<byte[]> parts = new List<byte[]>();
                    for (int i = 0; i < numParts; i++)
                    {
                        byte[] temp = new byte[lengthofEachPart];

                        for (int j = 0; j < lengthofEachPart; j++)
                        {
                            if (i == numParts - 1 && i * lengthofEachPart + j >= data.Length) //padding
                            {
                                temp[j] = 0x00000000;
                            }
                            else
                            {
                                temp[j] = data[i * lengthofEachPart + j];
                            }
                        }
                         
                        parts.Add(temp);
                    }

                    //we have the parts, calculate the parity part
                    byte[] parityPart = new byte[lengthofEachPart];

                    for (int j = 0; j < lengthofEachPart; j++)
                    {
                        byte xor = new byte();
                        xor = 0 ^ 0;
                        for (int i = 0; i < numParts; i++)
                        {
                            byte[] temp = (byte[])parts[i];
                            xor ^= temp[j];
                        }
                        parityPart[j] = xor;
                    }

                    parts.Add(parityPart);

                    //encrypt all parts with per file key
                    Random rand = new Random();
                    long randomNumToGenerateKey = rand.Next() % 25000;

                    byte[] randomNumToGenerateKeyByteEquivalent = new ASCIIEncoding().GetBytes(randomNumToGenerateKey.ToString());
                    perFileKey = cryptoTransformSHA1.ComputeHash(randomNumToGenerateKeyByteEquivalent);

                    byte[] reducedperfilekey = new byte[16];
                    for (int k = 0; k < 16; k++)
                    {
                        reducedperfilekey[k] = perFileKey[k];
                    }
                    cryptor.rijn.Key = reducedperfilekey;
                    for (int i = 0; i < numParts+1; i++)
                    {
                        string tempPart = cryptor.EncryptMessage(BytesToHex(parts[i]).Replace(" ", ""));
                        parts[i] = new ASCIIEncoding().GetBytes(tempPart);
                    }


                    //create the key and, secret share it with (n-1,n) threshold scheme.



                    ShamirSS sham = new ShamirSS((uint)parts.Count, (uint)parts.Count - 1, 25000);//burasý oldu lakin, reconstruct etmek cok zor. GF(2^8) kullanmak lazým en azýndan

                    SharedData[] shamirOut = sham.ShareData(randomNumToGenerateKey);
                    //connect to each ticket granted user to send its assigned part
                    //out of scope



                    // TODO ticketlarý gönder herkese
                    //rsapeer = new RSACryptoServiceProvider(2048);
                    for (int i = 0; i < dest_count; i++)
                    {
                        try
                        {
                            UpdateControls(false);
                            // Create the socket instance
                            m_peerSockets[m_peerCount] = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);

                            // Cet the remote IP address
                            IPAddress ip = IPAddress.Parse(clientlist[i].ip);
                            int iPortNo = System.Convert.ToInt16(clientlist[i].port);
                            // Create the end point 
                            IPEndPoint ipEnd = new IPEndPoint(ip, iPortNo);
                            // Connect to the remote host
                            m_peerSockets[m_peerCount].Connect(ipEnd);
                            if (m_peerSockets[m_peerCount].Connected)
                            {

                                UpdateControls(true);
                                //Wait for data asynchronously 
                                WaitForPeerData(m_peerSockets[m_peerCount]);//????
                                m_peerCount++;

                            }
                        }
                        catch (SocketException se)
                        {
                            string str;
                            str = "\nConnection failed, is the peer online?\n" + se.Message;
                            MessageBox.Show(str);
                            UpdateControls(false);
                        }
                        if (m_peerSockets[m_peerCount - 1].Connected)
                        {
                            try
                            {
                                string functionID = "/req";

                                string request = functionID + clientlist[i].ticket;

                                //Object objData = request;

                                byte[] byData = System.Text.Encoding.ASCII.GetBytes(request);


                                if (m_peerSockets[m_peerCount - 1] != null)
                                {

                                    m_peerSockets[m_peerCount - 1].Send(byData);
                                }
                            }
                            catch (SocketException se)
                            {
                                MessageBox.Show(se.Message);
                            }
                        }
                        else
                            MessageBox.Show("shit load");

                        // TODO: Ks yarat encrypt et yolla
                        cryptor.rijn.GenerateKey();
                        client temp = new client();
                        temp = clientlist[i];
                        temp.sessionkey = cryptor.rijn.Key;
                        clientlist[i] = temp;
                        tb_aesKey.Text = BytesToHex(cryptor.rijn.Key);
                        rsapeer.FromXmlString(clientlist[i].publicKey);
                        byte[] rsaEncData = rsapeer.Encrypt(cryptor.rijn.Key, true);
                        byte[] rsaSigned;
                        rsaSigned = rsa.SignData(rsaEncData, new SHA1CryptoServiceProvider());
                        string rsaSignedEncHex = BytesToHex(rsaEncData).Replace(" ", "") + " " + BytesToHex(rsaSigned).Replace(" ", "");
                        tb_encKey.Text = rsaSignedEncHex;
                        try
                        {
                            string functionID = "/key";

                            string request = functionID + rsaSignedEncHex;

                            //Object objData = request;

                            byte[] byData = System.Text.Encoding.ASCII.GetBytes(request);


                            if (m_peerSockets[m_peerCount - 1] != null)
                            {

                                m_peerSockets[m_peerCount - 1].Send(byData);
                            }
                        }
                        catch (SocketException se)
                        {
                            MessageBox.Show(se.Message);
                        }

                        System.Threading.Thread.Sleep(50);
                        try
                        {
                            MessageBox.Show("sending file parts");
                            string functionID = "/file";

                            string filepart = hash + " " + data.Length.ToString() + " " + BytesToHex(parts[i]).Replace(" ", "");
                            filepart += " " + shamirOut[i].xi.ToString() + " " + shamirOut[i].yi.ToString();

                            string filemsg = cryptor.EncryptMessage(filepart);


                            string request = functionID + filemsg;

                            //Object objData = request;

                            byte[] byData = System.Text.Encoding.ASCII.GetBytes(request);


                            if (m_peerSockets[m_peerCount - 1] != null)
                            {

                                m_peerSockets[m_peerCount - 1].Send(byData);
                            }
                        }
                        catch (SocketException se)
                        {
                            MessageBox.Show(se.Message);
                        }




                    }





                }
                else if (incoming.StartsWith("/rectck"))
                {
                    //recieved tickets

                    //receive tickets and import them to a arraylist.
                    mytickets tickets = new mytickets();
                    List<client> clientlist = new List<client>();


                    tickets.DecodeFromString(incoming.Substring(7));
                    int dest_count = tickets.GetClientCount();
                    enoughParts = dest_count;
                    for (int i = 0; i < dest_count; i++)
                    {
                        if ((!rsaserver.VerifyData(tickets.ticketlist[i].origFirst, new SHA1CryptoServiceProvider(), tickets.ticketlist[i].signFirst))
                            || (!rsaserver.VerifyData(tickets.ticketlist[i].origSecond, new SHA1CryptoServiceProvider(), tickets.ticketlist[i].signSecond)))
                        {
                            MessageBox.Show("AS is not authentic!");

                        }
                        else
                        {
                            ASCIIEncoding ByteConverter = new ASCIIEncoding();
                            string originalData = ByteConverter.GetString(tickets.ticketlist[i].origFirst);
                            string[] origfields = originalData.Split(' ');

                            if (!rsa.ToXmlString(false).Equals(origfields[2]))
                            {
                                MessageBox.Show("This ticket is not mine!");
                            }
                            else
                            {
                                string destData = ByteConverter.GetString(tickets.ticketlist[i].origSecond);
                                string[] destfields = destData.Split(' ');
                                client tempclient = new client();
                                tempclient.ip = destfields[0];
                                tempclient.port = destfields[1];
                                tempclient.publicKey = destfields[2];
                                tempclient.ticket = tickets.ExportSingleTicket(i);
                                clientlist.Add(tempclient);
                            }

                        }
                       

                    }



                    //partsFromOthers = new List<byte[]>();
                    for (int i = 0; i < clientlist.Count; i++)
                    {
                        //send tickets
                        //generate and send key
                        //send me the file
                        // TODO ticketlarý gönder herkese
                        try
                        {
                            UpdateControls(false);
                            // Create the socket instance
                            m_peerSockets[m_peerCount] = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);

                            // Cet the remote IP address
                            IPAddress ip = IPAddress.Parse(clientlist[i].ip);
                            int iPortNo = System.Convert.ToInt16(clientlist[i].port);
                            // Create the end point 
                            IPEndPoint ipEnd = new IPEndPoint(ip, iPortNo);
                            // Connect to the remote host
                            m_peerSockets[m_peerCount].Connect(ipEnd);
                            if (m_peerSockets[m_peerCount].Connected)
                            {

                                UpdateControls(true);
                                //Wait for data asynchronously 
                                WaitForPeerData(m_peerSockets[m_peerCount]);//????
                                m_peerCount++;

                            }
                        }
                        catch (SocketException se)
                        {
                            string str;
                            str = "\nConnection failed, is the peer online?\n" + se.Message;
                            MessageBox.Show(str);
                            UpdateControls(false);
                        }
                        if (m_peerSockets[m_peerCount - 1].Connected)
                        {
                            try
                            {
                                string functionID = "/sndreq";

                                string request = functionID + clientlist[i].ticket + " " + hash;

                                //Object objData = request;

                                byte[] byData = System.Text.Encoding.ASCII.GetBytes(request);


                                if (m_peerSockets[m_peerCount - 1] != null)
                                {

                                    m_peerSockets[m_peerCount - 1].Send(byData);
                                }
                            }
                            catch (SocketException se)
                            {
                                MessageBox.Show(se.Message);
                            }
                        }
                        else
                            MessageBox.Show("shit load");


                    }


                }

                else
                {
                    //decrypt message
                    tb_encRecv.Enabled = true;
                    tb_encRecv.Text = BytesToHex(Convert.FromBase64String(szData.Substring(0, szData.Length - 1)));
                    string decryptedText = cryptor.DecryptMessage(szData.Substring(0, szData.Length - 1));
                    richTextRxMessage.Text = decryptedText + "\n" + richTextRxMessage.Text;
                }




                WaitForData();
            }
            catch (ObjectDisposedException)
            {
                System.Diagnostics.Debugger.Log(0, "1", "\nOnDataReceived: Socket has been closed\n");
            }
            catch (SocketException se)
            {
                MessageBox.Show(se.Message);
            }
        }
        public void Reconstruct()
        {

            ShamirSS sham1 = new ShamirSS((uint)(enoughParts + 1), (uint)enoughParts, (long)(25000));

            SharedData[] shares = new SharedData[enoughParts];
            List<byte[]> finalParts = new List<byte[]>();

            for (int i = 0; i < enoughParts; i++)
            {
                shares[i] = secretsFromOthers[i];
            }

            long keygen = sham1.ReconstructData(shares);

            //decrypt parts


            byte[] reducedperfilekey = new byte[16];
            for (int k = 0; k < 16; k++)
            {
                reducedperfilekey[k] = perFileKey[k];
            }
            cryptor.rijn.Key = reducedperfilekey;
            //cryptor.rijn.Key = perFileKey;
            for (int i = 0; i < enoughParts; i++)
            {
                string tempString = new ASCIIEncoding().GetString(partsFromOthers[i]);
                string decrpytedHex = cryptor.DecryptMessage(tempString);
                finalParts.Add(ToByteArray(decrpytedHex));
            }

            bool[] foundParts = new bool[enoughParts + 1];
            for (int i = 0; i < enoughParts + 1; i++)
            {
                foundParts[i] = false;

            }

            for (int i = 0; i < enoughParts; i++)
            {
                foundParts[(uint)(shares[i].xi - 1)] = true;
            }

            byte[] finalFileData = new byte[finalParts[0].Length * enoughParts];
            if (foundParts[enoughParts])
            {
                //we have the parity part, xor to find the missing one
                //byte[] parityPart = new byte[finalParts[0].Length];

                //for (int j = 0; j < finalParts[0].Length; j++)
                //{
                //    byte xor = new byte();
                //    xor = 0 ^ 0;
                //    for (int i = 0; i < enoughParts; i++)
                //    {
                //        byte[] temp = (byte[])finalParts[i];
                //        xor ^= temp[j];
                //    }
                //    parityPart[j] = xor;
                //}
                //for (int i = 0; i < enoughParts+1; i++)
                //{
                //    int partNum = 0;
                //    //search Shamir
                //    for (int j = 0; j < enoughParts; j++)
                //    {
                //        if (shares[j].xi == i + 1)
                //            partNum = j;
                //    }
                //    finalParts[partNum].CopyTo(finalFileData, partNum * finalParts[0].Length);
                //}

            }
            else
            {
                //concatanate all
                
                for (int i = 0; i < enoughParts; i++)
                {
                    int partNum = 0;
                    //search Shamir
                    for (int j = 0; j < enoughParts; j++)
                    {
                        if (shares[j].xi == i + 1)
                            partNum = j;
                    }
                    finalParts[partNum].CopyTo(finalFileData, partNum * finalParts[0].Length);
                }
            }
            string filename = reconstructedFileName;
           
            FileStream fStream = new FileStream(filename, FileMode.CreateNew);

            BinaryWriter bw = new BinaryWriter(fStream);

            bw.Write(finalFileData);

            bw.Close();

            fStream.Close();

        }

        void ButtonConnectClick(object sender, System.EventArgs e)
        {
            cryptor.init(ToByteArray(sharedKeyBox.Text.Replace(" ", "")));
            tb_aesKey.Text = BytesToHex(cryptor.rijn.Key);



            // See if we have text on the IP and Port text fields
            if (textBoxIP.Text == "" || textBoxPort.Text == "")
            {
                MessageBox.Show("IP Address and Port Number are required to connect to the Server\n");
                return;
            }
            try
            {
                UpdateControls(false);
                // Create the socket instance
                m_clientSocket = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);

                // Cet the remote IP address
                IPAddress ip = IPAddress.Parse(textBoxIP.Text);
                int iPortNo = System.Convert.ToInt16(textBoxPort.Text);
                // Create the end point 
                IPEndPoint ipEnd = new IPEndPoint(ip, iPortNo);
                // Connect to the remote host
                m_clientSocket.Connect(ipEnd);
                if (m_clientSocket.Connected)
                {

                    UpdateControls(true);
                    //Wait for data asynchronously 
                    WaitForData();
                    //start Listening
                    ///////
                    try
                    {
                        // Check the port value
                        if (tb_clientListenPort.Text == "")
                        {
                            MessageBox.Show("Please enter a Port Number");
                            return;
                        }

                        myport = System.Convert.ToInt32(tb_clientListenPort.Text);
                        // Create the listening socket...
                        m_mainSocket = new Socket(AddressFamily.InterNetwork,
                                                  SocketType.Stream,
                                                  ProtocolType.Tcp);
                        IPEndPoint ipLocal = new IPEndPoint(IPAddress.Any, myport);
                        // Bind to local IP Address...
                        m_mainSocket.Bind(ipLocal);
                        // Start listening...
                        m_mainSocket.Listen(10);
                        // Create the call back for any client connections...
                        m_mainSocket.BeginAccept(new AsyncCallback(OnPeerConnect), null);

                        UpdateControls(true);

                    }
                    catch (SocketException se)
                    {
                        MessageBox.Show(se.Message);
                    }
                    //////
                }
            }
            catch (SocketException se)
            {
                string str;
                str = "\nConnection failed, is the server running?\n" + se.Message;
                MessageBox.Show(str);
                UpdateControls(false);
            }
        }
        void ButtonSendMessageClick(object sender, System.EventArgs e)
        {
            try
            {

                //encrypt the message using AES
                Object objData = cryptor.EncryptMessage(richTextTxMessage.Text);
                string encMsgHEX = BytesToHex(Convert.FromBase64String(objData.ToString()));
                byte[] byData = System.Text.Encoding.ASCII.GetBytes(objData.ToString());
                if (m_clientSocket != null)
                {

                    tb_encSent.Enabled = true;
                    tb_encSent.Text = encMsgHEX;

                    m_clientSocket.Send(byData);
                    richTextTxMessage.Text = "";
                }
            }
            catch (SocketException se)
            {
                MessageBox.Show(se.Message);
            }
        }
        void ButtonCloseClick(object sender, System.EventArgs e)
        {
            if (m_clientSocket != null)
            {
                m_clientSocket.Close();
                m_clientSocket = null;
            }
            Close();
        }
        void ButtonDisconnectClick(object sender, System.EventArgs e)
        {
            if (m_clientSocket != null)
            {
                m_clientSocket.Close();
                m_clientSocket = null;
                UpdateControls(false);
            }
        }
        private void backup_button_Click(object sender, EventArgs e)
        {
            //send a request to the admin server indicating; client wants to backup a file

            string fname = tb_filename.Text;
            FileInfo fInfo = new FileInfo(fname);

            long numBytes = fInfo.Length;

            FileStream fStream = new FileStream(fname, FileMode.Open, FileAccess.Read);

            BinaryReader br = new BinaryReader(fStream);

            data = br.ReadBytes((int)numBytes);

            // Show the number of bytes in the array.
            //label1.Text = Convert.ToString(data.Length);

            br.Close();

            fStream.Close();



            m_peerCount = 0;
            for (int i = 1; i < MAX_SOCKETS; i++)
            {
                if (m_peerSockets[i] != null)
                {
                    //m_peerSockets[i].Close();
                    m_peerSockets[i] = null;
                }
            }
            try
            {
                string functionID = "/bck";

                hash = BitConverter.ToString(cryptoTransformSHA1.ComputeHash(System.Text.Encoding.ASCII.GetBytes(fname))).Replace("-", "");

                string request = functionID + GetIP() + " " + myport + " " + hash + " " + data.Length.ToString();

                Object objData = request;

                byte[] byData = System.Text.Encoding.ASCII.GetBytes(objData.ToString());


                if (m_clientSocket != null)
                {

                    m_clientSocket.Send(byData);
                }
            }
            catch (SocketException se)
            {
                MessageBox.Show(se.Message);
            }

        }
        private void btn_recover_Click(object sender, EventArgs e)
        {
            m_peerCount = 0;
            for (int i = 1; i < MAX_SOCKETS; i++)
            {
                if (m_peerSockets[i] != null)
                {
                    //m_peerSockets[i].Close();
                    m_peerSockets[i] = null;
                }
            }
            try
            {
                string fname = tb_filename.Text;
                string functionID = "/rcv";
                reconstructedFileName = fname;
                

                hash = BitConverter.ToString(cryptoTransformSHA1.ComputeHash(System.Text.Encoding.ASCII.GetBytes(fname))).Replace("-", "");

                string request = functionID + GetIP() + " " + myport + " " + hash;

                //Object objData = request;

                byte[] byData = System.Text.Encoding.ASCII.GetBytes(request);


                if (m_clientSocket != null)
                {

                    m_clientSocket.Send(byData);
                }
            }
            catch (SocketException se)
            {
                MessageBox.Show(se.Message);
            }
        }
        private void UpdateControls(bool connected)
        {
            buttonConnect.Enabled = !connected;
            buttonDisconnect.Enabled = connected;
            string connectStatus = connected ? "Connected" : "Not Connected";
            textBoxConnectStatus.Text = connectStatus;
        }
        String GetIP()
        {
            String strHostName = Dns.GetHostName();

            // Find host by name
            IPHostEntry iphostentry = Dns.GetHostByName(strHostName);

            // Grab the first IP addresses
            String IPStr = "";
            foreach (IPAddress ipaddress in iphostentry.AddressList)
            {
                IPStr = ipaddress.ToString();
                return IPStr;
            }
            return IPStr;
        }
        public static string BytesToHex(byte[] bytes)
        {
            StringBuilder hexString = new StringBuilder(bytes.Length);
            for (int i = 0; i < bytes.Length; i++)
            {
                hexString.Append(bytes[i].ToString("X2") + " ");
            }

            return hexString.ToString().TrimEnd();
        }
        public static byte[] ToByteArray(String HexString)
        {

            int NumberChars = HexString.Length;
            byte[] bytes = new byte[NumberChars / 2];
            for (int i = 0; i < NumberChars; i += 2)
            {
                bytes[i / 2] = Convert.ToByte(HexString.Substring(i, 2), 16);
            }
            return bytes;
        }

  
       

    }

    


/****************************************************************/


    public class cryptor
    {

        public static RijndaelManaged rijn;
        public static ICryptoTransform encryptor;
        public static ICryptoTransform decryptor;
        

        public static void init(byte[] key)
        {
           

            rijn = new RijndaelManaged();
            rijn.Mode = CipherMode.ECB;
            rijn.Padding = PaddingMode.PKCS7;
            rijn.KeySize = 128;
            rijn.Key = key;


        }


        public static string EncryptMessage(string plainMessage)
        {

            ///////////////////////////////
            // Declare the streams used
            // to encrypt to an in memory
            // array of bytes.
            MemoryStream msEncrypt = null;
            CryptoStream csEncrypt = null;
            StreamWriter swEncrypt = null;

            try
            {

                // Create a encryptor to perform the stream transform.
                encryptor = rijn.CreateEncryptor();

                // Create the streams used for encryption.
                msEncrypt = new MemoryStream();
                csEncrypt = new CryptoStream(msEncrypt, encryptor, CryptoStreamMode.Write);
                swEncrypt = new StreamWriter(csEncrypt);

                //Write all data to the stream.
                swEncrypt.Write(plainMessage);
                if (swEncrypt != null)
                    swEncrypt.Close();
                if (csEncrypt != null)
                    csEncrypt.Close();
                if (msEncrypt != null)
                    msEncrypt.Close();

            }
            catch (CryptographicException ce)
            {
                MessageBox.Show(ce.Message + "\nProbably AES keys do not match!");
            }
        
            return Convert.ToBase64String(msEncrypt.ToArray());

           
        }

        public static string DecryptMessage(string encryptedBase64)
        {


            byte[] cipherText = Convert.FromBase64String(encryptedBase64);

            // TDeclare the streams used
            // to decrypt to an in memory
            // array of bytes.
            MemoryStream msDecrypt = null;
            CryptoStream csDecrypt = null;
            StreamReader srDecrypt = null;


            // Declare the string used to hold
            // the decrypted text.
            string plaintext = null;

            try
            {

                // Create a decryptor to perform the stream transform.
                decryptor = rijn.CreateDecryptor();

                // Create the streams used for decryption.
                msDecrypt = new MemoryStream(cipherText);
                csDecrypt = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Read);
                srDecrypt = new StreamReader(csDecrypt);

                // Read the decrypted bytes from the decrypting stream
                // and place them in a string.
                plaintext = srDecrypt.ReadToEnd();
                if (srDecrypt != null)
                    srDecrypt.Close();
                if (csDecrypt != null)
                    csDecrypt.Close();
                if (msDecrypt != null)
                    msDecrypt.Close();
            }
            catch (CryptographicException ce)
            {
                MessageBox.Show(ce.Message+"\nProbably AES keys do not match!");
            }
        

            return plaintext;
        }
    }
}
