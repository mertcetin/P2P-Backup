/*  
 *  Secure Messenger Server v1.0
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
	public class SecureMsgServer : System.Windows.Forms.Form
	{
		private System.Windows.Forms.Label label3;
		private System.Windows.Forms.Label label2;
		private System.Windows.Forms.RichTextBox richTextBoxReceivedMsg;
		private System.Windows.Forms.TextBox textBoxPort;
		private System.Windows.Forms.Label label5;
		private System.Windows.Forms.Label label4;
		private System.Windows.Forms.TextBox tb_statusmsg;
		private System.Windows.Forms.Button buttonStopListen;
		private System.Windows.Forms.Label label1;
		private System.Windows.Forms.RichTextBox richTextBoxSendMsg;
		private System.Windows.Forms.TextBox textBoxIP;
		private System.Windows.Forms.Button buttonStartListen;
        private System.Windows.Forms.Button buttonSendMsg;

        /////////////////////////////////////////////////////////////////////
		
		const int MAX_CLIENTS = 10;
        const int MAX_FILE = 10;
		
		public AsyncCallback pfnWorkerCallBack ;
		private  Socket m_mainSocket;
		private  Socket [] m_workerSocket = new Socket[256];
		private int m_clientCount = 0;
        public RSACryptoServiceProvider rsa;
        public List<clientInfo> clientsList;
        
        /////////////////////////////////////////////////////////////////////
        
        
        private TextBox tb_aeskey;
        private Label label6;
        private Label label7;
        private TextBox tb_encSent;
        private TextBox tb_encRecv;
        private Label label10;
        private GroupBox groupBox1;
        private TextBox sharedKeyBox;
        private RadioButton rb_RSA;
        private RadioButton radioButton1;
        private TextBox tb_RsaPublicKey;
        private GroupBox groupBox2;
        private RadioButton rb_aesMode3;
        private RadioButton rb_aesMode2;
        private RadioButton rb_aesMode1;
        private Label label9;
        private TextBox tb_RsaPublicKeyExpo;
        private Label label8;
        private GroupBox groupBox3;
        private Button b_ChangeMode;
        private Label label11;
        private TextBox tb_currentMode;
        private GroupBox groupBox4;
        private Button b_SendIV;
        private Button b_GenIV;
        private TextBox tb_IV;
        private Button b_setIV;
        private CheckBox cb_AutoGenerateIV;
        private TabControl tabControl1;
        private TabPage tabPage1;
        private TabPage tabPage2;
        private Label label12;
        private TextBox tb_encKey;
        private Label label13;
        private TextBox tb_CurIV;
        private Button buttonClose;
       
        //////////////////////////////////////////////////////////////////////////
        public class clientInfo
        {
            public string ip;
            public string port;
            public string publicKey;
            public file[] files;

            public clientInfo()
            {
                files = new file[MAX_FILE];
                for (int i = 0; i < MAX_FILE; i++)
                {
                    files[i].filetickets = new mytickets();
                }
            }
        }
        public struct file
        {
            public string fileID;
            public int filesize;
            public mytickets filetickets;
        }
        public class SocketPacket
        {
            public System.Net.Sockets.Socket m_currentSocket;
            public byte[] dataBuffer = new byte[65536 * 16];
        }
        public SecureMsgServer()
		{
			//
			// The InitializeComponent() call is required for Windows Forms designer support.
			//
			InitializeComponent();
            SecureMsgServer.CheckForIllegalCrossThreadCalls = false;
            
            // Display the local IP address on the GUI
            textBoxIP.Text = GetIP();
            
            // initialize RijndalManaged class with IV and shared Key inputs
            cryptor.init(HexToBytes(sharedKeyBox.Text.Replace(" ", "")));
            tb_currentMode.Text = cryptor.rijn.Mode.ToString();
            cryptor.rijn.IV = HexToBytes(tb_IV.Text.Replace(" ", ""));
            tb_CurIV.Text = BytesToHex(cryptor.rijn.IV);

            rsa = new RSACryptoServiceProvider(2048);

            clientsList = new List<clientInfo>();

		}
		
		[STAThread]
		public static void Main(string[] args)
		{
			Application.Run(new SecureMsgServer());
		}
        
		
		#region Windows Forms Designer generated code
		/// <summary>
		/// This method is required for Windows Forms designer support.
		/// Do not change the method contents inside the source code editor. The Forms designer might
		/// not be able to load this method if it was changed manually.
		/// </summary>
		private void InitializeComponent() {
            this.buttonSendMsg = new System.Windows.Forms.Button();
            this.buttonStartListen = new System.Windows.Forms.Button();
            this.textBoxIP = new System.Windows.Forms.TextBox();
            this.richTextBoxSendMsg = new System.Windows.Forms.RichTextBox();
            this.label1 = new System.Windows.Forms.Label();
            this.buttonStopListen = new System.Windows.Forms.Button();
            this.tb_statusmsg = new System.Windows.Forms.TextBox();
            this.label4 = new System.Windows.Forms.Label();
            this.label5 = new System.Windows.Forms.Label();
            this.textBoxPort = new System.Windows.Forms.TextBox();
            this.richTextBoxReceivedMsg = new System.Windows.Forms.RichTextBox();
            this.label2 = new System.Windows.Forms.Label();
            this.label3 = new System.Windows.Forms.Label();
            this.tb_aeskey = new System.Windows.Forms.TextBox();
            this.label6 = new System.Windows.Forms.Label();
            this.label7 = new System.Windows.Forms.Label();
            this.tb_encSent = new System.Windows.Forms.TextBox();
            this.tb_encRecv = new System.Windows.Forms.TextBox();
            this.label10 = new System.Windows.Forms.Label();
            this.groupBox1 = new System.Windows.Forms.GroupBox();
            this.groupBox3 = new System.Windows.Forms.GroupBox();
            this.tb_RsaPublicKey = new System.Windows.Forms.TextBox();
            this.label9 = new System.Windows.Forms.Label();
            this.label8 = new System.Windows.Forms.Label();
            this.tb_RsaPublicKeyExpo = new System.Windows.Forms.TextBox();
            this.sharedKeyBox = new System.Windows.Forms.TextBox();
            this.rb_RSA = new System.Windows.Forms.RadioButton();
            this.radioButton1 = new System.Windows.Forms.RadioButton();
            this.tabControl1 = new System.Windows.Forms.TabControl();
            this.tabPage1 = new System.Windows.Forms.TabPage();
            this.groupBox4 = new System.Windows.Forms.GroupBox();
            this.cb_AutoGenerateIV = new System.Windows.Forms.CheckBox();
            this.b_setIV = new System.Windows.Forms.Button();
            this.b_SendIV = new System.Windows.Forms.Button();
            this.b_GenIV = new System.Windows.Forms.Button();
            this.tb_IV = new System.Windows.Forms.TextBox();
            this.groupBox2 = new System.Windows.Forms.GroupBox();
            this.label11 = new System.Windows.Forms.Label();
            this.tb_currentMode = new System.Windows.Forms.TextBox();
            this.b_ChangeMode = new System.Windows.Forms.Button();
            this.rb_aesMode3 = new System.Windows.Forms.RadioButton();
            this.rb_aesMode2 = new System.Windows.Forms.RadioButton();
            this.rb_aesMode1 = new System.Windows.Forms.RadioButton();
            this.tabPage2 = new System.Windows.Forms.TabPage();
            this.buttonClose = new System.Windows.Forms.Button();
            this.label13 = new System.Windows.Forms.Label();
            this.tb_CurIV = new System.Windows.Forms.TextBox();
            this.tb_encKey = new System.Windows.Forms.TextBox();
            this.label12 = new System.Windows.Forms.Label();
            this.groupBox1.SuspendLayout();
            this.groupBox3.SuspendLayout();
            this.tabControl1.SuspendLayout();
            this.tabPage1.SuspendLayout();
            this.groupBox4.SuspendLayout();
            this.groupBox2.SuspendLayout();
            this.tabPage2.SuspendLayout();
            this.SuspendLayout();
            // 
            // buttonSendMsg
            // 
            this.buttonSendMsg.Location = new System.Drawing.Point(15, 150);
            this.buttonSendMsg.Name = "buttonSendMsg";
            this.buttonSendMsg.Size = new System.Drawing.Size(292, 24);
            this.buttonSendMsg.TabIndex = 7;
            this.buttonSendMsg.Text = "Send Message";
            this.buttonSendMsg.Click += new System.EventHandler(this.ButtonSendMsgClick);
            // 
            // buttonStartListen
            // 
            this.buttonStartListen.BackColor = System.Drawing.Color.Blue;
            this.buttonStartListen.Font = new System.Drawing.Font("Tahoma", 8.25F, System.Drawing.FontStyle.Bold, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.buttonStartListen.ForeColor = System.Drawing.Color.Yellow;
            this.buttonStartListen.Location = new System.Drawing.Point(273, 16);
            this.buttonStartListen.Name = "buttonStartListen";
            this.buttonStartListen.Size = new System.Drawing.Size(88, 40);
            this.buttonStartListen.TabIndex = 4;
            this.buttonStartListen.Text = "Start Listening";
            this.buttonStartListen.UseVisualStyleBackColor = false;
            this.buttonStartListen.Click += new System.EventHandler(this.ButtonStartListenClick);
            // 
            // textBoxIP
            // 
            this.textBoxIP.Location = new System.Drawing.Point(83, 16);
            this.textBoxIP.Name = "textBoxIP";
            this.textBoxIP.ReadOnly = true;
            this.textBoxIP.Size = new System.Drawing.Size(120, 20);
            this.textBoxIP.TabIndex = 12;
            // 
            // richTextBoxSendMsg
            // 
            this.richTextBoxSendMsg.Location = new System.Drawing.Point(15, 34);
            this.richTextBoxSendMsg.Name = "richTextBoxSendMsg";
            this.richTextBoxSendMsg.Size = new System.Drawing.Size(292, 110);
            this.richTextBoxSendMsg.TabIndex = 6;
            this.richTextBoxSendMsg.Text = "";
            // 
            // label1
            // 
            this.label1.Location = new System.Drawing.Point(11, 40);
            this.label1.Name = "label1";
            this.label1.Size = new System.Drawing.Size(48, 16);
            this.label1.TabIndex = 1;
            this.label1.Text = "Port:";
            // 
            // buttonStopListen
            // 
            this.buttonStopListen.BackColor = System.Drawing.Color.Red;
            this.buttonStopListen.Font = new System.Drawing.Font("Tahoma", 8.25F, System.Drawing.FontStyle.Bold, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.buttonStopListen.ForeColor = System.Drawing.Color.Yellow;
            this.buttonStopListen.Location = new System.Drawing.Point(367, 16);
            this.buttonStopListen.Name = "buttonStopListen";
            this.buttonStopListen.Size = new System.Drawing.Size(88, 40);
            this.buttonStopListen.TabIndex = 5;
            this.buttonStopListen.Text = "Stop Listening";
            this.buttonStopListen.UseVisualStyleBackColor = false;
            this.buttonStopListen.Click += new System.EventHandler(this.ButtonStopListenClick);
            // 
            // tb_statusmsg
            // 
            this.tb_statusmsg.BackColor = System.Drawing.SystemColors.Control;
            this.tb_statusmsg.BorderStyle = System.Windows.Forms.BorderStyle.None;
            this.tb_statusmsg.ForeColor = System.Drawing.SystemColors.HotTrack;
            this.tb_statusmsg.Location = new System.Drawing.Point(492, 40);
            this.tb_statusmsg.Name = "tb_statusmsg";
            this.tb_statusmsg.ReadOnly = true;
            this.tb_statusmsg.Size = new System.Drawing.Size(103, 13);
            this.tb_statusmsg.TabIndex = 14;
            this.tb_statusmsg.Text = "None";
            // 
            // label4
            // 
            this.label4.Location = new System.Drawing.Point(14, 18);
            this.label4.Name = "label4";
            this.label4.Size = new System.Drawing.Size(192, 16);
            this.label4.TabIndex = 8;
            this.label4.Text = "Broadcast Message To Clients:";
            // 
            // label5
            // 
            this.label5.Location = new System.Drawing.Point(314, 18);
            this.label5.Name = "label5";
            this.label5.Size = new System.Drawing.Size(192, 16);
            this.label5.TabIndex = 10;
            this.label5.Text = "Message Received From Clients:";
            // 
            // textBoxPort
            // 
            this.textBoxPort.Location = new System.Drawing.Point(83, 40);
            this.textBoxPort.Name = "textBoxPort";
            this.textBoxPort.Size = new System.Drawing.Size(40, 20);
            this.textBoxPort.TabIndex = 0;
            this.textBoxPort.Text = "8000";
            // 
            // richTextBoxReceivedMsg
            // 
            this.richTextBoxReceivedMsg.BackColor = System.Drawing.SystemColors.InactiveCaption;
            this.richTextBoxReceivedMsg.ForeColor = System.Drawing.SystemColors.InactiveCaptionText;
            this.richTextBoxReceivedMsg.Location = new System.Drawing.Point(317, 34);
            this.richTextBoxReceivedMsg.Name = "richTextBoxReceivedMsg";
            this.richTextBoxReceivedMsg.ReadOnly = true;
            this.richTextBoxReceivedMsg.Size = new System.Drawing.Size(290, 110);
            this.richTextBoxReceivedMsg.TabIndex = 9;
            this.richTextBoxReceivedMsg.Text = "";
            // 
            // label2
            // 
            this.label2.Location = new System.Drawing.Point(11, 16);
            this.label2.Name = "label2";
            this.label2.Size = new System.Drawing.Size(56, 16);
            this.label2.TabIndex = 2;
            this.label2.Text = "Server IP:";
            // 
            // label3
            // 
            this.label3.Location = new System.Drawing.Point(489, 19);
            this.label3.Name = "label3";
            this.label3.Size = new System.Drawing.Size(106, 16);
            this.label3.TabIndex = 13;
            this.label3.Text = "Status Message:";
            // 
            // tb_aeskey
            // 
            this.tb_aeskey.Font = new System.Drawing.Font("Courier New", 8.25F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, ((byte)(162)));
            this.tb_aeskey.HideSelection = false;
            this.tb_aeskey.Location = new System.Drawing.Point(15, 202);
            this.tb_aeskey.Name = "tb_aeskey";
            this.tb_aeskey.ReadOnly = true;
            this.tb_aeskey.Size = new System.Drawing.Size(457, 20);
            this.tb_aeskey.TabIndex = 15;
            // 
            // label6
            // 
            this.label6.AutoSize = true;
            this.label6.Location = new System.Drawing.Point(12, 186);
            this.label6.Name = "label6";
            this.label6.Size = new System.Drawing.Size(68, 13);
            this.label6.TabIndex = 16;
            this.label6.Text = "Session Key:";
            // 
            // label7
            // 
            this.label7.AutoSize = true;
            this.label7.Location = new System.Drawing.Point(12, 263);
            this.label7.Name = "label7";
            this.label7.Size = new System.Drawing.Size(152, 13);
            this.label7.TabIndex = 17;
            this.label7.Text = "Last Sent Encrypted Message:";
            // 
            // tb_encSent
            // 
            this.tb_encSent.Enabled = false;
            this.tb_encSent.Font = new System.Drawing.Font("Courier New", 8.25F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, ((byte)(162)));
            this.tb_encSent.HideSelection = false;
            this.tb_encSent.Location = new System.Drawing.Point(15, 280);
            this.tb_encSent.Multiline = true;
            this.tb_encSent.Name = "tb_encSent";
            this.tb_encSent.ReadOnly = true;
            this.tb_encSent.ScrollBars = System.Windows.Forms.ScrollBars.Vertical;
            this.tb_encSent.Size = new System.Drawing.Size(590, 60);
            this.tb_encSent.TabIndex = 18;
            // 
            // tb_encRecv
            // 
            this.tb_encRecv.Enabled = false;
            this.tb_encRecv.Font = new System.Drawing.Font("Courier New", 8.25F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, ((byte)(162)));
            this.tb_encRecv.HideSelection = false;
            this.tb_encRecv.Location = new System.Drawing.Point(15, 359);
            this.tb_encRecv.Multiline = true;
            this.tb_encRecv.Name = "tb_encRecv";
            this.tb_encRecv.ReadOnly = true;
            this.tb_encRecv.ScrollBars = System.Windows.Forms.ScrollBars.Vertical;
            this.tb_encRecv.Size = new System.Drawing.Size(590, 60);
            this.tb_encRecv.TabIndex = 31;
            // 
            // label10
            // 
            this.label10.AutoSize = true;
            this.label10.Location = new System.Drawing.Point(12, 343);
            this.label10.Name = "label10";
            this.label10.Size = new System.Drawing.Size(177, 13);
            this.label10.TabIndex = 30;
            this.label10.Text = "Last Recieved Decrypted Message:";
            // 
            // groupBox1
            // 
            this.groupBox1.Controls.Add(this.groupBox3);
            this.groupBox1.Controls.Add(this.sharedKeyBox);
            this.groupBox1.Controls.Add(this.rb_RSA);
            this.groupBox1.Controls.Add(this.radioButton1);
            this.groupBox1.FlatStyle = System.Windows.Forms.FlatStyle.Popup;
            this.groupBox1.Location = new System.Drawing.Point(8, 73);
            this.groupBox1.Name = "groupBox1";
            this.groupBox1.Size = new System.Drawing.Size(599, 346);
            this.groupBox1.TabIndex = 32;
            this.groupBox1.TabStop = false;
            this.groupBox1.Text = "Key Exchange Mechanism";
            // 
            // groupBox3
            // 
            this.groupBox3.Controls.Add(this.tb_RsaPublicKey);
            this.groupBox3.Controls.Add(this.label9);
            this.groupBox3.Controls.Add(this.label8);
            this.groupBox3.Controls.Add(this.tb_RsaPublicKeyExpo);
            this.groupBox3.Location = new System.Drawing.Point(24, 92);
            this.groupBox3.Name = "groupBox3";
            this.groupBox3.Size = new System.Drawing.Size(569, 248);
            this.groupBox3.TabIndex = 7;
            this.groupBox3.TabStop = false;
            this.groupBox3.Text = "Public Key";
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
            // label9
            // 
            this.label9.AutoSize = true;
            this.label9.Location = new System.Drawing.Point(6, 191);
            this.label9.Name = "label9";
            this.label9.Size = new System.Drawing.Size(55, 13);
            this.label9.TabIndex = 6;
            this.label9.Text = "Exponent:";
            // 
            // label8
            // 
            this.label8.AutoSize = true;
            this.label8.Location = new System.Drawing.Point(3, 20);
            this.label8.Name = "label8";
            this.label8.Size = new System.Drawing.Size(50, 13);
            this.label8.TabIndex = 4;
            this.label8.Text = "Modulus:";
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
            // sharedKeyBox
            // 
            this.sharedKeyBox.Font = new System.Drawing.Font("Courier New", 8.25F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, ((byte)(162)));
            this.sharedKeyBox.Location = new System.Drawing.Point(24, 42);
            this.sharedKeyBox.Name = "sharedKeyBox";
            this.sharedKeyBox.Size = new System.Drawing.Size(341, 20);
            this.sharedKeyBox.TabIndex = 2;
            this.sharedKeyBox.Text = "01 24 54 56 4A EB F4 E7 01 24 54 56 4A EB F4 E7";
            // 
            // rb_RSA
            // 
            this.rb_RSA.AutoSize = true;
            this.rb_RSA.Location = new System.Drawing.Point(6, 68);
            this.rb_RSA.Name = "rb_RSA";
            this.rb_RSA.Size = new System.Drawing.Size(161, 17);
            this.rb_RSA.TabIndex = 1;
            this.rb_RSA.Text = "RSA Key Exchange Protocol";
            this.rb_RSA.UseVisualStyleBackColor = true;
            // 
            // radioButton1
            // 
            this.radioButton1.AutoSize = true;
            this.radioButton1.Checked = true;
            this.radioButton1.Location = new System.Drawing.Point(6, 19);
            this.radioButton1.Name = "radioButton1";
            this.radioButton1.Size = new System.Drawing.Size(119, 17);
            this.radioButton1.TabIndex = 0;
            this.radioButton1.TabStop = true;
            this.radioButton1.Text = "A Priori Shared Key:";
            this.radioButton1.UseVisualStyleBackColor = true;
            // 
            // tabControl1
            // 
            this.tabControl1.Controls.Add(this.tabPage1);
            this.tabControl1.Controls.Add(this.tabPage2);
            this.tabControl1.Location = new System.Drawing.Point(1, 12);
            this.tabControl1.Name = "tabControl1";
            this.tabControl1.SelectedIndex = 0;
            this.tabControl1.Size = new System.Drawing.Size(623, 584);
            this.tabControl1.TabIndex = 8;
            // 
            // tabPage1
            // 
            this.tabPage1.Controls.Add(this.buttonStartListen);
            this.tabPage1.Controls.Add(this.label2);
            this.tabPage1.Controls.Add(this.textBoxPort);
            this.tabPage1.Controls.Add(this.groupBox4);
            this.tabPage1.Controls.Add(this.label1);
            this.tabPage1.Controls.Add(this.groupBox2);
            this.tabPage1.Controls.Add(this.buttonStopListen);
            this.tabPage1.Controls.Add(this.groupBox1);
            this.tabPage1.Controls.Add(this.textBoxIP);
            this.tabPage1.Controls.Add(this.tb_statusmsg);
            this.tabPage1.Controls.Add(this.label3);
            this.tabPage1.Location = new System.Drawing.Point(4, 22);
            this.tabPage1.Name = "tabPage1";
            this.tabPage1.Padding = new System.Windows.Forms.Padding(3);
            this.tabPage1.Size = new System.Drawing.Size(615, 558);
            this.tabPage1.TabIndex = 0;
            this.tabPage1.Text = "Settings";
            this.tabPage1.UseVisualStyleBackColor = true;
            // 
            // groupBox4
            // 
            this.groupBox4.Controls.Add(this.cb_AutoGenerateIV);
            this.groupBox4.Controls.Add(this.b_setIV);
            this.groupBox4.Controls.Add(this.b_SendIV);
            this.groupBox4.Controls.Add(this.b_GenIV);
            this.groupBox4.Controls.Add(this.tb_IV);
            this.groupBox4.Location = new System.Drawing.Point(8, 480);
            this.groupBox4.Name = "groupBox4";
            this.groupBox4.Size = new System.Drawing.Size(599, 70);
            this.groupBox4.TabIndex = 34;
            this.groupBox4.TabStop = false;
            this.groupBox4.Text = "Initialization Vector";
            // 
            // cb_AutoGenerateIV
            // 
            this.cb_AutoGenerateIV.AutoSize = true;
            this.cb_AutoGenerateIV.Location = new System.Drawing.Point(7, 45);
            this.cb_AutoGenerateIV.Name = "cb_AutoGenerateIV";
            this.cb_AutoGenerateIV.Size = new System.Drawing.Size(221, 17);
            this.cb_AutoGenerateIV.TabIndex = 12;
            this.cb_AutoGenerateIV.Text = "Auto Generate New IV for each Message";
            this.cb_AutoGenerateIV.UseVisualStyleBackColor = true;
            // 
            // b_setIV
            // 
            this.b_setIV.Enabled = false;
            this.b_setIV.Location = new System.Drawing.Point(350, 19);
            this.b_setIV.Name = "b_setIV";
            this.b_setIV.Size = new System.Drawing.Size(75, 23);
            this.b_setIV.TabIndex = 11;
            this.b_setIV.Text = "Set";
            this.b_setIV.UseVisualStyleBackColor = true;
            this.b_setIV.Click += new System.EventHandler(this.b_setIV_Click);
            // 
            // b_SendIV
            // 
            this.b_SendIV.Location = new System.Drawing.Point(512, 19);
            this.b_SendIV.Name = "b_SendIV";
            this.b_SendIV.Size = new System.Drawing.Size(75, 23);
            this.b_SendIV.TabIndex = 10;
            this.b_SendIV.Text = "Send";
            this.b_SendIV.UseVisualStyleBackColor = true;
            this.b_SendIV.Click += new System.EventHandler(this.b_SendIV_Click);
            // 
            // b_GenIV
            // 
            this.b_GenIV.Location = new System.Drawing.Point(431, 19);
            this.b_GenIV.Name = "b_GenIV";
            this.b_GenIV.Size = new System.Drawing.Size(75, 23);
            this.b_GenIV.TabIndex = 9;
            this.b_GenIV.Text = "Generate";
            this.b_GenIV.UseVisualStyleBackColor = true;
            this.b_GenIV.Click += new System.EventHandler(this.b_GenIV_Click);
            // 
            // tb_IV
            // 
            this.tb_IV.Font = new System.Drawing.Font("Courier New", 8.25F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, ((byte)(162)));
            this.tb_IV.Location = new System.Drawing.Point(6, 19);
            this.tb_IV.Name = "tb_IV";
            this.tb_IV.Size = new System.Drawing.Size(341, 20);
            this.tb_IV.TabIndex = 8;
            this.tb_IV.Text = "AA EE 54 12 4A EB F4 E7 01 24 54 56 4A FF F4 99";
            this.tb_IV.TextChanged += new System.EventHandler(this.tb_IV_TextChanged);
            // 
            // groupBox2
            // 
            this.groupBox2.Controls.Add(this.label11);
            this.groupBox2.Controls.Add(this.tb_currentMode);
            this.groupBox2.Controls.Add(this.b_ChangeMode);
            this.groupBox2.Controls.Add(this.rb_aesMode3);
            this.groupBox2.Controls.Add(this.rb_aesMode2);
            this.groupBox2.Controls.Add(this.rb_aesMode1);
            this.groupBox2.Location = new System.Drawing.Point(8, 419);
            this.groupBox2.Name = "groupBox2";
            this.groupBox2.Size = new System.Drawing.Size(599, 55);
            this.groupBox2.TabIndex = 33;
            this.groupBox2.TabStop = false;
            this.groupBox2.Text = "AES Mode";
            // 
            // label11
            // 
            this.label11.AutoSize = true;
            this.label11.Location = new System.Drawing.Point(199, 21);
            this.label11.Name = "label11";
            this.label11.Size = new System.Drawing.Size(74, 13);
            this.label11.TabIndex = 5;
            this.label11.Text = "Current Mode:";
            // 
            // tb_currentMode
            // 
            this.tb_currentMode.BackColor = System.Drawing.Color.DarkBlue;
            this.tb_currentMode.Font = new System.Drawing.Font("Calibri", 14F, System.Drawing.FontStyle.Bold, System.Drawing.GraphicsUnit.Point, ((byte)(162)));
            this.tb_currentMode.ForeColor = System.Drawing.Color.White;
            this.tb_currentMode.Location = new System.Drawing.Point(279, 16);
            this.tb_currentMode.Name = "tb_currentMode";
            this.tb_currentMode.ReadOnly = true;
            this.tb_currentMode.Size = new System.Drawing.Size(47, 30);
            this.tb_currentMode.TabIndex = 4;
            this.tb_currentMode.TextAlign = System.Windows.Forms.HorizontalAlignment.Center;
            // 
            // b_ChangeMode
            // 
            this.b_ChangeMode.Location = new System.Drawing.Point(484, 23);
            this.b_ChangeMode.Name = "b_ChangeMode";
            this.b_ChangeMode.Size = new System.Drawing.Size(97, 23);
            this.b_ChangeMode.TabIndex = 3;
            this.b_ChangeMode.Text = "Change Mode";
            this.b_ChangeMode.UseVisualStyleBackColor = true;
            this.b_ChangeMode.Click += new System.EventHandler(this.b_ChangeMode_Click);
            // 
            // rb_aesMode3
            // 
            this.rb_aesMode3.AutoSize = true;
            this.rb_aesMode3.Location = new System.Drawing.Point(112, 19);
            this.rb_aesMode3.Name = "rb_aesMode3";
            this.rb_aesMode3.Size = new System.Drawing.Size(45, 17);
            this.rb_aesMode3.TabIndex = 2;
            this.rb_aesMode3.Text = "CFB";
            this.rb_aesMode3.UseVisualStyleBackColor = true;
            // 
            // rb_aesMode2
            // 
            this.rb_aesMode2.AutoSize = true;
            this.rb_aesMode2.Location = new System.Drawing.Point(59, 19);
            this.rb_aesMode2.Name = "rb_aesMode2";
            this.rb_aesMode2.Size = new System.Drawing.Size(46, 17);
            this.rb_aesMode2.TabIndex = 1;
            this.rb_aesMode2.Text = "CBC";
            this.rb_aesMode2.UseVisualStyleBackColor = true;
            // 
            // rb_aesMode1
            // 
            this.rb_aesMode1.AutoSize = true;
            this.rb_aesMode1.Checked = true;
            this.rb_aesMode1.Location = new System.Drawing.Point(7, 20);
            this.rb_aesMode1.Name = "rb_aesMode1";
            this.rb_aesMode1.Size = new System.Drawing.Size(46, 17);
            this.rb_aesMode1.TabIndex = 0;
            this.rb_aesMode1.TabStop = true;
            this.rb_aesMode1.Text = "ECB";
            this.rb_aesMode1.UseVisualStyleBackColor = true;
            // 
            // tabPage2
            // 
            this.tabPage2.Controls.Add(this.buttonClose);
            this.tabPage2.Controls.Add(this.label13);
            this.tabPage2.Controls.Add(this.tb_CurIV);
            this.tabPage2.Controls.Add(this.tb_encKey);
            this.tabPage2.Controls.Add(this.label4);
            this.tabPage2.Controls.Add(this.richTextBoxSendMsg);
            this.tabPage2.Controls.Add(this.label12);
            this.tabPage2.Controls.Add(this.buttonSendMsg);
            this.tabPage2.Controls.Add(this.richTextBoxReceivedMsg);
            this.tabPage2.Controls.Add(this.label5);
            this.tabPage2.Controls.Add(this.tb_aeskey);
            this.tabPage2.Controls.Add(this.tb_encRecv);
            this.tabPage2.Controls.Add(this.label6);
            this.tabPage2.Controls.Add(this.label10);
            this.tabPage2.Controls.Add(this.label7);
            this.tabPage2.Controls.Add(this.tb_encSent);
            this.tabPage2.Location = new System.Drawing.Point(4, 22);
            this.tabPage2.Name = "tabPage2";
            this.tabPage2.Padding = new System.Windows.Forms.Padding(3);
            this.tabPage2.Size = new System.Drawing.Size(615, 558);
            this.tabPage2.TabIndex = 1;
            this.tabPage2.Text = "Messages";
            this.tabPage2.UseVisualStyleBackColor = true;
            // 
            // buttonClose
            // 
            this.buttonClose.Location = new System.Drawing.Point(502, 150);
            this.buttonClose.Name = "buttonClose";
            this.buttonClose.Size = new System.Drawing.Size(103, 24);
            this.buttonClose.TabIndex = 39;
            this.buttonClose.Text = "Close";
            this.buttonClose.Click += new System.EventHandler(this.buttonClose_Click);
            // 
            // label13
            // 
            this.label13.AutoSize = true;
            this.label13.Location = new System.Drawing.Point(12, 224);
            this.label13.Name = "label13";
            this.label13.Size = new System.Drawing.Size(57, 13);
            this.label13.TabIndex = 38;
            this.label13.Text = "Current IV:";
            // 
            // tb_CurIV
            // 
            this.tb_CurIV.BackColor = System.Drawing.SystemColors.Control;
            this.tb_CurIV.Font = new System.Drawing.Font("Courier New", 8.25F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, ((byte)(162)));
            this.tb_CurIV.HideSelection = false;
            this.tb_CurIV.Location = new System.Drawing.Point(15, 241);
            this.tb_CurIV.Name = "tb_CurIV";
            this.tb_CurIV.Size = new System.Drawing.Size(456, 20);
            this.tb_CurIV.TabIndex = 37;
            // 
            // tb_encKey
            // 
            this.tb_encKey.Font = new System.Drawing.Font("Courier New", 8.25F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, ((byte)(162)));
            this.tb_encKey.HideSelection = false;
            this.tb_encKey.Location = new System.Drawing.Point(15, 438);
            this.tb_encKey.Multiline = true;
            this.tb_encKey.Name = "tb_encKey";
            this.tb_encKey.ReadOnly = true;
            this.tb_encKey.Size = new System.Drawing.Size(590, 111);
            this.tb_encKey.TabIndex = 36;
            // 
            // label12
            // 
            this.label12.AutoSize = true;
            this.label12.Location = new System.Drawing.Point(14, 422);
            this.label12.Name = "label12";
            this.label12.Size = new System.Drawing.Size(124, 13);
            this.label12.TabIndex = 35;
            this.label12.Text = "Session Key (Ciphertext):";
            // 
            // SecureMsgServer
            // 
            this.AutoScaleBaseSize = new System.Drawing.Size(5, 13);
            this.ClientSize = new System.Drawing.Size(621, 595);
            this.Controls.Add(this.tabControl1);
            this.FormBorderStyle = System.Windows.Forms.FormBorderStyle.FixedSingle;
            this.Name = "SecureMsgServer";
            this.Text = "Secure Messenger Server v1.0";
            this.groupBox1.ResumeLayout(false);
            this.groupBox1.PerformLayout();
            this.groupBox3.ResumeLayout(false);
            this.groupBox3.PerformLayout();
            this.tabControl1.ResumeLayout(false);
            this.tabPage1.ResumeLayout(false);
            this.tabPage1.PerformLayout();
            this.groupBox4.ResumeLayout(false);
            this.groupBox4.PerformLayout();
            this.groupBox2.ResumeLayout(false);
            this.groupBox2.PerformLayout();
            this.tabPage2.ResumeLayout(false);
            this.tabPage2.PerformLayout();
            this.ResumeLayout(false);

		}
		#endregion
        // Start waiting for data from the client
        public void WaitForData(System.Net.Sockets.Socket soc)
        {
            try
            {
                if (pfnWorkerCallBack == null)
                {
                    // Specify the call back function which is to be 
                    // invoked when there is any write activity by the 
                    // connected client
                    pfnWorkerCallBack = new AsyncCallback(OnDataReceived);
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

        // This the call back function which will be invoked when the socket
        // detects any client writing of data on the stream
        public void OnDataReceived(IAsyncResult asyn)
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


                if (incoming.StartsWith("/rsaC"))
                {
#if _SHOWMSG
                    MessageBox.Show("RSA public key received");
#endif

                    string rsaKey = incoming.Substring(5);
                    string[] fields = rsaKey.Split(' ');


                    clientInfo tempclient = new clientInfo();
                    tempclient.ip = fields[0];
                    tempclient.port = fields[1];
                    tempclient.publicKey = fields[2];

                    if(!clientsList.Contains(tempclient)) clientsList.Add(tempclient);

                }
                else if (incoming.StartsWith("/bck"))
                {
                    //client wants to back up
                    //decide which parties to connect
                    //pseudo connections list.
                    string[] backupreq = incoming.Substring(4).Split(' ');

                    //client req = new client();                   
                    int clientnum = -1;
                    for (int i = 0; i < clientsList.Count; i++)
                    {
                        if (clientsList[i].ip.Equals(backupreq[0]))
                        {
                            if (clientsList[i].port.Equals(backupreq[1]))
                            {
                                clientnum = i;
                            }
                        }
                    }
                    if (clientnum == -1) MessageBox.Show("Backup Request from unauthenticated user");
                    else
                    {
                        //req = clientsList[clientnum];

                        clientsList[clientnum].files[0].fileID = backupreq[2];
                        clientsList[clientnum].files[0].filesize = System.Convert.ToInt32(backupreq[3]);


                        //first part of every ticket is same
                        string ticketData = clientsList[clientnum].ip + " " + clientsList[clientnum].port + " " + clientsList[clientnum].publicKey;

                        // Create a UnicodeEncoder to convert between byte array and string.
                        ASCIIEncoding ByteConverter = new ASCIIEncoding();
                        byte[] originalData = ByteConverter.GetBytes(ticketData);
                        byte[] signedData;

                        signedData = rsa.SignData(originalData, new SHA1CryptoServiceProvider());



                        for (int i = 0; i < clientsList.Count; i++)
                        {
                            //Ticket i = E(PRas, IPa + PUa) || E(PRas, IPb + PUb)

                            if (i != clientnum)
                            {
                                //second part of the ticket
                                string ticketSecondData = clientsList[i].ip + " " + clientsList[i].port + " " + clientsList[i].publicKey;

                                // Create a UnicodeEncoder to convert between byte array and string.
                                byte[] originalSecondData = ByteConverter.GetBytes(ticketSecondData);
                                byte[] signedSecondData;

                                signedSecondData = rsa.SignData(originalSecondData, new SHA1CryptoServiceProvider());

                                clientsList[clientnum].files[0].filetickets.AddToList(originalData, signedData, originalSecondData, signedSecondData);

                            }
                        }


                        //sends them to the client
                        try
                        {
                            string functionID = "/tck";
                            string strTickets = clientsList[clientnum].files[0].filetickets.EncodeToString();

                            //TODO: somehow concatanate the message header; functionID
                            string TicketListMsg = functionID + strTickets; //tickets

                            byte[] byData2 = System.Text.Encoding.ASCII.GetBytes(TicketListMsg);

                            if (m_workerSocket[clientnum] != null)
                            {
                                if (m_workerSocket[clientnum].Connected)
                                {
                                    m_workerSocket[clientnum].Send(byData2);
                                }
                            }
                        }
                        catch (SocketException se)
                        {
                            MessageBox.Show(se.Message);
                        }


                    }


                    //mytickets tickets = new mytickets();


                    //clients[] clientsList = new clients[5];
                    //for (int i = 0; i < 5; i++)
                    //{
                    //    clientsList[i].ip = i * 100;
                    //    clientsList[i].port = i * 1000;
                    //    clientsList[i].publicKey = (i * 10000).ToString();
                    //}







                }
                else if (incoming.StartsWith("/rcv"))
                {
                    //client wants to recover
                    //decide which parties to connect
                    //pseudo connections list.
                    string[] recoverreq = incoming.Substring(4).Split(' ');

                    //client req = new client();                   
                    int clientnum = -1;
                    int filenum = -1;
                    for (int i = 0; i < clientsList.Count; i++)
                    {
                        if (clientsList[i].ip.Equals(recoverreq[0]))
                        {
                            if (clientsList[i].port.Equals(recoverreq[1]))
                            {
                                for (int j = 0; j < MAX_FILE; j++)
                                {
                                    if (clientsList[i].files[j].fileID != null)
                                    {
                                        if (clientsList[i].files[j].fileID.Equals(recoverreq[2]))
                                        {
                                            clientnum = i;
                                            filenum = j;
                                            break;
                                        }
                                    }
                                }
                            }
                        }
                    }
                    if (clientnum == -1) MessageBox.Show("User nor authenticated!");
                    else if (filenum == -1) MessageBox.Show("File not in database!");
                    else
                    {
                        //req = clientsList[clientnum];
                        mytickets RecoveryTickets = new mytickets();
                        bool enoughFound = false;
                        for (int i = 0; !enoughFound && i < clientsList[clientnum].files[filenum].filetickets.ticketlist.Count; i++)
                        {

                            string possibleStorage = new ASCIIEncoding().GetString(clientsList[clientnum].files[filenum].filetickets.ticketlist[i].origSecond);
                            string[] fields = possibleStorage.Split(' ');
                            string possibleStorageIP = fields[0];
                            string possibleStoragePort = fields[1];
                            for (int j = 0; j < m_clientCount; j++)
                            {
                                if (m_workerSocket[j] != null)
                                {
                                    if (m_workerSocket[j].Connected)
                                    {
                                        if (possibleStorageIP.Equals(clientsList[j].ip))
                                        {
                                            if (possibleStoragePort.Equals(clientsList[j].port))
                                            {
                                                RecoveryTickets.AddToList(clientsList[clientnum].files[filenum].filetickets.ticketlist[i]);
                                                if (RecoveryTickets.ticketlist.Count >= clientsList[clientnum].files[filenum].filetickets.ticketlist.Count - 1)
                                                    enoughFound = true;
                                            }
                                        }
                                    }
                                }
                            }
                        }
                        //sends them to the client
                        try
                        {
                            string functionID = "/rectck";
                            string strTickets = RecoveryTickets.EncodeToString();

                            //TODO: somehow concatanate the message header; functionID
                            string TicketListMsg = functionID + strTickets; //tickets

                            byte[] byData2 = System.Text.Encoding.ASCII.GetBytes(TicketListMsg);

                            if (m_workerSocket[clientnum] != null)
                            {
                                if (m_workerSocket[clientnum].Connected)
                                {
                                    m_workerSocket[clientnum].Send(byData2);
                                }
                            }
                        }
                        catch (SocketException se)
                        {
                            MessageBox.Show(se.Message);
                        }
                    }
                }
                else
                {
                    tb_encRecv.Enabled = true;
                    tb_encRecv.Text = BytesToHex(Convert.FromBase64String(szData.Substring(0, szData.Length - 1)));
                    string decryptedText = cryptor.DecryptMessage(szData.Substring(0, szData.Length - 1));
                    richTextBoxReceivedMsg.Text = decryptedText + "\n" + richTextBoxReceivedMsg.Text;

                }


                // Continue the waiting for data on the Socket
                WaitForData(socketData.m_currentSocket);
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
                   
		// This is the call back function, which will be invoked when a client is connected
		public void OnClientConnect(IAsyncResult asyn)
		{
			try
			{
				// Here we complete/end the BeginAccept() asynchronous call
				// by calling EndAccept() - which returns the reference to
				// a new Socket object
				m_workerSocket[m_clientCount] = m_mainSocket.EndAccept (asyn);
                // Let the worker Socket do the further processing for the 
				// just connected client
				WaitForData(m_workerSocket[m_clientCount]);
				// Now increment the client count
				++m_clientCount;
				// Display this client connection as a status message on the GUI	
				String str = String.Format("Client # {0} connected", m_clientCount);
				
								
				// Since the main Socket is now free, it can go back and wait for
				// other clients who are attempting to connect
				m_mainSocket.BeginAccept(new AsyncCallback ( OnClientConnect ),null);



                // send the AES mode to the newly connected client
                try
                {
                    string changeMode = "/chg";
                    changeMode += Convert.ToInt32(cryptor.rijn.Mode);


                    Object objData = changeMode;

                    byte[] byData = System.Text.Encoding.ASCII.GetBytes(objData.ToString());

                    for (int i = 0; i < m_clientCount; i++)
                    {
                        if (m_workerSocket[i] != null)
                        {
                            if (m_workerSocket[i].Connected)
                            {
                                m_workerSocket[i].Send(byData);
                            }
                        }
                    }
                }
                catch (SocketException se)
                {
                    MessageBox.Show(se.Message);
                }


                // send the current IV to the newly connected client
                try
                {
                    string setIV = "/sIV";

                    string iv = BytesToHex(cryptor.rijn.IV).Replace(" ", "");

                    setIV += iv;
                    Object objData2 = setIV;

                    byte[] byData2 = System.Text.Encoding.ASCII.GetBytes(objData2.ToString());

                    for (int i = 0; i < m_clientCount; i++)
                    {
                        if (m_workerSocket[i] != null)
                        {
                            if (m_workerSocket[i].Connected)
                            {
                                m_workerSocket[i].Send(byData2);
                            }
                        }
                    }
                }
                catch (SocketException se)
                {
                    MessageBox.Show(se.Message);
                }


                
                // process the RSA key exhange
                if (rb_RSA.Checked)
                {
                    
                    string rsakey = rsa.ToXmlString(false);

                    RSAParameters rsap = rsa.ExportParameters(false);

                    tb_RsaPublicKey.Text = BytesToHex(rsap.Modulus);
                    tb_RsaPublicKeyExpo.Text = BytesToHex(rsap.Exponent);

                    try
                    {
                        MessageBox.Show("sending public key");
                        string rsamsg = "/rsaS";
                        rsamsg += rsakey;

                        Object objData = rsamsg;

                        byte[] byData = System.Text.Encoding.ASCII.GetBytes(objData.ToString());

                       
                        if (m_workerSocket[m_clientCount - 1 ] != null)
                        {
                            if (m_workerSocket[m_clientCount - 1].Connected)
                            {
                                m_workerSocket[m_clientCount - 1].Send(byData);
                            }
                        }
     


                    }
                    catch (SocketException se)
                    {
                        MessageBox.Show(se.Message);
                    }
                }
                else
                {
                    cryptor.rijn.Key = HexToBytes(sharedKeyBox.Text.Replace(" ", ""));
                    tb_aeskey.Text = BytesToHex(cryptor.rijn.Key);
                }
                               
               
			}
			catch(ObjectDisposedException)
			{
				System.Diagnostics.Debugger.Log(0,"1","\n OnClientConnection: Socket has been closed\n");
			}
			catch(SocketException se)
			{
				MessageBox.Show ( se.Message );
			}
			
		}

        void ButtonStartListenClick(object sender, System.EventArgs e)
        {
            try
            {
                // Check the port value
                if (textBoxPort.Text == "")
                {
                    MessageBox.Show("Please enter a Port Number");
                    return;
                }

                string portStr = textBoxPort.Text;
                int port = System.Convert.ToInt32(portStr);
                // Create the listening socket...
                m_mainSocket = new Socket(AddressFamily.InterNetwork,
                                          SocketType.Stream,
                                          ProtocolType.Tcp);
                IPEndPoint ipLocal = new IPEndPoint(IPAddress.Any, port);
                // Bind to local IP Address...
                m_mainSocket.Bind(ipLocal);
                // Start listening...
                m_mainSocket.Listen(10);
                // Create the call back for any client connections...
                m_mainSocket.BeginAccept(new AsyncCallback(OnClientConnect), null);

                UpdateControls(true);

            }
            catch (SocketException se)
            {
                MessageBox.Show(se.Message);
            }

        }

        private void UpdateControls(bool listening)
        {
            buttonStartListen.Enabled = !listening;
            buttonStopListen.Enabled = listening;
            string connectStatus = listening ? "Listening" : "Not Listening";
            tb_statusmsg.Text = connectStatus;
        }    

        void ButtonSendMsgClick(object sender, System.EventArgs e)
		{
            try
            {
                if (cb_AutoGenerateIV.Checked) // auto generate IV for each message
                {
                    cryptor.rijn.GenerateIV();
                    tb_IV.Text = BytesToHex(cryptor.rijn.IV);
                    tb_CurIV.Text = BytesToHex(cryptor.rijn.IV);
                    b_setIV.Enabled = false;

                    try
                    {
                        string setIV = "/sIV";

                        string iv = BytesToHex(cryptor.rijn.IV).Replace(" ","");

                        setIV += iv;
                        Object objData2 = setIV;

                        byte[] byData2 = System.Text.Encoding.ASCII.GetBytes(objData2.ToString());

                        for (int i = 0; i < m_clientCount; i++)
                        {
                            if (m_workerSocket[i] != null)
                            {
                                if (m_workerSocket[i].Connected)
                                {
                                   m_workerSocket[i].Send(byData2);
                                }
                            }
                        }
                    }
                    catch (SocketException se)
                    {
                        MessageBox.Show(se.Message);
                    }
                }
            
               
                Object objData = cryptor.EncryptMessage(richTextBoxSendMsg.Text);
                string encMsgHEX = BytesToHex(Convert.FromBase64String(objData.ToString()));


                byte[] byData = System.Text.Encoding.ASCII.GetBytes(objData.ToString());
                for (int i = 0; i < m_clientCount; i++)
                {
                    if (m_workerSocket[i] != null)
                    {
                        if (m_workerSocket[i].Connected)
                        {                    
                            
                            tb_encSent.Enabled = true;
                            tb_encSent.Text = encMsgHEX;

                            m_workerSocket[i].Send(byData);
                            richTextBoxSendMsg.Text = "";
                        }
                    }
                }
            }
            catch (SocketException se)
            {
                MessageBox.Show(se.Message);
            }
            
		}
		
		void ButtonStopListenClick(object sender, System.EventArgs e)
		{
			CloseSockets();			
			UpdateControls(false);
		}
	
	   String GetIP()
	   {	   
	   		String strHostName = Dns.GetHostName();
		
		   	// Find host by name
		   	IPHostEntry iphostentry = Dns.GetHostByName(strHostName);
		
		   	// Grab the first IP addresses
		   	String IPStr = "";
		   	foreach(IPAddress ipaddress in iphostentry.AddressList){
		        IPStr = ipaddress.ToString();
		   		return IPStr;
		   	}
		   	return IPStr;
	   }
	  
	   void CloseSockets()
	   {
	   		if(m_mainSocket != null){
	   			m_mainSocket.Close();
	   		}
			for(int i = 0; i < m_clientCount; i++){
				if(m_workerSocket[i] != null){
					m_workerSocket[i].Close();
					m_workerSocket[i] = null;
				}
			}	
	   }
             
       private void b_ChangeMode_Click(object sender, EventArgs e)
       {
           try
           {
               string changeMode = "/chg";
               CipherMode aesMode = new CipherMode();

               if(rb_aesMode1.Checked)
                   aesMode = CipherMode.ECB;
               else if( rb_aesMode2.Checked)
                   aesMode = CipherMode.CBC;
               else
                   aesMode = CipherMode.CFB;

               changeMode += Convert.ToInt32(aesMode);

               Object objData = changeMode;
               
               byte[] byData = System.Text.Encoding.ASCII.GetBytes(objData.ToString());
               
               for (int i = 0; i < m_clientCount; i++)
               {
                   if (m_workerSocket[i] != null)
                   {
                       if (m_workerSocket[i].Connected)
                       {
                           m_workerSocket[i].Send(byData);
                       }
                   }
               }
               cryptor.rijn.Mode = aesMode;
               tb_currentMode.Text = cryptor.rijn.Mode.ToString();
           }
           catch (SocketException se)
           {
               MessageBox.Show(se.Message);
           }
       }

       private void b_GenIV_Click(object sender, EventArgs e)
       {
           cryptor.rijn.GenerateIV();
           tb_IV.Text = BytesToHex(cryptor.rijn.IV);
           tb_CurIV.Text = BytesToHex(cryptor.rijn.IV);
           b_setIV.Enabled = false;
          
       }

       private void b_setIV_Click(object sender, EventArgs e)
       {
           cryptor.rijn.IV = HexToBytes(tb_IV.Text.Replace(" ", ""));
           tb_CurIV.Text = BytesToHex(cryptor.rijn.IV);
           b_setIV.Enabled = false;    
       }

       private void tb_IV_TextChanged(object sender, EventArgs e)
       {
           b_setIV.Enabled = true;
       }

       private void b_SendIV_Click(object sender, EventArgs e)
       {
           try
           {
               string setIV = "/sIV";

               string iv = BytesToHex(cryptor.rijn.IV).Replace(" ","");

               setIV += iv;
               Object objData = setIV;

               byte[] byData = System.Text.Encoding.ASCII.GetBytes(objData.ToString());

               for (int i = 0; i < m_clientCount; i++)
               {
                   if (m_workerSocket[i] != null)
                   {
                       if (m_workerSocket[i].Connected)
                       {
                           m_workerSocket[i].Send(byData);
                       }
                   }
               }
           }
           catch (SocketException se)
           {
               MessageBox.Show(se.Message);
           }
       }

       private void buttonClose_Click(object sender, EventArgs e)
       {
           CloseSockets();
           Close();
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

       public static byte[] HexToBytes(String HexString)
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
    //////////////////////////////////////////////////////////////////////////



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

                // Create a decrytor to perform the stream transform.
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

                // Create a decrytor to perform the stream transform.
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
            catch(CryptographicException ce)
            {
                MessageBox.Show(ce.Message + "\nProbably AES keys do not match!");
            }
       

            return plaintext;
        }
    }
}
