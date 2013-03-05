/**
  *         Commmon Internet File System API (CIFS)
  *----------------------------------------------------------------
  *  Copyright (C) 2000-2002  Oren Novotny
  *
  * This library is free software; you can redistribute it and/or
  * modify it under the terms of the GNU Lesser General Public
  * License as published by the Free Software Foundation; either
  * version 2.1 of the License, or (at your option) any later version.
  *
  * This library is distributed in the hope that it will be useful,
  * but WITHOUT ANY WARRANTY; without even the implied warranty of
  * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
  * Lesser General Public License for more details.
  *
  * You should have received a copy of the GNU Lesser General Public
  * License along with this library; if not, write to the Free Software
  * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
  *
  *  The full copyright text: http://www.gnu.org/copyleft/lesser.html
  *
  *----------------------------------------------------------------
  *
  *  Author: Oren Novotny
  *  Email : osn@po.cwru.edu
  *  Web   : http://cifs.novotny.org 
  *
  *-----------------------------------------------------------------
  * This has been adapted from jCIFS
  *
  *  Author: Norbert Hranitzky
  *  Email : norbert.hranitzky@mchp.siemens.de
  *  Web   : http://www.hranitzky.purespace.de
  */

using System.Collections;
using System.IO;
using System.Net;
using System.Text;
using Cifs.Util;

namespace Cifs
{
    using System;


    /// <summary>
    ///   Abstract base class of all service sessions
    /// </summary>
    /// <remarks>
    ///   CIFS servers select the most recent version of the protocol known to both
    ///   client and server.  Any CIFS server which supports dialects newer than the
    ///   original core dialect must support all the messages and semantics of the
    ///   dialects between the core dialect and the newer one.  This is to say that
    ///   a server which supports the NT LM 0.12 dialect must also support all of the
    ///   messages of the previous 10 dialects.  It is the client's responsibility to
    ///   ensure it only sends SMBs which are appropriate to the dialect negotiated.
    ///   Clients must be prepared to receive an SMB response from an earlier protocol
    ///   dialect -- even if the client used the most recent form of the request.
    /// </remarks>
    internal abstract class CifsSession : ICifsSession
    {
        /// <summary>
        ///   The original MSNET SMB protocol (otherwise known as the "core protocol")
        /// </summary>
        internal const int SMB_CORE = 0;

        /// <summary>
        ///   This is the first version of the full LANMAN 1.0 protocol
        /// </summary>
        internal const int LANMAN_1_0 = 1;

        /// <summary>
        ///   This is the first version of the full LANMAN 2.0 protocol
        /// </summary>
        internal const int LM_1_2X001 = 2;

        /// <summary>
        ///   The SMB protocol designed for NT networking.  This has special SMBs
        ///   which duplicate the NT semantics.
        /// </summary>
        internal const int NT_LM_0_12 = 3;

        /// <summary>
        ///   Max buffer size for setup.
        /// </summary>
        private const int CIFS_MAX_BUFFER_SIZE = 40*1024;

        //------------------- Security Mode ------------------------------
        private const int SM_USER_MODE = 0x01;
        private const int SM_ENCRYPT_PASSWORDS = 0x02;

        /// <summary>
        ///   Security signature (SMB sequence numbers) enabled
        /// </summary>
        private const int SM_SEC_SIG_ENABLED = 0x04;

        /// <summary>
        ///   Security signature (SMB sequence numbers) required
        /// </summary>
        private const int SM_SEC_SIG_REQUIRED = 0x08;


        /// <summary>
        ///   The server supports SMB_COM_READ_RAW and SMB_COM_WRITE_RAW
        /// </summary>
        internal const int CAP_RAW_MODE = 0x0001;

        /// <summary>
        ///   The server supports SMB_COM_READ_MPX and SMB_COM_WRITE_MPX
        /// </summary>
        internal const int CAP_MPX_MODE = 0x0002;

        /// <summary>
        ///   The server supports Unicode strings
        /// </summary>
        internal const int CAP_UNICODE = 0x0004;

        /// <summary>
        ///   The server supports large files with 64 bit offsets
        /// </summary>
        internal const int CAP_LARGE_FILES = 0x0008;

        ///<summary>
        ///  The server supports the SMBs particular to the NT LM 0.12 dialect
        ///</summary>
        internal const int CAP_NT_SMBS = 0x0010;

        /// <summary>
        ///   The sever supports remote API requests via RPC
        /// </summary>
        internal const int CAP_RPC_REMOTE_APIS = 0x0020;

        /// <summary>
        ///   The server can respond with 32 bit status codes in Status.Status
        /// </summary>
        internal const int CAP_STATUS32 = 0x0040;

        /// <summary>
        ///   The server supports level 2 oplocks
        /// </summary>
        internal const int CAP_LEVEL_II_OPLOCKS = 0x0080;

        /// <summary>
        ///   The server supports the SMB_COM_LOCK_AND_READ SMB
        /// </summary>
        internal const int CAP_LOCK_AND_READ = 0x0100;

        internal const int CAP_NT_FIND = 0x0200;

        /// <summary>
        ///   This server is DFS aware
        /// </summary>
        internal const int CAP_DFS = 0x1000;

        /// <summary>
        ///   This server supports SMB_BULK_READ, SMB_BULK_WRITE
        /// </summary>
        internal const int CAP_BULK_TRANSFER = 0x20000000;

        /// <summary>
        ///   This server supports compressed data transfer
        ///   (BULK_TRANSFER capability is required in order to support compressed data transfer)
        /// </summary>
        internal const int CAP_COMPRESSED_DATA = 0x40000000;

        ///<summary>
        ///  This server supports extended security validation
        ///</summary>
        internal const uint CAP_EXTENDED_SECURITY = 0x80000000;

        internal static readonly string[] SUPPORTED_DIALECTS = {
                                                                   "PC NETWORK PROGRAM 1.0",
                                                                   "LANMAN1.0",
                                                                   "LM1.2X002",
                                                                   "NT LM 0.12"
                                                               };

        /// <summary>
        ///   Process ID
        /// </summary>
        protected static int fPID = new Random(DateTime.Now.Millisecond).Next();

        ///<summary>
        ///  Session table
        ///</summary>
        private static readonly Hashtable fSessionTable = Hashtable.Synchronized(new Hashtable());

        private static int fSessionNameCounter = 1;
        private bool fAutoReconnect = true;

        ///<summary>
        ///  Service user properties
        ///</summary>
        protected Hashtable fCallerProperties = new Hashtable();

        ///<summary>
        ///  Server capabilities (see CAP_*)
        ///</summary>
        protected int fCapabilities;

        private long fConnectTime;

        ///<summary>
        ///  True if disconnected
        ///</summary>
        private bool fConnectionLost;

        ///<summary>
        ///  Encryption challenge key
        ///</summary>
        private byte[] fEncryptionKey;

        ///<summary>
        ///  Length of challenge encryption key
        ///</summary>
        protected int fEncryptionKeyLen;

        ///<summary>
        ///  Extended security
        ///</summary>
        protected bool fExtendedSecurity;

        ///<summary>
        ///  True if user ist logged in as guest
        ///</summary>
        protected bool fLoggedAsGuest;

        private int fMID;

        /// <summary>
        ///   Max transmit buffer size
        /// </summary>
        protected int fMaxBufferSize;

        /// <summary>
        ///   Max pending multiplexed requests
        /// </summary>
        protected int fMaxPendingMPRequests;

        ///<summary>
        ///  Maximum raw buffer size
        ///</summary>
        protected int fMaxRawSize;

        /// <summary>
        ///   Max VCs between client and server
        /// </summary>
        protected int fMaxVCs;

        /// <summary>
        ///   SMB Message
        /// </summary>
        internal SmbMessage fMsg;

        /// <summary>
        ///   NetBIOS over TCP/IP session
        /// </summary>
        internal NbtSession fNBTSession;

        ///<summary>
        ///  Negotiated protocol index
        ///</summary>
        protected int fProtocol;

        protected byte fSecurityMode;

        ///<summary>
        ///  Server LAN Manager (may be empty, Win95)
        ///</summary>
        protected string fServerLanMan = "";

        ///<summary>
        ///  Server OS (may be empty, Win95)
        ///</summary>
        protected string fServerOS = "";

        ///<summary>
        ///  Server Primary Domain (may be empty, Win95)
        ///</summary>
        protected string fServerPrimaryDomain = "";

        ///<summary>
        ///  Unique token identifying this session
        ///</summary>
        protected int fSessionKey;

        protected string fSessionName = "";

        /// <summary>
        ///   Share name
        /// </summary>
        internal Share fShare;

        ///<summary>
        ///  System time from 1/1/0001 in hundred-nanoseconds (ticks)
        ///</summary>
        protected long fSystemTime;

        /// <summary>
        ///   Tree ID (returned by the server)
        /// </summary>
        protected int fTID;

        ///<summary>
        ///  Time zone of server (min from UTC)
        ///</summary>
        protected int fTimeZone;

        /// <summary>
        ///   User ID (returned by the server)
        /// </summary>
        protected int fUID;

        /// <summary>
        ///   Constructor
        /// </summary>
        /// <param name = "sessionname">String identfying the session</param>
        /// <param name = "protocol"></param>
        /// <param name = "share">Share object</param>
        /// <param name = "nbt">NetBIOS session</param>
        /// <param name = "msg">Message containing negotiated data</param>
        internal CifsSession(string sessionname, int protocol, Share share, NbtSession nbt, SmbMessage msg)
        {
            fShare = share;
            fNBTSession = nbt;
            fMsg = msg;
            fProtocol = protocol;
            SetNegotiatedData(msg);
            if (sessionname == null)
                fSessionName = "Session" + fSessionNameCounter++;
            else
                fSessionName = sessionname;
        }

        #region ICifsSession Members

        /// <summary>
        ///   Sets automatic reconnection
        /// </summary>
        /// <value>true if automatic reconnection is allowed</value>
        public bool AllowAutoReconnection
        {
            get { return fAutoReconnect; }
            set { fAutoReconnect = value; }
        }

        /// <summary>
        ///   Returns share name
        /// </summary>
        /// <value>share name</value>
        public string ShareName
        {
            get { return fShare.ShareName; }
        }

        /// <summary>
        ///   Returns the name of this session
        /// </summary>
        /// <value>session name</value>
        public string SessionName
        {
            get { return fSessionName; }
        }

        /// <summary>
        ///   Returns server OS name
        /// </summary>
        /// <value>os name or blank if unknown</value>
        public string ServerOs
        {
            get
            {
                if (fServerOS.Length == 0)
                    return "Windows 95";

                return fServerOS;
            }
        }

        /// <summary>
        ///   Returns LAN Manager of the server
        /// </summary>
        /// <value>LAN Manager or blank if unknown</value>
        public string ServerLanMan
        {
            get { return fServerLanMan; }
        }

        /// <summary>
        ///   Returns the primrary domain of the server
        /// </summary>
        /// <value>primary domain or blank if unknown</value>
        public string ServerPrimaryDomain
        {
            get { return fNBTSession.WorkgroupName; }
        }

        public string NetBiosName
        {
            get { return fNBTSession.NetBiosName; }
        }

        /// <summary>
        ///   Gets the address of the server
        /// </summary>
        /// <returns>IPAddress address</returns>
        public IPAddress GetServerAddress()
        {
            return fNBTSession.InetAddress;
        }

        /// <summary>
        ///   Time zone of the server (min from UTC)
        /// </summary>
        /// <value>minutes</value>
        public int ServerTimeZone
        {
            get { return fTimeZone; }
        }

        /// <summary>
        ///   Returns server time (from 1/1/0001 in ticks)
        /// </summary>
        /// <value>Ticks</value>
        public long ServerTime
        {
            get { return fSystemTime; }
        }

        /// <summary>
        ///   Checks if the server is connected
        /// </summary>
        /// <value>true if the connection is alive</value>
        public bool IsConnected
        {
            get
            {
                lock (this)
                {
                    return (fNBTSession != null && fNBTSession.IsAlive);
                }
            }
        }

        /// <summary>
        ///   Sets an API-user property.  The value is not interpreted by
        ///   CifsService
        /// </summary>
        /// <param name = "key">property name</param>
        /// <param name = "value">property value</param>
        public void SetProperty(string key, object value)
        {
            fCallerProperties.Add(key, value);
        }

        /// <summary>
        ///   Gets an API-user property
        /// </summary>
        /// <param name = "key">key property name</param>
        /// <returns> property value</returns>
        public object GetProperty(string key)
        {
            return fCallerProperties[key];
        }

        /// <summary>
        ///   Returns true if the share has user level security
        /// </summary>
        /// <value>true user level, false share level</value>
        public bool IsUserLevelSecurity
        {
            get { return ((fSecurityMode & SM_USER_MODE) != 0); }
        }

        /// <summary>
        ///   Returns the connect time in ticks (base: 1/1/0001)
        /// </summary>
        /// <value>time in ticks</value>
        public long ConnectTime
        {
            get { return fConnectTime; }
        }

        /// <summary>
        ///   Reconnects server if disconnected
        /// </summary>
        public void Reconnect()
        {
            lock (this)
            {
                if (IsConnected)
                    return;

                if (Debug.DebugOn)
                    Debug.WriteLine(Debug.Info, "Reconnect session");

                if (fMsg == null)
                    fMsg = AllocateSmbMessage();

                if (fNBTSession == null)
                    fNBTSession = new NbtSession();

                fConnectionLost = false;

                try
                {
                    fProtocol = Negotiate(fNBTSession, fShare.HostName, fMsg);
                    SetNegotiatedData(fMsg);
                    Connect();
                }
                catch (IOException e)
                {
                    fNBTSession.DoHangup();
                    fNBTSession = null;

                    throw e;
                }
            } // lock
        }

        /// <summary>
        ///   Disconnect the connection
        /// </summary>
        public void Disconnect()
        {
            DoTreeDisconnect();
            //logoff();
            if (fNBTSession != null)
                fNBTSession.DoHangup();
            fNBTSession = null;
            fMsg = null;
            RemoveSession(fSessionName);
        }

        /// <summary>
        ///   Manual clean-up, since the Finalize call isn't garunteed
        /// </summary>
        public virtual void Dispose()
        {
            Disconnect();

            GC.SuppressFinalize(this);
        }

        /// <summary>
        ///   Ping the server to test the connection to the server and to
        ///   see if the server is still responding.
        /// </summary>
        /// <param name = "text">text to send</param>
        /// <returns>Text returned by server (must be the same as the input text)</returns>
        public string Echo(string text)
        {
            lock (this)
            {
                if (Debug.DebugOn)
                    Debug.WriteLine(Debug.Info, "ping (SMB_COM_ECHO)");


                // for now we only support 0 or 1
                int echos = 1;

                SetupSmbMessage(fMsg, SmbMessage.SMB_COM_ECHO);

                /*
                    UCHAR WordCount;	Count of parameter words = 1
                    USHORT EchoCount;	Number of times to echo data back
                    USHORT ByteCount;	Count of data bytes;    min = 1
                    UCHAR Buffer[1];	Data to echo
                */

                // Set WordCount
                fMsg.setWordCount(1);
                // Set echo count
                fMsg.setShortParameterAt(0, echos);

                var data = new MarshalBuffer(text.Length + 10);

                int pos = 0;
                pos += data.SetAsciiStringAt(pos, text);
                data.Size = pos;

                fMsg.setContent(data);

                fMsg.SendAndRecieve(fNBTSession, fMsg);

                int errorclass = fMsg.getErrorClass();

                if (errorclass != CifsIoException.SUCCESS)
                    throw new CifsIoException(errorclass, fMsg.getErrorCode());

                int size = fMsg.getContentSize();

                if (size == 0)
                    return "";

                pos = fMsg.getContentOffset();

                return fMsg.GetAsciiStringAt(pos, size);
            }
        }

        #endregion

        protected void CheckConnection()
        {
            if (!fConnectionLost && IsConnected)
                return;

            if (fConnectionLost && fAutoReconnect)
                Reconnect();
        }

        /// <summary>
        ///   Session setup and tree connect
        /// </summary>
        internal void Connect()
        {
            trySessionSetup();

            TryTreeConnect();

            AddSession(fSessionName, this);

            fConnectTime = DateTime.Now.Ticks;

            fNBTSession.ConnectionLost += (s, e) => fConnectionLost = true;

            fConnectionLost = false;

            if (Debug.DebugOn && Debug.DebugLevel >= Debug.Info)
                debug();
        }

        ~CifsSession()
        {
            Disconnect();
        }

        /// <summary>
        ///   Try session setup
        /// </summary>
        private void trySessionSetup()
        {
            // try first without asking for password
            while (true)
            {
                if (DoSessionSetup())
                    return;

                // ask for password -- Not implemented yet. Always returns false
                if (!PromptLogin())
                    throw new CifsIoException(CifsIoException.SRV_ERROR, CifsIoException.SRV_BAD_PASSWORD);
            }
        }

        /// <summary>
        ///   Try tree connect
        /// </summary>
        private void TryTreeConnect()
        {
            CifsLogin login = fShare.Login;

            string password = login.Password;

            while (true)
            {
                // Try as is
                if (DoTreeConnect(password))
                    return;

                // if no password, ask for password
                if (login.Password == null)
                {
                    if (!PromptLogin()) // promptLogin not implemented: always returns false
                        throw new CifsIoException(CifsIoException.ERROR_SRV, CifsIoException.SRV_BAD_PASSWORD);

                    password = login.Password;
                }
                else
                {
                    // check upper case password
                    string upper = login.Password.ToUpper();

                    if (DoTreeConnect(upper))
                        return;

                    if (!PromptLogin()) // promptLogin not implemented: always returns false
                        throw new CifsIoException(CifsIoException.ERROR_SRV, CifsIoException.SRV_BAD_PASSWORD);

                    password = login.Password;
                }
            }
        }

        /// <summary>
        ///   Allocates SMB message buffer
        /// </summary>
        internal static SmbMessage AllocateSmbMessage()
        {
            SmbMessage m;
            lock (typeof (CifsSession))
            {
                //m = new SMBMessage(CIFS_MAX_BUFFER_SIZE); 
                m = new SmbMessage(1024);
            }
            return m;
        }

        /// <summary>
        ///   Negotiates protocol (we only support NT_LM_0_12). Calls NetBIOS
        /// </summary>
        /// <param name = "nbt">NetBIOS session</param>
        /// <param name = "nbtname">NetBIOS name</param>
        /// <param name = "msg">SMB Message</param>
        /// <returns>Negotiated protocol</returns>
        internal static int Negotiate(NbtSession nbt, string nbtname, SmbMessage msg)
        {
            if (Debug.DebugOn)
                Debug.WriteLine(Debug.Info, "SMB_COM_NEGOTIATE");

            nbt.DoCall(nbtname);

            msg.setCommand(SmbMessage.SMB_COM_NEGOTIATE);
            msg.setPID(fPID);

            /**
             * struct {
             *			UCHAR BufferFormat;	 // DT_DIALECT
             *			UCHAR DialectName[]; // Null-terminated
             * } Dialects[];
             */

            var buf = new StringBuilder();
            for (int i = 0; i < SUPPORTED_DIALECTS.Length; i++)
            {
                buf.Append((char) SmbMessage.DT_DIALECT);
                buf.Append(SUPPORTED_DIALECTS[i]);
                buf.Append('\0');
            }

            msg.setContent(Encoding.UTF8.GetBytes(buf.ToString()));


            if (Debug.DebugOn && Debug.DebugLevel >= Debug.Buffer)
            {
                Debug.WriteLine(Debug.Buffer, "Supported Dialects:");
                Debug.WriteLine(Debug.Buffer, msg.getMessageBuffer(), 0, msg.getMessageSize());
            }


            msg.SendAndRecieve(nbt, msg);

            if (Debug.DebugOn && Debug.DebugLevel >= Debug.Buffer)
            {
                Debug.WriteLine(Debug.Buffer, "Dialects Response:");
                Debug.WriteLine(Debug.Buffer, msg.getMessageBuffer(), 0, msg.getMessageSize());
            }

            int protocol = msg.getParameter(0);

            if (protocol == -1)
                throw new CifsIoException("PE1");

            if (protocol != NT_LM_0_12)
                throw new CifsIoException("PE2", SUPPORTED_DIALECTS[protocol]);

            if (msg.getWordCount() != 17)
                throw new CifsIoException("PE2", SUPPORTED_DIALECTS[protocol]);

            if (Debug.DebugOn && Debug.DebugLevel >= Debug.Info)
                Debug.WriteLine(Debug.Info, "Negotiated protocol: " + SUPPORTED_DIALECTS[protocol]);

            return protocol;
        }

        /// <summary>
        ///   Sets negotiated data
        /// </summary>
        /// <param name = "msg">SMB message returned by negotiation</param>
        private void SetNegotiatedData(SmbMessage msg)
        {
            // Security mode at position 2
            fSecurityMode = msg.getByteParameterAt(2);

            fExtendedSecurity = ((fCapabilities & CAP_EXTENDED_SECURITY) != 0);

            fMaxPendingMPRequests = msg.getShortParameterAt(3);

            fMaxVCs = msg.getShortParameterAt(5);

            fMaxBufferSize = msg.getIntParameterAt(7);

            fMaxRawSize = msg.getIntParameterAt(11);

            fSessionKey = msg.getIntParameterAt(15);

            fCapabilities = msg.getIntParameterAt(19);

            // System time from 1601 in 100ns (ticks)
            long lo_time = msg.getIntParameterAt(23) & 0xffffffff;
            long hi_time = msg.getIntParameterAt(27) & 0xffffffff;

            // System time from 1601 in 100ns -> convert it to base 1/1/0001
            fSystemTime = DateTime.FromFileTime((hi_time << 32) + lo_time).Ticks;

            fTimeZone = msg.getSignedShortParameterAt(31);

            fEncryptionKeyLen = msg.getByteParameterAt(33) & 0xff;

            int off = msg.getContentOffset();
            byte[] msgbuf = msg.getMessageBuffer();
            int content_size = msg.getContentSize();

            if (!fExtendedSecurity)
            {
                // Encryption key
                fEncryptionKey = new byte[fEncryptionKeyLen];

                for (int i = 0; i < fEncryptionKeyLen; i++)
                    fEncryptionKey[i] = msgbuf[off + i];
            }
        }

        /// <summary>
        ///   Connects to the tree
        /// </summary>
        /// <param name = "password">password</param>
        /// <returns>true if ok, false if bad password</returns>
        private bool DoTreeConnect(string password)
        {
            if (Debug.DebugOn)
                Debug.WriteLine(Debug.Info, "SMB_COM_TREE_CONNECT_ANDX");

            SetupSmbMessage(fMsg, SmbMessage.SMB_COM_TREE_CONNECT_ANDX);
            fMsg.setTID(0);

            /*
               UCHAR WordCount;	Count of parameter words = 4
            0: UCHAR AndXCommand;	Secondary (X) command; 0xFF = none
            1: UCHAR AndXReserved;	Reserved (must be 0)
            2: USHORT AndXOffset;	Offset to next command WordCount
            4: USHORT Flags;	Additional information
                            bit 0 set = disconnect Tid
            6: USHORT PasswordLength;	Length of Password[]
                USHORT ByteCount;	Count of data bytes;    min = 3
                UCHAR Password[];	Password
                STRING Path[];	Server name and share name
                STRING Service[];	Service name
            */
            fMsg.setWordCount(4);

            //AndXCommand
            fMsg.setByteParameterAt(0, 0xFF);
            // AndXReserved
            fMsg.setByteParameterAt(1, 0);
            // AndXOffset
            fMsg.setShortParameterAt(2, 0);
            // Flags
            fMsg.setShortParameterAt(4, 0);

            byte[] challenge_response = null;

            if ((fSecurityMode & SM_ENCRYPT_PASSWORDS) != 0)
                challenge_response = CifsLogin.GetNtAuthData(password, fEncryptionKey);
            else
                challenge_response = Util.Util.GetZtStringBytes(password);

            //Debug.WriteLine("password=" + util.bytesToHex(challenge_response));
            fMsg.setShortParameterAt(6, challenge_response.Length);

            var data = new MarshalBuffer(100);

            // auth data
            int pos = 0;
            data.SetBytesAt(pos, challenge_response, 0, challenge_response.Length);
            pos += challenge_response.Length;

            // share name
            pos += data.SetZtAsciiStringAt(pos, fShare.ShareName.ToUpper());

            string dev;

            switch (fShare.ShareType)
            {
                case Share.DISK:
                    dev = "A:";
                    break;
                case Share.IPC:
                    dev = "IPC";
                    break;
                case Share.PRINTER:
                    dev = "LPT1:";
                    break;
                default:
                    dev = "A:";
                    break;
            }
            pos += data.SetZtAsciiStringAt(pos, dev);

            data.Size = pos;

            fMsg.setContent(data);

            fMsg.SendAndRecieve(fNBTSession, fMsg);

            int errorclass = fMsg.getErrorClass();

            if (errorclass != CifsIoException.SUCCESS)
            {
                int errorcode = fMsg.getErrorCode();

                if ((errorclass == CifsIoException.ERROR_SRV &&
                     errorcode == CifsIoException.SRV_BAD_PASSWORD) ||
                    (errorclass == CifsIoException.ERROR_DOS &&
                     errorcode == CifsIoException.DOS_NO_ACCESS))
                    return false;

                throw new CifsIoException(errorclass, errorcode);
            }

            fUID = fMsg.getUID();
            fTID = fMsg.getTID();

            return true;
        }

        /// <summary>
        ///   Set up the session
        /// </summary>
        /// <returns>true if ok, false if bad password</returns>
        private bool DoSessionSetup()
        {
            if (Debug.DebugOn)
                Debug.WriteLine(Debug.Info, "SMB_COM_SESSION_SETUP_ANDX");

            byte[] case_sensitive_passwd = null;
            byte[] case_insensitive_passwd = null;
            string string_passwd = fShare.Login.Password;

            SetupSmbMessage(fMsg, SmbMessage.SMB_COM_SESSION_SETUP_ANDX);

            if (Debug.DebugOn && Debug.DebugLevel >= Debug.Buffer)
            {
                Debug.WriteLine(Debug.Buffer, "New SMB Msg:");
                Debug.WriteLine(Debug.Buffer, fMsg.getMessageBuffer(), 0, fMsg.getMessageSize());
            }


            if ((fSecurityMode & SM_ENCRYPT_PASSWORDS) != 0)
            {
                case_sensitive_passwd = CifsLogin.GetNtAuthData(string_passwd, fEncryptionKey);
                case_insensitive_passwd = CifsLogin.GetLmAuthData(string_passwd, fEncryptionKey);
            }
            else
            {
                case_sensitive_passwd = CifsLogin.GetPasswordBytesUnicode(string_passwd);
                case_insensitive_passwd = CifsLogin.GetPasswordBytesAscii(string_passwd);
            }


            /*
                       UCHAR WordCount;	Count of parameter words = 13
                    0: UCHAR AndXCommand;	Secondary (X) command;  0xFF = none
                    1: UCHAR AndXReserved;	Reserved (must be 0)
                    2: USHORT AndXOffset;	Offset to next command WordCount
                    4: USHORT MaxBufferSize;	Client's maximum buffer size
                    6: USHORT MaxMpxCount;	Actual maximum multiplexed pending requests
                    8: USHORT VcNumber;	0 = first (only), nonzero=additional VC number
                    10:ULONG SessionKey;	Session key (valid iff VcNumber != 0)
                    14:USHORT CaseInsensitivePasswordLength;	Account password size, ANSI
                    16:USHORT CaseSensitivePasswordLength;	Account password size, Unicode
                    18:ULONG Reserved;	must be 0
                    22:ULONG Capabilities;	Client capabilities
                        USHORT ByteCount;	Count of data bytes;    min = 0
                        UCHAR CaseInsensitivePassword[];	Account Password, ANSI
                        UCHAR CaseSensitivePassword[];	Account Password, Unicode
                        STRING AccountName[];	Account Name, Unicode
                        STRING PrimaryDomain[];	Client's primary domain, Unicode
                        STRING NativeOS[];	Client's native operating system, Unicode
                        STRING NativeLanMan[];	Client's native LAN Manager type, Unicode
            */

            fMsg.setWordCount(13);

            // AndXCommand
            fMsg.setByteParameterAt(0, 0xFF);
            // AndXReserved
            fMsg.setByteParameterAt(1, 0);
            // AndXOffset
            fMsg.setShortParameterAt(2, 0);
            // MaxBufferSize
            fMsg.setShortParameterAt(4, CIFS_MAX_BUFFER_SIZE);
            // MaxMpxCount
            fMsg.setShortParameterAt(6, 1);
            // VcNumber
            fMsg.setShortParameterAt(8, 0);
            // SessionKey
            fMsg.setIntParameterAt(10, 0);

            // CaseInsensitivePasswordLength
            fMsg.setShortParameterAt(14, case_insensitive_passwd.Length);
            // CaseSensitivePasswordLength
            fMsg.setShortParameterAt(16, case_sensitive_passwd.Length);
            // Reserved
            fMsg.setIntParameterAt(18, 0);
            // Capabilities
            fMsg.setIntParameterAt(22, CAP_UNICODE | CAP_NT_SMBS);


            var data = new MarshalBuffer(200);

            int pos = 0;

            Debug.WriteLine(Debug.Buffer, "Before Ins Pass:");
            Debug.WriteLine(Debug.Buffer, data.GetBytes(), 0, data.Size);

            // CaseInsensitivePassword
            data.SetBytesAt(pos, case_insensitive_passwd, 0, case_insensitive_passwd.Length);
            pos += case_insensitive_passwd.Length;

            Debug.WriteLine(Debug.Buffer, "After Ins Pass:");
            Debug.WriteLine(Debug.Buffer, data.GetBytes(), 0, data.Size);

            // CaseSensitivePassword
            data.SetBytesAt(pos, case_sensitive_passwd, 0, case_sensitive_passwd.Length);
            pos += case_sensitive_passwd.Length;

            Debug.WriteLine(Debug.Buffer, "After Sens Pass:");
            Debug.WriteLine(Debug.Buffer, data.GetBytes(), 0, data.Size);

            // Account name
            pos += data.SetZtAsciiStringAt(pos, fShare.Login.Account);

            Debug.WriteLine(Debug.Buffer, "After Acct Name:");
            Debug.WriteLine(Debug.Buffer, data.GetBytes(), 0, data.Size);

            // Primary domain
            //string pdomain = Environment.GetEnvironmentVariable("CIFSDOMAIN"); // Can this be done better?
            string pdomain = "?"; // testing -- This works, but the above breaks... why?
            pos += data.SetZtAsciiStringAt(pos, pdomain);

            // Native OS
            pos += data.SetZtAsciiStringAt(pos, ".NET CIFS Client");

            data.Size = pos;

            Debug.WriteLine(Debug.Buffer, "Final data:");
            Debug.WriteLine(Debug.Buffer, data.GetBytes(), 0, data.Size);

            fMsg.setContent(data);

            if (Debug.DebugOn && Debug.DebugLevel >= Debug.Buffer)
            {
                Debug.WriteLine(Debug.Buffer, "Msg to send");
                Debug.WriteLine(Debug.Buffer, fMsg.getMessageBuffer(), 0, fMsg.getMessageSize());
            }

            fMsg.SendAndRecieve(fNBTSession, fMsg);

            if (!fMsg.isResponse())
                throw new CifsIoException("PE3");

            int errorclass = fMsg.getErrorClass();

            if (errorclass != CifsIoException.SUCCESS)
            {
                int errorcode = fMsg.getErrorCode();

                if ((errorclass == CifsIoException.ERROR_SRV &&
                     errorcode == CifsIoException.SRV_BAD_PASSWORD) ||
                    (errorclass == CifsIoException.ERROR_DOS &&
                     errorcode == CifsIoException.DOS_NO_ACCESS))
                    return false;

                throw new CifsIoException(errorclass, errorcode);
            }

            fUID = fMsg.getUID();

            /*
            if(Debug.debugOn && Debug.debugLevel >= Debug.INFO)
                Debug.WriteLine("UID = " + fMsg.getUID());
            */

            if (fMsg.getWordCount() != 3)
                return true;

            /*
               UCHAR WordCount;	Count of parameter words = 3
            0: UCHAR AndXCommand;	Secondary (X) command;  0xFF = none
            1: UCHAR AndXReserved;	Reserved (must be 0)
            2: USHORT AndXOffset;	Offset to next command WordCount
            4: USHORT Action;	Request mode:
                        bit0 = logged in as GUEST
            6: USHORT SecurityBlobLength	length of Security Blob that follows in a later field
            8: USHORT ByteCount;	Count of data bytes
                UCHAR SecurityBlob[]	SecurityBlob of length specified in field SecurityBlobLength
                STRING NativeOS[];	Server's native operating system
                STRING NativeLanMan[];	Server's native LAN Manager type
                STRING PrimaryDomain[];	Server's primary domain
            */

            byte action = fMsg.getByteParameterAt(4);

            if ((action & 0x01) != 0)
                fLoggedAsGuest = true;

            int byte_count = fMsg.getContentSize();
            int off = fMsg.getContentOffset();
            int max_off = off + byte_count;

            /*
            // Skip security blob
            off += fMsg.getShortParameterAt(6);
            */
            if (off >= max_off)
                return true;

            // Read Native OS
            fServerOS = fMsg.GetZtAsciiStringAt(off, max_off - off);
            off += fServerOS.Length + 1;

            if (off >= max_off)
                return true;

            // Read NativeLanMan
            fServerLanMan = fMsg.GetZtAsciiStringAt(off, max_off - off);
            off += fServerLanMan.Length + 1;

            if (off >= max_off)
                return true;

            // Read Primary Domain
            fServerPrimaryDomain = fNBTSession.WorkgroupName;

            return true;
        }

        /// <summary>
        ///   Disconnects the Tree
        /// </summary>
        private void DoTreeDisconnect()
        {
            if (Debug.DebugOn)
                Debug.WriteLine(Debug.Info, "SMB_COM_TREE_DISCONNECT");

            if (fNBTSession != null)
            {
                if (!fNBTSession.IsAlive)
                    return;
            }
            else
            {
                return;
            }


            try
            {
                SetupSmbMessage(fMsg, SmbMessage.SMB_COM_TREE_DISCONNECT);

                fMsg.setWordCount(0);
                fMsg.setContentSize(0);

                fMsg.SendAndRecieve(fNBTSession, fMsg);

                int errorclass = fMsg.getErrorClass();

                // Ignores errors
                if (errorclass != CifsIoException.SUCCESS)
                    Debug.WriteLine(Debug.Warning, "SMB_COM_TREE_DISCONNECT: Error= " + fMsg.getNTErrorCode());
            }
            catch (Exception e)
            {
                Debug.WriteLine(Debug.Warning, "SMB_COM_TREE_DISCONNECT: Exception= " + e);
            }
        }

        /// <summary>
        ///   Logoff (inverse of Setup session)
        /// </summary>
        /// <remarks>
        ///   TBD: Always returns error!!!!
        /// </remarks>
        private void Logoff()
        {
            if (Debug.DebugOn)
                Debug.WriteLine(Debug.Info, "SMB_COM_LOGOFF_ANDX");

            if (!fNBTSession.IsAlive)
                return;

            try
            {
                SetupSmbMessage(fMsg, SmbMessage.SMB_COM_LOGOFF_ANDX);

                fMsg.setWordCount(2);
                fMsg.setByteParameterAt(0, 0xff);
                fMsg.setByteParameterAt(1, 0);
                fMsg.setShortParameterAt(2, 0);
                fMsg.setContentSize(0);

                fMsg.SendAndRecieve(fNBTSession, fMsg);

                int errorclass = fMsg.getErrorClass();

                if (errorclass != CifsIoException.SUCCESS)
                    Debug.WriteLine(Debug.Warning, "SMB_COM_LOGOFF_ANDX: Error= " + fMsg.getNTErrorCode());
            }
            catch (Exception e)
            {
                Debug.WriteLine(Debug.Warning, "SMB_COM_LOGOFF_ANDX: Exception= " + e);
            }
        }

        /// <summary>
        ///   Sends SMB_COM_TRANSACTION
        /// </summary>
        /// <param name = "setup">setup words</param>
        /// <param name = "name">name string</param>
        /// <param name = "param">parameter buffer</param>
        /// <param name = "data">data to send</param>
        /// <param name = "ldata">length of data</param>
        internal void SendTransaction(short[] setup, string name, MarshalBuffer param,
                                      byte[] data, int ldata) // should be protected...
        {
            if (Debug.DebugOn)
                Debug.WriteLine(Debug.Info, "Send SMB_COM_TRANSACTION");

            int lparam = param.Size;
            int lsetup;

            if (setup == null)
                lsetup = 0;
            else
                lsetup = setup.Length;

            SetupSmbMessage(fMsg, SmbMessage.SMB_COM_TRANSACTION);

            /*
                 UCHAR WordCount;	Count of parameter words;   value = (14 + SetupCount)
                 USHORT TotalParameterCount;	Total parameter bytes being sent
                 USHORT TotalDataCount;	Total data bytes being sent
                 USHORT MaxParameterCount;	Max parameter bytes to return
                 USHORT MaxDataCount;	Max data bytes to return
                 UCHAR MaxSetupCount;	Max setup words to return
                 UCHAR Reserved;
                 USHORT Flags;	Additional information:
                                 bit 0 - also disconnect TID in TID
                 ULONG Timeout;
                 USHORT Reserved2;
                 USHORT ParameterCount;	Parameter bytes sent this buffer
                 USHORT ParameterOffset;	Offset (from header start) to Parameters
                 USHORT DataCount;	Data bytes sent this buffer
                 USHORT DataOffset;	Offset (from header start) to data
                 UCHAR SetupCount;	Count of setup words
                 UCHAR Reserved3;	Reserved (pad above to word)
                 USHORT Setup[SetupCount];	Setup words (# = SetupWordCount)
                 USHORT ByteCount;	Count of data bytes
                 STRING Name[];	Must be NULL
                 UCHAR Pad[];	Pad to SHORT or LONG
                 UCHAR Parameters[ ParameterCount];	Parameter bytes (# = ParameterCount)
                 UCHAR Pad1[];	Pad to SHORT or LONG
                 UCHAR Data[ DataCount ];	Data bytes (# = DataCount)
            */

            fMsg.setWordCount(14 + lsetup);

            // TotalParameterCount
            fMsg.setShortParameterAt(0, lparam);

            // TotalDataCount
            fMsg.setShortParameterAt(2, ldata);

            // MaxParameterCount returned by server
            fMsg.setShortParameterAt(4, 16);

            // MaxDataCount returned by server
            fMsg.setShortParameterAt(6, 3000);

            // MaxSetupCount returned by server
            fMsg.setByteParameterAt(8, 20);

            // Reserved
            fMsg.setByteParameterAt(9, 0);

            // Flags
            fMsg.setShortParameterAt(10, 0);

            // Timeout
            fMsg.setIntParameterAt(12, 0);

            // Reserved 2
            fMsg.setShortParameterAt(16, 0);

            // ParameterCount bytes sent this buffer
            fMsg.setShortParameterAt(18, 0);

            // ParameterOffset bytes sent this buffer
            fMsg.setShortParameterAt(20, 0);

            // DataCount bytes sent this buffer
            fMsg.setShortParameterAt(22, 0);

            // DataOffset bytes sent this buffer
            fMsg.setShortParameterAt(24, 0);

            // SetupCount
            fMsg.setByteParameterAt(26, (byte) lsetup);

            // Reserved 3
            fMsg.setByteParameterAt(27, 0);

            for (int i = 0; i < lsetup; i++)
                // Setup[0]
                fMsg.setShortParameterAt(28 + i, setup[i]);

            // byteCount
            fMsg.setContentSize(0);

            int bytes_off, off;

            bytes_off = off = fMsg.getContentOffset();

            // reserve 1 (Name) + 4 (Pad) + 4 (Pad1)
            // free bytes for Parameters and Data
            int free = Math.Min(fMsg.Capacity - bytes_off, fMaxBufferSize) - 9;

            int send_lparam = Math.Min(free, lparam);
            int send_ldata = Math.Min(free - send_lparam, ldata);

            // Name of trans (NULL terminated string)
            off += fMsg.SetZtAsciiStringAt(off, name);

            /*-------------------- set parameters -----------------*/
            // Calculate beginning of Parameters (offset from Header)
            int param_off = off = MarshalBuffer.Align(off, 2);

            // set parameter bytes
            fMsg.SetBytesAt(off, param, 0, send_lparam);

            // ParameterCount bytes sent this buffer
            fMsg.setShortParameterAt(18, send_lparam);

            // ParameterOffset bytes sent this buffer
            fMsg.setShortParameterAt(20, param_off);

            off += send_lparam;

            /*---------------------- set data ----------------------*/
            // Calculate beginning of data (offset from Header)
            int data_off = off = MarshalBuffer.Align(off, 2);

            // set data bytes
            if (send_ldata > 0)
                fMsg.SetBytesAt(off, data, 0, send_ldata);

            // DataCount bytes sent this buffer
            fMsg.setShortParameterAt(22, send_ldata);

            // DataOffset bytes sent this buffer
            fMsg.setShortParameterAt(24, data_off);

            off += send_ldata;

            // byteCount
            fMsg.setContentSize(off - bytes_off);

            fMsg.send(fNBTSession);

            if (send_lparam < lparam || send_ldata < ldata)
            {
                // recieve interim response

                fMsg.receive(fNBTSession);

                int errorclass = fMsg.getErrorClass();

                if (errorclass != CifsIoException.SUCCESS)
                    throw new CifsIoException(errorclass, fMsg.getErrorCode());

                int tot_ldata = send_ldata;
                int tot_lparam = send_lparam;

                while (tot_ldata < ldata || tot_lparam < lparam)
                {
                    // Now send the next packet

                    SetupSmbMessageSecondary(fMsg, SmbMessage.SMB_COM_TRANSACTION_SECONDARY);
                    /*
                       Command	SMB_COM_TRANSACTION_SECONDARY

                       UCHAR WordCount;	Count of parameter words = 8
                    0: USHORT TotalParameterCount;	Total parameter bytes being sent
                    2: USHORT TotalDataCount;	Total data bytes being sent
                    4: USHORT ParameterCount;	Parameter bytes sent this buffer
                    6: USHORT ParameterOffset;	Offset (from header start) to Parameters
                    8: USHORT ParameterDisplacement;	Displacement of these Parameter bytes
                    10:USHORT DataCount;	Data bytes sent this buffer
                    12:USHORT DataOffset;	Offset (from header start) to data
                    14:USHORT DataDisplacement;	Displacement of these data bytes
                    16:USHORT Fid;	FID for handle based requests, else 0xFFFF.  This field is present only if this is an SMB_COM_TRANSACTION2 request.
                       USHORT ByteCount;	Count of data bytes
                       UCHAR Pad[];	Pad to SHORT or LONG
                       UCHAR Parameters[ParameterCount];	Parameter bytes (# = ParameterCount)
                       UCHAR Pad1[];	Pad to SHORT or LONG
                       UCHAR Data[DataCount];	Data bytes (# = DataCount)
                    */

                    fMsg.setWordCount(8);

                    bytes_off = off = fMsg.getContentOffset();
                    free = Math.Min(fMsg.Capacity - bytes_off, fMaxBufferSize) - 9;

                    send_lparam = Math.Min(lparam - tot_lparam, free);

                    send_ldata = Math.Min(ldata - tot_ldata, free - send_lparam);

                    // TotalParameterCount
                    fMsg.setShortParameterAt(0, lparam);

                    // TotalDataCount
                    fMsg.setShortParameterAt(2, ldata);

                    // ParameterCount
                    fMsg.setShortParameterAt(4, send_lparam);

                    // ParameterDisplacement
                    fMsg.setShortParameterAt(8, tot_lparam);

                    // DataCount
                    fMsg.setShortParameterAt(10, send_ldata);

                    // DataDisplacement
                    fMsg.setShortParameterAt(14, tot_ldata);

                    // No FID

                    /*----------------- set parameters --------------------*/
                    // Calculate beginning of Parameters (offset from header)
                    param_off = off = MarshalBuffer.Align(off, 4);

                    // set parameter bytes
                    fMsg.SetBytesAt(off, param, tot_lparam, send_lparam);

                    // ParameterOffset bytes sent this buffer
                    fMsg.setShortParameterAt(6, param_off);

                    off += send_lparam;

                    /*---------------------- set data --------------------*/
                    // Calculate beginninf of data (offset from header)
                    data_off = off = MarshalBuffer.Align(off, 4);

                    // set data bytes
                    if (send_ldata > 0)
                        fMsg.SetBytesAt(off, data, tot_ldata, send_ldata);

                    // DataOffset bytes sent this buffer
                    fMsg.setShortParameterAt(12, data_off);

                    off += send_ldata;

                    // byteCount
                    fMsg.setContentSize(off - bytes_off);

                    fMsg.send(fNBTSession);

                    tot_lparam += send_lparam;
                    tot_ldata += send_ldata;
                } // while loop
            } // if we're recieving
        }

        // end of sentTransaction 

        /// <summary>
        ///   Sends SMB_COM_TRANSACTION2 message
        /// </summary>
        /// <param name = "setup">setup words</param>
        /// <param name = "param">name string</param>
        /// <param name = "data">data to send</param>
        /// <param name = "ldata">length of data</param>
        /// <param name = "fid">file id</param>
        internal void SendTransaction2(short setup, MarshalBuffer param, byte[] data,
                                       int ldata, int fid) // should be protected
        {
            if (Debug.DebugOn)
                Debug.WriteLine(Debug.Info, "Send SMB_COM_TRANSACTION2");

            int lparam = param.Size;

            SetupSmbMessage(fMsg, SmbMessage.SMB_COM_TRANSACTION2);

            /*
                UCHAR WordCount;	Count of parameter words;   value = (14 + SetupCount)
                USHORT TotalParameterCount;	Total parameter bytes being sent
                USHORT TotalDataCount;	Total data bytes being sent
                USHORT MaxParameterCount;	Max parameter bytes to return
                USHORT MaxDataCount;	Max data bytes to return
                UCHAR MaxSetupCount;	Max setup words to return
                UCHAR Reserved;
                USHORT Flags;	Additional information:
                                bit 0 - also disconnect TID in TID
                ULONG Timeout;
                USHORT Reserved2;
                USHORT ParameterCount;	Parameter bytes sent this buffer
                USHORT ParameterOffset;	Offset (from header start) to Parameters
                USHORT DataCount;	Data bytes sent this buffer
                USHORT DataOffset;	Offset (from header start) to data
                UCHAR SetupCount;	Count of setup words
                UCHAR Reserved3;	Reserved (pad above to word)
                USHORT Setup[SetupCount];	Setup words (# = SetupWordCount)
                USHORT ByteCount;	Count of data bytes
                STRING Name[];	Must be NULL
                UCHAR Pad[];	Pad to SHORT or LONG
                UCHAR Parameters[ ParameterCount];	Parameter bytes (# = ParameterCount)
                UCHAR Pad1[];	Pad to SHORT or LONG
                UCHAR Data[ DataCount ];	Data bytes (# = DataCount)
            */

            fMsg.setWordCount(14 + 1);

            // TotalParameterCount !!!!
            fMsg.setShortParameterAt(0, lparam);

            // TotalDataCount !!!!
            fMsg.setShortParameterAt(2, ldata);

            // MaxParameterCount returned by server
            fMsg.setShortParameterAt(4, 16);

            // MaxDataCount returned by server
            fMsg.setShortParameterAt(6, 3000);

            // MaxSetupCount returned by server
            fMsg.setByteParameterAt(8, 20);

            // Reserved
            fMsg.setByteParameterAt(9, 0);

            // Flags
            fMsg.setShortParameterAt(10, 0);

            // Timeout
            fMsg.setIntParameterAt(12, 0);

            // Reserved 2
            fMsg.setShortParameterAt(16, 0);

            // ParameterCount bytes sent this buffer
            fMsg.setShortParameterAt(18, 0);

            // ParameterOffset bytes sent this buffer
            fMsg.setShortParameterAt(20, 0);

            // DataCount bytes sent this buffer
            fMsg.setShortParameterAt(22, 0);

            // DataOffset bytes sent this buffer
            fMsg.setShortParameterAt(24, 0);

            // SetupCount
            fMsg.setByteParameterAt(26, 1);

            // Reserved3
            fMsg.setByteParameterAt(27, 0);

            // Setup[0]
            fMsg.setShortParameterAt(28, setup);


            // byteCount
            fMsg.setContentSize(0);

            int bytes_off, off;

            bytes_off = off = fMsg.getContentOffset();

            // reserve 1 (Name) + 4 (Pad) + 4 (Pad1)
            // free bytes for Parameters and Data
            int free = Math.Min(fMsg.Capacity - bytes_off, fMaxBufferSize) - 9;

            int send_lparam = Math.Min(free, lparam);
            int send_ldata = Math.Min(free - send_lparam, ldata);

            // Name of trans (null string)
            fMsg.SetByteAt(off, 0);
            off++;

            /*----------------- set parameters --------------------*/
            // Calculate beginning of Parameters (offset from Header)
            int param_off = off = MarshalBuffer.Align(off, 2);

            // set parameter bytes
            fMsg.SetBytesAt(off, param, 0, send_lparam);


            // ParameterCount bytes sent this buffer
            fMsg.setShortParameterAt(18, send_lparam);

            // ParameterOffset bytes sent this buffer
            fMsg.setShortParameterAt(20, param_off);

            off += send_lparam;

            /*---------------------- set data --------------------*/
            // Calculate beginning of data (offset from Header)
            int data_off = off = MarshalBuffer.Align(off, 2);

            // set data bytes

            if (send_ldata > 0)
                fMsg.SetBytesAt(off, data, 0, send_ldata);

            // DataCount bytes sent this buffer
            fMsg.setShortParameterAt(22, send_ldata);

            // DataOffset bytes sent this buffer
            fMsg.setShortParameterAt(24, data_off);

            off += send_ldata;


            // byteCount
            fMsg.setContentSize(off - bytes_off);

            fMsg.send(fNBTSession);

            if (send_lparam < lparam || send_ldata < ldata)
            {
                // receive interim response

                fMsg.receive(fNBTSession);


                int errorclass = fMsg.getErrorClass();

                if (errorclass != CifsIoException.SUCCESS)
                    throw new CifsIoException(errorclass, fMsg.getErrorCode());

                int tot_ldata = send_ldata;
                int tot_lparam = send_lparam;

                while (tot_ldata < ldata || tot_lparam < lparam)
                {
                    // Now send the next packet

                    SetupSmbMessageSecondary(fMsg, SmbMessage.SMB_COM_TRANSACTION_SECONDARY);

                    /*
                       Command	SMB_COM_TRANSACTION_SECONDARY

                       UCHAR WordCount;	Count of parameter words = 9 (! FID)
                    0: USHORT TotalParameterCount;	Total parameter bytes being sent
                    2: USHORT TotalDataCount;	Total data bytes being sent
                    4: USHORT ParameterCount;	Parameter bytes sent this buffer
                    6: USHORT ParameterOffset;	Offset (from header start) to Parameters
                    8: USHORT ParameterDisplacement;	Displacement of these Parameter bytes
                    10:USHORT DataCount;	Data bytes sent this buffer
                    12:USHORT DataOffset;	Offset (from header start) to data
                    14:USHORT DataDisplacement;	Displacement of these data bytes
                    16:USHORT Fid;	FID for handle based requests, else 0xFFFF.  This field is present only if this is an SMB_COM_TRANSACTION2 request.
                       USHORT ByteCount;	Count of data bytes
                       UCHAR Pad[];	Pad to SHORT or LONG
                       UCHAR Parameters[ParameterCount];	Parameter bytes (# = ParameterCount)
                       UCHAR Pad1[];	Pad to SHORT or LONG
                       UCHAR Data[DataCount];	Data bytes (# = DataCount)
                    */

                    fMsg.setWordCount(9);

                    bytes_off = off = fMsg.getContentOffset();
                    free = Math.Min(fMsg.Capacity - bytes_off, fMaxBufferSize) - 9;

                    send_lparam = Math.Min(lparam - tot_lparam, free);

                    send_ldata = Math.Min(ldata - tot_ldata, free - send_lparam);

                    // TotalParameterCount
                    fMsg.setShortParameterAt(0, lparam);

                    // TotalDataCount
                    fMsg.setShortParameterAt(2, ldata);

                    // ParameterCount
                    fMsg.setShortParameterAt(4, send_lparam);

                    // ParameterDisplacement
                    fMsg.setShortParameterAt(8, tot_lparam);

                    // DataCount
                    fMsg.setShortParameterAt(10, send_ldata);

                    // DataDisplacement
                    fMsg.setShortParameterAt(14, tot_ldata);

                    // FID
                    fMsg.setShortParameterAt(16, fid);


                    /*----------------- set parameters --------------------*/
                    // Calculate beginning of Parameters (offset from Header)
                    param_off = off = MarshalBuffer.Align(off, 4);

                    // set parameter bytes
                    fMsg.SetBytesAt(off, param, tot_lparam, send_lparam);

                    // ParameterOffset bytes sent this buffer
                    fMsg.setShortParameterAt(6, param_off);

                    off += send_lparam;

                    /*---------------------- set data --------------------*/
                    // Calculate beginning of data (offset from Header)
                    data_off = off = MarshalBuffer.Align(off, 4);

                    // set data bytes
                    if (send_ldata > 0)
                        fMsg.SetBytesAt(off, data, tot_ldata, send_ldata);


                    // DataOffset bytes sent this buffer
                    fMsg.setShortParameterAt(12, data_off);

                    off += send_ldata;


                    // byteCount
                    fMsg.setContentSize(off - bytes_off);

                    fMsg.send(fNBTSession);

                    tot_lparam += send_lparam;
                    tot_ldata += send_ldata;
                } // while loop
            } // if recieving
        }

        /// <summary>
        ///   Receives SMB_COM_TRANSACTION
        /// </summary>
        /// <param name = "param">param parameters</param>
        /// <param name = "data">data buffer</param>
        internal void receiveTransaction(MarshalBuffer param, MarshalBuffer data)
        {
            if (Debug.DebugOn)
                Debug.WriteLine(Debug.Info, "Receive SMB_COM_TRANSACTION");

            fMsg.receive(fNBTSession);

            int errorclass = fMsg.getErrorClass();

            if (errorclass != CifsIoException.SUCCESS)
                throw new CifsIoException(errorclass, fMsg.getErrorCode());

            /*
              UCHAR WordCount;	Count of data bytes; value = 10 + SetupCount
            0:USHORT TotalParameterCount;	Total parameter bytes being sent
            2:USHORT TotalDataCount;	Total data bytes being sent
            4:USHORT Reserved;
            6:USHORT ParameterCount;	Parameter bytes sent this buffer
            8:USHORT ParameterOffset;	Offset (from header start) to Parameters
            10:USHORT ParameterDisplacement;	Displacement of these Parameter bytes
            12:USHORT DataCount;	Data bytes sent this buffer
            14:USHORT DataOffset;	Offset (from header start) to data
            16:USHORT DataDisplacement;	Displacement of these data bytes
            18:UCHAR SetupCount;	Count of setup words
            19:UCHAR Reserved2;	Reserved (pad above to word)
            20:USHORT Setup[SetupWordCount];	Setup words (# = SetupWordCount)
                USHORT ByteCount;	Count of data bytes
                UCHAR Pad[];	Pad to SHORT or LONG
                UCHAR Parameters[ParameterCount];	Parameter bytes (# = ParameterCount)
                UCHAR Pad1[];	Pad to SHORT or LONG
                UCHAR Data[DataCount];	Data bytes (# = DataCount)
            */

            int lparam = 0;
            int ldata = 0;

            // TotalParameterCount
            int tot_lparam = fMsg.getShortParameterAt(0);
            int tot_ldata = fMsg.getShortParameterAt(2);

            // alloca buffer
            param.Capacity = tot_lparam;
            data.Capacity = tot_ldata;

            while (true)
            {
                int rcv_lparam = fMsg.getShortParameterAt(6);
                int rcv_ldata = fMsg.getShortParameterAt(12);

                if (rcv_lparam + lparam > tot_lparam ||
                    rcv_ldata + ldata > tot_ldata)
                    throw new SystemException("Invalid Data");

                if (rcv_lparam > 0)
                {
                    int off_param = fMsg.getShortParameterAt(8);
                    int dsp_param = fMsg.getShortParameterAt(10);

                    param.SetBytesAt(dsp_param, fMsg, off_param, rcv_lparam);
                }
                if (rcv_ldata > 0)
                {
                    int off_data = fMsg.getShortParameterAt(14);
                    int dsp_data = fMsg.getShortParameterAt(16);

                    data.SetBytesAt(dsp_data, fMsg, off_data, rcv_ldata);
                }

                lparam += rcv_lparam;
                ldata += rcv_ldata;

                // get Total (they can shrink!)
                tot_lparam = fMsg.getShortParameterAt(0);
                tot_ldata = fMsg.getShortParameterAt(2);

                if (tot_lparam <= lparam && tot_ldata <= ldata)
                    break;

                fMsg.receive(fNBTSession);

                errorclass = fMsg.getErrorClass();

                if (errorclass != CifsIoException.SUCCESS)
                    throw new CifsIoException(errorclass, fMsg.getErrorCode());
            } // while loop

            param.Size = lparam;
            data.Size = ldata;
        }


        /// <summary>
        ///   Initializes the SMB message
        /// </summary>
        /// <param name = "msg">SMB message</param>
        /// <param name = "cmd">Command</param>
        internal void SetupSmbMessage(SmbMessage msg, byte cmd) // should be protected
        {
            msg.setCommand(cmd);
            msg.setUID(fUID);
            msg.setTID(fTID);
            msg.setPID(fPID);
            msg.setMID(nextMID());
            msg.setCanHandleLongNames();
            msg.setExtededAttributes();

            if (cmd == SmbMessage.SMB_COM_TREE_CONNECT_ANDX ||
                cmd == SmbMessage.SMB_COM_TREE_DISCONNECT ||
                cmd == SmbMessage.SMB_COM_SESSION_SETUP_ANDX ||
                cmd == SmbMessage.SMB_COM_LOGOFF_ANDX)
                return;

            CheckConnection();
        }

        /// <summary>
        ///   Initializes SMB message for SMB_COM_TRANSACTION_SECONDARY
        /// </summary>
        /// <param name = "msg">SMB message</param>
        /// <param name = "cmd">Command</param>
        internal void SetupSmbMessageSecondary(SmbMessage msg, byte cmd) // should be protected
        {
            msg.setCommand(cmd);
            msg.setUID(fUID);
            msg.setTID(fTID);
            msg.setPID(fPID);
            msg.setMID(fMID);
            msg.setCanHandleLongNames();
            msg.setExtededAttributes();
        }

        /// <summary>
        ///   Prompts for login dialog (not implemented)
        ///   Currently always returns false, meaning guest only.
        /// </summary>
        /// <returns>false if dialog canceled.  Currently, always false</returns>
        internal bool PromptLogin()
        {
            if (!CifsSessionManager.AllowLoginDialog)
                return false;

            // This should bring up a dialog to prompt for a username and password
            // This has not been implemented, so we must always return false
            // Basicly, we can only browse as guest
            return false;
        }

        /// <summary>
        ///   Returns max number of bytes which can be sent
        /// </summary>
        /// <returns>number of bytes</returns>
        internal int HowManyBytesCanWeSend()
        {
            // Message_Capacity - 100 ( > 32 (Header) - 2*15 (Max parameters) )

            return Math.Min(fMsg.Capacity - 100, fMaxBufferSize - 100);
        }

        internal static Hashtable GetSessionTable()
        {
            return fSessionTable;
        }

        internal static IDictionaryEnumerator GetEnumerator()
        {
            return fSessionTable.GetEnumerator();
        }

        internal static ICifsSession[] GetSessions()
        {
            ICifsSession[] sessions;

            lock (fSessionTable)
            {
                sessions = new CifsSession[fSessionTable.Count];

                int i = 0;
                foreach (IDictionaryEnumerator en in fSessionTable)
                {
                    sessions[i++] = (ICifsSession) en.Value;
                }

                return sessions;
            }
        }

        internal static ICifsSession LookupSession(string sessionname)
        {
            return (ICifsSession) fSessionTable[sessionname];
        }

        internal static void AddSession(string sessionname, ICifsSession session)
        {
            lock (fSessionTable)
            {
                //fSessionTable.Add(sessionname, session);
            }
        }

        internal void RemoveSession(string sessionname)
        {
            lock (fSessionTable)
            {
                fSessionTable.Remove(sessionname);
            }
        }

        internal abstract int GetSortPosition();

        private int nextMID()
        {
            lock (this)
            {
                fMID++;
                if (fMID == short.MaxValue)
                    fMID = 0;

                return fMID;
            }
        }

        private void debug()
        {
            if (!Debug.DebugOn || Debug.DebugLevel < Debug.Info)

                return;

            Debug.WriteLine(Debug.Info, "Security mode                     = " + fSecurityMode);
            string am = (IsUserLevelSecurity ? "User" : "Share");
            Debug.WriteLine(Debug.Info, "Access mode                       = " + am);
            Debug.WriteLine(Debug.Info, "Max pending multiplexed requests  = " + fMaxPendingMPRequests);
            Debug.WriteLine(Debug.Info, "Max VCs between client and server = " + fMaxVCs);
            Debug.WriteLine(Debug.Info, "Max transmit buffer size          = " + fMaxBufferSize);
            Debug.WriteLine(Debug.Info, "Max raw      buffer size          = " + fMaxRawSize);
            Debug.WriteLine(Debug.Info, "Session key                       = " + Util.Util.IntToHex(fSessionKey));
            Debug.WriteLine(Debug.Info, "Server capabilities               = " + Util.Util.IntToHex(fCapabilities));
            Debug.WriteLine(Debug.Info, "System time                       = " + new DateTime(fSystemTime));
            Debug.WriteLine(Debug.Info, "Time zone                         = " + fTimeZone);
            Debug.WriteLine(Debug.Info, "Encryption key length             = " + fEncryptionKeyLen);
            Debug.WriteLine(Debug.Info, "Encryption key                    = " + Util.Util.BytesToHex(fEncryptionKey));
            Debug.WriteLine(Debug.Info, "UID                               = " + fUID);
            Debug.WriteLine(Debug.Info, "TID                               = " + fTID);
            Debug.WriteLine(Debug.Info, "PID                               = " + fPID);
            Debug.WriteLine(Debug.Info, "Logged as guest                   = " + fLoggedAsGuest);
            Debug.WriteLine(Debug.Info, "Server OS                         = " + fServerOS);
            Debug.WriteLine(Debug.Info, "Server Lanman                     = " + fServerLanMan);
            Debug.WriteLine(Debug.Info, "Server Primary Domain             = " + fServerPrimaryDomain);

            // We can dump the contents of the user-config once its enabled
        }
    }

    // class SessionImpl
}

// namespace Cifs