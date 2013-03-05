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


namespace Cifs
{
    using System;
    using System.IO;
    using System.Net.Sockets;
    using System.Text;

    using Cifs.Util;

    /// <summary>
    ///    Summary description for SMBMessage.
    /// </summary>
    internal sealed class SmbMessage: MarshalBuffer, INbtOutput, INbtInput
    {
        public const byte SMB_COM_CREATE_DIRECTORY	    = (byte)0x00;
        public const byte SMB_COM_DELETE_DIRECTORY	    = (byte)0x01;
        public const byte SMB_COM_OPEN	                = (byte)0x02;
        public const byte SMB_COM_CREATE	            = (byte)0x03;
        public const byte SMB_COM_CLOSE	                = (byte)0x04;
        public const byte SMB_COM_FLUSH	                = (byte)0x05;
        public const byte SMB_COM_DELETE	            = (byte)0x06;
        public const byte SMB_COM_RENAME	            = (byte)0x07;
        public const byte SMB_COM_QUERY_INFORMATION	    = (byte)0x08;
        public const byte SMB_COM_SET_INFORMATION	    = (byte)0x09;
        public const byte SMB_COM_READ	                = (byte)0x0A;
        public const byte SMB_COM_WRITE	                = (byte)0x0B;
        public const byte SMB_COM_LOCK_BYTE_RANGE	    = (byte)0x0C;
        public const byte SMB_COM_UNLOCK_BYTE_RANGE	    = (byte)0x0D;
        public const byte SMB_COM_CREATE_TEMPORARY	    = (byte)0x0E;
        public const byte SMB_COM_CREATE_NEW	        = (byte)0x0F;
        public const byte SMB_COM_CHECK_DIRECTORY	    = (byte)0x10;
        public const byte SMB_COM_PROCESS_EXIT	        = (byte)0x11;
        public const byte SMB_COM_SEEK	                = (byte)0x12;
        public const byte SMB_COM_LOCK_AND_READ	        = (byte)0x13;
        public const byte SMB_COM_WRITE_AND_UNLOCK	    = (byte)0x14;
        public const byte SMB_COM_READ_RAW	            = (byte)0x1A;
        public const byte SMB_COM_READ_MPX	            = (byte)0x1B;
        public const byte SMB_COM_READ_MPX_SECONDARY	= (byte)0x1C;
        public const byte SMB_COM_WRITE_RAW	            = (byte)0x1D;
        public const byte SMB_COM_WRITE_MPX	            = (byte)0x1E;
        public const byte SMB_COM_WRITE_COMPLETE	    = (byte)0x20;
        public const byte SMB_COM_SET_INFORMATION2	    = (byte)0x22;
        public const byte SMB_COM_QUERY_INFORMATION2	= (byte)0x23;
        public const byte SMB_COM_LOCKING_ANDX	        = (byte)0x24;
        public const byte SMB_COM_TRANSACTION	        = (byte)0x25;
        public const byte SMB_COM_TRANSACTION_SECONDARY	= (byte)0x26;
        public const byte SMB_COM_IOCTL	                = (byte)0x27;
        public const byte SMB_COM_IOCTL_SECONDARY	    = (byte)0x28;
        public const byte SMB_COM_COPY	                = (byte)0x29;
        public const byte SMB_COM_MOVE	                = (byte)0x2A;
        public const byte SMB_COM_ECHO	                = (byte)0x2B;
        public const byte SMB_COM_WRITE_AND_CLOSE	    = (byte)0x2C;
        public const byte SMB_COM_OPEN_ANDX	            = (byte)0x2D;
        public const byte SMB_COM_READ_ANDX	            = (byte)0x2E;
        public const byte SMB_COM_WRITE_ANDX	        = (byte)0x2F;
        public const byte SMB_COM_CLOSE_AND_TREE_DISC	= (byte)0x31;
        public const byte SMB_COM_TRANSACTION2	        = (byte)0x32;
        public const byte SMB_COM_TRANSACTION2_SECONDARY = (byte)0x33;
        public const byte SMB_COM_FIND_CLOSE2	        = (byte)0x34;
        public const byte SMB_COM_FIND_NOTIFY_CLOSE	    = (byte)0x35;
        public const byte SMB_COM_TREE_CONNECT	        = (byte)0x70;
        public const byte SMB_COM_TREE_DISCONNECT	    = (byte)0x71;
        public const byte SMB_COM_NEGOTIATE	            = (byte)0x72;
        public const byte SMB_COM_SESSION_SETUP_ANDX	= (byte)0x73;
        public const byte SMB_COM_LOGOFF_ANDX	        = (byte)0x74;
        public const byte SMB_COM_TREE_CONNECT_ANDX	    = (byte)0x75;
        public const byte SMB_COM_QUERY_INFORMATION_DISK = (byte)0x80;
        public const byte SMB_COM_SEARCH	            = (byte)0x81;
        public const byte SMB_COM_FIND	                = (byte)0x82;
        public const byte SMB_COM_FIND_UNIQUE	        = (byte)0x83;
        public const byte SMB_COM_NT_TRANSACT	        = (byte)0xA0;
        public const byte SMB_COM_NT_TRANSACT_SECONDARY	= (byte)0xA1;
        public const byte SMB_COM_NT_CREATE_ANDX	    = (byte)0xA2;
        public const byte SMB_COM_NT_CANCEL	            = (byte)0xA4;
        public const byte SMB_COM_OPEN_PRINT_FILE	    = (byte)0xC0;
        public const byte SMB_COM_WRITE_PRINT_FILE	    = (byte)0xC1;
        public const byte SMB_COM_CLOSE_PRINT_FILE	    = (byte)0xC2;
        public const byte SMB_COM_GET_PRINT_QUEUE	    = (byte)0xC3; 
    
        /*----------------- SMB_COM_TRANSACTION2 Subcommand codes ----------------*/

        // Create file with extended attributes
        public const short TRANS2_OPEN2	= (short)0x00;

        // Begin search for files
        public const short TRANS2_FIND_FIRST2	=(short)0x01;

        // Resume search for files
        public const short TRANS2_FIND_NEXT2	=(short)0x02;

        // Get file system information
        public const short TRANS2_QUERY_FS_INFORMATION	=(short)0x03;

        // Get information about a named file or directory
        public const short TRANS2_QUERY_PATH_INFORMATION	=(short)0x05;

        // Set information about a named file or directory
        public const short TRANS2_SET_PATH_INFORMATION	=(short)0x06;

        // Get information about a handle
        public const short TRANS2_QUERY_FILE_INFORMATION	=(short)0x07;

        // Set information by handle
        public const short TRANS2_SET_FILE_INFORMATION	=(short)0x08;

        // Create directory with extended attributes
        public const short TRANS2_CREATE_DIRECTORY	=(short)0x0D;

        // Session setup with extended security information
        public const short TRANS2_SESSION_SETUP	=(short)0x0E;

        // Get a DFS referral
        public const short TRANS2_GET_DFS_REFERRAL	=(short)0x10;

        // Report a DFS knowledge inconsistency
        public const short TRANS2_REPORT_DFS_INCONSISTENCY	=(short)0x11	;


        // InformationLevels
        public const short SMB_INFO_STANDARD	                = 1;
        public const short SMB_INFO_QUERY_EA_SIZE	        = 2;
        public const short SMB_INFO_QUERY_EAS_FROM_LIST	    = 3;
        public const short SMB_FIND_FILE_DIRECTORY_INFO	    = 0x101;
        public const short SMB_FIND_FILE_FULL_DIRECTORY_INFO	= 0x102;
        public const short SMB_FIND_FILE_NAMES_INFO	        = 0x103;
        public const short SMB_FIND_FILE_BOTH_DIRECTORY_INFO	= 0x104;

        /*
         * Data portion types
         */
        public const  byte DT_DATA_BLOCK     = 1;
        public const  byte DT_DIALECT        = 2;
        public const  byte DT_PATHNAME       = 3;
        public const  byte DT_ASCII          = 4;
        public const  byte DT_VARIABLE_BLOCK = 5;


        /*
         *  All reserved fields in the SMB header must be zero.
         *  All quantities are sent in native Intel format.
         */

        // Contains 0xff 'SMB'
        private const int  MAGIC_4       = 0;

        // Command code
        private const int  COMMAND_1     = 4;       // uchar

        // Status
        // NT-style 32-bit error code
        private const int  NT_STATUS_4  = 5;      // ulong (little-endian)

        // Error Class
        private const int  ERROR_CLASS_1 = 5;    // uchar
        // Reserved
        private const int  RESERVED1_1   = 6;     // uchar (0x00)
        // Error
        private const int  ERROR_CODE_2  = 7;     // ushort
        // Flags
        private const int  FLAGS_1       = 9;      // uchar
        // Flags2
        private const int  FLAGS2_2      = 10;     // ushort

        /*
         * Connectionless (12 bytes)
         *
         * CONNECTIONLESS. SID, and CONNECTIONLESS.SEQUENCENUMBER are
         * used when the client to server connection is on a datagram
         * oriented protocol such as IPX.
         */

         // High part of PID (used by NTCREATEANDX )
        private const int  PID_HIGH_2       = 12;     // ushort
        private const int  SECURITY_SIG_8   = 14;     // uchar[8]
        // Reserved
        private const int  RESERVED2_2      = 22;     // uchar[2] (0x00)


        // Tree identifier
        // TID identifies the subdirectory, or "tree", on the server
        // which the client is accessing.  SMBs which do not reference
        // a particular tree should set TID to 0xFFFF
        private const int   TID_2            = 24;     // ushort

        // Caller's process id
        // PID is the caller's process id, and is generated by the client
        // to uniquely identify a process within the client computer.

        private const int   PID_2            = 26;      // ushort

        // Unauthenticated user id
        private const int   UID_2            = 28;      // ushort

        // multiplex id
        // o MID is reserved for multiplexing multiple messages on a
        // single Virtual Circuit (VC).  A response message will always
        // contain the same value as the corresponding request message.
        private const int   MID_2            = 30;      // ushort
            // ushort
        // Count of parameter words
        private const int  PARAMETER_COUNT_1 = 32;      // uchar
         // The parameter words
         // ushort[PARAMETER_COUNT_1] Paramter
         // ushort ByteCount
         // uchar buffer[ByteCount]


        // When on, this SMB is being sent from the server
        private const int FLAG_IS_RESPONSE        = 0x80;

        // When on, all pathnames in this SMB must be treated as caseless
        private const int FLAG_CASELESS_PATHNAMES = 0x08;

        // If set, any strings in this SMB message are encoded as UNICODE, otherwise ASCII
        private const int FLAG2_STRING_AS_UNICODE = 0x8000;

        private const int FLAG2_CLIENT_EXT_ATTR   = 0x0002;

        private const int FLAG2_CAN_LONG_NAMES    = 0x0001;


        private readonly static String NL = System.Environment.NewLine;

        // helper array for initialization
        private readonly static byte[] ZEROS = new byte[PARAMETER_COUNT_1];		

        
        //------------------------------- Object Fields ---------------------

        internal SmbMessage(int capacity): base(capacity)
        {
            reset();
        }

        
        private void reset()
        {
            Array.Copy(ZEROS, 0, fBuffer, 0, ZEROS.Length);

            /*
             for(int i=0; i<PARAMETER_COUNT_1; i++)
                fBuffer[i] = 0;
            */

            fBuffer[MAGIC_4]   = (byte)0xFF;
            fBuffer[MAGIC_4+1] = (byte)'S';
            fBuffer[MAGIC_4+2] = (byte)'M';
            fBuffer[MAGIC_4+3] = (byte)'B';
            SetShortAt(TID_2, (ushort)(0xFFFF));
        }

        /// <summary>
        /// Set command type and resets packet
        /// </summary>
        /// <param name="cmd">command</param>
        public void setCommand(byte cmd)
        {
            reset();
            fBuffer[COMMAND_1] = cmd;
        }

        public byte getCommand()
        {
            return fBuffer[COMMAND_1];
        }

        public int getErrorClass()
        {
            return fBuffer[ERROR_CLASS_1] & 0xFF;
        }

        public int getErrorCode()
        {
            return GetShortAt(ERROR_CODE_2);
        }

        public int getNTErrorCode()
        {
            return GetIntAt(NT_STATUS_4);
        }

        private int getFlags()
        {
            return fBuffer[FLAGS_1] & 0xFF;
        }

        public bool isResponse()
        {
            return ((getFlags() & FLAG_IS_RESPONSE) != 0);
        }

        /// <summary>
        /// Strings in SMB are UNICODE encoded (Flag2)
        /// </summary>
        public void setStringsAsUnicode()
        {
            int flag = getFlags2() | FLAG2_STRING_AS_UNICODE;
            setFlags2(flag);
        }

        /// <summary>
        /// Strings in SMB are UNICODE encoded (Flag2)
        /// </summary>
        public bool isStringsAsUnicode()
        {
            return ((getFlags2() & FLAG2_STRING_AS_UNICODE) != 0);
        }

        /// <summary>
        /// We can handle long components in path names in the response
        /// </summary>
        public void setCanHandleLongNames()
        {
            int flag = getFlags2() | FLAG2_CAN_LONG_NAMES;
            setFlags2(flag);
        }

        /// <summary>
        /// If set, the client is aware of extended attributes
        /// </summary>
        public void setExtededAttributes()
        {
            int flag = getFlags2() | FLAG2_CLIENT_EXT_ATTR;
            setFlags2(flag);
        }

        public void setCalselessPathnames()
        {
            int flag = getFlags() | FLAG_CASELESS_PATHNAMES;
            fBuffer[FLAGS_1] = (byte)(flag & 0xff);
        }

        private int getFlags2()
        {
            return GetShortAt(FLAGS2_2);
        }

        private void setFlags2(int flag)
        {
            SetShortAt(FLAGS2_2, (ushort)(flag & 0xFFFF));
        }

        public int getTID()
        {
            return GetShortAt(TID_2);
        }

        public void setTID(int tid)
        {
            SetShortAt(TID_2, tid);
        }

        public int getPID()
        {
            return GetShortAt(PID_2);
        }

        public void setPID(int pid)
        {
            SetShortAt(PID_2, pid);
        }

        public int getUID()
        {
            return GetShortAt(UID_2);
        }

        public void setUID(int uid)
        {
            SetShortAt(UID_2, uid);
        }

        public int getMID()
        {
            return GetShortAt(MID_2);
        }

        public void setMID(int mid)
        {
            SetShortAt(MID_2, mid);
        }

        public void setWordCount(int num)
        {
            fBuffer[PARAMETER_COUNT_1] = (byte)(num & 0xff);
        }

        public int getWordCount()
        {
            return fBuffer[PARAMETER_COUNT_1] & 0xff;
        }

        public int getParameter(int index)
        {
            int offset = PARAMETER_COUNT_1 + 1 + 2*index;
            return GetShortAt(offset);
        }

        public int getShortParameterAt(int pos)
        {
            int offset = PARAMETER_COUNT_1 + 1 + pos;
            return GetShortAt(offset);
        }

        public short getSignedShortParameterAt(int pos)
        {
            int offset = PARAMETER_COUNT_1 + 1 + pos;
            return GetSignedShortAt(offset);
        }

        public void setShortParameterAt(int pos, int val)
        {
            int offset = PARAMETER_COUNT_1 + 1 + pos;
            SetShortAt(offset, val);
        }

        public int getIntParameterAt(int pos)
        {
            int offset = PARAMETER_COUNT_1 + 1 + pos;
            return GetIntAt(offset);
        }

        public void setIntParameterAt(int pos, int val)
        {
            int offset = PARAMETER_COUNT_1 + 1 + pos;
            SetIntAt(offset, val);
        }

        public void setByteParameterAt(int pos, byte val)
        {
            int offset = PARAMETER_COUNT_1 + 1 + pos;
            fBuffer[offset] = val;
        }

        public byte getByteParameterAt(int pos)
        {
            int offset = PARAMETER_COUNT_1 + 1 + pos;
            return fBuffer[offset];
        }

        public void setContent(byte[] content, int offset, int len)
        {
            // pos points to ByteCount
            int pos = getContentOffset() - 2;
            SetShortAt(pos, (short)(len & 0xFFFF));
            pos += 2;
            for(int i=0; i<len; i++)
                fBuffer[pos+i] = content[offset+i];
        }

        public void setContent(byte[] content)
        {
            setContent(content, 0, content.Length);
        }

        public void setContentSize(int size)
        {
            int pos = getContentOffset() - 2;
            SetShortAt(pos, size);
        }

        public void setContent(MarshalBuffer content)
        {
            setContent(content.GetBytes(), 0, content.Size);
        }

        public int getContentSize()
        {
            int pos = getContentOffset() - 2;
            return GetShortAt(pos);
        }

        public int getContentOffset()
        {
            int param = getWordCount();
            return (PARAMETER_COUNT_1 + 1 + param*2 + 2);
        }

        public void CopyTo(int pos, ref byte[] buf, int off, int len)
        {
            Array.Copy(fBuffer, pos, buf, off, len);
        }

        public int getMessageSize()
        {
            return getContentOffset() + getContentSize();
        }

        public byte[] getMessageBuffer()
        {
            return fBuffer;
        }

        public void zero(int pos, int len)
        {
            if (pos + len > fBuffer.Length)
                len = fBuffer.Length - pos;

            for(int i=0; i<len ; i++)
                fBuffer[pos+i] = (byte)0;
        }

        public void send(NbtSession nbt)
        {
            if(Debug.DebugOn)
                dumpPacket("Send SMB buffer"); 
            

            nbt.DoSend(this);
        }

        public void receive(NbtSession nbt)
        {
            nbt.DoRecieve(this);
            
            if(Debug.DebugOn)
                dumpPacket("Recieve SMB buffer");
            
        }

        public void SendAndRecieve(NbtSession nbt, SmbMessage reply)
        {
            nbt.DoSend(this);

            if(Debug.DebugOn)
                dumpPacket("Send SMB buffer");
            

            nbt.DoRecieve(reply);

            if(Debug.DebugOn)
                dumpPacket("Recieve SMB buffer");
            
        }

        //-------------------------- NetBIOSOutput --------------------------

        public int Size
        {
            get { return getMessageSize(); }
        }

        public void writeTo(TextWriter o, int size)
        {
            for(int i=0; i < size; i++)
                o.Write(fBuffer[i] & 0xff);
        }

        public void WriteTo(NetworkStream o, int size)
        {
            o.Write(fBuffer, 0, size);
        }

        /// <summary>
        /// Wites the buffer to the output stream
        /// </summary>
        /// <param name="pos">offset in the buffer</param>
        /// <param name="o">output stream</param>
        /// <param name="size">size to write</param>
        public void writeTo(int pos, NetworkStream o, int size)
        {
            o.Write(fBuffer, pos, size);
        }

        public void writeTo(int pos, TextWriter o, int size)
        {
            for(int i=0; i<size; i++)
                o.Write(fBuffer[pos+i] & 0xff);
        }

        //----------------------- NetBIOSInput -----------------------------

        public int ReadFrom(NetworkStream ins, int size)
        {
            if (size <= 0)
                return 0;

            if(fBuffer.Length < size)
                Capacity = size;

            int count = 0;

            while(size > 0)
            {
                int result = ins.Read(fBuffer, count, size);

                if(result <= 0)
                    throw new EndOfStreamException();

                count += result;
                size  -= result;
            }
            return count;
        }

        //-------------------- Debugging helper ----------------------------

        
        private void dumpPacket(string title)
        {
            if(!Debug.DebugOn || Debug.DebugLevel < Debug.Buffer)
                return;

            Debug.WriteLine(Debug.Buffer, title);

            StringBuilder buf = new StringBuilder(300);

            buf.Append("smb_com  = 0x" + Util.Util.ByteToHex(getCommand()) + NL);
            buf.Append("smb_rcls = " + getErrorClass() + NL);
            buf.Append("smb_reh  = " + getErrorCode() + NL);
            buf.Append("smb_flg  = 0x" + Util.Util.IntToHex(getFlags()) + NL);
            buf.Append("smb_flg2 = 0x" + Util.Util.IntToHex(getFlags2()) + NL);
            buf.Append("smb_tid  = 0x" + Util.Util.ShortToHex(getTID()) + NL);
            buf.Append("smb_pid  = 0x" + Util.Util.ShortToHex(getPID()) + NL);
            buf.Append("smb_uid  = 0x" + Util.Util.ShortToHex(getUID()) + NL);
            buf.Append("smb_mid  = 0x" + Util.Util.ShortToHex(getMID()) + NL);

            int wc = getWordCount();
            buf.Append("smb_wct  = " + wc + NL);

            for(int i=0; i<wc ; i++)
            {
                int par = getParameter(i);
                buf.Append("smb_vwv[" + i + "]= 0x" + Util.Util.ShortToHex(par));
                buf.Append(" (" + par + ")" + NL);
            }
            int len = getContentSize();
            buf.Append("smb_bcc  = " + len + NL);


            int off = getContentOffset();
            buf.Append("smb_boff = " + off + NL);

            Debug.WriteLine(Debug.Buffer, buf.ToString());
            Debug.WriteLine(Debug.Buffer, fBuffer, off, len);

        }

    } // class SMBMessage
} // namespace Cifs
