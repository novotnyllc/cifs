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
    using System.Net;
    using System.Net.Sockets;
    //using System.Threading;
    

    using Cifs.Util;

    /// <summary>
    ///   NetBIOS over TCP/IP (Session Service)
    /// </summary>
    /// <remarks>
    ///  After the server name has been resolved to an IP address, then a connection
    ///  to the server needs to be established if one has not already been set up.
    ///  Connection establishment is done using  the NETBIOS session service,
    ///  which requires the client to provide a "calling name" and a "called name".
    ///  The calling name is not significant in CIFS, except that an identical name
    ///  from the same transport address is assumed to represent the same client;
    ///  the called name is always "*SMBSERVER      ". Connection establishment
    ///  results in a "Session Request" packet to port 139 (see section 4.3.2 of RFC 1002).
    ///  <para>
    ///  <strong>Backwards Compatibiltiy</strong>
    ///  </para>
    ///  <para>
    ///  If a CIFS client wishes to inter-operate with older SMB servers,
    ///  then if the server rejects the session request, it can retry with a new called name.
    ///  The choice of the new called name depends on the name resolution mechanism used.
    ///  If DNS was used, the called name should be constructed from the first component
    ///  of the server's DNS name, truncated to 15 characters if necessary, and then padded
    ///  to 16 characters with blank (20 hex) characters. If NETBIOS was used, then the called
    ///  named is just the NETBIOS name. If these fail, then a NETBIOS "Adapter Status"
    ///  request may be made to obtain the server's NETBIOS name, and the connection
    ///  establishment retried with that as the called name.
    ///  </para>
    ///  </remarks>
    internal sealed class NbtSession
    {
        /// <summary>
        /// Standard called name for NetBIOS
        /// </summary>
        private const string SMBSERVER_NAME = "*SMBSERVER      ";

        /// <summary>
        /// Session packet type (byte)
        /// </summary>
        private const int HDR_TYPE_1  = 0;

        /// <summary>
        /// Bit 7 is the LENGTH extension
        /// Bit 0-6 are reserved and must be 0
        /// </summary>
        private const int HDR_FLAGS_1 = 1;

        /// <summary>
        /// Session packet length without header (ushort) and BIG-Endian!!!
        /// </summary>
        private const int HDR_LENGTH_2 = 2;

        private const int HDR_SIZE = 4;

        /// <summary>
        /// Session packet types (Field HDR_TYPE_B)
        /// </summary>
        private const byte SPT_MESSAGE      = (byte)0;
        private const byte SPT_REQUEST      = (byte)0x81;
        private const byte SPT_POS_RESPONSE = (byte)0x82;
        private const byte SPT_NEG_RESPONSE = (byte)0x83;

        /// <summary>
        /// Retarget session response
        /// </summary>
        private const byte SPT_RTG_RESPONSE = (byte)0x84;

        private const byte SPT_KEEPALIVE    = (byte)0x85;

        /// <summary>
        /// Session request packet
        /// </summary>
        private const int RQ_CALLED_NAME_32 = 4;

        //----------------- Session Positive response packet -----------------
        // no trailer, LENGTH=0


        /// <summary>
        /// Session Negative response packet
        /// </summary>
        private const int NR_ERROR_CODE_1 = 8;

        /// <summary>
        /// Session Retargeted response packet
        /// </summary>
        private const int RT_IP_ADDRESS_4 = 8;
        private const int RT_PORT_2		  = 12;
        private const int RT_SIZE         = 6;

        /// <summary>
        /// Session message packet
        /// </summary>
        private const int MS_DATA         = 4;

        //------------------ Session keep alive packet ---------------
        // has no trailer

        private const int SSN_SRVC_TCP_PORT      = 139;
        private const int SSN_RETRY_COUNT        = 4; // Default
        
        /// <summary>
        /// Default (sec)
        /// </summary>
        private const int SSN_CLOSE_TIMEOUT		 = 30;
        
        /// <summary>
        /// Default (sec) 
        /// </summary>
        private const int SSN_KEEP_ALIVE_TIMEOUT = 60;

        // Negative response codes
        /*
        private const byte  NR_EC_NOT_LISTINING_CALLED_NAME  = (byte)0x80; // 128
        private const byte  NR_EC_NOT_LISTINING_CALLING_NAME = (byte)0x81; // 129
        private const byte  NR_EC_CALLED_NAME_NOT_PRESENT    = (byte)0x82; // 130
        private const byte  NR_EC_INSUFFICIENT_RESOURCES     = (byte)0x83; // 131
        private const byte  NR_EC_UNSPECIFIED_ERROR          = (byte)0x8F; // 143
        */

        //private int				fPort		 = SSN_SRVC_TCP_PORT;  //This was in the java version...it isn't used...
        private static string	fLocalHostName = Dns.GetHostName();
        private string			fCallingName;
        // private static int	fLocalNameId = 0;

        private TcpClient		fSocket = null;
        private NetworkStream	fInput = null;
        private NetworkStream   fOutput = null;
        
        private byte[]			fSessionHeader = new byte[HDR_SIZE];

        private int				fTimeout;
        private bool			fTcpNoDelay;

        public event EventHandler ConnectionLost;

        public NbtSession()
        {
            InetAddress = null;
            NetBiosName = null;
            WorkgroupName = null;
            // Get properties...  This user configurable stuff will be added later
            fTimeout = SSN_CLOSE_TIMEOUT;
            
            //time in millisec
            fTimeout *= 1000;

            // NoDelay param
            fTcpNoDelay = true;

            // Calling name
            fCallingName = Environment.GetEnvironmentVariable("COMPUTERNAME");
            
            if(Debug.DebugOn && Debug.DebugLevel >= Debug.Info)
            {
                Debug.WriteLine(Debug.Info, "NetBIOS: Timeout=" + fTimeout);
                Debug.WriteLine(Debug.Info, "NetBIOS: Tcpnodelay=" + fTcpNoDelay);
            }
        }

        public string NetBiosName { get; private set; }

        public string WorkgroupName { get; private set; }

        public IPAddress InetAddress { get; private set; }

        private static void SetShortAt(int pos, byte[] buffer, short val)
        {
             // use big-endian encoding
            buffer[pos]   = (byte)((val >> 8) & 0xff);
            buffer[pos+1] = (byte)(val & 0xff);
        }
        
        private static int GetShortAt(int pos, byte[] buffer)
        {
            if(pos + 2 > buffer.Length)
                throw new ArgumentOutOfRangeException();

            return ((buffer[pos+1]  & 0xff)     +
                   ((buffer[pos]    & 0xff) << 8) ) & 0xffff;
        }

        private void NotifyConnectionLost()
        {
            var evt = ConnectionLost;
            if (evt != null)
                evt(this, EventArgs.Empty);
        }

        public void DoCall(string netbiosname)
        {
            lock(this)	// This entire method needs to be synchronized
         {
            // int retry_count = 0;  
             int port = SSN_SRVC_TCP_PORT;
             
             InetAddress = NbtNameResolver.Resolve(netbiosname);
             
             // Get the real NetBIOS name & Workgroup from an IP
             NBTNameService ns = new NBTNameService();
             NbInfo info = ns.queryStatus(InetAddress);
             NetBiosName = info.Name;
             WorkgroupName = info.Workgroup;

             // If we couldn't resolve the name, then the host either doesn't
             // exist or does not support CIFS.
             if(NetBiosName == null)
                throw new CifsIoException("CM2", InetAddress.ToString());


             DoConnect(InetAddress, port);
             byte[] packet = MakeRequestPacket(NetBiosName);
            
             if(Debug.DebugOn && Debug.DebugLevel >= Debug.Info)
             {
                Debug.WriteLine(Debug.Info, "NetBIOS: doCall");
                Debug.WriteLine(Debug.Info, "Called name=" + NetBiosName);
                Debug.WriteLine(Debug.Info, "Calling name=" + fCallingName);
                Debug.WriteLine(Debug.Info, "Called addr=" + InetAddress.ToString());
                
                if(Debug.DebugLevel >= Debug.Buffer)
                {
                    Debug.WriteLine(Debug.Buffer, "Packet to send:");
                    Debug.WriteLine(Debug.Buffer, packet, 0, packet.Length);
                }
             }

             try
             {
                 fOutput.Write(packet, 0, packet.Length);
                 fOutput.Flush();
             }
             catch(IOException e)
             {
                 DoHangup();
                 throw new CifsIoException("NB500").setDetail(e);
             }

             // read header
             try
             {
                 int count = Read(packet, 0, HDR_SIZE);

                 
                 if(Debug.DebugOn && Debug.DebugLevel >= Debug.Buffer)
                 {				 
                     Debug.WriteLine(Debug.Buffer, "Recieved packet:");
                     Debug.WriteLine(Debug.Buffer, packet, 0, packet.Length);
                 }
                 


                 if(count < HDR_SIZE)
                 {
                     DoHangup();
                     throw new CifsIoException("NB501");
                 }

                 byte type = packet[HDR_TYPE_1];

                 switch(type)
                 {
                     case SPT_POS_RESPONSE:
                    /*
                        POSITIVE SESSION RESPONSE PACKET

                                            1 1 1 1 1 1 1 1 1 1 2 2 2 2 2 2 2 2 2 2 3 3
                        0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
                        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
                        |      TYPE     |     FLAGS     |            LENGTH             |
                        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
                    */						 
                         break;

                     case SPT_NEG_RESPONSE:
                    /*
                        NEGATIVE SESSION RESPONSE PACKET

                                            1 1 1 1 1 1 1 1 1 1 2 2 2 2 2 2 2 2 2 2 3 3
                        0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
                        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
                        |      TYPE     |     FLAGS     |            LENGTH             |
                        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
                        |   ERROR_CODE  |
                        +-+-+-+-+-+-+-+-+
                     */
                         
                         int rc = fInput.ReadByte();
                         Debug.WriteLine(Debug.Error, "NetBIOS: Negative response: " + rc);

                         DoHangup();
                         throw CifsIoException.getNBException(rc & 0xff);				

                     case SPT_RTG_RESPONSE:
                    /*
                       SESSION RETARGET RESPONSE PACKET

                           1 1 1 1 1 1 1 1 1 1 2 2 2 2 2 2 2 2 2 2 3 3
                       0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
                       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
                       |      TYPE     |     FLAGS     |            LENGTH             |
                       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
                       |                      RETARGET_IP_ADDRESS                      |
                       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
                       |           PORT                |
                       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
                     */						 
                         count = Read(packet, 0, RT_SIZE);
                         DoHangup();
                         throw new CifsIoException("NB502");
                         
                     default:
                         DoHangup();
                         throw new CifsRuntimeException("NB503", (Int32)type  );
                        
                 }
             }
             catch(IOException e)
             {
                 DoHangup();
                 throw new CifsIoException("NB501").setDetail(e);
             }

         }
        }

        private int Read(byte[] buffer, int off, int len)
        {
            if (len <= 0)
             return 0;

            int count = 0;

            while(len > 0)
            {
                int result = fInput.Read(buffer, count, len);

                if (result <= 0)
                    throw new IOException();

                count += result;
                len   -= result;
            }

            return count;
        }

        internal bool IsAlive
        {
            get { return (fSocket != null); }
        }


        public void DoSend(INbtOutput data)
        {
            if(!IsAlive)
                throw new CifsIoException("NB504");

            int size = data.Size & 0xffff;

            // set packet header
            fSessionHeader[HDR_TYPE_1]  = SPT_MESSAGE;
            fSessionHeader[HDR_FLAGS_1] = 0;
            SetShortAt(HDR_LENGTH_2, fSessionHeader, (short)size);

            try
            {
                fOutput.Write(fSessionHeader, 0, fSessionHeader.Length);
                data.WriteTo(fOutput, size);
                fOutput.Flush();
            }
            catch(IOException e)
            {
                DoHangup(true);
                throw new CifsIoException("NB500").setDetail(e).setConnectionLost();
            }
        }

        public int DoRecieve(INbtInput data)
        {
            byte type;

            try
            {
                do
                {
                    int count = Read(fSessionHeader, 0, HDR_SIZE);

                    if(count < HDR_SIZE)
                    {
                        DoHangup(true);
                        throw new CifsIoException("NB501");
                    }

                    type = fSessionHeader[0];

                } while (type == SPT_KEEPALIVE); 

                if (type != SPT_MESSAGE)
                {
                    DoHangup(true);
                    throw new CifsIoException("NB503", type).setConnectionLost();
                }

                int data_size = GetShortAt(HDR_LENGTH_2, fSessionHeader);

                return data.ReadFrom(fInput, data_size);
            }
            catch(IOException e)
            {
                DoHangup(true);
                throw new CifsIoException("NB501").setDetail(e).setConnectionLost();
            }
        }


        private void DoConnect(IPAddress addr, int port)
        {
        
            try
            {			
                lock(this)
                {
                    if(IsAlive)
                        return;

                    fSocket = new TcpClient();
                    
                    fSocket.Connect(addr, port);
                    
                    fSocket.NoDelay = fTcpNoDelay;
                    fSocket.ReceiveTimeout = fTimeout;
                    fSocket.SendTimeout = fTimeout;

                    

                    fInput = fSocket.GetStream();
                    fOutput = fSocket.GetStream();
                } // lock
            }
            catch(SocketException)
            {
                throw new CifsIoException(Dns.GetHostByAddress(addr).ToString());
                //throw new CifsIOException(Dns.InetNtoa(addr));
            }
                    
        }
        
        /// <summary>
        /// Creates the session request packet
        /// </summary>
        /// <remarks>
        /// <pre>
        ///         SESSION REQUEST PACKET:
        ///
        ///                            1 1 1 1 1 1 1 1 1 1 2 2 2 2 2 2 2 2 2 2 3 3
        ///        0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
        ///        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        ///        |      TYPE     |     FLAGS     |            LENGTH             |
        ///        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        ///        |                                                               |
        ///        /                          CALLED NAME                          /
        ///        |                                                               |
        ///        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        ///        |                                                               |
        ///        /                          CALLING NAME                         /
        ///        |                                                               |
        ///        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        ///        </pre></remarks>
        /// <param name="callname"> </param>
        private byte[] MakeRequestPacket(string callname)
        {
            // build called and calling names
            byte[] calledname = NBTNameService.buildSecondLevelEncodedName(callname); // NetBIOS.SMBSERVER_NAME
            
            byte[] callingname = NBTNameService.buildSecondLevelEncodedName(fCallingName);
            
            int packetsize = HDR_SIZE + calledname.Length + callingname.Length;
            byte[] packet = new byte[packetsize];
            
            // set packet header
            packet[HDR_TYPE_1]  = SPT_REQUEST;
            packet[HDR_FLAGS_1] = 0;
            SetShortAt(HDR_LENGTH_2, packet, (short)(packetsize - HDR_SIZE));

            int pos = RQ_CALLED_NAME_32;

            for(int i = 0; i < calledname.Length; i++)
                packet[pos++] = calledname[i];

            for(int i = 0; i < callingname.Length; i++)
                packet[pos++] = callingname[i];

            return packet;

        }

        public void DoHangup()
        {
            DoHangup(false);
        }
        private void DoHangup(bool notify)
        {
            if (fSocket != null)
            {
                try
                {	
                    fInput.Close();  // This closes both the stream and the socket
                    fOutput.Close(); // We'ere closing this again -- this needs to be pruned
                    fSocket.Close(); // Closing the socket again					
                }
                catch(Exception)	// ignore it for now...
                {
                }

            }

            fSocket = null;
            fInput  = null;
            fOutput = null;

            if(notify)
                NotifyConnectionLost();
        }
        

    } // class NBTSession

} // namespace Cifs
