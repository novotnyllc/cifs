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

using System.Net;
using System.Net.Sockets;
using System.Text;

namespace Cifs
{
    using System;

    /// <summary>
    ///   Universal Naming Convention
    ///   <para>UNC: \\machine\share</para>
    ///   <para>URL: cifs://machine/share</para>
    /// </summary>
    internal sealed class Share
        // Should be internal, but Cifs.SessionImpl.fShare uses it, and SessionImpl is a public class
    {
        //private string		fName;	// not apparantly used in Java version...
        internal const int DISK = 0;
        internal const int IPC = 1;
        internal const int PRINTER = 2;

        private const string UNC_PREFIX = @"\\";
        private const string URL_PREFIX = "cifs://";
        private string fShareName;

        internal Share(CifsLogin login)
        {
            ShareType = DISK;
            Login = login;
        }

        internal Share(string name, int type)
        {
            SetName(name);
            ShareType = type;
            Login = new CifsLogin();
        }

        internal Share(string name, int type, CifsLogin login)
        {
            SetName(name);
            ShareType = type;
            Login = login;
        }

        public CifsLogin Login { get; private set; }

        public string NodeName { get; private set; }

        public string HostName { get; private set; }

        public string ShareName
        {
            get
            {
                var sb = new StringBuilder();

                sb.Append(@"\\");
                sb.Append(NodeName);
                sb.Append(@"\");
                sb.Append(fShareName);

                return sb.ToString();
            }
        }

        public string NbtName { get; private set; }
        internal int ShareType { get; private set; }

        internal void SetInfo(int type, string host, string sharename)
        {
            try
            {
                IPHostEntry he = Dns.Resolve(host); // this will throw a FormatException if the param is not an IP		
                IPAddress a = he.AddressList[0];
                HostName = he.HostName;
            }
            catch (FormatException)
            {
                HostName = host;
            }
            catch (SocketException) // We can't get the dns, so use the supplied one
            {
                HostName = host;
            }

            ShareType = type;
            //fHostName  = host;
            fShareName = sharename;
            SetNodeName();
        }

        private void SetName(string name)
        {
            name = name.Trim();

            if (name.StartsWith(UNC_PREFIX) && name.Length > 5)
                SetUncName(name);
            else if (name.StartsWith(URL_PREFIX) && name.Length > 8)
                SetUrlName(name);
            else
                throw new CifsShareNameException(name); // enhance later

            // set the node name
            SetNodeName();
        }

        private void SetNodeName()
        {
            int p = HostName.IndexOf('.');

            if (p < 0)
            {
                NodeName = HostName;
                NbtName = HostName; // If there are no dots, assume it's a netbios name
            }
            else // if it has dot's assume it's a dns name
            {
                NodeName = HostName.Substring(0, p);

                NbtName = NodeName; // assume the nodename is a dns one

                if (NbtName.Length > 15)
                    NbtName = NbtName.Substring(0, 15); // truncate down to 15 if needed

                // Pad upto 15 if needed, and add to 16
                //fNBTName.PadRight(16, (char)0x20);

                while (NbtName.Length < 16)
                {
                    byte pad = 0x20;

                    NbtName += (char) pad;
                }
            }
        }

        private void SetUrlName(string name)
        {
            int off = URL_PREFIX.Length;

            // cifs://server/share
            //        |      |
            //       off     p
            int p = name.IndexOf('/', off);

            if (p <= 0)
                throw new CifsShareNameException(name); // enhance later

            HostName = name.Substring(off, p);

            off = p + 1;

            if (off >= name.Length)
                throw new CifsShareNameException(name); // enhance later

            fShareName = name.Substring(off);
        }

        private void SetUncName(string name)
        {
            int off = URL_PREFIX.Length;

            int p = name.IndexOf(@"\", off);
            if (p < 0)
                throw new CifsShareNameException(name); // enhance later

            // \\Server\Share
            //          |
            //  off     p

            HostName = name.Substring(off, p);

            off = p + 1;

            if (off >= name.Length)
                throw new CifsShareNameException(name); // enhance later

            fShareName = name.Substring(off);
        }

        public override string ToString()
        {
            return ShareName;
        }
    }

    // class Share

    public struct NbInfo
    {
        public string Name;
        public string Workgroup;
    }
}

// namespace Cifs