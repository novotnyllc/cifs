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
    using System.Text;

    /// <summary>
    ///    Summary description for CifsShareInfo.
    /// </summary>
    public class CifsShareInfo
    {
        
        // Share types

        /// <summary>
        /// Disk Directory Tree
        /// </summary>
        public const short STYPE_DISKTREE = 0;

        /// <summary>
        /// Printer Queue
        /// </summary>
        public const short STYPE_PRINTQ   = 1;

        /// <summary>
        /// Communications device
        /// </summary>
        public const short STYPE_DEVICE   = 2;

        /// <summary>
        /// Inter-process communication (IPC)
        /// </summary>
        public const short STYPE_IPC      = 3;

        internal string fHostName  = null;


        internal CifsShareInfo(string host)
        {
            ShareType = 0;
            Remark = null;
            ShareName = null;
            fHostName = host;
        }

        public string ShareName { get; internal set; }

        public string Remark { get; internal set; }

        public int ShareType { get; internal set; }

        public string Unc
        {
            get { return @"\\" + fHostName + @"\" + ShareName; }
        }

        public override string ToString()
        {
            StringBuilder buf = new StringBuilder();
            buf.Append(ShareName);
            for(int i=ShareName.Length; i<15; i++)
                buf.Append(' ');
            
            switch(ShareType)
            {
                case STYPE_DISKTREE:
                    buf.Append("DISK   ");
                    break;
                case STYPE_PRINTQ:
                    buf.Append("PRINT  ");
                    break;
                case STYPE_DEVICE:
                    buf.Append("DEVICE ");
                    break;
                case STYPE_IPC:
                    buf.Append("IPC    ");
                    break;
                default:
                    buf.Append("?????? ");
                    break;
            }
            buf.Append(Remark);
            return buf.ToString();
        }
    
    } // class CifsShareInfo
} // namespace Cifs
