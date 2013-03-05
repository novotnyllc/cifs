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

    /// <summary>
    ///    Summary description for CifsServerInfo.
    /// </summary>
    public sealed class CifsServerInfo
    {
    
        /// <summary>
        /// Enum all server types
        /// </summary>
        public const uint SV_TYPE_ALL     	    = 0xFFFFFFFF;
        /// <summary>
        ///  Enum all workstations
        /// </summary>
        public const uint SV_TYPE_WORKSTATION	    = 0x00000001;
        /// <summary>
        /// Enum servers
        /// </summary>
        public const uint SV_TYPE_SERVER	        = 0x00000002;
        /// <summary>
        /// Enum any server running with SQL server
        /// </summary>
        public const uint SV_TYPE_SQLSERVER	    = 0x00000004;
        /// <summary>
        /// Primary domain controller
        /// </summary>
        public const uint SV_TYPE_DOMAIN_CTRL	    = 0x00000008;
        /// <summary>
        /// Backup domain controller
        /// </summary>
        public const uint SV_TYPE_DOMAIN_BAKCTRL	= 0x00000010;
        /** Server running the timesource service */
        public const uint SV_TYPE_TIME_SOURCE	    = 0x00000020;
        /// <summary>
        /// Apple File Protocol servers
        /// </summary>
        public const uint SV_TYPE_AFP	            = 0x00000040;
        /// <summary>
        /// Novell servers
        /// </summary>
        public const uint SV_TYPE_NOVELL	        = 0x00000080;
        /// <summary>
        /// Domain Member
        /// </summary>
        public const uint SV_TYPE_DOMAIN_MEMBER	= 0x00000100;
        /// <summary>
        /// Server sharing print queue 
        /// </summary>
        public const uint SV_TYPE_PRINTQ_SERVER	= 0x00000200;
        /// <summary>
        /// Server running dialin service.
        /// </summary>
        public const uint SV_TYPE_DIALIN_SERVER	= 0x00000400;
        /// <summary>
        /// Xenix server 
        /// </summary>
        public const uint SV_TYPE_XENIX_SERVER	= 0x00000800;
        /// <summary>
        /// NT server
        /// </summary>
        public const uint SV_TYPE_NT	            = 0x00001000;
        /// <summary>
        /// Server running Windows for Workgroups 
        /// </summary>
        public const uint SV_TYPE_WFW	            = 0x00002000;
        /// <summary>
        /// Windows NT non DC server
        /// </summary>
        public const uint SV_TYPE_SERVER_NT	    =  0x00008000;
        /// <summary>
        /// Server that can run the browser service
        /// </summary>
        public const uint SV_TYPE_POTENTIAL_BROWSER=  0x00010000;
        /// <summary>
        /// Backup browser server
        /// </summary>
        public const uint SV_TYPE_BACKUP_BROWSER	=  0x00020000;
        /// <summary>
        /// Master browser server
        /// </summary>
        public const uint SV_TYPE_MASTER_BROWSER	=  0x00040000;
        /// <summary>
        /// EDomain Master Browser server
        /// </summary>
        public const uint SV_TYPE_DOMAIN_MASTER	=  0x00080000;
        /// <summary>
        /// Enumerate only entries marked "local"
        /// </summary>
        public const uint SV_TYPE_LOCAL_LIST_ONLY = 0x40000000;
        /// <summary>
        /// Enumerate Domains
        /// </summary>
        public const uint SV_TYPE_DOMAIN_ENUM	    = 0x80000000;


      

        /// <summary>
        /// The name of the computer
        /// </summary>
        public string ComputerName { get; internal set; }

        /// <summary>
        /// If the getType() indicates that the entry is for a domain,
        /// this specifies the name of the domain master browser;
        /// otherwise, it specifies a comment describing the server.
        /// The comment can be a null string
        /// </summary>
        public string Comment { get; internal set; }

        /// <summary>
        /// The type of software the computer is running (see SW_*)
        /// </summary>
        public uint ServerType { get; internal set; }

        /// <summary>
        /// The major version number of the networking
        /// software the workstation is running.
        /// </summary>
        public int MajorVersion { get; internal set; }

        /// <summary>
        /// The minor version number of the networking
        /// sofware the workstation is running.
        /// </summary>
        public int MinorVersion { get; internal set; }
    } // class CifsServerInfo
} // namespace Cifs
