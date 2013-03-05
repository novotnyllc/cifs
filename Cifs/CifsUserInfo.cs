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
    ///    Summary description for CifsUserInfo.
    /// </summary>
    public sealed class CifsUserInfo
    {
        /// <summary>
        /// User is a guest
        /// </summary>
        public const int USER_PRIV_GUEST  = 0;

        /// <summary>
        /// User group
        /// </summary>
        public const int USER_PRIV_USER   = 1;

        /// <summary>
        /// User has Administrator group
        /// </summary>
        public const int USER_PRIV_ADMIN  = 2;
        
        /// <summary>
        /// Print operator group
        /// </summary>
        public const int AF_OP_PRINT	  = 0;

        /// <summary>
        /// Communications operator group
        /// </summary>
        public const int AF_OP_COMM		  = 1;
    
        /// <summary>
        /// Accounts operator group
        /// </summary>
        public const int AF_OP_ACCOUNTS	  = 3;

        internal long      fLastLogon = 0;		// Last Logon time in Ticks
        internal long      fLastLogoff = 0;

        // Protected Constructer; internal use only
        internal CifsUserInfo()
        {
            CountryCode = 0;
            LogonServer = null;
            Logons = 0;
            BadLogons = 0;
            HomeDir = null;
            PasswordAge = 0;
            OperatorPrivileges = 0;
            UserPrivilege = 0;
            FullUserName = null;
            UserComment = null;
            Comment = null;
            UserName = null;
        }

        /// <summary>
        /// Gets the user name for which information is retrieved
        /// </summary>
        /// <value>user name</value>
        public string UserName { get; internal set; }

        /// <summary>
        /// Gets comment
        /// </summary>
        /// <value>comment</value>
        public string Comment { get; internal set; }

        /// <summary>
        /// Gets comment about the user
        /// </summary>
        /// <value>full user name</value>
        public string UserComment { get; internal set; }

        /// <summary>
        /// Gets the full name of the user
        /// </summary>
        /// <value>full user name</value>
        public string FullUserName { get; internal set; }

        /// <summary>
        /// Gets the level of the privilege assigned to the user
        /// </summary>
        /// <value>Privilege (see USER_*)</value>
        public int UserPrivilege { get; internal set; }

        /// <summary>
        /// Gets the account operator privileges
        /// </summary>
        /// <value>privilege (see AF_OP_*)</value>
        public int OperatorPrivileges { get; internal set; }

        /// <summary>
        /// Gets how many seconds have elapsed since the password was last changed
        /// </summary>
        /// <value>number of seconds</value>
        public long PasswordAge { get; internal set; }

        /// <summary>
        /// Gets the path name of the user's home directory
        /// </summary>
        /// <value>home directory</value>
        public string HomeDir { get; internal set; }

        /// <summary>
        /// Gets the time when the user last logged on
        /// </summary>
        /// <value>date or DateTime.MinValue if last logon is unknown.</value>
        public DateTime LastLogon
        {
            get
            {
                if (fLastLogon == 0)
                    return DateTime.MinValue;
                return new DateTime(fLastLogon);
            }
        }

        /// <summary>
        /// Gets the time when the user last logged off
        /// </summary>
        /// <value>date or DateTime.MinValue if last logon is unknown.</value>
        public DateTime LastLogoff
        {
            get
            {
                if (fLastLogoff == 0)
                    return DateTime.MinValue;

                return new DateTime(fLastLogoff);
            }
        }

        /// <summary>
        /// Gets the number of incorrect passwords since the last successful logon.
        /// </summary>
        /// <value>bad logon counter.</value>
        public int BadLogons { get; internal set; }

        /// <summary>
        /// Gets the number of times this user has logged on.
        /// </summary>
        /// <value>A value of -1 means the number is unknown</value>
        public int Logons { get; internal set; }

        /// <summary>
        /// Gets the name of the server to which logon requests are sent.
        /// A null string indicates logon requests should be sent to the
        /// domain controller.
        /// </summary>
        /// <value>server name</value>
        public string LogonServer { get; internal set; }

        /// <summary>
        /// Gets the country code for the user's language of choice
        /// </summary>
        /// <value>country code</value>
        public int CountryCode { get; internal set; }
    } // class CifsUserInfo
} // namespace Cifs
