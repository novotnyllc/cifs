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

/*

 The ***parameters section** of the Transact SMB request contains thefollowing
 (in the order described)
 - The function number: an unsigned short 16 bit integer identifying the
   function being remoted
 - The parameter descriptor string: a null terminated ASCII string
 - The data descriptor string: a null terminated ASCII string.
 - The request parameters, as described by the parameter descriptor  string,
   in the order that the request parameter descriptor characters  appear in
   the parameter descriptor string
 - An optional auxiliary data descriptor string:  a null terminated ASCII  string.
   It will be present if there is an auxiliary data structure  count in the primary
   data struct (an "N" descriptor in the data  descriptor string).RAP requires
   that the length of the return parameters be less than orequal to the length
   of the parameters being sent; this requirement ismade to simply buffer management
   in implementations. This is reasonableas the functions were designed to return
   data in the data section anduse the return parameters for items like data length,
   handles, etc. Ifneed be, this restriction can be circumvented by filling in
   some padbytes into the parameters being sent.

   The Data section for the transaction request is present if the parameter description
   string contains an "s" (SENDBUF) descriptor. If present, itcontains:
 - A primary data struct, as described by the data descriptor string

 - Zero or more instances of the auxiliary data struct, as described by
   the auxiliary data descriptor string. The number of instances is  determined
   by the value of the an auxiliary data structure count  member of the primary
   data struct, indicated by the "N" (AUXCOUNT)  descriptor. The auxiliary data
   is present only if the auxiliary data  descriptor string is non null.

 - Possibly some pad bytes
 - The heap: the data referenced by pointers in the primary and  auxiliary data structs.


 */
using System.Collections.Generic;
using Cifs.Util;

namespace Cifs
{
    using System;

    /// <summary>
    ///   The Remote Administration Protocol (RAP) provides operations
    ///   <para>- to get list of share names;</para>
    ///   <para>- to get user information;</para>
    ///   <para>- to get workstation information;</para>
    ///   <para>- to get information about print jobs; - not implemented yet</para>
    ///   <para>- to manage print jobs. - not implemented yet</para>
    /// </summary>
    internal sealed class CifsRemoteAdmin : CifsSession, ICifsRemoteAdmin
    {
        private const short NetShareEnum = 0;
        private const short NetShareEnum2 = 104;
        private const short NetGetServerInfo = 13;
        private const short NetWkstaGetInfo = 63;
        private const short SamOEMChangePassword = 214;
        private const short NetUserGetInfo = 56;

        // The Print constants have been ommited in this version

        private const short NetUserPasswordSet = 115;


        private int fReturnBufferSize = 3000;

        private ShareInfoComparator fShareInfoComparator;


        internal CifsRemoteAdmin(string sessionname, int prot, Share share, NbtSession nbt, SmbMessage packet)
            : base(sessionname, prot, share, nbt, packet)
        {
        }

        #region ICifsRemoteAdmin Members

        /// <summary>
        ///   Returns the list of shares on the computer
        /// </summary>
        /// <param name = "sort">if true, the names are sorted</param>
        /// <returns>list of <code>CifsShareInfo</code> objects</returns>
        public CifsShareInfo[] ListSharesInfo(bool sort)
        {
            lock (this)
            {
                if (Debug.DebugOn)
                    Debug.WriteLine(Debug.Info, "IPC:NetShareEnum");

                var param = new MarshalBuffer(100);

                int pos = 0;
                pos += param.SetShortAt(pos, NetShareEnum);
                // parameter descriptor string
                pos += param.SetZtAsciiStringAt(pos, "WrLeh");

                // The data descriptor string for the (returned) data which is "B13BWz"
                pos += param.SetZtAsciiStringAt(pos, "B13BWz");

                // corresponding to the "W"
                pos += param.SetShortAt(pos, 1);

                // buffer size
                pos += param.SetShortAt(pos, fReturnBufferSize);

                param.Size = pos;

                SendTransaction(null, "\\PIPE\\LANMAN", param, null, 0);

                var data = new MarshalBuffer(1000);

                receiveTransaction(param, data);

                pos = 0;

                int error = param.GetShortAt(pos);

                // ignore more data
                if (error != 0 && error != 234)
                    throw CifsIoException.getLMException(error);

                pos += 2;

                // converter
                int converter = param.GetShortAt(pos);
                pos += 2;

                // number of entries
                int counter = param.GetShortAt(pos);
                pos += 2;

                // number max of entries
                int maxcounter = param.GetShortAt(pos);


                /*
                   The SHARE_INFO_1 structure is defined as:

                   struct SHARE_INFO_1 {
                       char                shi1_netname[13]
                       char                shi1_pad;
                       unsigned short  shi1_type
                       char            *shi1_remark;
                   }

                   where:

                   shi1_netname contains a null terminated ASCII string that
                               specifies the share name of the resource.

                   shi1_pad aligns the next data strructure element to a word
                           boundary.

                   shi1_type contains an integer that specifies the type of the
                           shared resource.


                   shi1_remark points to a null terminated ASCII string that contains
                       a comment abthe shared resource. The value for shi1_remark is null
                       for ADMIN$ and IPC$ share names.  The shi1_remark pointer is a 32
                       bit pointer. The higher 16 bits need to be ignored. The converter
                       word returned in the parameters section needs to be subtracted
                       from the lower 16 bits to calculate an offset into the return
                       buffer where this ASCII string resides.

                       In case there are multiple SHARE_INFO_1 data structures to return,
                       the server may put all these fixed length structures in the return
                       buffer, leave some space and then put all the variable length data
                       (the actual value of the shi1_remark strings) at the end of the
                   buffer.
                */

                if (Debug.DebugOn)
                    data.debug("NetShareEnum data");

                var result = new CifsShareInfo[counter];
                CifsShareInfo info;
                pos = 0;

                for (int i = 0; i < counter; i++)
                {
                    info = new CifsShareInfo(fShare.HostName);

                    // shil_netname[13]
                    info.ShareName = data.GetZtAsciiStringAt(pos, 13);
                    pos += 13;

                    pos += 1; // pad

                    // shil_type
                    info.ShareType = data.GetShortAt(pos);

                    pos += 2;

                    // shil_remark
                    int rptr = (data.GetIntAt(pos) & 0xffff);
                    pos += 4;

                    info.Remark = data.GetZtAsciiStringAt(rptr - converter, 255);

                    result[i] = info;
                }

                if (sort)
                    Util.Util.Sort(result, GetShareInfoComparator());

                return result;
            } // lock
        }

        /// <summary>
        ///   Returns detailed information about a workstation
        /// </summary>
        public CifsWorkstationInfo WorkstationInfo
        {
            get
            {
                if (Debug.DebugOn)
                    Debug.WriteLine(Debug.Info, "IPC:NetWkstaGetInfo");

                var param = new MarshalBuffer(100);

                int pos = 0;
                pos += param.SetShortAt(pos, NetWkstaGetInfo);
                // parameter descriptor string
                pos += param.SetZtAsciiStringAt(pos, "WrLh");

                // The data descriptor string for the (returned) data which is "zzzBBzz"
                pos += param.SetZtAsciiStringAt(pos, "zzzBBzz");

                // corresponding to "W"
                pos += param.SetShortAt(pos, 10);

                param.Size = pos;

                SendTransaction(null, "\\PIPE\\LANMAN", param, null, 0);

                var data = new MarshalBuffer(1000);

                param.Zero(param.Size);

                receiveTransaction(param, data);

                pos = 0;

                int error = param.GetShortAt(pos);

                // ignore more data
                if (error != 0 && error != 234)
                    throw CifsIoException.getLMException(error);

                pos += 2;

                // converter
                int converter = param.GetShortAt(pos);

                pos += 2;

                /* A 16 bit number representing the total number of available bytes.
               This has meaning only if the return status is NERR_Success or
               ERROR_MORE_DATA. Upon success, this number indicates the number of
               useful bytes available. Upon failure, this indicates how big the
               receive buffer needs to be.
            */
                int bytes = param.GetShortAt(pos);

                pos += 2;

                /*
             struct user_info_11 {
             char                *wki10_computername;
             char                *wki10_username;
             char                *wki10_langroup;
             unsigned char   wki10_ver_major;
             unsigned char       wki10_ver_minor;
             char                *wki10_logon_domain;
             char            *wki10_oth_domains;
             };
            */

                var info = new CifsWorkstationInfo();

                if (Debug.DebugOn)
                    data.debug("NetWkstaGetInfo data");

                pos = 0;

                int ptr = data.GetIntAt(pos) & 0xffff;

                if (Debug.DebugOn)
                    Debug.WriteLine(Debug.Buffer, "bytes=" + bytes + " pos=" + pos + ", ptr=" + (ptr - converter));

                pos += 4;
                info.WorkstationName = data.GetZtAsciiStringAt(ptr - converter, bytes);

                // User name
                ptr = data.GetIntAt(pos) & 0xffff;
                pos += 4;
                info.UserName = data.GetZtAsciiStringAt(ptr - converter, bytes);

                // Domain to which the workstation belongs
                ptr = data.GetIntAt(pos) & 0xffff;
                pos += 4;
                info.Domain = data.GetZtAsciiStringAt(ptr - converter, bytes);

                // Major version number of the networking software
                info.MajorVersion = data.GetByteAt(pos) & 0xff;
                pos++;

                // Minor version number of the networking software
                info.MinorVersion = data.GetByteAt(pos) & 0xff;
                pos++;

                // The domain in which the user is logged on
                ptr = data.GetIntAt(pos) & 0xffff;
                pos += 4;
                info.LogonDomain = data.GetZtAsciiStringAt(ptr - converter, bytes);

                // All domains in which the computer is enlisted
                ptr = data.GetIntAt(pos) & 0xffff;
                pos += 4;
                info.AllDomains = data.GetZtAsciiStringAt(ptr - converter, bytes);

                return info;
            }
        }

        /// <summary>
        ///   Returns detailed information about a particular user
        /// </summary>
        /// <param name = "user">User Name</param>
        /// <returns>user information</returns>
        public CifsUserInfo GetUserInfo(string user)
        {
            if (Debug.DebugOn)
                Debug.WriteLine(Debug.Info, "IPC:NetUserGetInfo");

            var param = new MarshalBuffer(100);
            int pos = 0;
            pos += param.SetShortAt(pos, NetUserGetInfo);
            // parameter descriptor string
            pos += param.SetZtAsciiStringAt(pos, "zWrLh");

            // he data descriptor string for the (returned) data which is "B21BzzzWDDzzDDWWzWzDWb21W"
            pos += param.SetZtAsciiStringAt(pos, "B21BzzzWDDzzDDWWzWzDWb21W");

            // user
            pos += param.SetZtAsciiStringAt(pos, user);

            // corresponding to the "W"
            pos += param.SetShortAt(pos, 11);

            // buffer size
            pos += param.SetShortAt(pos, fReturnBufferSize);

            param.Size = pos;

            SendTransaction(null, "\\PIPE\\LANMAN", param, null, 0);

            var data = new MarshalBuffer(1000);

            receiveTransaction(param, data);

            pos = 0;

            int error = param.GetShortAt(pos);

            // ignore more data
            if (error != 0 && error != 234)
                throw CifsIoException.getLMException(error);

            pos += 2;

            // converter
            int converter = param.GetShortAt(pos);
            pos += 2;

            /* A 16 bit number representing the total number of available bytes.
                This has meaning only if the return status is NERR_Success or
                ERROR_MORE_DATA. Upon success, this number indicates the number of
                useful bytes available. Upon failure, this indicates how big the
                receive buffer needs to be.
             */
            int bytes = param.GetShortAt(pos);

            pos += 2;


            /*
             struct user_info_11 {
            char                usri11_name[21];
            char                usri11_pad;
            char                *usri11_comment;
            char            *usri11_usr_comment;
            char                *usri11_full_name;
            unsigned short      usri11_priv;
            unsigned long       usri11_auth_flags;
            long                usri11_password_age;
            char                *usri11_homedir;
            char            *usri11_parms;
            long                usri11_last_logon;
            long                usri11_last_logoff;
            unsigned short      usri11_bad_pw_count;
            unsigned short      usri11_num_logons;
            char                *usri11_logon_server;
            unsigned short      usri11_country_code;
            char            *usri11_workstations;
            unsigned long       usri11_max_storage;
            unsigned short      usri11_units_per_week;
            unsigned char       *usri11_logon_hours;
            unsigned short      usri11_code_page;

            };
            */

            if (Debug.DebugOn)
                data.debug("NetUserGetInfo data");

            var info = new CifsUserInfo();

            pos = 0;

            // user name for which information is retireved

            info.UserName = data.GetZtAsciiStringAt(pos, 21);
            pos += 21;

            // pad
            pos++;

            //comment
            int ptr = data.GetIntAt(pos) & 0xffff;
            pos += 4;
            info.Comment = data.GetZtAsciiStringAt(ptr - converter, bytes);
            // comment about user
            ptr = data.GetIntAt(pos) & 0xffff;
            pos += 4;
            info.UserComment = data.GetZtAsciiStringAt(ptr - converter, bytes);

            // full name  of the user
            ptr = data.GetIntAt(pos) & 0xffff;
            pos += 4;
            info.FullUserName = data.GetZtAsciiStringAt(ptr - converter, bytes);

            // level of the privilege assigned to the user
            info.UserPrivilege = data.GetShortAt(pos);
            pos += 2;

            // account operator privileges.
            info.OperatorPrivileges = data.GetIntAt(pos);
            pos += 4;

            // how many seconds have elapsed since the password was last changed.
            info.PasswordAge = data.GetIntAt(pos) & 0xffffffff;
            pos += 4;

            // path name of the user's home directory.
            ptr = data.GetIntAt(pos) & 0xffff;
            pos += 4;
            info.HomeDir = data.GetZtAsciiStringAt(ptr - converter, bytes);

            // skip usri11_parms
            pos += 4;

            // last logon
            info.fLastLogon = data.GetIntAt(pos) & 0xffffffff;
            pos += 4;

            // last logon
            info.fLastLogoff = data.GetIntAt(pos) & 0xffffffff;
            pos += 4;

            // bad logons
            info.BadLogons = data.GetShortAt(pos);
            pos += 2;

            // num logons
            info.Logons = data.GetShortAt(pos);
            pos += 2;

            // logon server
            ptr = data.GetIntAt(pos) & 0xffff;
            pos += 4;
            info.LogonServer = data.GetZtAsciiStringAt(ptr - converter, bytes);

            return info;
        }

        // Several functions relating to printing have been ommited for now


        ///<summary>
        ///  Lists all computers of the specified type or types that are visible
        ///  in the specified domain.  It may also enumerate domains.
        ///</summary>
        ///<param name = "domain">The name of the workgroup in which to enumerate computers
        ///  of the specified type or types.  If domain is nul, servers
        ///  are enumerated for the current domain of the computer</param>
        ///<param name = "types">The type or types of computer to enumerate.  Computers that
        ///  match at least one of the specified types are returned (SV_*)</param>
        public CifsServerInfo[] ListServersInfo(string domain, uint types)
        {
            if (Debug.DebugOn)
                Debug.WriteLine(Debug.Info, "listServersInfo");

            var param = new MarshalBuffer(100);
            var data = new MarshalBuffer(1000);

            DoNetServerEnum2(domain, types, 1, param, data);

            int pos = 0;

            pos += 2;

            // converter
            int converter = param.GetShortAt(pos);
            pos += 2;

            // number of entries
            int counter = param.GetShortAt(pos);
            pos += 2;

            int maxcounter = param.GetShortAt(pos);
            pos += 2;


            if (maxcounter > counter)
                if (Debug.DebugOn)
                    Debug.WriteLine(Debug.Warning, "The buffer for NetServerEnum2 was too small.");

            /*
            struct SERVER_INFO_1 {
                char			sv1_name[16];
                char			sv1_version_major;
                char			sv1_version_minor;
                unsigned long	sv1_type;
                char  		*sv1_comment_or_master_browser;
            };
            */

            var infolist = new CifsServerInfo[counter];

            pos = 0;
            for (int i = 0; i < counter; i++)
            {
                var info = new CifsServerInfo();

                info.ComputerName = data.GetZtAsciiStringAt(pos, 16);
                pos += 16;

                info.MajorVersion = data.GetByteAt(pos) & 0xff;
                pos += 1;

                info.MinorVersion = data.GetByteAt(pos) & 0xff;
                pos += 1;

                info.ServerType = (UInt32) (data.GetIntAt(pos));
                pos += 4;

                int rptr = (data.GetIntAt(pos) & 0xffff);
                pos += 4;

                if (rptr != 0)
                    info.Comment = data.GetZtAsciiStringAt(rptr - converter, 255);

                infolist[i] = info;
            }

            return infolist;
        }

        ///<summary>
        ///  Lists all computers of the specified type or types that are visible
        ///  in the specified domain.  It may also enumerate domains.
        ///</summary>
        ///<param name = "domain">The name of the workgroup in which to enumerate computers
        ///  of the specified type or types.  If domain is null, servers
        ///  are enumerated for the current domain of the computer</param>
        ///<param name = "types">The type or types o fcoimputer to enumerate.  Computers that match
        ///  at least one of the specified types are returned (SV_*)</param>
        ///<returns><code>System.String</code> (sorted)</returns>
        public string[] ListServersNames(string domain, uint types)
        {
            lock (this)
            {
                if (Debug.DebugOn)
                    Debug.WriteLine(Debug.Info, "listServersNames");

                var param = new MarshalBuffer(100);
                var data = new MarshalBuffer(1000);

                // Level 0
                DoNetServerEnum2(domain, types, 0, param, data);

                int pos = 0;

                pos += 2;

                // converter
                int converter = param.GetShortAt(pos);
                pos += 2;

                // number of entries
                int counter = param.GetShortAt(pos);
                pos += 2;

                int maxcounter = param.GetShortAt(pos);
                pos += 2;

                if (maxcounter > counter)
                    if (Debug.DebugOn)
                        Debug.WriteLine(Debug.Warning, "The buffer for NetServerEnum2 was too small.");

                /*
                struct SERVER_INFO_0 {
                    char		sv0_name[16];
                };
                */

                var names = new string[counter];

                for (int i = 0; i < counter; i++)
                    names[i] = data.GetZtAsciiStringAt(pos, i*16);

                Util.Util.SortStrings(names);

                return names;
            } // lock
        }

        /// <summary>
        ///   Returns information about the current server
        /// </summary>
        /// <value>Server information</value>
        public CifsServerInfo ServerInfo
        {
            get
            {
                lock (this)
                {
                    if (Debug.DebugOn)
                        Debug.WriteLine(Debug.Info, "getServerInfo");

                    var param = new MarshalBuffer(100);
                    var data = new MarshalBuffer(1000);


                    int pos = 0;
                    pos += param.SetShortAt(pos, NetGetServerInfo);
                    // parameter descriptor string
                    pos += param.SetZtAsciiStringAt(pos, "WrLh");

                    // data descriptor
                    pos += param.SetZtAsciiStringAt(pos, "B16BBDz");


                    // corresponding to the "W": Level 1
                    pos += param.SetShortAt(pos, 1);

                    // buffer size
                    pos += param.SetShortAt(pos, fReturnBufferSize);

                    param.Size = pos;


                    SendTransaction(null, "\\PIPE\\LANMAN", param, null, 0);
                    receiveTransaction(param, data);

                    pos = 0;
                    int error = param.GetShortAt(pos);

                    // ignore more data
                    if (error != 0 && error != 234)
                        throw CifsIoException.getLMException(error);

                    pos += 2;

                    // converter
                    int converter = param.GetShortAt(pos);
                    pos += 2;

                    // number of entries
                    int counter = param.GetShortAt(pos);
                    pos += 2;

                    int bytes = param.GetShortAt(pos);
                    pos += 2;


                    /*
                struct SERVER_INFO_1 {
                    char			sv1_name[16];
                    char			sv1_version_major;
                    char			sv1_version_minor;
                    unsigned long	sv1_type;
                    char  		*sv1_comment_or_master_browser;
                };
                */

                    var info = new CifsServerInfo();

                    pos = 0;

                    info.ComputerName = data.GetZtAsciiStringAt(pos, 16);
                    pos += 16;

                    info.MajorVersion = data.GetByteAt(pos) & 0xff;
                    pos += 1;

                    info.MinorVersion = data.GetByteAt(pos) & 0xff;
                    pos += 1;

                    info.ServerType = (UInt32) (data.GetIntAt(pos));
                    pos += 4;

                    int rptr = (data.GetIntAt(pos) & 0xffff);
                    pos += 4;

                    if (rptr != 0)
                        info.Comment = data.GetZtAsciiStringAt(rptr - converter, 255);

                    return info;
                } // lock
            }
        }

        #endregion

        private void DoNetServerEnum2(string domain, uint types, int level,
                                      MarshalBuffer param, MarshalBuffer data)
        {
            int pos = 0;
            pos += param.SetShortAt(pos, NetShareEnum2);
            // parameter descriptor string
            pos += param.SetZtAsciiStringAt(pos, "WrLehDz");

            // the data descriptor string for the (returned) data
            switch (level)
            {
                case 0:
                    pos += param.SetZtAsciiStringAt(pos, "B16");
                    break;
                case 1:
                    pos += param.SetZtAsciiStringAt(pos, "B16BBDz");
                    break;
                default:
                    Debug.WriteLine(Debug.Error, "Invalid NetServerEnum2 level");
                    throw new ApplicationException("doNetServerEnum2");
            }


            // corresponding to the "W": Level 1
            pos += param.SetShortAt(pos, level);

            // buffer size
            pos += param.SetShortAt(pos, fReturnBufferSize);

            if (domain == null)
                types |= CifsServerInfo.SV_TYPE_DOMAIN_ENUM;

            // select types
            pos += param.SetIntAt(pos, (Int32) types);


            // domain
            if (domain != null)
                pos += param.SetZtAsciiStringAt(pos, domain);
            else
                pos += param.SetByteAt(pos, 0);

            param.Size = pos;


            SendTransaction(null, "\\PIPE\\LANMAN", param, null, 0);
            receiveTransaction(param, data);


            int error = param.GetShortAt(0);

            // ignore more data
            if (error != 0 && error != 234)
                throw CifsIoException.getLMException(error);
        }

        /// <summary>
        ///   Changes password on the server
        /// </summary>
        /// <param name = "user">user name</param>
        /// <param name = "oldpwd">old password</param>
        /// <param name = "newpwd">new password</param>
        public void ChangePassword(string user, string oldpwd, string newpwd)
        {
            lock (this)
            {
                if (Debug.DebugOn)
                    Debug.WriteLine(Debug.Info, "SamOEMChangePassword");

                var param = new MarshalBuffer(100);

                int pos = 0;
                pos += param.SetShortAt(pos, SamOEMChangePassword);
                // parameter descriptor string
                pos += param.SetZtAsciiStringAt(pos, "zsT");

                // the data descriptor string for the (returned) data which = null string
                pos += param.SetZtAsciiStringAt(pos, "B516B16");

                // user
                pos += param.SetZtAsciiStringAt(pos, user);

                // data size
                pos += param.SetShortAt(pos, 532);

                param.Size = pos;

                byte[] data = CifsLogin.GetChangePasswordData(oldpwd, newpwd);


                SendTransaction(null, "\\PIPE\\LANMAN", param, data, data.Length);

                var rdata = new MarshalBuffer(100);

                receiveTransaction(param, rdata);

                pos = 0;

                int error = param.GetShortAt(pos);

                // ignore more data
                if (error != 0 && error != 234)
                    throw CifsIoException.getLMException(error);
            } // lock
        }


        public override string ToString()
        {
            return "Session:" + fSessionName + ", Type=Admin, Host=" + fShare.HostName;
        }

        internal override int GetSortPosition() // should also be protected
        {
            return 2;
        }

        private ShareInfoComparator GetShareInfoComparator()
        {
            if (fShareInfoComparator == null)
                fShareInfoComparator = new ShareInfoComparator();

            return fShareInfoComparator;
        }
    }

    // class RemoteAdminImpl

    internal class ShareInfoComparator : IComparer<CifsShareInfo>
    {
        #region IComparer<CifsShareInfo> Members

        public int Compare(CifsShareInfo o1, CifsShareInfo o2)
        {
            return String.Compare(o1.ShareName, o2.ShareName);
        }

        #endregion
    }

    // class ShareInfoComparator
}

// namespace Cifs