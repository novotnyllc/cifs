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
using System.Collections.Generic;
using System.IO;
using Cifs.Util;

namespace Cifs
{
    using System;


    /// <summary>
    ///   This abtract class implements the factory methods for CIFS services
    ///   (Disk, Printer, RemoteAdmin).  -- At the moment, only RemoteAdmin is supported
    /// </summary>
    public abstract class CifsSessionManager
    {
        private const string VERSION = "1.0";
        private const string COPYRIGHT = "(c) 2001, Oren Novotny, GNU Library Public License";

        // Sort sessions by name
        public const int SESSION_SORT_NAME = 0;

        // Sort sessions by type
        public const int SESSION_SORT_TYPE = 1;

        /** Debug none */
        public const int DEBUG_NONE = Debug.None;
        /** Debug errors */
        public const int DEBUG_ERROR = Debug.Error;
        /** Debug errors, warnings */
        public const int DEBUG_WARNING = Debug.Warning;
        /** Debug errors, warnings, infos */
        public const int DEBUG_INFO = Debug.Info;
        /** Debug errors, warnings, infos, buffers */
        public const int DEBUG_BUFFER = Debug.Buffer;


        private static readonly CifsLogin fDefaultLogin = new CifsLogin();

        // Counter for session name generation
        private static int fSessionSeqNumber;


        private CifsSessionManager()
        {
        }

        /// <summary>
        ///   Returns the version number of the CIFS assembly
        /// </summary>
        /// <value>Version number</value>
        public static string AssemblyVersion
        {
            get { return VERSION; }
        }

        /// <summary>
        ///   Returns the copyright text
        /// </summary>
        /// <value>Copyright text</value>
        public static string PackageCopyright
        {
            get { return COPYRIGHT; }
        }

        /// <summary>
        ///   Sets the debug level
        /// </summary>
        /// <param name = "level">debug level (DEBUG_*)</param>
        public static void SetDebugLevel(int level)
        {
            Debug.SetDebugLevel(level);
        }

        /// <summary>
        ///   Sets the debug file.  If fname is null, the debug file is closed
        /// </summary>
        /// <param name = "fname">debug output file</param>
        public static void SetDebugFile(string fname)
        {
            Debug.SetDebugFile(fname);
        }

        /// <summary>
        ///   Sets the account name for all connections.  If user name is not set,
        ///   the user name of the process is used.
        /// </summary>
        /// <param name = "account">account name</param>
        public static void SetAccount(string account)
        {
            fDefaultLogin.SetAccount(account);
        }

        /// <summary>
        ///   Sets the password for all connections
        /// </summary>
        /// <param name = "password">password</param>
        public static void SetPassword(string password)
        {
            fDefaultLogin.SetPassword(password);
        }

        public static ICifsSession LookupSession(string sessionname)
        {
            return CifsSession.LookupSession(sessionname);
        }

        /// <summary>
        ///   Enumerates connected sessions (unsorted)
        /// </summary>
        /// <returns>Enumerator</returns>
        public static IDictionaryEnumerator GetEnumerator()
        {
            return CifsSession.GetEnumerator();
        }

        /// <summary>
        ///   List sessions
        /// </summary>
        /// <param name = "sortby">sorted by (SESSION_SORT_NAME or SESSION_SORT_TYPE)</param>
        /// <returns>CifsSession array</returns>
        public static ICifsSession[] GetSessions(int sortby)
        {
            var sessions = (CifsSession[]) CifsSession.GetSessions();

            Util.Util.Sort(sessions, new SessionComparator(sortby));
            return sessions;
        }

        /// <summary>
        ///   Disconnectes the given session
        /// </summary>
        /// <param name = "sessionname">name of the session</param>
        public static void DisconnectSession(string sessionname)
        {
            ICifsSession session = LookupSession(sessionname);

            if (session == null)
                throw new CifsIoException("SS2", sessionname);

            session.Disconnect();
        }

        /// <summary>
        ///   Connect to Remote Admin Protocol
        /// </summary>
        /// <param name = "admname">local alias name for this connection</param>
        /// <param name = "host">host name</param>
        public static ICifsRemoteAdmin ConnectRemoteAdmin(string admname, string host)
        {
            return ConnectRemoteAdmin(admname, host, (CifsLogin) fDefaultLogin.Clone());
        }

        /// <summary>
        ///   Connect to Remote Admin Protocol
        /// </summary>
        /// <param name = "sessionname">local alias name for this connection</param>
        /// <param name = "host">host name</param>
        /// <param name = "login">authentication data</param>
        public static ICifsRemoteAdmin ConnectRemoteAdmin(string sessionname, string host, CifsLogin login)
        {
            // check if the admname connection is already open
            ICifsSession session = LookupSession(sessionname);

            if (session != null)
                throw new CifsIoException("SS1", sessionname);

            if (login == null)
                login = fDefaultLogin;

            var share = new Share(login);
            share.SetInfo(Share.IPC, host, "IPC$");

            var nbt = new NbtSession();
            SmbMessage smb = CifsSession.AllocateSmbMessage();

            int protocol;
            CifsRemoteAdmin admin = null;

            try
            {
                protocol = CifsSession.Negotiate(nbt, share.HostName, smb);
                admin = new CifsRemoteAdmin(sessionname, protocol, share, nbt, smb);
                admin.Connect();
            }
            catch (IOException e)
            {
                //nbt.doHangup();
                if (admin != null)
                    admin.Dispose();
                else
                    nbt.DoHangup();


                throw;
            }

            return admin;
        }

        public static ArrayList EnumberateRemoteAdminSessions()
        {
            //IDictionaryEnumerator enu = SessionImpl.enumerateSessions();
            var admins = new ArrayList();

            foreach (IDictionaryEnumerator en in CifsSession.GetSessionTable())
            {
                var session = (ICifsSession) en.Value;

                if (session is ICifsRemoteAdmin)
                    admins.Add(session);
            }

            return admins;
        }

        public static bool AllowLoginDialog { get; private set; }

        /// <summary>
        ///   Clears the name resolver chache and reloads LMHosts file
        /// </summary>
        public static void ClearNameResolverCache()
        {
            NbtNameResolver.ClearCache();
        }

        public static string CreateUsn()
        {
            lock (typeof (CifsSessionManager))
            {
                return "$usn_" + (fSessionSeqNumber++);
            } //lock
        }
    }

    // class CifsSessionManager


    internal class SessionComparator : IComparer<CifsSession>
    {
        private readonly int fSort;

        public SessionComparator(int sort)
        {
            fSort = sort;
        }

        #region IComparer<SessionImpl> Members

        public int Compare(CifsSession fo1, CifsSession fo2)
        {
            switch (fSort)
            {
                case CifsSessionManager.SESSION_SORT_NAME:
                    return String.Compare(fo1.SessionName, fo2.SessionName);

                case CifsSessionManager.SESSION_SORT_TYPE:
                    int p1 = fo1.GetSortPosition();
                    int p2 = fo2.GetSortPosition();

                    if (p1 == p2)
                        return String.Compare(fo1.SessionName, fo2.SessionName);

                    return (p1 < p2) ? -1 : +1;
            }

            throw new ApplicationException("SessionComparator");
        }

        #endregion
    }

    // class SessionComparator
}

// namespace Cifs