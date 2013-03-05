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

    /// <summary>
    ///    Interface of all service sessions
    /// </summary>
    public interface ICifsSession : IDisposable
    {
        /// <summary>
        /// Sets automatic reconnection
        /// </summary>
        /// <value>true if automatic reconnection allowed</value>
        bool AllowAutoReconnection { set; get; }

        /// <summary>
        /// Returns the name of this share </summary>
        /// <value>share name</value>
        string ShareName { get; }

        /// <summary>
        /// Returns session name</summary>
        /// <value>session name</value>
        string SessionName { get; }

        /// <summary>
        /// Returns the server OS name</summary>
        /// <value>os name or blank if unknown</value>
        string ServerOs { get; }

        /// <summary>
        /// Returns LAN Manager of the server</summary>
        /// <value>lan manager or blank if unknown</value>
        string ServerLanMan { get; }

        /// <summary>
        /// Returns the primary domain of the server</summary>
        /// <value>primary domain or blank if unknown</value>
        string ServerPrimaryDomain { get; }

        /// <summary>
        /// Gets NetBIOS name</summary>
        /// <value>NetBIOS name of the server</value>
        string NetBiosName { get; }

        /// <summary>
        /// Gets the address of the server</summary>
        /// <returns>IP Address</returns>
        IPAddress GetServerAddress();

        /// <summary>
        /// Time zone of server (min from UTC)</summary>
        /// <value>minutes</value>
        int ServerTimeZone { get; }

        /// <summary>
        /// Returns server time (from 1/1/0001 in Ticks)</summary>
        /// <value>msec</value>
        long ServerTime { get; }

        /// <summary>
        /// Checks if the server is connected</summary>
        /// <value>true if the connection is alive</value>
        bool IsConnected { get; }

        /// <summary>
        /// Sets an API-user property.  The value is not interpreted by 
        /// CifsService</summary>
        /// <param name="key">property name</param>
        /// <param name="value">property value</param>
        /// <seealso cref="GetProperty">Also see getProperty</seealso>
        void SetProperty(string key, object value);

        /// <summary>
        /// Gets an API-user property</summary>
        /// <param name="key">property name</param>
        /// <returns>property value</returns>
        /// <seealso cref="SetProperty">Also see setProperty</seealso>
        object GetProperty(string key);

        /// <summary>
        /// Returns true if the share has user level security</summary>
        /// <value>true user level, false share level</value>
        bool IsUserLevelSecurity { get; }

        /// <summary>
        /// Returns the connect time in milliseconds (base: Jan 1, 1970 UTC)</summary>
        /// <value>time in milliseconds</value>
        long ConnectTime { get; }

        /// <summary>
        /// Reconnects server if disconnected
        /// exception IOException if an I/O error occurs</summary>
        void Reconnect();

        /// <summary>
        /// Disconnects session</summary>
        void Disconnect();

        /// <summary>
        /// Ping the server to test the connectoin to the server and to
        /// see if the server is still responding
        /// exception IOException if an I/O error occurs
        /// </summary>
        /// <param name="text">text to send</param>
        /// <returns>text returned by server (must be the same as the input text)</returns>
        string Echo(string text);


    } // interface CifsSession
} // namespace Cifs
