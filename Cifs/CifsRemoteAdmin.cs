/**
  *         Commmon Internet File System API (CIFS)
  *----------------------------------------------------------------
  *  Copyright (C) 2000  Oren Novotny
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

// This class has been partially completed.  Printing is not implemented
// nor is password changing.

namespace Cifs
{
    using System;
    

    /// <summary>
    /// The Remote Administration Protocol (RAP) provides operations <br />
    /// - to get list of share names; <br />
    /// - to get user informations; <br />
    /// - to get workstation informations; <br />
    /// - to get informations about print jobs;<br />
    /// - to manage print jobs. 
    /// </summary>
    /// <remarks>
    ///  <p>The ***parameters section** of the Transact SMB request contains thefollowing
    /// (in the order described) <br />
    /// - The function number: an unsigned short 16 bit integer identifying the
    ///   function being remoted <br />
    /// - The parameter descriptor string: a null terminated ASCII string <br />
    /// - The data descriptor string: a null terminated ASCII string. <br />
    /// - The request parameters, as described by the parameter descriptor  string,
    ///   in the order that the request parameter descriptor characters  appear in
    ///   the parameter descriptor string <br />
    /// - An optional auxiliary data descriptor string:  a null terminated ASCII  string.
    ///   It will be present if there is an auxiliary data structure  count in the primary
    ///   data struct (an "N" descriptor in the data  descriptor string).RAP requires
    ///   that the length of the return parameters be less than orequal to the length
    ///   of the parameters being sent; this requirement ismade to simply buffer management
    ///   in implementations. This is reasonableas the functions were designed to return
    ///	  data in the data section anduse the return parameters for items like data length,
    ///   handles, etc. If need be, this restriction can be circumvented by filling in
    ///   some padbytes into the parameters being sent. <br />&nbsp; <br />
    ///
    ///   The Data section for the transaction request is present if the parameter description
    ///   string contains an "s" (SENDBUF) descriptor. If present, itcontains:
    /// - A primary data struct, as described by the data descriptor string <br />
    ///
    /// - Zero or more instances of the auxiliary data struct, as described by
    ///   the auxiliary data descriptor string. The number of instances is  determined
    ///   by the value of the an auxiliary data structure count  member of the primary
    ///   data struct, indicated by the "N" (AUXCOUNT)  descriptor. The auxiliary data
    ///   is present only if the auxiliary data  descriptor string is non null. <br /> &nbsp; <br />
    ///
    /// - Possibly some pad bytes <br />
    /// - The heap: the data referenced by pointers in the primary and  auxiliary data structs.
    /// </remarks>
    public interface ICifsRemoteAdmin: ICifsSession
    {
    
        /// <summary>
        ///  Returns the list of shares on the computer
        /// </summary>
        /// <param name="sort">if true, the names are sorted</param>
        /// <returns>list of <code>CifsShareInfo</code> objects</returns>
        CifsShareInfo[] ListSharesInfo(bool sort);

        /// <summary>
        /// Returns detailed information about a workstation
        /// </summary>
        /// <value>information about a workstation</value>
        CifsWorkstationInfo WorkstationInfo { get; }

        /// <summary>
        /// Returns detailed information about a particular user
        /// </summary>
        /// <param name="user">user name</param>
        /// <returns>user information</returns>
        CifsUserInfo GetUserInfo(string user);
    
        /// <summary>
        /// Lists all computers of the specified type or types that are visible
        /// in the specified domain.  It may also enumerate domains.
        /// </summary>
        /// <param name="domain">The name of the workgroup in which to enumerate computers
        ///						 of the specified type or types.  If domain is null, servers
        ///						 are enumerated for the current domain of the computer.</param>
        ///	<param name="types">The type or types of computers to enumerate. Computers that
        ///						match at least one of the specified types are returned (SV_*)</param>
        CifsServerInfo[] ListServersInfo(string domain, uint types);

        /// <summary>
        /// Lists all computers of the specified type or types that are visible
        /// in the specified domain.  It may also enumerate domains.
        /// </summary>
        /// <param name="domain">The name of the workgroup in which to enumerate computers
        ///						 of the specified type or types.  If domain is null, servers
        ///						 are enumerated for the current domain of the computer.</param>
        ///	<param name="types">The type or types of computers to enumerate. Computers that
        ///						match at least one of the specified types are returned (SV_*)</param>
        /// <returns><code>System.String</code> (sorted)</returns>
        string[] ListServersNames(string domain, uint types);

        /// <summary>
        /// Returns information about the current server
        /// </summary>
        /// <value>Server information</value>
        CifsServerInfo ServerInfo { get; }
    }
}
