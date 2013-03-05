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
    ///    Information about the workstation
    /// </summary>
    public sealed class CifsWorkstationInfo
    {
        internal CifsWorkstationInfo()
        {
        }

        /// <summary>
        /// Returns the name of the workstation
        /// </summary>
        /// <value>the name of the workstation</value>
        public string WorkstationName { get; internal set; }

        /// <summary>
        /// Returns user who is logged on at the workstation
        /// </summary>
        /// <value>user name</value>
        public string UserName { get; internal set; }

        /// <summary>
        /// Returns the domain to which the workstation belongs
        /// </summary>
        /// <value>domain name</value>
        public string Domain { get; internal set; }

        /// <summary>
        /// Returns the major version number fo the network software
        /// the workstation is running.
        /// </summary>
        /// <value>major version number</value>
        public int MajorVersion { get; internal set; }

        /// <summary>
        /// Returns the minor version number of the networking software
        /// the workstation is running.
        /// </summary>
        /// <value>ninor version number</value>
        public int MinorVersion { get; internal set; }

        /// <summary>
        /// Returns the domain for which a user is logged on
        /// </summary>
        /// <value>domain name</value>
        public string LogonDomain { get; internal set; }

        /// <summary>
        /// Returns all domains in which the computer is enlisted
        /// </summary>
        /// <value>domain list</value>
        public string AllDomains { get; internal set; }
    } // class CifsWorkstationInfo
} // namespace Cifs
