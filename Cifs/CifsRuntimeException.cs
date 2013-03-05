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
    ///    Runtime exception class
    /// </summary>
    public class CifsRuntimeException: SystemException
    {
        private Exception fDetail = null;
        protected string  fText   = null;
        protected string  fCode   = null;

        private static Res.Resources fResourceBundle = new Res.Resources();

        public CifsRuntimeException(string msg, bool key)
        {
            if(key)
            {
                fCode = msg;
                fText = fResourceBundle[msg];
            }
            else
                fText = msg;
        } 

        public CifsRuntimeException(string key): this(key, true)
        {
        }

        public CifsRuntimeException(string key, object i1)
        {
            object[] ins = {i1};
            fText = String.Format(fResourceBundle[key], ins);
            fCode = key;
        }

        public CifsRuntimeException(string key, object i1, object i2)
        {
            object[] ins = {i1, i2};
            fText = String.Format(fResourceBundle[key], ins);
            fCode = key;
        }

        public CifsRuntimeException SetDetail(Exception detail)
        {
            fDetail = detail;
            return this;
        }

        /// <summary>
        /// Returns the encapsulated exception (optional)
        /// </summary>
        public Exception GetDetail()
        {
            return fDetail;
        }

        public static string GetMessage(string key)
        {
            return fResourceBundle[key];
        }

        public static string GetMessage(string key, object i1)
        {
            object[] ins = {i1};
            return String.Format(fResourceBundle[key], ins);
        }

        public static string GetMessage(string key, object i1, object i2)
        {
            object[] ins = {i1, i2};
            return String.Format(fResourceBundle[key], ins);
        }

        /// <summary>
        /// Produce the message, include the message from the nested
        /// exception if there is one
        /// </summary>
        public string GetMessage()
        {
            if(fDetail == null)
                return '[' + fCode + "] " + fText;
            else
                return '[' + fCode + "] " + fText + "[" + fDetail.Message + "]";
        }
        

    } // class CifsRuntimeException
} // namespace Cifs
