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

using System.Collections.Generic;
using System.IO;
using System.Net;

namespace Cifs.Util
{
    using System;

    /// <summary>
    ///   Summary description for LMHosts.
    /// </summary>
    internal class LmHosts
    {
        private readonly Dictionary<string, string> fHostTable = new Dictionary<string, string>();
        private readonly string fLMHostFile;

        public LmHosts(string urlstring)
        {
            if (urlstring != null)
                Load(urlstring);
            fLMHostFile = urlstring;
        }

        public void Refresh()
        {
            if (fLMHostFile != null)
                Load(fLMHostFile);
        }

        private void Load(string urlstring)
        {
            StreamReader reader;

            int p = urlstring.IndexOf("://");
            if (p > 0)
            {
                //WebRequest wc = WebRequestFactory.Create(urlstring);
                WebRequest wc = WebRequest.Create(urlstring);
                WebResponse wr = wc.GetResponse();
                reader = new StreamReader(wr.GetResponseStream());
            }
            else
            {
                reader = new StreamReader(new FileStream(urlstring, FileMode.Open, FileAccess.Read));
            }

            string line;
            string ip;
            string name;

            while ((line = reader.ReadLine()) != null)
            {
                if (line.Length == 0 || line[0] == '#')
                    continue;

                // parse line
                p = line.IndexOf(' ');
                if (p <= 0)
                    continue;

                ip = line.Substring(0, p);
                int q = line.IndexOf('#', p + 1);

                if (q < 0)
                {
                    name = line.Substring(p + 1).Trim();
                }
                else
                {
                    name = line.Substring(p + 1, q).Trim();
                }

                if (name.StartsWith("\""))
                {
                    if (name.EndsWith("\""))
                    {
                        name = name.Substring(1, name.Length - 1);
                    }
                    else
                        continue;
                }

                fHostTable.Add(name.ToUpper(), ip);
            }

            try
            {
                reader.Close();
            }
            catch (IOException)
            {
            }
        }

        public string Lookup(string netbios)
        {
            string value;
            fHostTable.TryGetValue(netbios.ToUpperInvariant(), out value);
            return value;
        }
    }

    // class LMHosts
}

// namespace Cifs