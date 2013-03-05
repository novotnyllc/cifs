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
    using System.Collections;
    using System.IO;
    using System.Net;

    using Cifs.Util;

    /// <summary>
    ///    NetBIOS Name Resolver
    /// </summary>
    internal static class NbtNameResolver
    {
        private static LmHosts fLMHosts = null;

        private static Hashtable fCache = Hashtable.Synchronized(new Hashtable());
        private static NBTNameService fWins     = null;
        private static IPAddress      fWinsAddr = null;
        
        private const int RESOLVE_CACHE	  = 0;
        private const int RESOLVE_WINS    = 1;
        private const int RESOLVE_LMHOSTS = 2;
        private const int RESOLVE_DNS     = 3;

        private static int[] fResoveOrder = null;
        private static bool  fUseCache = false;

        private const string DEFAULT_RESOLVE_ORDER = "dns,lmhosts, wins";
        private static readonly string[] KEYSTABLE = {"Cache", "WINS", "LMHOSTS", "DNS"};

        internal static void ClearCache()
        {
            fCache.Clear();
            fLMHosts = null;
        }

        /// <summary>
        /// Resolve NetBIOS name:
        /// - 1. check cache
        /// - 2. LMHosts
        /// - 3. WINS
        /// - 4. DNS
        /// </summary>
        /// <param name="netbiosname">Name to resolve</param>
        internal static IPAddress Resolve(string netbiosname)
        {
            IPAddress addr = null;
            string netbiosup = netbiosname.ToUpper();

            int[] resolveOrder = GetResolveOrder();
            int index = RESOLVE_CACHE;

            addr = ResolveInCache(netbiosup);
            
            for(int i=0; i<resolveOrder.Length && addr == null; i++)
            {
                index = resolveOrder[i];

                switch(index)
                {
                    case RESOLVE_LMHOSTS:
                        addr = ResolveInLmHosts(netbiosup);
                        break;

                    case RESOLVE_WINS:
                        addr = ResolveInWins(netbiosup);
                        break;

                    case RESOLVE_DNS:
                        addr = ResolveInDns(netbiosname);
                        break;

                    default:
                        break;
                }
            }

            if(addr != null)
            {
                if(Debug.DebugOn && Debug.DebugLevel >= Debug.Info)
                {
                    Debug.WriteLine(Debug.Info, "NetBIOS name found in " + KEYSTABLE[index] + ": " + netbiosname + "=" + addr.ToString());
                }
                
            
                //if(index != RESOLVE_CACHE && fUseCache)
                //	fCache.Add(netbiosup, addr);

                return addr;
            }
            throw new CifsIoException("CM3", netbiosname);
        }

        private static IPAddress ResolveInWins(string netbios)
        {
            if(fWins == null)
            {
                // Add external configuration....
                string wins = "wins2.cwru.edu";  // CWRU's wins server (129.22.4.11)

                if(wins == null)
                    return null;
                if(Debug.DebugOn && Debug.DebugLevel >= Debug.Info)
                    Debug.WriteLine(Debug.Info, "Check name in WINS");
                

                try
                {
                    fWinsAddr = Dns.Resolve(wins).AddressList[0];
                    fWins     = new NBTNameService();
                }
                catch(Exception)
                {
                    return null;
                }
            }
            return fWins.lookup(fWinsAddr, netbios);
        }

        private static IPAddress ResolveInCache(string netbios)
        {
            if(!fUseCache)
                return null;

            if(Debug.DebugOn && Debug.DebugLevel >= Debug.Info)
                Debug.WriteLine(Debug.Info, "Check name in Cache");
            
            string netbiosup = netbios.ToUpper();
            return (IPAddress)fCache[netbiosup];
        }

        private static IPAddress ResolveInDns(string netbios)
        {
            if(Debug.DebugOn && Debug.DebugLevel >= Debug.Info)
                Debug.WriteLine(Debug.Info, "Check name in DNS");

            try
            {
                return Dns.Resolve(netbios).AddressList[0];
            }
            catch(Exception)
            {
            }
            return null;
        }

        private static IPAddress ResolveInLmHosts(string netbios)
        {
            if(fLMHosts == null)
            {
                string url = null;
                try
                {
                    if(Debug.DebugOn && Debug.DebugLevel >= Debug.Info)
                        Debug.WriteLine(Debug.Info, "Check name in LMHOSTS");

                    // Make this user-configurable later...
                    url = Environment.SystemDirectory + @"\drivers\etc\lmhosts"; 
                    fLMHosts = new LmHosts(url);
                }
                catch(IOException)
                {
                    Debug.WriteLine(Debug.Warning, "LMHOSTS file cannot be read: " + url);
                    return null;
                }
            }

            string ip = fLMHosts.Lookup(netbios);
            if(ip != null)
            {
                try
                {
                    return Dns.GetHostByName(ip).AddressList[0];
                    //return DNS.InetAddr(ip); // This converts the string into an instance of IPAddress
                }
                catch(Exception)
                {
                }
            }
            return null;
        }


        private static int[] GetResolveOrder()
        {
            if(fResoveOrder != null)
                return fResoveOrder;

            // Add user-configurable stuff later
            fUseCache = true;
            string order = DEFAULT_RESOLVE_ORDER;

            string[] token = order.Split(",".ToCharArray());

            
            //bool cacheSpec   = false;
            bool lmhostsSpec = false;
            bool dnsSpec     = false;
            bool winsSpec    = false;

            fResoveOrder = new int[3];

            for(int i = 0; i < token.Length; i++)
            {
                string key = token[i];

                if (String.Compare(key, "lmhosts", true) == 0)
                {
                    if(!lmhostsSpec) fResoveOrder[i] = RESOLVE_LMHOSTS;
                    lmhostsSpec = true;
                }
                else if(String.Compare(key, "dns", true) == 0)
                {
                    if(!dnsSpec) fResoveOrder[i] = RESOLVE_DNS;
                    dnsSpec = true;
                }
                else if(String.Compare(key, "wins", true) == 0)
                {
                    if(!winsSpec) fResoveOrder[i] = RESOLVE_WINS;
                    winsSpec = true;
                }
            }
            return fResoveOrder;
        }


    } // class NBTNameResolver
} // namespace Cifs
