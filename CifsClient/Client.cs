using System;
using Cifs;
using Cifs.Util;

namespace CifsClient
{
    

    /// <summary>
    ///   This is a test &amp; example of how to use CIFS
    /// </summary>
    public class Client
    {
        public static int Main(string[] args)
        {
            CifsSessionManager.SetDebugLevel(6);
            CifsSessionManager.SetDebugFile("cifs.log");


            DoRemoteAdmin();

            return 0;
        }

        private static void DoRemoteAdmin()
        {
            var login = new CifsLogin("guest", null);
            ICifsRemoteAdmin ra = null;
            try
            {
                // in this example, "test" is the session name, "athena" the hostname.
                // you can enter any validly resolving entry for the hostname (IP, computername, etc)
                ra = CifsSessionManager.ConnectRemoteAdmin("test", "athena", login);

                ShowServer(ra);

                Console.WriteLine("\nShare's");
                DoShares(ra);

                Console.WriteLine("\nWorkstation Info");
                DoWInfo(ra);

                Console.WriteLine("\nServer Info");
                DoSInfo(ra);


                Console.Read(); // pause

                ICifsSession s = ra;

                s.Disconnect();
            }
            catch (Exception) // ignore all
            {
                if (ra != null)
                {
                    ICifsSession s = ra;
                    s.Disconnect();
                }
            }
        }

        private static void ShowServer(ICifsSession service)
        {
            try
            {
                string os = service.ServerOs;
                string lm = service.ServerLanMan;
                string pd = service.ServerPrimaryDomain;
                Console.WriteLine(service.ToString());
                Console.WriteLine("[OS=" + os + ", LanMan=" + lm + ", PrimaryDomain=" + pd + "]");
            }
            catch (Exception)
            {
            }
        }

        public static void DoSInfo(ICifsRemoteAdmin ra)
        {
            CifsServerInfo info;

            try
            {
                info = ra.ServerInfo;

                Console.WriteLine("Computer = " + info.ComputerName);
                Console.WriteLine("Type     = " + Util.IntToHex((int) info.ServerType));
                Console.WriteLine("Version  = " + info.MajorVersion + "." + info.MinorVersion);
                Console.WriteLine("Comment  = " + info.Comment);
            }
            catch (Exception)
            {
            }
        }

        public static void DoWInfo(ICifsRemoteAdmin ra)
        {
            try
            {
                CifsWorkstationInfo info = ra.WorkstationInfo;

                Console.WriteLine("Computer     = " + info.WorkstationName);
                Console.WriteLine("User         = " + info.UserName);
                Console.WriteLine("Domain       = " + info.Domain);
                Console.WriteLine("Version      = " + info.MajorVersion + "." + info.MinorVersion);
                Console.WriteLine("Logon Domain = " + info.LogonDomain);
                Console.WriteLine("All Domains  = " + info.AllDomains);
            }
            catch (Exception)
            {
            }
        }

        public static void DoShares(ICifsRemoteAdmin ra)
        {
            try
            {
                CifsShareInfo[] result = ra.ListSharesInfo(true);

                for (int i = 0; i < result.Length; i++)
                {
                    Console.WriteLine(result[i].ToString());
                }
            }
            catch (Exception)
            {
            }
        }

        internal static void Disconnect()
        {
            /*
            foreach(IDictionaryEnumerator en )
            {
                CifsSession session = (CifsSession)en.Value;

                try
                {
                    session.disconnect();
                }
                catch(Exception)
                {
                }
            }
            */
        }
    }

    // class
}

//namespace