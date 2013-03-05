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

namespace Cifs.Util
{
    using System;
    using System.IO;
    using System.Text;


    /// <summary>
    ///    To enable the debug version, set the field debugOn to true and compile the
    ///    sources again
    /// </summary>
    internal class Debug
    {
        
        public const int None    = 0;
        public const int Error   = 1;
        public const int Warning = 2;
        public const int Info    = 3;
        public const int Buffer  = 4;
        public const int Method  = 5;

        public const bool AssertOn = true;

        public const bool DebugOn = true;
        public static int DebugLevel = None;

        private static TextWriter  fStdOutput = Console.Error;
        private static TextWriter  fOutput    = fStdOutput;

        private static readonly string       NL = Environment.NewLine;
        
        private readonly static char[]  CHARS ={ '0','1','2','3','4','5','6','7',
                                                '8','9','A','B','C','D','E','F'};
        
        public static void SetDebugLevel(int level)
        {
            DebugLevel = level;
        }

        public static void SetDebugFile(string fname)
        {
            lock(typeof(Debug))
            {
                Close();

                if(fname != null)
                {
                    try
                    {
                        FileInfo f = new FileInfo("cifs.log");
                        fOutput = f.AppendText();
                                
                        fOutput.WriteLine(" **** CIFS debug output ***");
                        fOutput.WriteLine("Open timestamp=" + DateTime.Now.ToLongDateString() + " " + DateTime.Now.ToLongTimeString());
                    }
                    catch(IOException e)
                    {
                        Console.Error.WriteLine("Cannot open Debug-File:" + fname);
                        Console.Error.WriteLine(e.StackTrace);
                    }
                }
            } // lock
        }

        public static void Close()
        {
            if(fOutput != fStdOutput)
            {
                fOutput.Flush();
                fOutput.Close();
                fOutput = fStdOutput;
            }
        }

        public static void method()
        {
            if(DebugOn && DebugLevel >= Method)
                fOutput.WriteLine("[method]:" + GetTracedMethod());
        }

        public static void WriteLine(int level, byte[] data, int off, int len)
        {
            if(DebugOn && DebugLevel >= level)
            {
                fOutput.WriteLine(DumpBytes(data, off, len));
                fOutput.Flush();
            }
        }

        public static void Write(int level, string data)
        {
            if(DebugOn && DebugLevel >= level)
            {
                fOutput.Write(data);
                fOutput.Flush();
            }
        }

        public static void WriteLine(int level, string data)
        {
            if(DebugOn && DebugLevel >= level)
            {
                fOutput.WriteLine(data);
                fOutput.Flush();
            }
        }

        public static void WriteLine(string data)
        {
            WriteLine(None, data); // Output this at the 0 level to trace all instances and fix
        }
        
        public static void Assert(bool expr)
        {
            if(AssertOn)
            {
                if(!expr)
                {
                    fOutput.WriteLine("[assert]: Assertion failed:" + GetTracedMethod());
                    Console.Error.WriteLine("Asserion failed:" + GetTracedMethod());
                    Environment.Exit(1);
                }
            }
        }

        private static string GetTracedMethod()
        {
            return Environment.StackTrace;
        }

        public static string DumpBytes(byte[] b, int off, int len)
        {
            StringBuilder buf = new StringBuilder();
            StringBuilder hex = new StringBuilder();
            StringBuilder chr = new StringBuilder();

            int p;
            char c;
            int n = 0;
            for(int i=0; i < len; i++)
            {
                p = b[off+i] & 0xff;
                if(p >= 20 && p <= 125)
                    c = (char)p;
                else
                    c = '.';

                int x = ((p & 0xf0) >> 4) & 0x0f;
                hex.Append(CHARS[x]);

                x = p & 0x0f;
                hex.Append(CHARS[x] + " ");

                chr.Append(c);

                if(n++ == 15)
                {
                    n = 0;
                    buf.Append(hex.ToString() + "    " + chr.ToString() + NL);
                    hex.Length = 0;
                    chr.Length = 0;
                }
            }

            if (n < 15)
            {
                for(;n < 16; n++)
                {
                    hex.Append("   ");
                    chr.Append(' ');
                }
            }
            
            buf.Append(hex.ToString() + "    " + chr.ToString());
            return buf.ToString();
        }

        public static string dumpBytesAlt(byte[] b, int len)
        {
            StringBuilder hex = new StringBuilder();

            int p;
            
            for(int i=0; i < len; i++)
            {
                p = b[i] & 0xff;

                int x = ((p & 0xf0) >> 4) & 0x0f;
                hex.Append(CHARS[x]);

                x = p & 0x0f;
                hex.Append(CHARS[x]);
            }
            
            return hex.ToString();
        }

    }
}
