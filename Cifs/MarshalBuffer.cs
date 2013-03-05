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


using System.Text;
using Cifs.Util;

namespace Cifs
{
    using System;

    /// <summary>
    ///   Summary description for MarshalBuffer.
    /// </summary>
    internal class MarshalBuffer
    {
        private const int MASK = 0xFF;
        protected byte[] fBuffer;

        //public const string ISO8859_1 = "8859_1";

        internal MarshalBuffer(int capacity)
        {
            fBuffer = new byte[capacity];
        }

        internal int Capacity
        {
            get { return fBuffer.Length; }
            set
            {
                if (value > fBuffer.Length)
                {
                    var nbuf = new byte[value];

                    fBuffer = nbuf;
                }
            }
        }

        protected internal int Size { get; set; }

        internal byte[] GetBytes()
        {
            return fBuffer;
        }

        internal void Zero(int len)
        {
            if (len > fBuffer.Length)
                len = fBuffer.Length;
            for (int i = 0; i < len; i++)
                fBuffer[i] = 0;
        }

        public int SetIntAt(int pos, int val)
        {
            // use little-endian encoding (Intel)
            fBuffer[pos] = (byte) (val & MASK);
            fBuffer[pos + 1] = (byte) ((val >> 8) & MASK);
            fBuffer[pos + 2] = (byte) ((val >> 16) & MASK);
            fBuffer[pos + 3] = (byte) ((val >> 24) & MASK);

            return 4;
        }

        public static int SetIntAt(int pos, byte[] buf, int val)
        {
            // use little-endian encoding (Intel)
            buf[pos] = (byte) (val & MASK);
            buf[pos + 1] = (byte) ((val >> 8) & MASK);
            buf[pos + 2] = (byte) ((val >> 16) & MASK);
            buf[pos + 3] = (byte) ((val >> 24) & MASK);

            return 4;
        }

        public int GetIntAt(int pos)
        {
            if (pos + 4 > fBuffer.Length)
                throw new ArgumentOutOfRangeException();


            return ((fBuffer[pos] & MASK) +
                    ((fBuffer[pos + 1] & MASK) << 8) +
                    ((fBuffer[pos + 2] & MASK) << 16) +
                    ((fBuffer[pos + 3] & MASK) << 24));
        }

        public long GetLongAt(int pos)
        {
            if (pos + 8 > fBuffer.Length)
                throw new ArgumentOutOfRangeException();

            long val = ((fBuffer[pos] & MASK) +
                        ((fBuffer[pos + 1] & MASK) << 8) +
                        ((fBuffer[pos + 2] & MASK) << 16) +
                        ((fBuffer[pos + 3] & MASK) << 24) +
                        ((fBuffer[pos + 4] & MASK) << 32) +
                        ((fBuffer[pos + 5] & MASK) << 40) +
                        ((fBuffer[pos + 6] & MASK) << 48) +
                        ((fBuffer[pos + 7] & MASK) << 56));

            return val;
        }

        public int SetShortAt(int pos, short val)
        {
            // use little-endian encoding (Intel)
            fBuffer[pos] = (byte) (val & MASK);
            fBuffer[pos + 1] = (byte) ((val >> 8) & MASK);

            return 2;
        }

        public int SetShortAt(int pos, int val)
        {
            return SetShortAt(pos, (short) (val & 0xffff));
        }

        public int GetShortAt(int pos)
        {
            if (pos > fBuffer.Length)
                throw new ArgumentOutOfRangeException();

            return ((fBuffer[pos] & MASK) +
                    ((fBuffer[pos + 1] & MASK) << 8)) & 0xFFFF;
        }

        public short GetSignedShortAt(int pos)
        {
            if (pos > fBuffer.Length)
                throw new ArgumentOutOfRangeException();

            return (short) (((fBuffer[pos] & MASK) << 8) +
                            ((fBuffer[pos + 1] & MASK)));
        }

        /// <summary>
        ///   Read Zero Terminated Ascii string
        /// </summary>
        public string GetZtAsciiStringAt(int pos, int maximum)
        {
            int maxpos = pos + maximum;
            int endpos = pos;
            while (fBuffer[endpos] != 0 && endpos < maxpos)
                endpos++;

            if (endpos < maxpos)
                return Encoding.ASCII.GetString(fBuffer, pos, endpos - pos);
            else
                return null;
        }

        public string GetUnicodeStringAt(int pos, int bytes)
        {
            int n = bytes/2;

            var chars = new char[n];
            for (int i = 0; i < n; i++)
            {
                int val = GetShortAt(pos + i*2);
                chars[i] = (char) (val & 0xffff);
            }

            return new string(chars);
        }

        public string GetAsciiStringAt(int pos, int len)
        {
            return BitConverter.ToString(fBuffer, pos, len);
        }

        public int SetZtAsciiStringAt(int pos, string s)
        {
            int i = 0;

            for (i = 0; i < s.Length; i++)
                fBuffer[pos + i] = (byte) (s[i] & 0xff);
            fBuffer[pos + i] = 0;

            return s.Length + 1;
        }

        public int SetAsciiStringAt(int pos, string s)
        {
            int i = 0;

            for (i = 0; i < s.Length; i++)
                fBuffer[pos + i] = (byte) (s[i] & 0xff);

            return s.Length;
        }

        public int SetByteAt(int off, byte val)
        {
            fBuffer[off] = val;
            return 1;
        }

        public byte GetByteAt(int off)
        {
            return fBuffer[off];
        }

        public int SetBytesAt(int pos, byte[] bytes, int off, int len)
        {
            Array.Copy(bytes, off, fBuffer, pos, len);
            return len;
        }

        public int SetBytesAt(int pos, char[] bytes, int off, int len)
        {
            for (int i = 0; i < len; i++)
                fBuffer[pos + i] = (byte) (bytes[off + i] & 0xff);

            return len;
        }

        public void SetBytesAt(int pos, MarshalBuffer bytes, int from, int len)
        {
            Array.Copy(bytes.fBuffer, from, fBuffer, pos, len);
        }

        internal void debug(string title)
        {
            if (!Debug.DebugOn || Debug.DebugLevel < Debug.Buffer)
                return;

            Debug.WriteLine(Debug.Buffer, title);

            Debug.WriteLine(Debug.Buffer, fBuffer, 0, Size);
        }

        /// <summary>
        ///   Aligns p to a bytes
        /// </summary>
        /// <param name = "p">alignment (2,4,8)</param>
        /// <param name = "a">aligned p</param>
        public static int Align(int p, int a) // This was protected in the Java ver...why?
        {
            return (((((a) - 1) + (p))) & ((~((a) - 1))));
        }
    }

    // class MarshalBuffer
}

// namespace Cifs