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

using System;
using System.Collections.Generic;
using System.Text;

namespace Cifs.Util
{

    /// <summary>
    ///   Utility class for CIFS
    /// </summary>
    public static class Util
    {
        //private const long MSEC_BASE_1601AD = 11644477199910L;


        /// Set's a byte array to zero
        public static void Zero(byte[] a, int aoffset, int len)
        {
            Fill(0, a, aoffset, len);
        }

        /// Fills a byte array with a value
        public static void Fill(byte a, byte[] b, int boffset, int len)
        {
            for (int i = 0; i < len; ++i)
                b[boffset + i] = a;
        }

        public static byte[] GetZtStringBytes(string s)
        {
            s += ' ';
            byte[] r = Encoding.UTF8.GetBytes(s);
            r[r.Length - 1] = 0;
            return r;
        }

        public static byte[] GetUnicodeBytes(string s, bool nullterm)
        {
            if (nullterm)
                s += ' ';

            byte[] u = Encoding.UTF8.GetBytes(s);

            return Encoding.Convert(Encoding.UTF8, Encoding.Unicode, u);
        }

        public static byte[] GetStringBytes(string s)
        {
            return Encoding.UTF8.GetBytes(s);
        }

        public static bool Equals(byte[] a, byte[] b)
        {
            return a.Equals(b);
        }

        public static string BytesToHex(byte[] a)
        {
            return BytesToHex(a, a.Length);
        }

        public static string BytesToHex(byte[] a, int len)
        {
            return Debug.dumpBytesAlt(a, len);
        }

        public static void IntsToBytes(int[] a, int aoffset, int len, byte[] b, int boffset)
        {
            for (int i = 0; i < len; ++i)
                IntToBytes(a[aoffset + i], b, boffset);
        }

        public static void IntToBytes(int a, byte[] b, int bo)
        {
            b[bo] = (byte) ((a >> 24) & 0xff);
            b[bo + 1] = (byte) ((a >> 16) & 0xff);
            b[bo + 2] = (byte) ((a >> 8) & 0xff);
            b[bo + 3] = (byte) (a & 0xff);
        }

        public static void ShortToBytes(int a, byte[] b, int bo)
        {
            b[bo] = (byte) ((a >> 8) & 0xff);
            b[bo + 1] = (byte) (a & 0xff);
        }

        public static int BytesToInt(byte[] a, int aoffset)
        {
            return BitConverter.ToInt32(a, aoffset);
        }

        public static void BytesToInts(byte[] a, int ao, int[] b, int bo, int len)
        {
            for (int i = 0; i < len; ++i)
                b[bo + i] = BytesToInt(a, ao + (i << 2));
        }

        public static string ByteToBits(byte b)
        {
            var buf = new StringBuilder();

            int n = 256;
            for (int i = 0; i < 8; i++)
            {
                n /= 2;
                if ((b & n) != 0) buf.Append('1');
                else buf.Append('0');
            }
            return buf.ToString();
        }

        public static long BytesToLong(byte[] a, int ao)
        {
            return BitConverter.ToInt64(a, ao);
        }

        public static string LongToHex(long a)
        {
            string temp = BitConverter.ToString(BitConverter.GetBytes(a));

            temp.Replace('-', ' ');

            return temp;
        }

        public static string ByteToHex(byte b)
        {
            var t = new byte[1];
            t[0] = b;

            return BitConverter.ToString(t);

            /*
            StringBuilder s = new StringBuilder();

            s.Append ( ((int)((b >> 4) & 0xf) ).ToChar() );
            s.Append ( ((int)( b & 0xf)).ToChar());
            
            return s.ToString();
            */
        }

        public static string IntToHex(int a)
        {
            var b = new byte[4];
            IntToBytes(a, b, 0);
            return BytesToHex(b);
            /*
            string temp = BitConverter.ToString(BitConverter.GetBytes(a));
            
            temp.Replace('-', ' ');

            return temp.ToString();
            */
        }

        public static string ShortToHex(short a)
        {
            string temp = BitConverter.ToString(BitConverter.GetBytes(a));

            temp.Replace('-', ' ');

            return temp;
        }

        public static string ShortToHex(int a)
        {
            var b = new byte[2];
            ShortToBytes(a, b, 0);
            return BytesToHex(b);
        }

        /// <summary>
        ///   Reverses the order of the bits in the byte
        /// </summary>
        /// <param name = "b">byte to reverse</param>
        public static byte Swab(byte b)
        {
            return (byte) (((b << 7) | ((b & 0x02) << 5) | ((b & 0x04) << 3) | ((b & 0x08) << 1) |
                            ((b & 0x80) >> 7) | ((b & 0x40) >> 5) | ((b & 0x20) >> 3) | ((b & 0x10) >> 1)) & 0xff);
        }

        public static void Swab(byte[] b)
        {
            for (int i = 0; i < b.Length; i++)
                b[i] = Swab(b[i]);
        }

        public static byte[] ConvertStringToByteArray(string s)
        {
            return Encoding.UTF8.GetBytes(s);
        }

        /// <summary>
        ///   Converts a long into bytes
        /// </summary>
        /// <param name = "a">long value</param>
        /// <param name = "b">byte array to store the result in</param>
        /// <param name = "bo">offset of the array to start storing bytes</param>
        public static void LongToBytes(long a, byte[] b, int bo)
        {
            b[bo] = (byte) (a >> 56);
            b[bo + 1] = (byte) (a >> 48);
            b[bo + 2] = (byte) (a >> 40);
            b[bo + 3] = (byte) (a >> 32);
            b[bo + 4] = (byte) (a >> 24);
            b[bo + 5] = (byte) (a >> 16);
            b[bo + 6] = (byte) (a >> 8);
            b[bo + 7] = (byte) (a);
        }


        public static void SortStrings(string[] array)
        {
            Sort(array, array.Length, Comparer<string>.Default);
        }

        public static void Sort<T>(T[] array, IComparer<T> comparator)
        {
            Sort(array, array.Length, comparator);
        }


        /// Sorts array (Heapsort)
        public static void Sort<T>(T[] array, int count, IComparer<T> comparator)
        {
            int i, top, t, largest, l, r, here;
            T temp;

            int elementCount = count;

            if (elementCount <= 1)
            {
                return;
            }

            top = elementCount - 1;
            t = elementCount/2;


            do
            {
                --t;
                largest = t;

                /* heapify */

                do
                {
                    i = largest;
                    l = Left(largest);
                    r = Right(largest);

                    if (l <= top)
                    {
                        if (comparator.Compare(array[l], array[i]) > 0)
                            largest = l;
                    }
                    if (r <= top)
                    {
                        if (comparator.Compare(array[r], array[l]) > 0)
                            largest = r;
                    }
                    if (largest != i)
                    {
                        temp = array[largest];
                        array[largest] = array[i];
                        array[i] = temp;
                    }
                } while (largest != i);
            } while (t > 0);


            t = elementCount;

            do
            {
                --top;
                --t;

                here = t;

                temp = array[here];
                array[here] = array[0];
                array[0] = temp;

                largest = 0;

                do
                {
                    i = largest;
                    l = Left(largest);
                    r = Right(largest);

                    if (l <= top)
                    {
                        if (comparator.Compare(array[l], array[i]) > 0)
                            largest = l;
                    }
                    if (r <= top)
                    {
                        if (comparator.Compare(array[r], array[largest]) > 0)
                            largest = r;
                    }
                    if (largest != i)
                    {
                        temp = array[largest];
                        array[largest] = array[i];
                        array[i] = temp;
                    }
                } while (largest != i);
            } while (t > 1);
        }

        private static int Left(int i)
        {
            return 2*i + 1;
        }

        private static int Right(int i)
        {
            return 2*i + 2;
        }

        public static String GetIpAddress(byte[] b, int off)
        {
            var addr = new StringBuilder();

            addr.Append(b[off++] & 0xff);
            addr.Append('.');
            addr.Append(b[off++] & 0xff);
            addr.Append('.');
            addr.Append(b[off++] & 0xff);
            addr.Append('.');
            addr.Append(b[off++] & 0xff);
            return addr.ToString();
        }
    }

}