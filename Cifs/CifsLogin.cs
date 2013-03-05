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
    ///   CifsLogin holds user authentication data
    /// </summary>
    public class CifsLogin 
    {
        private static readonly byte[] NONE_PASSWORD = new byte[0];
        private static readonly byte[] NULL_PASSWORD = {0x00};

        /// "KGS!@#$%
        private static readonly byte[] S8 = {
                                                0x4b, 0x47, 0x53, 0x21,
                                                0x40, 0x23, 0x24, 0x25
                                            };

        /// <summary>
        ///   Creates a new object.  The user name is the environment variable USERNAME
        /// </summary>
        public CifsLogin()
        {
            Password = null;
            Account = null;
            SetAccount(Environment.GetEnvironmentVariable("USERNAME"));
        }

        /// <summary>
        ///   Creates a new object.  The user name is the environment variable USERNAME
        /// </summary>
        /// <param name = "password">user password</param>
        public CifsLogin(string password)
        {
            Password = null;
            Account = null;
            SetAccount(Environment.GetEnvironmentVariable("USERNAME"));
            SetPassword(password);
        }

        /// <summary>
        ///   Creates a new object
        /// </summary>
        /// <param name = "account">user name</param>
        /// <param name = "password">user password</param>
        public CifsLogin(string account, string password)
        {
            Password = null;
            Account = null;
            SetAccount(account);
            SetPassword(password);
        }

        /// <summary>
        ///   Returns the account name
        /// </summary>
        /// <value>account name</value>
        public string Account { get; private set; }

        /// <summary>
        ///   Returns the password
        /// </summary>
        /// <value>password</value>
        internal string Password { get; private set; }

        #region ICloneable Members

        /// <summary>
        ///   Clone this object
        /// </summary>
        public object Clone()
        {
            var newlogin = new CifsLogin();

            lock (this)
            {
                if (Account != null)
                    newlogin.Account = (string) Account.Clone();
                if (Password != null)
                    newlogin.Password = (string) Password.Clone();
            }

            return newlogin;
        }

        #endregion

        /// <summary>
        ///   Sets the account name
        /// </summary>
        /// <param name = "account">The user name</param>
        public void SetAccount(string account)
        {
            Account = account;
        }

        /// <summary>
        ///   Sets the password
        /// </summary>
        /// <param name = "password">password</param>
        public void SetPassword(string password)
        {
            Password = password;
        }

        /// <summary>
        ///   Compares if the two objects are the same (same account and password)
        /// </summary>
        /// <param name = "obj">the object to test</param>
        /// <returns>true if obj is the same <code>CifsLogin</code> object</returns>
        public override bool Equals(object obj)
        {
            if ((obj != null) && (typeof (CifsLogin) == obj.GetType()))
            {
                var anobj = (CifsLogin) obj;

                if (!anobj.Account.Equals(Account))
                    return false;

                if (anobj.Password == null && Password == null)
                    return true;

                if (anobj.Password != null || Password != null)
                    return false;

                return (anobj.Password.Equals(Password));
            }
            return false;
        }


        public override string ToString()
        {
            return "[Login] Account=" + Account;
        }

        /*====================================================================
     *                    Helper methods for authentication
     *===================================================================*/
        // These should be const....

        /// <summary>
        ///   Generates NT authentication response data
        /// </summary>
        /// <param name = "password">password</param>
        /// <param name = "c8">challange</param>
        /// <returns>byte[24] authentication data</returns>
        internal static byte[] GetNtAuthData(string password, byte[] c8)
        {
            if (password == null)
                return NONE_PASSWORD;

            byte[] s21 = GetNtSessionKey(password);

            return GetAuthData(s21, c8);
        }


        /// <summary>
        ///   Generates LM authentication response data
        /// </summary>
        /// <param name = "password">password</param>
        /// <param name = "c8">challange</param>
        /// <returns>byte[24] authentication data</returns>
        internal static byte[] GetLmAuthData(string password, byte[] c8)
        {
            if (password == null)
                return NONE_PASSWORD;

            var p14 = new byte[15];
            var p21 = new byte[21];
            var p24 = new byte[24];

            password = password.ToUpper();

            for (int i = 0; i < password.Length && i < 14; i++)
                p14[i] = (byte) (password[i] & 0xff);

            E_P16(p14, p21);

            SmbOwfEncrypt(p21, c8, p24);

            return p24;
        }

        /// <summary>
        ///   Encrypts password
        /// </summary>
        /// <param name = "s21">Session key</param>
        /// <param name = "c8">challange</param>
        /// <returns>byte[24]</returns>
        internal static byte[] GetAuthData(byte[] s21, byte[] c8)
        {
            var key7 = new byte[7];
            var key8 = new byte[8];
            var e8 = new byte[8];
            var rn = new byte[24];

            for (int i = 0; i < 3; i++)
            {
                Array.Copy(s21, 7*i, key7, 0, 7);

                Des.MakeSmbKey(key7, key8);

                var des = new Des(key8);

                des.Encrypt(c8, e8);

                Array.Copy(e8, 0, rn, 8*i, 8);
            }
            return rn;
        }


        internal static byte[] GetNtSessionKey(string password)
        {
            var utf = new UTF8Encoding();
            byte[] pn = Util.Util.ConvertStringToByteArray(password);

            //MD4 Stuff goes here...
            // MD4 md4 = new MD4();
            // md4.update(pn);
            var dig = new byte[22]; //md4.digest();
            var s21 = new byte[21];

            Array.Copy(dig, 0, s21, 0, dig.Length);

            return s21;
        }


        private static void E_P16(byte[] p14, byte[] p16)
        {
            var key7 = new byte[7];
            var key8 = new byte[8];
            var e8 = new byte[8];

            for (int i = 0; i < 2; i++)
            {
                Array.Copy(p14, 7*i, key7, 0, 7);

                Des.MakeSmbKey(key7, key8);

                var des = new Des(key8);
                des.Encrypt(S8, e8);

                Array.Copy(e8, 0, p16, 8*i, 8);
            }
        }

        private static void E_P24(byte[] p21, byte[] c8, byte[] p24)
        {
            var key7 = new byte[7];
            var key8 = new byte[8];
            var e8 = new byte[8];

            for (int i = 0; i < 3; i++)
            {
                Array.Copy(p21, 7*i, key7, 0, 7);
                Des.MakeSmbKey(key7, key8);

                var des = new Des(key8);

                des.Encrypt(c8, e8);

                Array.Copy(e8, 0, p24, 8*i, 8);
            }
        }

        private static void SmbOwfEncrypt(byte[] passwd16, byte[] c8, byte[] p24)
        {
            var p21 = new byte[21];

            Array.Copy(passwd16, 0, p21, 0, 16);

            E_P24(p21, c8, p24);
        }

        /// <summary>
        ///   One-way transformation.  The spec says that the password must be
        ///   padded with blanks, Samba does it iwth 0 ???
        ///   <para>OWF = Ex(P14, S8)</para>
        /// </summary>
        /// <param name = "password">password</param>
        /// <returns>byte[16]</returns>
        internal static byte[] GetLmOwf(string password)
        {
            var p14 = new byte[14];

            password = password.ToUpper();
            for (int i = 0; i < password.Length; i++)
                p14[i] = (byte) (password[i] & 0xff);


            var s16 = new byte[16];
            var key7 = new byte[7];
            var key8 = new byte[8];
            var e8 = new byte[8];

            for (int i = 0; i < 2; i++)
            {
                Array.Copy(p14, 7*i, key7, 0, 7);
                Des.MakeSmbKey(key7, key8);

                var des = new Des(key8);

                des.Encrypt(S8, e8);

                Array.Copy(e8, 0, s16, 8*i, 8);
            }

            return s16;
        }

        /// <summary>
        ///   <pre>
        ///     +----------------------+
        ///     |                      |
        ///     |   new password       + 512
        ///     |   new password len   + 516
        ///     |   encrypted hash     |
        ///     +----------------------+
        ///   </pre>
        /// </summary>
        /// <param name = "oldpwd">Old Password</param>
        /// <param name = "newpwd">New Password</param>
        internal static byte[] GetChangePasswordData(string oldpwd, string newpwd)
        {
            var data = new byte[532];

            // calculate OWF of the old password
            byte[] oldpwdhash = GetLmOwf(oldpwd);

            // string p = Util.bytesToHex(oldpwdhash);
            // Debug.WriteLine(p);

            // setup new password structure
            byte[] plainnewpwd = Util.Util.ConvertStringToByteArray(newpwd);

            Array.Copy(plainnewpwd, 0, data, 512 - plainnewpwd.Length, plainnewpwd.Length);

            data.SetValue(plainnewpwd.Length, 512);

            // encrypt new password structure
            SamOemHash(data, oldpwdhash, 1);

            // calculate OWF of the new password
            byte[] newpwdhash = GetLmOwf(newpwd);

            // now encrypte new password hash with the old password hash
            byte[] sig = GetOldPwHash(newpwdhash, oldpwdhash);
            Array.Copy(sig, 0, data, 516, 16);

            return data;
        }

        private static byte[] GetOldPwHash(byte[] p14key, byte[] in16)
        {
            var s16 = new byte[16];
            var key7 = new byte[7];
            var key8 = new byte[8];
            var e8 = new byte[8];
            var s8 = new byte[8];

            for (int i = 0; i < 2; i++)
            {
                Array.Copy(p14key, 7*i, key7, 0, 7);
                Des.MakeSmbKey(key7, key8);

                var des = new Des(key8);
                Array.Copy(in16, 8*i, s8, 0, 8);

                des.Encrypt(s8, e8);

                Array.Copy(e8, 0, s16, 8*i, 8);
            }

            return s16;
        }

        /// <summary>
        ///   Returns the password as a byte array.  Each Unicode character
        ///   is represented by the 2 bytes in Intel byte-order (little-endian)
        /// </summary>
        /// <param name = "password">password</param>
        /// <returns>byte array</returns>
        internal static byte[] GetPasswordBytesUnicode(string password)
        {
            if (password == null)
                return NONE_PASSWORD;

            return Util.Util.GetUnicodeBytes(password, false);
        }


        /// <summary>
        ///   Returns the password as a byte array.  The byte array
        ///   contains the Ascii characters an null terminated.
        /// </summary>
        /// <param name = "password">password</param>
        /// <returns>byte array</returns>
        internal static byte[] GetPasswordBytesAscii(string password)
        {
            if (password == null)
                return NULL_PASSWORD;

            return Util.Util.GetZtStringBytes(password.ToUpper());
        }

        /// <summary>
        ///   Code from Samba
        /// </summary>
        /// <param name = "data">password data structure</param>
        /// <param name = "key">key</param>
        /// <param name = "val">val</param>
        internal static void SamOemHash(byte[] data, byte[] key, int val)
        {
            var s_box = new byte[256];
            int index_i = 0;
            int index_j = 0;
            int j = 0;
            int ind;

            for (ind = 0; ind < 256; ind++)
                s_box[ind] = (byte) (ind & 0xff);

            for (ind = 0; ind < 256; ind++)
            {
                byte tc;

                j = (j + (s_box[ind] + key[ind%16])) & 0xff;
                tc = s_box[ind];
                s_box[ind] = s_box[j];
                s_box[j] = tc;
            }

            for (ind = 0; ind < (val != 0 ? 516 : 16); ind++)
            {
                int tc;
                int t;

                index_i = (index_i + 1) & 0xff;
                index_j = (index_j + s_box[index_i]) & 0xff;


                tc = s_box[index_i] & 0xff;
                s_box[index_i] = s_box[index_j];
                s_box[index_j] = (byte) tc;

                t = ((s_box[index_i] + s_box[index_j]) & 0xff);
                // Debug.WriteLine("index_i={0}, index_j={1}, t={2}", index_i, index_j, t);
                data[ind] = (byte) ((data[ind] ^ s_box[t]) & 0xff);
            }
        }
    }

    // class CifsLogin
}

// namespace Cifs