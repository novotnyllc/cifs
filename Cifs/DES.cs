namespace Cifs.Util
{
    using System;
    using System.IO;
    using System.Text;
    using System.Security.Cryptography;
   
    /// <summary>
    ///    Summary description for DES.
    /// </summary>
    internal class Des
    {
        
        

        private byte[] key;

        /*
        public DES()
        {
            
        }
        */


        /// <summary>
        /// Constructor, byte-array key
        /// </summary>
        /// <param name="k">byte-array key</param>
        public Des(byte[] k)
        {
            key = k;
        }
    

        public static void MakeSmbKey(byte[] key7, byte[] key8)
        {
            int i;

            key8[0] = (byte) ( ( key7[0] >> 1) & 0xff);
            key8[1] = (byte)(( ((key7[0] & 0x01) << 6) | (((key7[1] & 0xff)>>2) & 0xff)) & 0xff );
            key8[2] = (byte)(( ((key7[1] & 0x03) << 5) | (((key7[2] & 0xff)>>3) & 0xff)) & 0xff );
            key8[3] = (byte)(( ((key7[2] & 0x07) << 4) | (((key7[3] & 0xff)>>4) & 0xff)) & 0xff );
            key8[4] = (byte)(( ((key7[3] & 0x0F) << 3) | (((key7[4] & 0xff)>>5) & 0xff)) & 0xff );
            key8[5] = (byte)(( ((key7[4] & 0x1F) << 2) | (((key7[5] & 0xff)>>6) & 0xff)) & 0xff );
            key8[6] = (byte)(( ((key7[5] & 0x3F) << 1) | (((key7[6] & 0xff)>>7) & 0xff)) & 0xff );
            key8[7] = (byte)(key7[6] & 0x7F);
            for (i=0;i<8;i++) 
            {
                key8[i] = (byte)( key8[i] << 1);
            }
        }
        
        

        public string DesDecrypt(String stringToDecrypt)
        {
            
            
            DES des = DES.Create();

            des.Key = key;
            //des.IV = IV;
            des.GenerateIV();
            
            
            //Convert the input into a byte array
            byte[] dataToDecrypt = Encoding.UTF8.GetBytes(stringToDecrypt);
            
            MemoryStream ms = new MemoryStream();

            CryptoStream cms = new CryptoStream(ms, des.CreateDecryptor(), CryptoStreamMode.Write );

            cms.Write(dataToDecrypt, 0, dataToDecrypt.Length);

            cms.Close();

            char[] decryptedCharArray = Encoding.UTF8.GetChars(ms.ToArray());

            return decryptedCharArray.ToString();

            /*
            //SymmetricStreamDecryptor ssd = des.CreateDecryptor();
            ssd.SetSink(cms);
            ssd.Write(dataToDecrypt);
            ssd.CloseStream();
            
            char[] decryptedCharArray = Encoding.UTF8.GetChars(cms.Data);
            
            return decryptedCharArray.ToString();

            */
        }

        public void Decrypt(byte[]cipherText, byte[] clearText)
        {
            DES des = DES.Create();
            des.Key = key;
            //des.IV = IV;
            des.GenerateIV();			

            MemoryStream ms = new MemoryStream();

            CryptoStream cms = new CryptoStream(ms, des.CreateDecryptor(), CryptoStreamMode.Write );
            
            cms.Write(cipherText, 0, cipherText.Length);

            cms.Close();

            // If this worked, then we should have text...
            clearText = ms.ToArray();
            
    
            /*
            SymmetricStreamDecryptor ssd = des.CreateDecryptor();
            ssd.SetSink(cms);
            ssd.Write(cipherText);
            ssd.CloseStream();
            
            clearText = cms.Data;
            */
        }

        public void Encrypt(byte[] clearText, byte[] cipherText)
        {
            DES des = DES.Create();

            des.Key = key;	  // set the key to the provided one

            des.GenerateIV(); // Generate a random init vector

            MemoryStream ms = new MemoryStream();	
        
            CryptoStream cs = new CryptoStream(ms, des.CreateEncryptor(), CryptoStreamMode.Write);

            cs.Write(clearText, 0, clearText.Length);
            
            cs.Close();

            // If the above worked, we should be able to get the encrypted bytes...
            cipherText = ms.ToArray();

            // This junk was from .net b1	
            // Create the stream encryptor
            //SymmetricStreamEncryptor sse = des.CreateEncryptor();

            //CryptoMemoryStream cms = new CryptoMemoryStream();

            //sse.SetSink(cms);
            
            //sse.Write(clearText);
            //sse.CloseStream();

            //cipherText = cms.Data;	// Return the encrypted bytes

        }

        public string DesEncrypt(String stringToEncrypt){
                          
              byte[] inputByteArray = Encoding.UTF8.GetBytes(stringToEncrypt);

                
              // Create instance of DES class
              DES des = DES.Create();
              des.Key = key;
              des.GenerateIV();

              MemoryStream ms = new MemoryStream();
              
              CryptoStream cs = new CryptoStream(ms, des.CreateEncryptor(), CryptoStreamMode.Write);
            
            cs.Write(inputByteArray, 0, inputByteArray.Length);

            cs.Close();

            char[] c = Encoding.UTF8.GetChars(ms.ToArray());

            /* b1 junk
            // Create stream encryptor
              SymmetricStreamEncryptor sse = des.CreateEncryptor();

              CryptoMemoryStream cms = new CryptoMemoryStream();

              sse.SetSink(cms);

              sse.Write(inputByteArray);
              sse.CloseStream();

              
             // Converth the bytes back into a string
              char[] c = Encoding.UTF8.GetChars(cms.Data);
            */
              return c.ToString();
        }


    } // class DES
} // namespace Cifs.Util
