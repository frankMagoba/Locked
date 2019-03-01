using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.IO;
using System.Security;
using System.Security.Cryptography;
using System.Runtime.InteropServices;
using System.Text.RegularExpressions;

namespace PrivateLocker
{
    public static class EncryptionUtils
    {
        static List<FileInfo> files = new List<FileInfo>();  // List that will hold the files and sub files in path
        static List<DirectoryInfo> folders = new List<DirectoryInfo>(); // List that hold directories that cannot be accessed


        public static bool EncryptedFolder(string folderDirectory,string pword)
        {
            bool status = false;

            try
            {
                status = Directory.Exists(folderDirectory);

                if(status)
                {
                    DirectoryInfo di = new DirectoryInfo(folderDirectory);
                    
                    //Clear Folder and File list
                    folders = new List<DirectoryInfo>();
                    files = new List<FileInfo>();
                    //Build new Folder and File list
                    GetAllFilesInDir(di, "*");

                    foreach (FileInfo fi in files)
                    {
                        EncryptFile(fi.FullName,pword);
                    }
                }
                
            }
            catch (Exception ex)
            {
                Console.WriteLine(ex.Message);
                status = false;
            }

            return status;
        }

        public static bool DecryptFolder(string folderDirectory,string pword)
        {
            bool status = false;

            try
            {
                status = Directory.Exists(folderDirectory);

                if (status)
                {
                    DirectoryInfo di = new DirectoryInfo(folderDirectory);

                    //Clear Folder and File list
                    folders = new List<DirectoryInfo>();
                    files = new List<FileInfo>();
                    //Build new Folder and File list
                    GetAllFilesInDir(di, "*");

                    foreach (FileInfo fi in files)
                    {
                        DecryptFile(fi.FullName, pword);
                    }
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine(ex.Message);
                status = false;
            }

            return status;
        }

        private static void GetAllFilesInDir(DirectoryInfo dir, string searchPattern)
        {
            // list the files
            try
            {
                foreach (FileInfo f in dir.GetFiles(searchPattern))
                {
                    //Console.WriteLine("File {0}", f.FullName);
                    files.Add(f);
                }
            }
            catch
            {
                Console.WriteLine("Directory {0}  \n could not be accessed!!!!", dir.FullName);
                return;  // We already got an error trying to access dir so don't try to access it again
            }

            // process each directory
            // If I have been able to see the files in the directory I should also be able 
            // to look at its directories so I don't think I should place this in a try catch block
            foreach (DirectoryInfo d in dir.GetDirectories())
            {
                folders.Add(d);
                GetAllFilesInDir(d, searchPattern);
            }
        }

        private static void EncryptFile(string inputFile, string pword)
        {
            try
            {
                string ext = Path.GetExtension(inputFile);
                string outputFile = inputFile.Replace(ext, "_enc" + ext);
                string password = pword;

                //Encrypt the password and make sure its a 128Bit / 16 byte key
                System.Text.UTF8Encoding UTF8 = new UTF8Encoding();
                MD5CryptoServiceProvider HashProvider = new MD5CryptoServiceProvider();
                byte[] key = HashProvider.ComputeHash(UTF8.GetBytes(password));;

                //Prepare the file for encryption by getting it into a stream
                string cryptFile = outputFile;
                FileStream fsCrypt = new FileStream(cryptFile, FileMode.Create);

                //Setup the Encryption Standard using Write mode
                RijndaelManaged RMCrypto = new RijndaelManaged();
                CryptoStream cs = new CryptoStream(fsCrypt,RMCrypto.CreateEncryptor(key, key),CryptoStreamMode.Write);

                //Write the encrypted file stream
                FileStream fsIn = new FileStream(inputFile, FileMode.Open);
                int data;
                while ((data = fsIn.ReadByte()) != -1)
                { 
                    cs.WriteByte((byte)data); 
                }

                //Close all the Writers
                fsIn.Close();
                cs.Close();
                fsCrypt.Close();

                //Delete the original file
                File.Delete(inputFile);
                //Rename the encrypted file to that of the original
                File.Copy(outputFile, inputFile);
                File.Delete(outputFile);
            }
            catch (Exception ex)
            {
                Console.WriteLine(ex.Message);
            }
        }

        private static void DecryptFile(string inputFile, string pword)
        {
            string ext = Path.GetExtension(inputFile);
            string outputFile = inputFile.Replace(ext, "_enc" + ext);
            string password = pword;

            //Encrypt the password and make sure its a 128Bit / 16 byte key
            System.Text.UTF8Encoding UTF8 = new UTF8Encoding();
            MD5CryptoServiceProvider HashProvider = new MD5CryptoServiceProvider();
            byte[] key = HashProvider.ComputeHash(UTF8.GetBytes(password)); ;

            //Prepare the file for decryption by getting it into a stream
            FileStream fsCrypt = new FileStream(inputFile, FileMode.Open);

            //Setup the Decryption Standard using Read mode
            RijndaelManaged RMCrypto = new RijndaelManaged();
            CryptoStream cs = new CryptoStream(fsCrypt, RMCrypto.CreateDecryptor(key, key), CryptoStreamMode.Read);

            //Write the decrypted file stream
            FileStream fsOut = new FileStream(outputFile, FileMode.Create);
            int data;
            while ((data = cs.ReadByte()) != -1)
            { fsOut.WriteByte((byte)data); }

            //Close all the Writers
            fsOut.Close();
            cs.Close();
            fsCrypt.Close();

            //Delete the original file
            File.Delete(inputFile);
            //Rename the encrypted file to that of the original
            File.Copy(outputFile, inputFile);
            File.Delete(outputFile);
        }
    }

    

    
}
