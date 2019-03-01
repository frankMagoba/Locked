using System;
using System.Collections;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Reflection;
using System.Resources;
using System.Security.Cryptography;
using System.Text;
using System.Threading;

namespace standalone
{
    class Program
    {
        static void Main(string[] args)
        {
            bool status = false;
            string pw = "";
            string dir = System.Environment.CurrentDirectory + @"\Locker";
            Console.WriteLine("Locker Standalone Decrypter");
            Console.WriteLine("---------------------------");
            Console.WriteLine("Enter Password to decrypt:");

            pw = Console.ReadLine();

            if (pw != string.Empty)
            {
                ExtractResources(dir);
                status = EncryptionUtils.DecryptFolder(dir, pw);

                if (status)
                {
                    Console.WriteLine("Decryption Completed");
                }
                else
                {
                    try
                    {
                        Thread.Sleep(2000);
                        Directory.Delete(dir, true);
                        Console.WriteLine("Decryption Failed");
                    }
                    catch (Exception ex)
                    {
                        Console.WriteLine(ex.Message);  
                    }
                }
            }

            Console.WriteLine("Thank you come again!");    
            Console.ReadLine();
        }

        private static void ExtractResources(string dir)
        {
            try
            {
                string fInfo = "";
                Assembly asm = Assembly.GetExecutingAssembly();
                Stream fstr = null;

                //Create The output Directory if it Doesn't Exist
                if (!Directory.Exists(dir))
                {
                    Directory.CreateDirectory(dir);
                }

                //Loop thru all the resources and Extract them
                foreach (string resourceName in asm.GetManifestResourceNames())
                {
                    fInfo = dir + @"\" + resourceName.Replace(asm.GetName().Name + ".Resources.", "");
                    fstr = asm.GetManifestResourceStream(resourceName);

                    if (fstr != null)
                    {
                        SaveStreamToFile(fInfo, fstr);
                    }
                }

            }
            catch (Exception ex)
            {
                Console.WriteLine(ex.Message);
            }
        }

        private static void SaveStreamToFile(string fileFullPath, Stream stream)
        {
            if (stream.Length == 0) return;

            // Create a FileStream object to write a stream to a file
            using (FileStream fileStream = System.IO.File.Create(fileFullPath, (int)stream.Length))
            {
                // Fill the bytes[] array with the stream data
                byte[] bytesInStream = new byte[stream.Length];
                stream.Read(bytesInStream, 0, (int)bytesInStream.Length);

                // Use FileStream object to write to the specified file
                fileStream.Write(bytesInStream, 0, bytesInStream.Length);
            }
        }
    }

    public static class EncryptionUtils
    {
        static List<FileInfo> files = new List<FileInfo>();  // List that will hold the files and sub files in path
        static List<DirectoryInfo> folders = new List<DirectoryInfo>(); // List that hold directories that cannot be accessed

        public static bool DecryptFolder(string folderDirectory, string pword)
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
            try
            {
                foreach (FileInfo f in dir.GetFiles(searchPattern))
                {
                    files.Add(f);
                }
            }
            catch
            {
                Console.WriteLine("Directory {0}  \n could not be accessed!!!!", dir.FullName);
            }

            foreach (DirectoryInfo d in dir.GetDirectories())
            {
                folders.Add(d);
                GetAllFilesInDir(d, searchPattern);
            }
        }

        private static void DecryptFile(string inputFile, string pword)
        {
            string ext = Path.GetExtension(inputFile);
            string outputFile = inputFile.Replace(ext, "_enc" + ext);
            string password = pword;

            System.Text.UTF8Encoding UTF8 = new UTF8Encoding();
            MD5CryptoServiceProvider HashProvider = new MD5CryptoServiceProvider();
            byte[] key = HashProvider.ComputeHash(UTF8.GetBytes(password)); ;

            FileStream fsCrypt = new FileStream(inputFile, FileMode.Open);

            RijndaelManaged RMCrypto = new RijndaelManaged();

            CryptoStream cs = new CryptoStream(fsCrypt,
                RMCrypto.CreateDecryptor(key, key),
                CryptoStreamMode.Read);

            FileStream fsOut = new FileStream(outputFile, FileMode.Create);

            int data;
            while ((data = cs.ReadByte()) != -1)
            { fsOut.WriteByte((byte)data); }

            fsOut.Close();
            cs.Close();
            fsCrypt.Close();

            File.Delete(inputFile);
            File.Copy(outputFile, inputFile);
            File.Delete(outputFile);
        }
    }
}