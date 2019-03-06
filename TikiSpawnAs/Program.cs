using System;

namespace TikiSpawnAs
{
    class Program
    {
        static void Main(string[] args)
        {
            string encodedShellcode = @"";

            if (args.Length != 3)
            {
                Console.WriteLine("Usage: TikiSpawnAs.exe DOMAIN\\User targetProcess");
                Console.WriteLine("       TikiSpawnAs.exe LAB\\Rasta \"C:\\\\Program Files\\\\Internet Explorer\\\\iexplore.exe\"");

                Environment.Exit(1);
            }

            
            string username = args[0];
            string password = args[1];
            string targetProcess = args[2];

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