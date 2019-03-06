using System.Diagnostics;

namespace TikiTorch
{
    public class PPID
    {
        public static int FindExplorer()
        {
            int pid;

            Process[] processes = Process.GetProcessesByName("explorer");

            if (processes.Length == 1)
            {
                pid = processes[0].Id;
            } else
            {
                pid = 0;
            }

            return pid;

        }
    }
}
