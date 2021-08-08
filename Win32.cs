using System;
using System.Runtime.InteropServices;
using System.Text;
using Microsoft.Win32;

namespace SharpReflectiveDll
{
	// Token: 0x02000005 RID: 5
	public static class Win32
	{
		// Token: 0x02000013 RID: 19
		public static class Kernel32
		{
			// Token: 0x06000031 RID: 49
			[DllImport("kernel32.dll")]
			public static extern IntPtr GetCurrentThread();

			// Token: 0x06000032 RID: 50
			[DllImport("kernel32.dll")]
			public static extern IntPtr GetCurrentProcess();

			// Token: 0x06000033 RID: 51
			[DllImport("kernel32.dll", CharSet = CharSet.Ansi, ExactSpelling = true, SetLastError = true)]
			public static extern IntPtr GetProcAddress(IntPtr hModule, string procName);

			// Token: 0x06000034 RID: 52
			[DllImport("kernel32.dll")]
			public static extern void GetSystemInfo(out Win32.WinBase._SYSTEM_INFO lpSystemInfo);

			// Token: 0x06000035 RID: 53
			[DllImport("kernel32.dll", SetLastError = true)]
			public static extern IntPtr GlobalSize(IntPtr hMem);

			// Token: 0x06000036 RID: 54
			[DllImport("kernel32.dll")]
			public static extern IntPtr OpenProcess(Win32.Kernel32.ProcessAccessFlags dwDesiredAccess, bool bInheritHandle, uint dwProcessId);

			// Token: 0x06000037 RID: 55
			[DllImport("kernel32.dll")]
			public static extern bool OpenProcessToken(IntPtr hProcess, uint dwDesiredAccess, out IntPtr hToken);

			// Token: 0x06000038 RID: 56
			[DllImport("kernel32.dll")]
			public static extern bool OpenThreadToken(IntPtr ThreadHandle, uint DesiredAccess, bool OpenAsSelf, ref IntPtr TokenHandle);

			// Token: 0x06000039 RID: 57
			[DllImport("kernel32.dll")]
			public static extern IntPtr OpenThread(uint dwDesiredAccess, bool bInheritHandle, uint dwThreadId);

			// Token: 0x0600003A RID: 58
			[DllImport("kernel32.dll")]
			public static extern bool ReadProcessMemory(IntPtr hProcess, uint lpBaseAddress, IntPtr lpBuffer, uint nSize, ref uint lpNumberOfBytesRead);

			// Token: 0x0600003B RID: 59
			[DllImport("kernel32.dll", EntryPoint = "ReadProcessMemory")]
			public static extern bool ReadProcessMemory64(IntPtr hProcess, ulong lpBaseAddress, IntPtr lpBuffer, ulong nSize, ref uint lpNumberOfBytesRead);

			// Token: 0x0600003C RID: 60
			[DllImport("kernel32.dll")]
			public static extern uint SearchPath(string lpPath, string lpFileName, string lpExtension, uint nBufferLength, [MarshalAs(UnmanagedType.LPTStr)] StringBuilder lpBuffer, ref IntPtr lpFilePart);

			// Token: 0x0600003D RID: 61
			[DllImport("kernel32.dll", EntryPoint = "VirtualQueryEx")]
			public static extern int VirtualQueryEx32(IntPtr hProcess, IntPtr lpAddress, out Win32.WinNT._MEMORY_BASIC_INFORMATION32 lpBuffer, uint dwLength);

			// Token: 0x0600003E RID: 62
			[DllImport("kernel32.dll", EntryPoint = "VirtualQueryEx")]
			public static extern int VirtualQueryEx64(IntPtr hProcess, IntPtr lpAddress, out Win32.WinNT._MEMORY_BASIC_INFORMATION64 lpBuffer, uint dwLength);

			// Token: 0x0600003F RID: 63
			[DllImport("kernel32.dll")]
			public static extern IntPtr VirtualAlloc(IntPtr lpStartAddr, uint size, uint flAllocationType, uint flProtect);

			// Token: 0x06000040 RID: 64
			[DllImport("kernel32.dll")]
			public static extern bool VirtualProtect(IntPtr lpAddress, UIntPtr dwSize, uint flNewProtect, out uint lpflOldProtect);

			// Token: 0x06000041 RID: 65
			[DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
			public static extern IntPtr LoadLibrary(string lpFileName);

			// Token: 0x06000042 RID: 66
			[DllImport("kernel32.dll")]
			public static extern IntPtr CreateThread(IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr param, uint dwCreationFlags, IntPtr lpThreadId);

			// Token: 0x06000043 RID: 67
			[DllImport("kernel32.dll")]
			public static extern uint WaitForSingleObject(IntPtr hHandle, uint dwMilliseconds);

			// Token: 0x06000044 RID: 68
			[DllImport("kernel32.dll", SetLastError = true)]
			public static extern IntPtr LocalFree(IntPtr hMem);

			// Token: 0x06000045 RID: 69
			[DllImport("kernel32.dll")]
			public static extern bool CloseHandle(IntPtr hProcess);

			// Token: 0x040000AB RID: 171
			public static uint MEM_COMMIT = 4096U;

			// Token: 0x040000AC RID: 172
			public static uint MEM_RESERVE = 8192U;

			// Token: 0x0200001E RID: 30
			public struct IMAGE_BASE_RELOCATION
			{
				// Token: 0x040000D6 RID: 214
				public uint VirtualAdress;

				// Token: 0x040000D7 RID: 215
				public uint SizeOfBlock;
			}

			// Token: 0x0200001F RID: 31
			public struct IMAGE_IMPORT_DESCRIPTOR
			{
				// Token: 0x040000D8 RID: 216
				public uint OriginalFirstThunk;

				// Token: 0x040000D9 RID: 217
				public uint TimeDateStamp;

				// Token: 0x040000DA RID: 218
				public uint ForwarderChain;

				// Token: 0x040000DB RID: 219
				public uint Name;

				// Token: 0x040000DC RID: 220
				public uint FirstThunk;
			}

			// Token: 0x02000020 RID: 32
			[Flags]
			public enum ProcessAccessFlags : uint
			{
				// Token: 0x040000DE RID: 222
				PROCESS_ALL_ACCESS = 2035711U,
				// Token: 0x040000DF RID: 223
				PROCESS_CREATE_PROCESS = 128U,
				// Token: 0x040000E0 RID: 224
				PROCESS_CREATE_THREAD = 2U,
				// Token: 0x040000E1 RID: 225
				PROCESS_DUP_HANDLE = 64U,
				// Token: 0x040000E2 RID: 226
				PROCESS_QUERY_INFORMATION = 1024U,
				// Token: 0x040000E3 RID: 227
				PROCESS_QUERY_LIMITED_INFORMATION = 4096U,
				// Token: 0x040000E4 RID: 228
				PROCESS_SET_INFORMATION = 512U,
				// Token: 0x040000E5 RID: 229
				PROCESS_SET_QUOTA = 256U,
				// Token: 0x040000E6 RID: 230
				PROCESS_SUSPEND_RESUME = 2048U,
				// Token: 0x040000E7 RID: 231
				PROCESS_TERMINATE = 1U,
				// Token: 0x040000E8 RID: 232
				PROCESS_VM_OPERATION = 8U,
				// Token: 0x040000E9 RID: 233
				PROCESS_VM_READ = 16U,
				// Token: 0x040000EA RID: 234
				PROCESS_VM_WRITE = 32U,
				// Token: 0x040000EB RID: 235
				SYNCHRONIZE = 1048576U
			}
		}

		// Token: 0x02000014 RID: 20
		public static class Netapi32
		{
			// Token: 0x06000047 RID: 71
			[DllImport("netapi32.dll")]
			public static extern int NetLocalGroupEnum([MarshalAs(UnmanagedType.LPWStr)] string servername, int level, out IntPtr bufptr, int prefmaxlen, out int entriesread, out int totalentries, ref int resume_handle);

			// Token: 0x06000048 RID: 72
			[DllImport("netapi32.dll")]
			public static extern int NetLocalGroupGetMembers([MarshalAs(UnmanagedType.LPWStr)] string servername, [MarshalAs(UnmanagedType.LPWStr)] string localgroupname, int level, out IntPtr bufptr, int prefmaxlen, out int entriesread, out int totalentries, ref int resume_handle);

			// Token: 0x06000049 RID: 73
			[DllImport("netapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
			public static extern int NetWkstaUserEnum(string servername, int level, out IntPtr bufptr, int prefmaxlen, out int entriesread, out int totalentries, ref int resume_handle);

			// Token: 0x0600004A RID: 74
			[DllImport("netapi32.dll", SetLastError = true)]
			public static extern int NetSessionEnum([MarshalAs(UnmanagedType.LPWStr)] [In] string ServerName, [MarshalAs(UnmanagedType.LPWStr)] [In] string UncClientName, [MarshalAs(UnmanagedType.LPWStr)] [In] string UserName, int level, out IntPtr bufptr, int prefmaxlen, out int entriesread, out int totalentries, ref int resume_handle);

			// Token: 0x0600004B RID: 75
			[DllImport("netapi32.dll", SetLastError = true)]
			public static extern int NetApiBufferFree(IntPtr Buffer);

			// Token: 0x02000021 RID: 33
			[StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
			public struct LOCALGROUP_USERS_INFO_0
			{
				// Token: 0x040000EC RID: 236
				[MarshalAs(UnmanagedType.LPWStr)]
				internal string name;
			}

			// Token: 0x02000022 RID: 34
			public struct LOCALGROUP_USERS_INFO_1
			{
				// Token: 0x040000ED RID: 237
				[MarshalAs(UnmanagedType.LPWStr)]
				public string name;

				// Token: 0x040000EE RID: 238
				[MarshalAs(UnmanagedType.LPWStr)]
				public string comment;
			}

			// Token: 0x02000023 RID: 35
			[StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
			public struct LOCALGROUP_MEMBERS_INFO_2
			{
				// Token: 0x040000EF RID: 239
				public IntPtr lgrmi2_sid;

				// Token: 0x040000F0 RID: 240
				public int lgrmi2_sidusage;

				// Token: 0x040000F1 RID: 241
				[MarshalAs(UnmanagedType.LPWStr)]
				public string lgrmi2_domainandname;
			}

			// Token: 0x02000024 RID: 36
			[StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
			public struct WKSTA_USER_INFO_1
			{
				// Token: 0x040000F2 RID: 242
				public string wkui1_username;

				// Token: 0x040000F3 RID: 243
				public string wkui1_logon_domain;

				// Token: 0x040000F4 RID: 244
				public string wkui1_oth_domains;

				// Token: 0x040000F5 RID: 245
				public string wkui1_logon_server;
			}

			// Token: 0x02000025 RID: 37
			[StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
			public struct SESSION_INFO_10
			{
				// Token: 0x040000F6 RID: 246
				public string sesi10_cname;

				// Token: 0x040000F7 RID: 247
				public string sesi10_username;

				// Token: 0x040000F8 RID: 248
				public int sesi10_time;

				// Token: 0x040000F9 RID: 249
				public int sesi10_idle_time;
			}

			// Token: 0x02000026 RID: 38
			public enum SID_NAME_USE : ushort
			{
				// Token: 0x040000FB RID: 251
				SidTypeUser = 1,
				// Token: 0x040000FC RID: 252
				SidTypeGroup,
				// Token: 0x040000FD RID: 253
				SidTypeDomain,
				// Token: 0x040000FE RID: 254
				SidTypeAlias,
				// Token: 0x040000FF RID: 255
				SidTypeWellKnownGroup,
				// Token: 0x04000100 RID: 256
				SidTypeDeletedAccount,
				// Token: 0x04000101 RID: 257
				SidTypeInvalid,
				// Token: 0x04000102 RID: 258
				SidTypeUnknown,
				// Token: 0x04000103 RID: 259
				SidTypeComputer
			}
		}

		// Token: 0x02000015 RID: 21
		public static class Advapi32
		{
			// Token: 0x0600004C RID: 76
			[DllImport("advapi32.dll", SetLastError = true)]
			public static extern bool AdjustTokenPrivileges(IntPtr TokenHandle, bool DisableAllPrivileges, ref Win32.WinNT._TOKEN_PRIVILEGES NewState, uint BufferLengthInBytes, ref Win32.WinNT._TOKEN_PRIVILEGES PreviousState, out uint ReturnLengthInBytes);

			// Token: 0x0600004D RID: 77
			[DllImport("advapi32.dll", SetLastError = true)]
			public static extern bool AllocateAndInitializeSid(ref Win32.WinNT._SID_IDENTIFIER_AUTHORITY pIdentifierAuthority, byte nSubAuthorityCount, int dwSubAuthority0, int dwSubAuthority1, int dwSubAuthority2, int dwSubAuthority3, int dwSubAuthority4, int dwSubAuthority5, int dwSubAuthority6, int dwSubAuthority7, out IntPtr pSid);

			// Token: 0x0600004E RID: 78
			[DllImport("advapi32.dll", SetLastError = true)]
			public static extern bool AllocateAndInitializeSid(ref Win32.WinNT._SID_IDENTIFIER_AUTHORITY pIdentifierAuthority, byte nSubAuthorityCount, int dwSubAuthority0, int dwSubAuthority1, int dwSubAuthority2, int dwSubAuthority3, int dwSubAuthority4, int dwSubAuthority5, int dwSubAuthority6, int dwSubAuthority7, ref Win32.WinNT._SID pSid);

			// Token: 0x0600004F RID: 79
			[DllImport("advapi32.dll", CharSet = CharSet.Auto, SetLastError = true)]
			public static extern bool ConvertSidToStringSid(IntPtr Sid, out IntPtr StringSid);

			// Token: 0x06000050 RID: 80
			[DllImport("advapi32.dll", SetLastError = true)]
			public static extern bool CreateProcessAsUser(IntPtr hToken, IntPtr lpApplicationName, IntPtr lpCommandLine, ref Win32.WinBase._SECURITY_ATTRIBUTES lpProcessAttributes, ref Win32.WinBase._SECURITY_ATTRIBUTES lpThreadAttributes, bool bInheritHandles, Win32.Advapi32.CREATION_FLAGS dwCreationFlags, IntPtr lpEnvironment, IntPtr lpCurrentDirectory, ref Win32.ProcessThreadsAPI._STARTUPINFO lpStartupInfo, out Win32.ProcessThreadsAPI._PROCESS_INFORMATION lpProcessInfo);

			// Token: 0x06000051 RID: 81
			[DllImport("advapi32.dll", SetLastError = true)]
			public static extern bool CreateProcessAsUserW(IntPtr hToken, IntPtr lpApplicationName, IntPtr lpCommandLine, IntPtr lpProcessAttributes, IntPtr lpThreadAttributes, bool bInheritHandles, Win32.Advapi32.CREATION_FLAGS dwCreationFlags, IntPtr lpEnvironment, IntPtr lpCurrentDirectory, ref Win32.ProcessThreadsAPI._STARTUPINFO lpStartupInfo, out Win32.ProcessThreadsAPI._PROCESS_INFORMATION lpProcessInfo);

			// Token: 0x06000052 RID: 82
			[DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
			public static extern bool CreateProcessWithLogonW(string userName, string domain, string password, int logonFlags, string applicationName, string commandLine, int creationFlags, IntPtr environment, string currentDirectory, ref Win32.ProcessThreadsAPI._STARTUPINFO startupInfo, out Win32.ProcessThreadsAPI._PROCESS_INFORMATION processInformation);

			// Token: 0x06000053 RID: 83
			[DllImport("advapi32.dll", SetLastError = true)]
			public static extern bool CreateProcessWithTokenW(IntPtr hToken, Win32.Advapi32.LOGON_FLAGS dwLogonFlags, IntPtr lpApplicationName, IntPtr lpCommandLine, Win32.Advapi32.CREATION_FLAGS dwCreationFlags, IntPtr lpEnvironment, IntPtr lpCurrentDirectory, ref Win32.ProcessThreadsAPI._STARTUPINFO lpStartupInfo, out Win32.ProcessThreadsAPI._PROCESS_INFORMATION lpProcessInfo);

			// Token: 0x06000054 RID: 84
			[DllImport("advapi32.dll", SetLastError = true)]
			public static extern bool CredEnumerateW(string Filter, int Flags, out int Count, out IntPtr Credentials);

			// Token: 0x06000055 RID: 85
			[DllImport("advapi32.dll", SetLastError = true)]
			public static extern bool CredFree(IntPtr Buffer);

			// Token: 0x06000056 RID: 86
			[DllImport("advapi32.dll", SetLastError = true)]
			public static extern bool CredReadW(string target, Win32.WinCred.CRED_TYPE type, int reservedFlag, out IntPtr credentialPtr);

			// Token: 0x06000057 RID: 87
			[DllImport("advapi32.dll", SetLastError = true)]
			public static extern bool CredWriteW(ref Win32.WinCred._CREDENTIAL userCredential, uint flags);

			// Token: 0x06000058 RID: 88
			[DllImport("advapi32.dll", SetLastError = true)]
			public static extern bool DuplicateTokenEx(IntPtr hExistingToken, uint dwDesiredAccess, ref Win32.WinBase._SECURITY_ATTRIBUTES lpTokenAttributes, Win32.WinNT._SECURITY_IMPERSONATION_LEVEL ImpersonationLevel, Win32.WinNT.TOKEN_TYPE TokenType, out IntPtr phNewToken);

			// Token: 0x06000059 RID: 89
			[DllImport("advapi32.dll", SetLastError = true)]
			public static extern bool GetTokenInformation(IntPtr TokenHandle, Win32.WinNT._TOKEN_INFORMATION_CLASS TokenInformationClass, IntPtr TokenInformation, uint TokenInformationLength, out uint ReturnLength);

			// Token: 0x0600005A RID: 90
			[DllImport("advapi32.dll", SetLastError = true)]
			public static extern bool GetTokenInformation(IntPtr TokenHandle, Win32.WinNT._TOKEN_INFORMATION_CLASS TokenInformationClass, ref Win32.WinNT._TOKEN_STATISTICS TokenInformation, uint TokenInformationLength, out uint ReturnLength);

			// Token: 0x0600005B RID: 91
			[DllImport("advapi32.dll", SetLastError = true)]
			public static extern bool ImpersonateLoggedOnUser(IntPtr hToken);

			// Token: 0x0600005C RID: 92
			[DllImport("advapi32.dll", SetLastError = true)]
			public static extern bool ImpersonateSelf(Win32.WinNT._SECURITY_IMPERSONATION_LEVEL ImpersonationLevel);

			// Token: 0x0600005D RID: 93
			[DllImport("advapi32.dll", SetLastError = true)]
			public static extern bool LogonUserA(string lpszUsername, string lpszDomain, string lpszPassword, Win32.Advapi32.LOGON_TYPE dwLogonType, Win32.Advapi32.LOGON_PROVIDER dwLogonProvider, out IntPtr phToken);

			// Token: 0x0600005E RID: 94
			[DllImport("advapi32.dll", CharSet = CharSet.Auto, SetLastError = true)]
			public static extern bool LookupAccountSid(string lpSystemName, IntPtr Sid, StringBuilder lpName, ref uint cchName, StringBuilder ReferencedDomainName, ref uint cchReferencedDomainName, out Win32.WinNT._SID_NAME_USE peUse);

			// Token: 0x0600005F RID: 95
			[DllImport("advapi32.dll", SetLastError = true)]
			public static extern bool LookupPrivilegeName(string lpSystemName, IntPtr lpLuid, StringBuilder lpName, ref int cchName);

			// Token: 0x06000060 RID: 96
			[DllImport("advapi32.dll", SetLastError = true)]
			public static extern bool LookupPrivilegeValue(string lpSystemName, string lpName, ref Win32.WinNT._LUID luid);

			// Token: 0x06000061 RID: 97
			[DllImport("advapi32.dll", SetLastError = true)]
			public static extern bool PrivilegeCheck(IntPtr ClientToken, Win32.WinNT._PRIVILEGE_SET RequiredPrivileges, out IntPtr pfResult);

			// Token: 0x06000062 RID: 98
			[DllImport("advapi32.dll", CharSet = CharSet.Auto, SetLastError = true)]
			public static extern int RegOpenKeyEx(UIntPtr hKey, string subKey, int ulOptions, int samDesired, out UIntPtr hkResult);

			// Token: 0x06000063 RID: 99
			[DllImport("advapi32.dll", SetLastError = true)]
			public static extern uint RegQueryValueEx(UIntPtr hKey, string lpValueName, int lpReserved, ref RegistryValueKind lpType, IntPtr lpData, ref int lpcbData);

			// Token: 0x06000064 RID: 100
			[DllImport("advapi32.dll", SetLastError = true)]
			public static extern int RegQueryInfoKey(UIntPtr hKey, StringBuilder lpClass, ref uint lpcchClass, IntPtr lpReserved, out uint lpcSubkey, out uint lpcchMaxSubkeyLen, out uint lpcchMaxClassLen, out uint lpcValues, out uint lpcchMaxValueNameLen, out uint lpcbMaxValueLen, IntPtr lpSecurityDescriptor, IntPtr lpftLastWriteTime);

			// Token: 0x06000065 RID: 101
			[DllImport("advapi32.dll", SetLastError = true)]
			public static extern bool RevertToSelf();

			// Token: 0x040000AD RID: 173
			public const uint STANDARD_RIGHTS_REQUIRED = 983040U;

			// Token: 0x040000AE RID: 174
			public const uint STANDARD_RIGHTS_READ = 131072U;

			// Token: 0x040000AF RID: 175
			public const uint TOKEN_ASSIGN_PRIMARY = 1U;

			// Token: 0x040000B0 RID: 176
			public const uint TOKEN_DUPLICATE = 2U;

			// Token: 0x040000B1 RID: 177
			public const uint TOKEN_IMPERSONATE = 4U;

			// Token: 0x040000B2 RID: 178
			public const uint TOKEN_QUERY = 8U;

			// Token: 0x040000B3 RID: 179
			public const uint TOKEN_QUERY_SOURCE = 16U;

			// Token: 0x040000B4 RID: 180
			public const uint TOKEN_ADJUST_PRIVILEGES = 32U;

			// Token: 0x040000B5 RID: 181
			public const uint TOKEN_ADJUST_GROUPS = 64U;

			// Token: 0x040000B6 RID: 182
			public const uint TOKEN_ADJUST_DEFAULT = 128U;

			// Token: 0x040000B7 RID: 183
			public const uint TOKEN_ADJUST_SESSIONID = 256U;

			// Token: 0x040000B8 RID: 184
			public const uint TOKEN_READ = 131080U;

			// Token: 0x040000B9 RID: 185
			public const uint TOKEN_ALL_ACCESS = 983551U;

			// Token: 0x040000BA RID: 186
			public const uint TOKEN_ALT = 15U;

			// Token: 0x02000027 RID: 39
			[Flags]
			public enum CREATION_FLAGS
			{
				// Token: 0x04000105 RID: 261
				NONE = 0,
				// Token: 0x04000106 RID: 262
				CREATE_DEFAULT_ERROR_MODE = 67108864,
				// Token: 0x04000107 RID: 263
				CREATE_NEW_CONSOLE = 16,
				// Token: 0x04000108 RID: 264
				CREATE_NEW_PROCESS_GROUP = 512,
				// Token: 0x04000109 RID: 265
				CREATE_SEPARATE_WOW_VDM = 2048,
				// Token: 0x0400010A RID: 266
				CREATE_SUSPENDED = 4,
				// Token: 0x0400010B RID: 267
				CREATE_UNICODE_ENVIRONMENT = 1024,
				// Token: 0x0400010C RID: 268
				EXTENDED_STARTUPINFO_PRESENT = 524288
			}

			// Token: 0x02000028 RID: 40
			[Flags]
			public enum LOGON_FLAGS
			{
				// Token: 0x0400010E RID: 270
				LOGON_WITH_PROFILE = 1,
				// Token: 0x0400010F RID: 271
				LOGON_NETCREDENTIALS_ONLY = 2
			}

			// Token: 0x02000029 RID: 41
			public enum LOGON_TYPE
			{
				// Token: 0x04000111 RID: 273
				LOGON32_LOGON_INTERACTIVE = 2,
				// Token: 0x04000112 RID: 274
				LOGON32_LOGON_NETWORK,
				// Token: 0x04000113 RID: 275
				LOGON32_LOGON_BATCH,
				// Token: 0x04000114 RID: 276
				LOGON32_LOGON_SERVICE,
				// Token: 0x04000115 RID: 277
				LOGON32_LOGON_UNLOCK = 7,
				// Token: 0x04000116 RID: 278
				LOGON32_LOGON_NETWORK_CLEARTEXT,
				// Token: 0x04000117 RID: 279
				LOGON32_LOGON_NEW_CREDENTIALS
			}

			// Token: 0x0200002A RID: 42
			public enum LOGON_PROVIDER
			{
				// Token: 0x04000119 RID: 281
				LOGON32_PROVIDER_DEFAULT,
				// Token: 0x0400011A RID: 282
				LOGON32_PROVIDER_WINNT35,
				// Token: 0x0400011B RID: 283
				LOGON32_PROVIDER_WINNT40,
				// Token: 0x0400011C RID: 284
				LOGON32_PROVIDER_WINNT50
			}
		}

		// Token: 0x02000016 RID: 22
		public static class Dbghelp
		{
			// Token: 0x06000066 RID: 102
			[DllImport("dbghelp.dll", SetLastError = true)]
			public static extern bool MiniDumpWriteDump(IntPtr hProcess, uint ProcessId, SafeHandle hFile, Win32.Dbghelp.MINIDUMP_TYPE DumpType, IntPtr ExceptionParam, IntPtr UserStreamParam, IntPtr CallbackParam);

			// Token: 0x0200002B RID: 43
			public enum MINIDUMP_TYPE
			{
				// Token: 0x0400011E RID: 286
				MiniDumpNormal,
				// Token: 0x0400011F RID: 287
				MiniDumpWithDataSegs,
				// Token: 0x04000120 RID: 288
				MiniDumpWithFullMemory,
				// Token: 0x04000121 RID: 289
				MiniDumpWithHandleData = 4,
				// Token: 0x04000122 RID: 290
				MiniDumpFilterMemory = 8,
				// Token: 0x04000123 RID: 291
				MiniDumpScanMemory = 16,
				// Token: 0x04000124 RID: 292
				MiniDumpWithUnloadedModules = 32,
				// Token: 0x04000125 RID: 293
				MiniDumpWithIndirectlyReferencedMemory = 64,
				// Token: 0x04000126 RID: 294
				MiniDumpFilterModulePaths = 128,
				// Token: 0x04000127 RID: 295
				MiniDumpWithProcessThreadData = 256,
				// Token: 0x04000128 RID: 296
				MiniDumpWithPrivateReadWriteMemory = 512,
				// Token: 0x04000129 RID: 297
				MiniDumpWithoutOptionalData = 1024,
				// Token: 0x0400012A RID: 298
				MiniDumpWithFullMemoryInfo = 2048,
				// Token: 0x0400012B RID: 299
				MiniDumpWithThreadInfo = 4096,
				// Token: 0x0400012C RID: 300
				MiniDumpWithCodeSegs = 8192,
				// Token: 0x0400012D RID: 301
				MiniDumpWithoutAuxiliaryState = 16384,
				// Token: 0x0400012E RID: 302
				MiniDumpWithFullAuxiliaryState = 32768,
				// Token: 0x0400012F RID: 303
				MiniDumpWithPrivateWriteCopyMemory = 65536,
				// Token: 0x04000130 RID: 304
				MiniDumpIgnoreInaccessibleMemory = 131072,
				// Token: 0x04000131 RID: 305
				MiniDumpWithTokenInformation = 262144,
				// Token: 0x04000132 RID: 306
				MiniDumpWithModuleHeaders = 524288,
				// Token: 0x04000133 RID: 307
				MiniDumpFilterTriage = 1048576,
				// Token: 0x04000134 RID: 308
				MiniDumpValidTypeFlags = 2097151
			}
		}

		// Token: 0x02000017 RID: 23
		public static class ActiveDs
		{
			// Token: 0x06000067 RID: 103
			[DllImport("activeds.dll")]
			public static extern IntPtr Init(int lnSetType, [MarshalAs(UnmanagedType.BStr)] string bstrADsPath);

			// Token: 0x06000068 RID: 104
			[DllImport("activeds.dll")]
			public static extern IntPtr Set(int lnSetType, [MarshalAs(UnmanagedType.BStr)] string bstrADsPath);

			// Token: 0x06000069 RID: 105
			[DllImport("activeds.dll")]
			public static extern IntPtr Get(int lnSetType, [MarshalAs(UnmanagedType.BStr)] ref string pbstrADsPath);

			// Token: 0x0600006A RID: 106
			[DllImport("activeds.dll")]
			public static extern IntPtr InitEx(int lnSetType, [MarshalAs(UnmanagedType.BStr)] string bstrADsPath, [MarshalAs(UnmanagedType.BStr)] string bstrUserID, [MarshalAs(UnmanagedType.BStr)] string bstrDomain, [MarshalAs(UnmanagedType.BStr)] string bstrPassword);

			// Token: 0x0600006B RID: 107
			[DllImport("activeds.dll")]
			public static extern IntPtr put_ChaseReferral(int lnChangeReferral);
		}

		// Token: 0x02000018 RID: 24
		public class WinBase
		{
			// Token: 0x0200002C RID: 44
			public struct _SYSTEM_INFO
			{
				// Token: 0x04000135 RID: 309
				public ushort wProcessorArchitecture;

				// Token: 0x04000136 RID: 310
				public ushort wReserved;

				// Token: 0x04000137 RID: 311
				public uint dwPageSize;

				// Token: 0x04000138 RID: 312
				public IntPtr lpMinimumApplicationAddress;

				// Token: 0x04000139 RID: 313
				public IntPtr lpMaximumApplicationAddress;

				// Token: 0x0400013A RID: 314
				public IntPtr dwActiveProcessorMask;

				// Token: 0x0400013B RID: 315
				public uint dwNumberOfProcessors;

				// Token: 0x0400013C RID: 316
				public uint dwProcessorType;

				// Token: 0x0400013D RID: 317
				public uint dwAllocationGranularity;

				// Token: 0x0400013E RID: 318
				public ushort wProcessorLevel;

				// Token: 0x0400013F RID: 319
				public ushort wProcessorRevision;
			}

			// Token: 0x0200002D RID: 45
			public struct _SECURITY_ATTRIBUTES
			{
				// Token: 0x04000140 RID: 320
				private uint nLength;

				// Token: 0x04000141 RID: 321
				private IntPtr lpSecurityDescriptor;

				// Token: 0x04000142 RID: 322
				private bool bInheritHandle;
			}
		}

		// Token: 0x02000019 RID: 25
		public class WinNT
		{
			// Token: 0x040000BB RID: 187
			public const uint PAGE_NOACCESS = 1U;

			// Token: 0x040000BC RID: 188
			public const uint PAGE_READONLY = 2U;

			// Token: 0x040000BD RID: 189
			public const uint PAGE_READWRITE = 4U;

			// Token: 0x040000BE RID: 190
			public const uint PAGE_WRITECOPY = 8U;

			// Token: 0x040000BF RID: 191
			public const uint PAGE_EXECUTE = 16U;

			// Token: 0x040000C0 RID: 192
			public const uint PAGE_EXECUTE_READ = 32U;

			// Token: 0x040000C1 RID: 193
			public const uint PAGE_EXECUTE_READWRITE = 64U;

			// Token: 0x040000C2 RID: 194
			public const uint PAGE_EXECUTE_WRITECOPY = 128U;

			// Token: 0x040000C3 RID: 195
			public const uint PAGE_GUARD = 256U;

			// Token: 0x040000C4 RID: 196
			public const uint PAGE_NOCACHE = 512U;

			// Token: 0x040000C5 RID: 197
			public const uint PAGE_WRITECOMBINE = 1024U;

			// Token: 0x040000C6 RID: 198
			public const uint PAGE_TARGETS_INVALID = 1073741824U;

			// Token: 0x040000C7 RID: 199
			public const uint PAGE_TARGETS_NO_UPDATE = 1073741824U;

			// Token: 0x040000C8 RID: 200
			public const uint SE_PRIVILEGE_ENABLED = 2U;

			// Token: 0x040000C9 RID: 201
			public const uint SE_PRIVILEGE_ENABLED_BY_DEFAULT = 1U;

			// Token: 0x040000CA RID: 202
			public const uint SE_PRIVILEGE_REMOVED = 4U;

			// Token: 0x040000CB RID: 203
			public const uint SE_PRIVILEGE_USED_FOR_ACCESS = 3U;

			// Token: 0x040000CC RID: 204
			public const ulong SE_GROUP_ENABLED = 4UL;

			// Token: 0x040000CD RID: 205
			public const ulong SE_GROUP_ENABLED_BY_DEFAULT = 2UL;

			// Token: 0x040000CE RID: 206
			public const ulong SE_GROUP_INTEGRITY = 32UL;

			// Token: 0x040000CF RID: 207
			public const uint SE_GROUP_INTEGRITY_32 = 32U;

			// Token: 0x040000D0 RID: 208
			public const ulong SE_GROUP_INTEGRITY_ENABLED = 64UL;

			// Token: 0x040000D1 RID: 209
			public const ulong SE_GROUP_LOGON_ID = 3221225472UL;

			// Token: 0x040000D2 RID: 210
			public const ulong SE_GROUP_MANDATORY = 1UL;

			// Token: 0x040000D3 RID: 211
			public const ulong SE_GROUP_OWNER = 8UL;

			// Token: 0x040000D4 RID: 212
			public const ulong SE_GROUP_RESOURCE = 536870912UL;

			// Token: 0x040000D5 RID: 213
			public const ulong SE_GROUP_USE_FOR_DENY_ONLY = 16UL;

			// Token: 0x0200002E RID: 46
			public enum _SECURITY_IMPERSONATION_LEVEL
			{
				// Token: 0x04000144 RID: 324
				SecurityAnonymous,
				// Token: 0x04000145 RID: 325
				SecurityIdentification,
				// Token: 0x04000146 RID: 326
				SecurityImpersonation,
				// Token: 0x04000147 RID: 327
				SecurityDelegation
			}

			// Token: 0x0200002F RID: 47
			public enum TOKEN_TYPE
			{
				// Token: 0x04000149 RID: 329
				TokenPrimary = 1,
				// Token: 0x0400014A RID: 330
				TokenImpersonation
			}

			// Token: 0x02000030 RID: 48
			public enum _TOKEN_ELEVATION_TYPE
			{
				// Token: 0x0400014C RID: 332
				TokenElevationTypeDefault = 1,
				// Token: 0x0400014D RID: 333
				TokenElevationTypeFull,
				// Token: 0x0400014E RID: 334
				TokenElevationTypeLimited
			}

			// Token: 0x02000031 RID: 49
			public struct _MEMORY_BASIC_INFORMATION32
			{
				// Token: 0x0400014F RID: 335
				public uint BaseAddress;

				// Token: 0x04000150 RID: 336
				public uint AllocationBase;

				// Token: 0x04000151 RID: 337
				public uint AllocationProtect;

				// Token: 0x04000152 RID: 338
				public uint RegionSize;

				// Token: 0x04000153 RID: 339
				public uint State;

				// Token: 0x04000154 RID: 340
				public uint Protect;

				// Token: 0x04000155 RID: 341
				public uint Type;
			}

			// Token: 0x02000032 RID: 50
			public struct _MEMORY_BASIC_INFORMATION64
			{
				// Token: 0x04000156 RID: 342
				public ulong BaseAddress;

				// Token: 0x04000157 RID: 343
				public ulong AllocationBase;

				// Token: 0x04000158 RID: 344
				public uint AllocationProtect;

				// Token: 0x04000159 RID: 345
				public uint __alignment1;

				// Token: 0x0400015A RID: 346
				public ulong RegionSize;

				// Token: 0x0400015B RID: 347
				public uint State;

				// Token: 0x0400015C RID: 348
				public uint Protect;

				// Token: 0x0400015D RID: 349
				public uint Type;

				// Token: 0x0400015E RID: 350
				public uint __alignment2;
			}

			// Token: 0x02000033 RID: 51
			public struct _LUID_AND_ATTRIBUTES
			{
				// Token: 0x0400015F RID: 351
				public Win32.WinNT._LUID Luid;

				// Token: 0x04000160 RID: 352
				public uint Attributes;
			}

			// Token: 0x02000034 RID: 52
			public struct _LUID
			{
				// Token: 0x04000161 RID: 353
				public uint LowPart;

				// Token: 0x04000162 RID: 354
				public uint HighPart;
			}

			// Token: 0x02000035 RID: 53
			public struct _TOKEN_STATISTICS
			{
				// Token: 0x04000163 RID: 355
				public Win32.WinNT._LUID TokenId;

				// Token: 0x04000164 RID: 356
				public Win32.WinNT._LUID AuthenticationId;

				// Token: 0x04000165 RID: 357
				public ulong ExpirationTime;

				// Token: 0x04000166 RID: 358
				public Win32.WinNT.TOKEN_TYPE TokenType;

				// Token: 0x04000167 RID: 359
				public Win32.WinNT._SECURITY_IMPERSONATION_LEVEL ImpersonationLevel;

				// Token: 0x04000168 RID: 360
				public uint DynamicCharged;

				// Token: 0x04000169 RID: 361
				public uint DynamicAvailable;

				// Token: 0x0400016A RID: 362
				public uint GroupCount;

				// Token: 0x0400016B RID: 363
				public uint PrivilegeCount;

				// Token: 0x0400016C RID: 364
				public Win32.WinNT._LUID ModifiedId;
			}

			// Token: 0x02000036 RID: 54
			public struct _TOKEN_PRIVILEGES
			{
				// Token: 0x0400016D RID: 365
				public uint PrivilegeCount;

				// Token: 0x0400016E RID: 366
				public Win32.WinNT._LUID_AND_ATTRIBUTES Privileges;
			}

			// Token: 0x02000037 RID: 55
			public struct _TOKEN_MANDATORY_LABEL
			{
				// Token: 0x0400016F RID: 367
				public Win32.WinNT._SID_AND_ATTRIBUTES Label;
			}

			// Token: 0x02000038 RID: 56
			public struct _SID
			{
				// Token: 0x04000170 RID: 368
				public byte Revision;

				// Token: 0x04000171 RID: 369
				public byte SubAuthorityCount;

				// Token: 0x04000172 RID: 370
				public Win32.WinNT._SID_IDENTIFIER_AUTHORITY IdentifierAuthority;

				// Token: 0x04000173 RID: 371
				[MarshalAs(UnmanagedType.ByValArray, SizeConst = 1)]
				public ulong[] SubAuthority;
			}

			// Token: 0x02000039 RID: 57
			public struct _SID_IDENTIFIER_AUTHORITY
			{
				// Token: 0x04000174 RID: 372
				[MarshalAs(UnmanagedType.ByValArray, SizeConst = 6, ArraySubType = UnmanagedType.I1)]
				public byte[] Value;
			}

			// Token: 0x0200003A RID: 58
			public struct _SID_AND_ATTRIBUTES
			{
				// Token: 0x04000175 RID: 373
				public IntPtr Sid;

				// Token: 0x04000176 RID: 374
				public uint Attributes;
			}

			// Token: 0x0200003B RID: 59
			public struct _PRIVILEGE_SET
			{
				// Token: 0x04000177 RID: 375
				public uint PrivilegeCount;

				// Token: 0x04000178 RID: 376
				public uint Control;

				// Token: 0x04000179 RID: 377
				[MarshalAs(UnmanagedType.ByValArray, SizeConst = 1)]
				public Win32.WinNT._LUID_AND_ATTRIBUTES[] Privilege;
			}

			// Token: 0x0200003C RID: 60
			public struct _TOKEN_USER
			{
				// Token: 0x0400017A RID: 378
				public Win32.WinNT._SID_AND_ATTRIBUTES User;
			}

			// Token: 0x0200003D RID: 61
			public enum _SID_NAME_USE
			{
				// Token: 0x0400017C RID: 380
				SidTypeUser = 1,
				// Token: 0x0400017D RID: 381
				SidTypeGroup,
				// Token: 0x0400017E RID: 382
				SidTypeDomain,
				// Token: 0x0400017F RID: 383
				SidTypeAlias,
				// Token: 0x04000180 RID: 384
				SidTypeWellKnownGroup,
				// Token: 0x04000181 RID: 385
				SidTypeDeletedAccount,
				// Token: 0x04000182 RID: 386
				SidTypeInvalid,
				// Token: 0x04000183 RID: 387
				SidTypeUnknown,
				// Token: 0x04000184 RID: 388
				SidTypeComputer,
				// Token: 0x04000185 RID: 389
				SidTypeLabel
			}

			// Token: 0x0200003E RID: 62
			public enum _TOKEN_INFORMATION_CLASS
			{
				// Token: 0x04000187 RID: 391
				TokenUser = 1,
				// Token: 0x04000188 RID: 392
				TokenGroups,
				// Token: 0x04000189 RID: 393
				TokenPrivileges,
				// Token: 0x0400018A RID: 394
				TokenOwner,
				// Token: 0x0400018B RID: 395
				TokenPrimaryGroup,
				// Token: 0x0400018C RID: 396
				TokenDefaultDacl,
				// Token: 0x0400018D RID: 397
				TokenSource,
				// Token: 0x0400018E RID: 398
				TokenType,
				// Token: 0x0400018F RID: 399
				TokenImpersonationLevel,
				// Token: 0x04000190 RID: 400
				TokenStatistics,
				// Token: 0x04000191 RID: 401
				TokenRestrictedSids,
				// Token: 0x04000192 RID: 402
				TokenSessionId,
				// Token: 0x04000193 RID: 403
				TokenGroupsAndPrivileges,
				// Token: 0x04000194 RID: 404
				TokenSessionReference,
				// Token: 0x04000195 RID: 405
				TokenSandBoxInert,
				// Token: 0x04000196 RID: 406
				TokenAuditPolicy,
				// Token: 0x04000197 RID: 407
				TokenOrigin,
				// Token: 0x04000198 RID: 408
				TokenElevationType,
				// Token: 0x04000199 RID: 409
				TokenLinkedToken,
				// Token: 0x0400019A RID: 410
				TokenElevation,
				// Token: 0x0400019B RID: 411
				TokenHasRestrictions,
				// Token: 0x0400019C RID: 412
				TokenAccessInformation,
				// Token: 0x0400019D RID: 413
				TokenVirtualizationAllowed,
				// Token: 0x0400019E RID: 414
				TokenVirtualizationEnabled,
				// Token: 0x0400019F RID: 415
				TokenIntegrityLevel,
				// Token: 0x040001A0 RID: 416
				TokenUIAccess,
				// Token: 0x040001A1 RID: 417
				TokenMandatoryPolicy,
				// Token: 0x040001A2 RID: 418
				TokenLogonSid,
				// Token: 0x040001A3 RID: 419
				TokenIsAppContainer,
				// Token: 0x040001A4 RID: 420
				TokenCapabilities,
				// Token: 0x040001A5 RID: 421
				TokenAppContainerSid,
				// Token: 0x040001A6 RID: 422
				TokenAppContainerNumber,
				// Token: 0x040001A7 RID: 423
				TokenUserClaimAttributes,
				// Token: 0x040001A8 RID: 424
				TokenDeviceClaimAttributes,
				// Token: 0x040001A9 RID: 425
				TokenRestrictedUserClaimAttributes,
				// Token: 0x040001AA RID: 426
				TokenRestrictedDeviceClaimAttributes,
				// Token: 0x040001AB RID: 427
				TokenDeviceGroups,
				// Token: 0x040001AC RID: 428
				TokenRestrictedDeviceGroups,
				// Token: 0x040001AD RID: 429
				TokenSecurityAttributes,
				// Token: 0x040001AE RID: 430
				TokenIsRestricted,
				// Token: 0x040001AF RID: 431
				MaxTokenInfoClass
			}

			// Token: 0x0200003F RID: 63
			[Flags]
			public enum ACCESS_MASK : uint
			{
				// Token: 0x040001B1 RID: 433
				DELETE = 65536U,
				// Token: 0x040001B2 RID: 434
				READ_CONTROL = 131072U,
				// Token: 0x040001B3 RID: 435
				WRITE_DAC = 262144U,
				// Token: 0x040001B4 RID: 436
				WRITE_OWNER = 524288U,
				// Token: 0x040001B5 RID: 437
				SYNCHRONIZE = 1048576U,
				// Token: 0x040001B6 RID: 438
				STANDARD_RIGHTS_REQUIRED = 983040U,
				// Token: 0x040001B7 RID: 439
				STANDARD_RIGHTS_READ = 131072U,
				// Token: 0x040001B8 RID: 440
				STANDARD_RIGHTS_WRITE = 131072U,
				// Token: 0x040001B9 RID: 441
				STANDARD_RIGHTS_EXECUTE = 131072U,
				// Token: 0x040001BA RID: 442
				STANDARD_RIGHTS_ALL = 2031616U,
				// Token: 0x040001BB RID: 443
				SPECIFIC_RIGHTS_ALL = 4095U,
				// Token: 0x040001BC RID: 444
				ACCESS_SYSTEM_SECURITY = 16777216U,
				// Token: 0x040001BD RID: 445
				MAXIMUM_ALLOWED = 33554432U,
				// Token: 0x040001BE RID: 446
				GENERIC_READ = 2147483648U,
				// Token: 0x040001BF RID: 447
				GENERIC_WRITE = 1073741824U,
				// Token: 0x040001C0 RID: 448
				GENERIC_EXECUTE = 536870912U,
				// Token: 0x040001C1 RID: 449
				GENERIC_ALL = 268435456U,
				// Token: 0x040001C2 RID: 450
				DESKTOP_READOBJECTS = 1U,
				// Token: 0x040001C3 RID: 451
				DESKTOP_CREATEWINDOW = 2U,
				// Token: 0x040001C4 RID: 452
				DESKTOP_CREATEMENU = 4U,
				// Token: 0x040001C5 RID: 453
				DESKTOP_HOOKCONTROL = 8U,
				// Token: 0x040001C6 RID: 454
				DESKTOP_JOURNALRECORD = 16U,
				// Token: 0x040001C7 RID: 455
				DESKTOP_JOURNALPLAYBACK = 32U,
				// Token: 0x040001C8 RID: 456
				DESKTOP_ENUMERATE = 64U,
				// Token: 0x040001C9 RID: 457
				DESKTOP_WRITEOBJECTS = 128U,
				// Token: 0x040001CA RID: 458
				DESKTOP_SWITCHDESKTOP = 256U,
				// Token: 0x040001CB RID: 459
				WINSTA_ENUMDESKTOPS = 1U,
				// Token: 0x040001CC RID: 460
				WINSTA_READATTRIBUTES = 2U,
				// Token: 0x040001CD RID: 461
				WINSTA_ACCESSCLIPBOARD = 4U,
				// Token: 0x040001CE RID: 462
				WINSTA_CREATEDESKTOP = 8U,
				// Token: 0x040001CF RID: 463
				WINSTA_WRITEATTRIBUTES = 16U,
				// Token: 0x040001D0 RID: 464
				WINSTA_ACCESSGLOBALATOMS = 32U,
				// Token: 0x040001D1 RID: 465
				WINSTA_EXITWINDOWS = 64U,
				// Token: 0x040001D2 RID: 466
				WINSTA_ENUMERATE = 256U,
				// Token: 0x040001D3 RID: 467
				WINSTA_READSCREEN = 512U,
				// Token: 0x040001D4 RID: 468
				WINSTA_ALL_ACCESS = 895U
			}
		}

		// Token: 0x0200001A RID: 26
		public class ProcessThreadsAPI
		{
			// Token: 0x02000040 RID: 64
			public struct _STARTUPINFO
			{
				// Token: 0x040001D5 RID: 469
				public uint cb;

				// Token: 0x040001D6 RID: 470
				public string lpReserved;

				// Token: 0x040001D7 RID: 471
				public string lpDesktop;

				// Token: 0x040001D8 RID: 472
				public string lpTitle;

				// Token: 0x040001D9 RID: 473
				public uint dwX;

				// Token: 0x040001DA RID: 474
				public uint dwY;

				// Token: 0x040001DB RID: 475
				public uint dwXSize;

				// Token: 0x040001DC RID: 476
				public uint dwYSize;

				// Token: 0x040001DD RID: 477
				public uint dwXCountChars;

				// Token: 0x040001DE RID: 478
				public uint dwYCountChars;

				// Token: 0x040001DF RID: 479
				public uint dwFillAttribute;

				// Token: 0x040001E0 RID: 480
				public uint dwFlags;

				// Token: 0x040001E1 RID: 481
				public ushort wShowWindow;

				// Token: 0x040001E2 RID: 482
				public ushort cbReserved2;

				// Token: 0x040001E3 RID: 483
				public IntPtr lpReserved2;

				// Token: 0x040001E4 RID: 484
				public IntPtr hStdInput;

				// Token: 0x040001E5 RID: 485
				public IntPtr hStdOutput;

				// Token: 0x040001E6 RID: 486
				public IntPtr hStdError;
			}

			// Token: 0x02000041 RID: 65
			public struct _STARTUPINFOEX
			{
				// Token: 0x040001E7 RID: 487
				private Win32.ProcessThreadsAPI._STARTUPINFO StartupInfo;
			}

			// Token: 0x02000042 RID: 66
			public struct _PROCESS_INFORMATION
			{
				// Token: 0x040001E8 RID: 488
				public IntPtr hProcess;

				// Token: 0x040001E9 RID: 489
				public IntPtr hThread;

				// Token: 0x040001EA RID: 490
				public uint dwProcessId;

				// Token: 0x040001EB RID: 491
				public uint dwThreadId;
			}
		}

		// Token: 0x0200001B RID: 27
		public class WinCred
		{
			// Token: 0x02000043 RID: 67
			[StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
			public struct _CREDENTIAL
			{
				// Token: 0x040001EC RID: 492
				public Win32.WinCred.CRED_FLAGS Flags;

				// Token: 0x040001ED RID: 493
				public uint Type;

				// Token: 0x040001EE RID: 494
				public IntPtr TargetName;

				// Token: 0x040001EF RID: 495
				public IntPtr Comment;

				// Token: 0x040001F0 RID: 496
				public FILETIME LastWritten;

				// Token: 0x040001F1 RID: 497
				public uint CredentialBlobSize;

				// Token: 0x040001F2 RID: 498
				public uint Persist;

				// Token: 0x040001F3 RID: 499
				public uint AttributeCount;

				// Token: 0x040001F4 RID: 500
				public IntPtr Attributes;

				// Token: 0x040001F5 RID: 501
				public IntPtr TargetAlias;

				// Token: 0x040001F6 RID: 502
				public IntPtr UserName;
			}

			// Token: 0x02000044 RID: 68
			public enum CRED_FLAGS : uint
			{
				// Token: 0x040001F8 RID: 504
				NONE,
				// Token: 0x040001F9 RID: 505
				PROMPT_NOW = 2U,
				// Token: 0x040001FA RID: 506
				USERNAME_TARGET = 4U
			}

			// Token: 0x02000045 RID: 69
			public enum CRED_PERSIST : uint
			{
				// Token: 0x040001FC RID: 508
				Session = 1U,
				// Token: 0x040001FD RID: 509
				LocalMachine,
				// Token: 0x040001FE RID: 510
				Enterprise
			}

			// Token: 0x02000046 RID: 70
			public enum CRED_TYPE : uint
			{
				// Token: 0x04000200 RID: 512
				Generic = 1U,
				// Token: 0x04000201 RID: 513
				DomainPassword,
				// Token: 0x04000202 RID: 514
				DomainCertificate,
				// Token: 0x04000203 RID: 515
				DomainVisiblePassword,
				// Token: 0x04000204 RID: 516
				GenericCertificate,
				// Token: 0x04000205 RID: 517
				DomainExtended,
				// Token: 0x04000206 RID: 518
				Maximum,
				// Token: 0x04000207 RID: 519
				MaximumEx = 1007U
			}
		}

		// Token: 0x0200001C RID: 28
		public class Secur32
		{
			// Token: 0x06000070 RID: 112
			[DllImport("Secur32.dll")]
			public static extern uint LsaGetLogonSessionData(IntPtr luid, out IntPtr ppLogonSessionData);

			// Token: 0x02000047 RID: 71
			public struct _SECURITY_LOGON_SESSION_DATA
			{
				// Token: 0x04000208 RID: 520
				public uint Size;

				// Token: 0x04000209 RID: 521
				public Win32.WinNT._LUID LoginID;

				// Token: 0x0400020A RID: 522
				public Win32.Secur32._LSA_UNICODE_STRING Username;

				// Token: 0x0400020B RID: 523
				public Win32.Secur32._LSA_UNICODE_STRING LoginDomain;

				// Token: 0x0400020C RID: 524
				public Win32.Secur32._LSA_UNICODE_STRING AuthenticationPackage;

				// Token: 0x0400020D RID: 525
				public uint LogonType;

				// Token: 0x0400020E RID: 526
				public uint Session;

				// Token: 0x0400020F RID: 527
				public IntPtr pSid;

				// Token: 0x04000210 RID: 528
				public ulong LoginTime;

				// Token: 0x04000211 RID: 529
				public Win32.Secur32._LSA_UNICODE_STRING LogonServer;

				// Token: 0x04000212 RID: 530
				public Win32.Secur32._LSA_UNICODE_STRING DnsDomainName;

				// Token: 0x04000213 RID: 531
				public Win32.Secur32._LSA_UNICODE_STRING Upn;
			}

			// Token: 0x02000048 RID: 72
			public struct _LSA_UNICODE_STRING
			{
				// Token: 0x04000214 RID: 532
				public ushort Length;

				// Token: 0x04000215 RID: 533
				public ushort MaximumLength;

				// Token: 0x04000216 RID: 534
				public IntPtr Buffer;
			}
		}

		// Token: 0x0200001D RID: 29
		public class NtDll
		{
			// Token: 0x06000072 RID: 114
			[DllImport("ntdll.dll", SetLastError = true)]
			public static extern int NtFilterToken(IntPtr TokenHandle, uint Flags, IntPtr SidsToDisable, IntPtr PrivilegesToDelete, IntPtr RestrictedSids, ref IntPtr hToken);

			// Token: 0x06000073 RID: 115
			[DllImport("ntdll.dll", SetLastError = true)]
			public static extern int NtSetInformationToken(IntPtr TokenHandle, int TokenInformationClass, ref Win32.WinNT._TOKEN_MANDATORY_LABEL TokenInformation, int TokenInformationLength);
		}
	}
}
