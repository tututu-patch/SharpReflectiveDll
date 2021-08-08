using System;
using System.IO;
using System.Runtime.InteropServices;

namespace SharpReflectiveDll
{
	// Token: 0x02000002 RID: 2
	public class PE
	{
		// Token: 0x17000001 RID: 1
		// (get) Token: 0x06000001 RID: 1 RVA: 0x00002048 File Offset: 0x00000248
		public bool Is32BitHeader
		{
			get
			{
				ushort num = 256;
				return (num & this.FileHeader.Characteristics) == num;
			}
		}

		// Token: 0x17000002 RID: 2
		// (get) Token: 0x06000002 RID: 2 RVA: 0x0000206B File Offset: 0x0000026B
		// (set) Token: 0x06000003 RID: 3 RVA: 0x00002073 File Offset: 0x00000273
		public PE.IMAGE_FILE_HEADER FileHeader { get; private set; }

		// Token: 0x17000003 RID: 3
		// (get) Token: 0x06000004 RID: 4 RVA: 0x0000207C File Offset: 0x0000027C
		// (set) Token: 0x06000005 RID: 5 RVA: 0x00002084 File Offset: 0x00000284
		public PE.IMAGE_OPTIONAL_HEADER32 OptionalHeader32 { get; private set; }

		// Token: 0x17000004 RID: 4
		// (get) Token: 0x06000006 RID: 6 RVA: 0x0000208D File Offset: 0x0000028D
		// (set) Token: 0x06000007 RID: 7 RVA: 0x00002095 File Offset: 0x00000295
		public PE.IMAGE_OPTIONAL_HEADER64 OptionalHeader64 { get; private set; }

		// Token: 0x17000005 RID: 5
		// (get) Token: 0x06000008 RID: 8 RVA: 0x0000209E File Offset: 0x0000029E
		// (set) Token: 0x06000009 RID: 9 RVA: 0x000020A6 File Offset: 0x000002A6
		public PE.IMAGE_SECTION_HEADER[] ImageSectionHeaders { get; private set; }

		// Token: 0x17000006 RID: 6
		// (get) Token: 0x0600000A RID: 10 RVA: 0x000020AF File Offset: 0x000002AF
		// (set) Token: 0x0600000B RID: 11 RVA: 0x000020B7 File Offset: 0x000002B7
		public byte[] PEBytes { get; private set; }

		// Token: 0x0600000C RID: 12 RVA: 0x000020C0 File Offset: 0x000002C0
		public PE(byte[] PEBytes)
		{
			using (MemoryStream memoryStream = new MemoryStream(PEBytes, 0, PEBytes.Length))
			{
				BinaryReader binaryReader = new BinaryReader(memoryStream);
				this.dosHeader = PE.FromBinaryReader<PE.IMAGE_DOS_HEADER>(binaryReader);
				memoryStream.Seek((long)((ulong)this.dosHeader.e_lfanew), SeekOrigin.Begin);
				binaryReader.ReadUInt32();
				this.FileHeader = PE.FromBinaryReader<PE.IMAGE_FILE_HEADER>(binaryReader);
				if (this.Is32BitHeader)
				{
					this.OptionalHeader32 = PE.FromBinaryReader<PE.IMAGE_OPTIONAL_HEADER32>(binaryReader);
				}
				else
				{
					this.OptionalHeader64 = PE.FromBinaryReader<PE.IMAGE_OPTIONAL_HEADER64>(binaryReader);
				}
				this.ImageSectionHeaders = new PE.IMAGE_SECTION_HEADER[(int)this.FileHeader.NumberOfSections];
				for (int i = 0; i < this.ImageSectionHeaders.Length; i++)
				{
					this.ImageSectionHeaders[i] = PE.FromBinaryReader<PE.IMAGE_SECTION_HEADER>(binaryReader);
				}
				this.PEBytes = PEBytes;
			}
		}

		// Token: 0x0600000D RID: 13 RVA: 0x00002198 File Offset: 0x00000398
		public static PE Load(byte[] PEBytes)
		{
			PE pe = new PE(PEBytes);
			if (pe.Is32BitHeader)
			{
				PE.codebase = Win32.Kernel32.VirtualAlloc(IntPtr.Zero, pe.OptionalHeader32.SizeOfImage, Win32.Kernel32.MEM_COMMIT, 64U);
			}
			else
			{
				PE.codebase = Win32.Kernel32.VirtualAlloc(IntPtr.Zero, pe.OptionalHeader64.SizeOfImage, Win32.Kernel32.MEM_COMMIT, 64U);
			}
			for (int i = 0; i < (int)pe.FileHeader.NumberOfSections; i++)
			{
				IntPtr destination = Win32.Kernel32.VirtualAlloc(PE.IntPtrAdd(PE.codebase, (int)pe.ImageSectionHeaders[i].VirtualAddress), pe.ImageSectionHeaders[i].SizeOfRawData, Win32.Kernel32.MEM_COMMIT, 64U);
				Marshal.Copy(pe.PEBytes, (int)pe.ImageSectionHeaders[i].PointerToRawData, destination, (int)pe.ImageSectionHeaders[i].SizeOfRawData);
			}
			IntPtr intPtr = PE.codebase;
			long num;
			if (pe.Is32BitHeader)
			{
				num = (long)(intPtr.ToInt32() - (int)pe.OptionalHeader32.ImageBase);
			}
			else
			{
				num = intPtr.ToInt64() - (long)pe.OptionalHeader64.ImageBase;
			}
			IntPtr intPtr2;
			if (pe.Is32BitHeader)
			{
				intPtr2 = PE.IntPtrAdd(PE.codebase, (int)pe.OptionalHeader32.BaseRelocationTable.VirtualAddress);
			}
			else
			{
				intPtr2 = PE.IntPtrAdd(PE.codebase, (int)pe.OptionalHeader64.BaseRelocationTable.VirtualAddress);
			}
			Win32.Kernel32.IMAGE_BASE_RELOCATION image_BASE_RELOCATION = default(Win32.Kernel32.IMAGE_BASE_RELOCATION);
			image_BASE_RELOCATION = (Win32.Kernel32.IMAGE_BASE_RELOCATION)Marshal.PtrToStructure(intPtr2, typeof(Win32.Kernel32.IMAGE_BASE_RELOCATION));
			int num2 = Marshal.SizeOf(typeof(Win32.Kernel32.IMAGE_BASE_RELOCATION));
			IntPtr a = intPtr2;
			int num3 = (int)image_BASE_RELOCATION.SizeOfBlock;
			IntPtr ptr = intPtr2;
			Win32.Kernel32.IMAGE_BASE_RELOCATION image_BASE_RELOCATION2;
			do
			{
				image_BASE_RELOCATION2 = default(Win32.Kernel32.IMAGE_BASE_RELOCATION);
				image_BASE_RELOCATION2 = (Win32.Kernel32.IMAGE_BASE_RELOCATION)Marshal.PtrToStructure(PE.IntPtrAdd(intPtr2, num3), typeof(Win32.Kernel32.IMAGE_BASE_RELOCATION));
				IntPtr a2 = PE.IntPtrAdd(PE.codebase, (int)image_BASE_RELOCATION.VirtualAdress);
				for (int j = 0; j < (int)(((ulong)image_BASE_RELOCATION.SizeOfBlock - (ulong)((long)num2)) / 2UL); j++)
				{
					ushort num4 = (ushort)Marshal.ReadInt16(ptr, 8 + 2 * j);
					ushort num5 = (ushort)(num4 >> 12);
					ushort b = (ushort)(num4 & 4095);
					if (num5 != 0)
					{
						if (num5 != 3)
						{
							if (num5 == 10)
							{
								IntPtr ptr2 = PE.IntPtrAdd(a2, (int)b);
								long num6 = Marshal.ReadInt64(ptr2);
								Marshal.WriteInt64(ptr2, num6 + num);
							}
						}
						else
						{
							IntPtr ptr3 = PE.IntPtrAdd(a2, (int)b);
							int num7 = Marshal.ReadInt32(ptr3);
							Marshal.WriteInt32(ptr3, num7 + (int)num);
						}
					}
				}
				ptr = PE.IntPtrAdd(intPtr2, num3);
				num3 += (int)image_BASE_RELOCATION2.SizeOfBlock;
				image_BASE_RELOCATION = image_BASE_RELOCATION2;
				a = PE.IntPtrAdd(a, num3);
			}
			while (image_BASE_RELOCATION2.SizeOfBlock != 0U);
			int num8;
			if (pe.Is32BitHeader)
			{
				PE.IntPtrAdd(PE.codebase, (int)pe.ImageSectionHeaders[1].VirtualAddress);
				num8 = Marshal.ReadInt32(PE.IntPtrAdd(PE.IntPtrAdd(PE.codebase, (int)pe.OptionalHeader32.ImportTable.VirtualAddress), 16));
			}
			else
			{
				PE.IntPtrAdd(PE.codebase, (int)pe.ImageSectionHeaders[1].VirtualAddress);
				num8 = Marshal.ReadInt32(PE.IntPtrAdd(PE.IntPtrAdd(PE.codebase, (int)pe.OptionalHeader64.ImportTable.VirtualAddress), 16));
			}
			int virtualAddress;
			int addressOfEntryPoint;
			int b2;
			if (pe.Is32BitHeader)
			{
				virtualAddress = (int)pe.OptionalHeader32.ImportTable.VirtualAddress;
				addressOfEntryPoint = (int)pe.OptionalHeader32.AddressOfEntryPoint;
				b2 = 4;
			}
			else
			{
				virtualAddress = (int)pe.OptionalHeader64.ImportTable.VirtualAddress;
				addressOfEntryPoint = (int)pe.OptionalHeader64.AddressOfEntryPoint;
				b2 = 8;
			}
			int num9 = 0;
			for (;;)
			{
				IntPtr a3 = PE.IntPtrAdd(PE.codebase, 20 * num9 + virtualAddress);
				int num10 = Marshal.ReadInt32(PE.IntPtrAdd(a3, 16));
				IntPtr intPtr3 = PE.IntPtrAdd(PE.codebase, (int)(pe.ImageSectionHeaders[1].VirtualAddress + (uint)(num10 - num8)));
				string text = Marshal.PtrToStringAnsi(PE.IntPtrAdd(PE.codebase, Marshal.ReadInt32(PE.IntPtrAdd(a3, 12))));
				if (text == "")
				{
					break;
				}
				IntPtr hModule = Win32.Kernel32.LoadLibrary(text);
				int num11 = 0;
				for (;;)
				{
					string text2 = Marshal.PtrToStringAnsi(PE.IntPtrAdd(PE.IntPtrAdd(PE.codebase, Marshal.ReadInt32(intPtr3)), 2));
					IntPtr procAddress = Win32.Kernel32.GetProcAddress(hModule, text2);
					if (pe.Is32BitHeader)
					{
						Marshal.WriteInt32(intPtr3, (int)procAddress);
					}
					else
					{
						Marshal.WriteInt64(intPtr3, (long)procAddress);
					}
					intPtr3 = PE.IntPtrAdd(intPtr3, b2);
					if (text2 == "")
					{
						break;
					}
					num11++;
				}
				num9++;
			}
			((PE.main)Marshal.GetDelegateForFunctionPointer(PE.IntPtrAdd(PE.codebase, addressOfEntryPoint), typeof(PE.main)))(PE.codebase, 1U, IntPtr.Zero);
			return pe;
		}

		// Token: 0x0600000E RID: 14 RVA: 0x0000263C File Offset: 0x0000083C
		public IntPtr GetFunctionExport(string funcName)
		{
			IntPtr ptr = IntPtr.Zero;
			if (this.Is32BitHeader && this.OptionalHeader32.ExportTable.Size == 0U)
			{
				return IntPtr.Zero;
			}
			if (!this.Is32BitHeader && this.OptionalHeader64.ExportTable.Size == 0U)
			{
				return IntPtr.Zero;
			}
			if (this.Is32BitHeader)
			{
				ptr = (IntPtr)((long)PE.codebase + (long)((ulong)this.OptionalHeader32.ExportTable.VirtualAddress));
			}
			else
			{
				ptr = (IntPtr)((long)PE.codebase + (long)((ulong)this.OptionalHeader64.ExportTable.VirtualAddress));
			}
			PE.IMAGE_EXPORT_DIRECTORY image_EXPORT_DIRECTORY = (PE.IMAGE_EXPORT_DIRECTORY)Marshal.PtrToStructure(ptr, typeof(PE.IMAGE_EXPORT_DIRECTORY));
			int num = 0;
			while ((long)num < (long)((ulong)image_EXPORT_DIRECTORY.NumberOfNames))
			{
				IntPtr intPtr = (IntPtr)((long)PE.codebase + (long)((ulong)image_EXPORT_DIRECTORY.AddressOfNames));
				intPtr = (IntPtr)((long)intPtr + (long)(num * Marshal.SizeOf(typeof(uint))));
				if (Marshal.PtrToStringAnsi((IntPtr)((long)PE.codebase + (long)((ulong)((uint)Marshal.PtrToStructure(intPtr, typeof(uint)))))).Contains(funcName))
				{
					IntPtr value = (IntPtr)((long)PE.codebase + (long)((ulong)image_EXPORT_DIRECTORY.AddressOfFunctions));
					ushort num2 = (ushort)Marshal.PtrToStructure((IntPtr)((long)PE.codebase + (long)((ulong)image_EXPORT_DIRECTORY.AddressOfOrdinals + (ulong)((long)(num * Marshal.SizeOf(typeof(ushort)))))), typeof(ushort));
					IntPtr ptr2 = (IntPtr)((long)value + (long)((int)num2 * Marshal.SizeOf(typeof(uint))));
					return (IntPtr)((long)PE.codebase + (long)((ulong)((uint)Marshal.PtrToStructure(ptr2, typeof(uint)))));
				}
				num++;
			}
			return IntPtr.Zero;
		}

		// Token: 0x0600000F RID: 15 RVA: 0x00002820 File Offset: 0x00000A20
		private static T FromBinaryReader<T>(BinaryReader reader)
		{
			GCHandle gchandle = GCHandle.Alloc(reader.ReadBytes(Marshal.SizeOf(typeof(T))), GCHandleType.Pinned);
			T result = (T)((object)Marshal.PtrToStructure(gchandle.AddrOfPinnedObject(), typeof(T)));
			gchandle.Free();
			return result;
		}

		// Token: 0x06000010 RID: 16 RVA: 0x0000286B File Offset: 0x00000A6B
		private static IntPtr IntPtrAdd(IntPtr a, int b)
		{
			return new IntPtr(a.ToInt64() + (long)b);
		}

		// Token: 0x04000006 RID: 6
		private PE.IMAGE_DOS_HEADER dosHeader;

		// Token: 0x04000007 RID: 7
		private static IntPtr codebase;

		// Token: 0x02000007 RID: 7
		[Flags]
		public enum DataSectionFlags : uint
		{
			// Token: 0x0400000F RID: 15
			Stub = 0U
		}

		// Token: 0x02000008 RID: 8
		// (Invoke) Token: 0x06000026 RID: 38
		[UnmanagedFunctionPointer(CallingConvention.Cdecl)]
		private delegate bool main(IntPtr arg1, uint arg2, IntPtr lparam);

		// Token: 0x02000009 RID: 9
		public struct IMAGE_DOS_HEADER
		{
			// Token: 0x04000010 RID: 16
			public ushort e_magic;

			// Token: 0x04000011 RID: 17
			public ushort e_cblp;

			// Token: 0x04000012 RID: 18
			public ushort e_cp;

			// Token: 0x04000013 RID: 19
			public ushort e_crlc;

			// Token: 0x04000014 RID: 20
			public ushort e_cparhdr;

			// Token: 0x04000015 RID: 21
			public ushort e_minalloc;

			// Token: 0x04000016 RID: 22
			public ushort e_maxalloc;

			// Token: 0x04000017 RID: 23
			public ushort e_ss;

			// Token: 0x04000018 RID: 24
			public ushort e_sp;

			// Token: 0x04000019 RID: 25
			public ushort e_csum;

			// Token: 0x0400001A RID: 26
			public ushort e_ip;

			// Token: 0x0400001B RID: 27
			public ushort e_cs;

			// Token: 0x0400001C RID: 28
			public ushort e_lfarlc;

			// Token: 0x0400001D RID: 29
			public ushort e_ovno;

			// Token: 0x0400001E RID: 30
			public ushort e_res_0;

			// Token: 0x0400001F RID: 31
			public ushort e_res_1;

			// Token: 0x04000020 RID: 32
			public ushort e_res_2;

			// Token: 0x04000021 RID: 33
			public ushort e_res_3;

			// Token: 0x04000022 RID: 34
			public ushort e_oemid;

			// Token: 0x04000023 RID: 35
			public ushort e_oeminfo;

			// Token: 0x04000024 RID: 36
			public ushort e_res2_0;

			// Token: 0x04000025 RID: 37
			public ushort e_res2_1;

			// Token: 0x04000026 RID: 38
			public ushort e_res2_2;

			// Token: 0x04000027 RID: 39
			public ushort e_res2_3;

			// Token: 0x04000028 RID: 40
			public ushort e_res2_4;

			// Token: 0x04000029 RID: 41
			public ushort e_res2_5;

			// Token: 0x0400002A RID: 42
			public ushort e_res2_6;

			// Token: 0x0400002B RID: 43
			public ushort e_res2_7;

			// Token: 0x0400002C RID: 44
			public ushort e_res2_8;

			// Token: 0x0400002D RID: 45
			public ushort e_res2_9;

			// Token: 0x0400002E RID: 46
			public uint e_lfanew;
		}

		// Token: 0x0200000A RID: 10
		public struct IMAGE_DATA_DIRECTORY
		{
			// Token: 0x0400002F RID: 47
			public uint VirtualAddress;

			// Token: 0x04000030 RID: 48
			public uint Size;
		}

		// Token: 0x0200000B RID: 11
		[StructLayout(LayoutKind.Sequential, Pack = 1)]
		public struct IMAGE_OPTIONAL_HEADER32
		{
			// Token: 0x04000031 RID: 49
			public ushort Magic;

			// Token: 0x04000032 RID: 50
			public byte MajorLinkerVersion;

			// Token: 0x04000033 RID: 51
			public byte MinorLinkerVersion;

			// Token: 0x04000034 RID: 52
			public uint SizeOfCode;

			// Token: 0x04000035 RID: 53
			public uint SizeOfInitializedData;

			// Token: 0x04000036 RID: 54
			public uint SizeOfUninitializedData;

			// Token: 0x04000037 RID: 55
			public uint AddressOfEntryPoint;

			// Token: 0x04000038 RID: 56
			public uint BaseOfCode;

			// Token: 0x04000039 RID: 57
			public uint BaseOfData;

			// Token: 0x0400003A RID: 58
			public uint ImageBase;

			// Token: 0x0400003B RID: 59
			public uint SectionAlignment;

			// Token: 0x0400003C RID: 60
			public uint FileAlignment;

			// Token: 0x0400003D RID: 61
			public ushort MajorOperatingSystemVersion;

			// Token: 0x0400003E RID: 62
			public ushort MinorOperatingSystemVersion;

			// Token: 0x0400003F RID: 63
			public ushort MajorImageVersion;

			// Token: 0x04000040 RID: 64
			public ushort MinorImageVersion;

			// Token: 0x04000041 RID: 65
			public ushort MajorSubsystemVersion;

			// Token: 0x04000042 RID: 66
			public ushort MinorSubsystemVersion;

			// Token: 0x04000043 RID: 67
			public uint Win32VersionValue;

			// Token: 0x04000044 RID: 68
			public uint SizeOfImage;

			// Token: 0x04000045 RID: 69
			public uint SizeOfHeaders;

			// Token: 0x04000046 RID: 70
			public uint CheckSum;

			// Token: 0x04000047 RID: 71
			public ushort Subsystem;

			// Token: 0x04000048 RID: 72
			public ushort DllCharacteristics;

			// Token: 0x04000049 RID: 73
			public uint SizeOfStackReserve;

			// Token: 0x0400004A RID: 74
			public uint SizeOfStackCommit;

			// Token: 0x0400004B RID: 75
			public uint SizeOfHeapReserve;

			// Token: 0x0400004C RID: 76
			public uint SizeOfHeapCommit;

			// Token: 0x0400004D RID: 77
			public uint LoaderFlags;

			// Token: 0x0400004E RID: 78
			public uint NumberOfRvaAndSizes;

			// Token: 0x0400004F RID: 79
			public PE.IMAGE_DATA_DIRECTORY ExportTable;

			// Token: 0x04000050 RID: 80
			public PE.IMAGE_DATA_DIRECTORY ImportTable;

			// Token: 0x04000051 RID: 81
			public PE.IMAGE_DATA_DIRECTORY ResourceTable;

			// Token: 0x04000052 RID: 82
			public PE.IMAGE_DATA_DIRECTORY ExceptionTable;

			// Token: 0x04000053 RID: 83
			public PE.IMAGE_DATA_DIRECTORY CertificateTable;

			// Token: 0x04000054 RID: 84
			public PE.IMAGE_DATA_DIRECTORY BaseRelocationTable;

			// Token: 0x04000055 RID: 85
			public PE.IMAGE_DATA_DIRECTORY Debug;

			// Token: 0x04000056 RID: 86
			public PE.IMAGE_DATA_DIRECTORY Architecture;

			// Token: 0x04000057 RID: 87
			public PE.IMAGE_DATA_DIRECTORY GlobalPtr;

			// Token: 0x04000058 RID: 88
			public PE.IMAGE_DATA_DIRECTORY TLSTable;

			// Token: 0x04000059 RID: 89
			public PE.IMAGE_DATA_DIRECTORY LoadConfigTable;

			// Token: 0x0400005A RID: 90
			public PE.IMAGE_DATA_DIRECTORY BoundImport;

			// Token: 0x0400005B RID: 91
			public PE.IMAGE_DATA_DIRECTORY IAT;

			// Token: 0x0400005C RID: 92
			public PE.IMAGE_DATA_DIRECTORY DelayImportDescriptor;

			// Token: 0x0400005D RID: 93
			public PE.IMAGE_DATA_DIRECTORY CLRRuntimeHeader;

			// Token: 0x0400005E RID: 94
			public PE.IMAGE_DATA_DIRECTORY Reserved;
		}

		// Token: 0x0200000C RID: 12
		[StructLayout(LayoutKind.Sequential, Pack = 1)]
		public struct IMAGE_OPTIONAL_HEADER64
		{
			// Token: 0x0400005F RID: 95
			public ushort Magic;

			// Token: 0x04000060 RID: 96
			public byte MajorLinkerVersion;

			// Token: 0x04000061 RID: 97
			public byte MinorLinkerVersion;

			// Token: 0x04000062 RID: 98
			public uint SizeOfCode;

			// Token: 0x04000063 RID: 99
			public uint SizeOfInitializedData;

			// Token: 0x04000064 RID: 100
			public uint SizeOfUninitializedData;

			// Token: 0x04000065 RID: 101
			public uint AddressOfEntryPoint;

			// Token: 0x04000066 RID: 102
			public uint BaseOfCode;

			// Token: 0x04000067 RID: 103
			public ulong ImageBase;

			// Token: 0x04000068 RID: 104
			public uint SectionAlignment;

			// Token: 0x04000069 RID: 105
			public uint FileAlignment;

			// Token: 0x0400006A RID: 106
			public ushort MajorOperatingSystemVersion;

			// Token: 0x0400006B RID: 107
			public ushort MinorOperatingSystemVersion;

			// Token: 0x0400006C RID: 108
			public ushort MajorImageVersion;

			// Token: 0x0400006D RID: 109
			public ushort MinorImageVersion;

			// Token: 0x0400006E RID: 110
			public ushort MajorSubsystemVersion;

			// Token: 0x0400006F RID: 111
			public ushort MinorSubsystemVersion;

			// Token: 0x04000070 RID: 112
			public uint Win32VersionValue;

			// Token: 0x04000071 RID: 113
			public uint SizeOfImage;

			// Token: 0x04000072 RID: 114
			public uint SizeOfHeaders;

			// Token: 0x04000073 RID: 115
			public uint CheckSum;

			// Token: 0x04000074 RID: 116
			public ushort Subsystem;

			// Token: 0x04000075 RID: 117
			public ushort DllCharacteristics;

			// Token: 0x04000076 RID: 118
			public ulong SizeOfStackReserve;

			// Token: 0x04000077 RID: 119
			public ulong SizeOfStackCommit;

			// Token: 0x04000078 RID: 120
			public ulong SizeOfHeapReserve;

			// Token: 0x04000079 RID: 121
			public ulong SizeOfHeapCommit;

			// Token: 0x0400007A RID: 122
			public uint LoaderFlags;

			// Token: 0x0400007B RID: 123
			public uint NumberOfRvaAndSizes;

			// Token: 0x0400007C RID: 124
			public PE.IMAGE_DATA_DIRECTORY ExportTable;

			// Token: 0x0400007D RID: 125
			public PE.IMAGE_DATA_DIRECTORY ImportTable;

			// Token: 0x0400007E RID: 126
			public PE.IMAGE_DATA_DIRECTORY ResourceTable;

			// Token: 0x0400007F RID: 127
			public PE.IMAGE_DATA_DIRECTORY ExceptionTable;

			// Token: 0x04000080 RID: 128
			public PE.IMAGE_DATA_DIRECTORY CertificateTable;

			// Token: 0x04000081 RID: 129
			public PE.IMAGE_DATA_DIRECTORY BaseRelocationTable;

			// Token: 0x04000082 RID: 130
			public PE.IMAGE_DATA_DIRECTORY Debug;

			// Token: 0x04000083 RID: 131
			public PE.IMAGE_DATA_DIRECTORY Architecture;

			// Token: 0x04000084 RID: 132
			public PE.IMAGE_DATA_DIRECTORY GlobalPtr;

			// Token: 0x04000085 RID: 133
			public PE.IMAGE_DATA_DIRECTORY TLSTable;

			// Token: 0x04000086 RID: 134
			public PE.IMAGE_DATA_DIRECTORY LoadConfigTable;

			// Token: 0x04000087 RID: 135
			public PE.IMAGE_DATA_DIRECTORY BoundImport;

			// Token: 0x04000088 RID: 136
			public PE.IMAGE_DATA_DIRECTORY IAT;

			// Token: 0x04000089 RID: 137
			public PE.IMAGE_DATA_DIRECTORY DelayImportDescriptor;

			// Token: 0x0400008A RID: 138
			public PE.IMAGE_DATA_DIRECTORY CLRRuntimeHeader;

			// Token: 0x0400008B RID: 139
			public PE.IMAGE_DATA_DIRECTORY Reserved;
		}

		// Token: 0x0200000D RID: 13
		[StructLayout(LayoutKind.Sequential, Pack = 1)]
		public struct IMAGE_FILE_HEADER
		{
			// Token: 0x0400008C RID: 140
			public ushort Machine;

			// Token: 0x0400008D RID: 141
			public ushort NumberOfSections;

			// Token: 0x0400008E RID: 142
			public uint TimeDateStamp;

			// Token: 0x0400008F RID: 143
			public uint PointerToSymbolTable;

			// Token: 0x04000090 RID: 144
			public uint NumberOfSymbols;

			// Token: 0x04000091 RID: 145
			public ushort SizeOfOptionalHeader;

			// Token: 0x04000092 RID: 146
			public ushort Characteristics;
		}

		// Token: 0x0200000E RID: 14
		[StructLayout(LayoutKind.Explicit)]
		public struct IMAGE_SECTION_HEADER
		{
			// Token: 0x1700000E RID: 14
			// (get) Token: 0x06000029 RID: 41 RVA: 0x00002CAA File Offset: 0x00000EAA
			public string Section
			{
				get
				{
					return new string(this.Name);
				}
			}

			// Token: 0x04000093 RID: 147
			[FieldOffset(0)]
			[MarshalAs(UnmanagedType.ByValArray, SizeConst = 8)]
			public char[] Name;

			// Token: 0x04000094 RID: 148
			[FieldOffset(8)]
			public uint VirtualSize;

			// Token: 0x04000095 RID: 149
			[FieldOffset(12)]
			public uint VirtualAddress;

			// Token: 0x04000096 RID: 150
			[FieldOffset(16)]
			public uint SizeOfRawData;

			// Token: 0x04000097 RID: 151
			[FieldOffset(20)]
			public uint PointerToRawData;

			// Token: 0x04000098 RID: 152
			[FieldOffset(24)]
			public uint PointerToRelocations;

			// Token: 0x04000099 RID: 153
			[FieldOffset(28)]
			public uint PointerToLinenumbers;

			// Token: 0x0400009A RID: 154
			[FieldOffset(32)]
			public ushort NumberOfRelocations;

			// Token: 0x0400009B RID: 155
			[FieldOffset(34)]
			public ushort NumberOfLinenumbers;

			// Token: 0x0400009C RID: 156
			[FieldOffset(36)]
			public PE.DataSectionFlags Characteristics;
		}

		// Token: 0x0200000F RID: 15
		[StructLayout(LayoutKind.Explicit)]
		public struct IMAGE_EXPORT_DIRECTORY
		{
			// Token: 0x0400009D RID: 157
			[FieldOffset(0)]
			public uint Characteristics;

			// Token: 0x0400009E RID: 158
			[FieldOffset(4)]
			public uint TimeDateStamp;

			// Token: 0x0400009F RID: 159
			[FieldOffset(8)]
			public ushort MajorVersion;

			// Token: 0x040000A0 RID: 160
			[FieldOffset(10)]
			public ushort MinorVersion;

			// Token: 0x040000A1 RID: 161
			[FieldOffset(12)]
			public uint Name;

			// Token: 0x040000A2 RID: 162
			[FieldOffset(16)]
			public uint Base;

			// Token: 0x040000A3 RID: 163
			[FieldOffset(20)]
			public uint NumberOfFunctions;

			// Token: 0x040000A4 RID: 164
			[FieldOffset(24)]
			public uint NumberOfNames;

			// Token: 0x040000A5 RID: 165
			[FieldOffset(28)]
			public uint AddressOfFunctions;

			// Token: 0x040000A6 RID: 166
			[FieldOffset(32)]
			public uint AddressOfNames;

			// Token: 0x040000A7 RID: 167
			[FieldOffset(36)]
			public uint AddressOfOrdinals;
		}

		// Token: 0x02000010 RID: 16
		public struct IMAGE_BASE_RELOCATION
		{
			// Token: 0x040000A8 RID: 168
			public uint VirtualAdress;

			// Token: 0x040000A9 RID: 169
			public uint SizeOfBlock;
		}
	}
}
