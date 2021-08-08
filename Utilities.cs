using System;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Reflection;

namespace SharpReflectiveDll
{
	// Token: 0x02000004 RID: 4
	public static class Utilities
	{
		// Token: 0x0600001A RID: 26 RVA: 0x00002A30 File Offset: 0x00000C30
		public static byte[] GetEmbeddedResourceBytes(string resourceName)
		{
			string text = Utilities.manifestResources.FirstOrDefault((string N) => N.Contains(resourceName + ".comp"));
			if (text != null)
			{
				return Utilities.Decompress(Assembly.GetExecutingAssembly().GetManifestResourceStream(text).ReadFully());
			}
			if ((text = Utilities.manifestResources.FirstOrDefault((string N) => N.Contains(resourceName))) != null)
			{
				return Assembly.GetExecutingAssembly().GetManifestResourceStream(text).ReadFully();
			}
			return null;
		}

		// Token: 0x0600001B RID: 27 RVA: 0x00002AA8 File Offset: 0x00000CA8
		public static byte[] ReadFully(this Stream input)
		{
			byte[] array = new byte[16384];
			byte[] result;
			using (MemoryStream memoryStream = new MemoryStream())
			{
				int count;
				while ((count = input.Read(array, 0, array.Length)) > 0)
				{
					memoryStream.Write(array, 0, count);
				}
				result = memoryStream.ToArray();
			}
			return result;
		}

		// Token: 0x0600001C RID: 28 RVA: 0x00002B08 File Offset: 0x00000D08
		public static byte[] Compress(byte[] Bytes)
		{
			byte[] result;
			using (MemoryStream memoryStream = new MemoryStream())
			{
				using (DeflateStream deflateStream = new DeflateStream(memoryStream, CompressionMode.Compress))
				{
					deflateStream.Write(Bytes, 0, Bytes.Length);
				}
				result = memoryStream.ToArray();
			}
			return result;
		}

		// Token: 0x0600001D RID: 29 RVA: 0x00002B6C File Offset: 0x00000D6C
		public static byte[] Decompress(byte[] compressed)
		{
			byte[] result;
			using (MemoryStream memoryStream = new MemoryStream(compressed.Length))
			{
				memoryStream.Write(compressed, 0, compressed.Length);
				memoryStream.Seek(0L, SeekOrigin.Begin);
				using (MemoryStream memoryStream2 = new MemoryStream())
				{
					using (DeflateStream deflateStream = new DeflateStream(memoryStream, CompressionMode.Decompress))
					{
						byte[] array = new byte[4096];
						int count;
						while ((count = deflateStream.Read(array, 0, array.Length)) != 0)
						{
							memoryStream2.Write(array, 0, count);
						}
					}
					result = memoryStream2.ToArray();
				}
			}
			return result;
		}

		// Token: 0x0400000B RID: 11
		private static string[] manifestResources = Assembly.GetExecutingAssembly().GetManifestResourceNames();
	}
}
