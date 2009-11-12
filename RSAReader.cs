using System;
using System.IO;
using System.Text;

namespace DOL.Crypt
{
	/// <summary>
	/// RSAReader is a wrapper to read easily the rsa key of libtomcrypt
	/// </summary>

	public class RSAReader : MemoryStream
	{
		/// <summary>
		/// Default constructor
		/// </summary>
		public RSAReader() : base()
		{
		}

		/// <summary>
		/// Constructor
		/// </summary>
		/// <param name="size">Size of the internal buffer</param>
		public RSAReader(int size) : base(size)
		{
		}

		/// <summary>
		/// Constructor
		/// </summary>
		/// <param name="buf">Buffer containing packet data to read from</param>
		public RSAReader(byte[] buf) : base(buf)
		{
		}

		/// <summary>
		/// Constructor
		/// </summary>
		/// <param name="buf">Buffer containing packet data to read from</param>
		/// <param name="canwrite">True if writing to the buffer is allowed</param>
		public RSAReader(byte[] buf, bool canwrite) : base(buf, canwrite)
		{
		}

		/// <summary>
		/// Constructor
		/// </summary>
		/// <param name="buf">Buffer containing packet data to read from</param>
		/// <param name="start">Starting index into buf</param>
		/// <param name="size">Number of bytes to read from buf</param>
		public RSAReader(byte[] buf, int start, int size) : base(buf, start, size)
		{
		}

		/// <summary>
		/// Constructor
		/// </summary>
		/// <param name="buf">Buffer containing packet data to read from</param>
		/// <param name="start">Starting index into buf</param>
		/// <param name="size">Number of bytes to read from buf</param>
		/// <param name="canwrite">True if writing to the buffer is allowed</param>
		public RSAReader(byte[] buf, int start, int size, bool canwrite) : base(buf, start, size, canwrite)
		{
		}

		/// <summary>
		/// Constructor
		/// </summary>
		/// <param name="buf">Buffer containing packet data to read from</param>
		/// <param name="start">Starting index into buf</param>
		/// <param name="size">Number of bytes to read from buf</param>
		/// <param name="canwrite">True if writing to the buffer is allowed</param>
		/// <param name="getbuf">True if you can retrieve a copy of the internal buffer</param>
		public RSAReader(byte[] buf, int start, int size, bool canwrite, bool getbuf) : base(buf, start, size, canwrite, getbuf)
		{
		}

		/// <summary>
		/// Reads in 2 bytes and converts it from network to host byte order
		/// </summary>
		/// <returns>A 2 byte (short) value</returns>
		public virtual ushort ReadShort()
		{
			int v1 = ReadByte();
			int v2 = ReadByte();

			return (ushort)((v2 & 0xff) | (v1 & 0xff) << 8);
		}

		/// <summary>
		/// Reads in 2 bytes
		/// </summary>
		/// <returns>A 2 byte (short) value in network byte order</returns>
		public virtual ushort ReadShortLowEndian()
		{
			int v1 = ReadByte();
			int v2 = ReadByte();

			return (ushort)((v1 & 0xff) | (v2 & 0xff) << 8);
		}

		/// <summary>
		/// Reads in 4 bytes and converts it from network to host byte order
		/// </summary>
		/// <returns>A 4 byte value</returns>
		public virtual uint ReadInt()
		{
			int v1 = ReadByte();
			int v2 = ReadByte();
			int v3 = ReadByte();
			int v4 = ReadByte();

			return (uint)((v1 << 24) | (v2 << 16) | (v3 << 8) | v4);
		}

		/// <summary>
		/// Skips 'num' bytes ahead in the stream
		/// </summary>
		/// <param name="num">Number of bytes to skip ahead</param>
		public void Skip(long num)
		{
			Seek(num, SeekOrigin.Current);
		}

		/// <summary>
		/// read a bignum formated number for RSA
		/// </summary>
		/// <returns>return the byte array of bignum formated number for RSA</returns>
		public byte[] ReadBignum()
		{
			uint length = this.ReadInt();
			byte[] bignum = new byte[length];
			this.Read(bignum,0,(int)length);
			return bignum;
		}
	}
}
