using System;
using System.IO;
using System.Text;

namespace DOL.Crypt
{
	/// <summary>
	/// RSAWriter is a wrapper to write easily the rsa key of libtomcrypt
	/// </summary>
	public class RSAWriter : MemoryStream
	{
		/// <summary>
		/// Default Constructor
		/// </summary>
		public RSAWriter() : base()
		{
		}

		/// <summary>
		/// Constructor
		/// </summary>
		/// <param name="size">Size of the internal buffer</param>
		public RSAWriter(int size) : base(size)
		{
		}

		/// <summary>
		/// Constructor
		/// </summary>
		/// <param name="buf">Buffer to write to</param>
		public RSAWriter(byte[] buf) : base(buf)
		{
		}

		/// <summary>
		/// Constructor
		/// </summary>
		/// <param name="buf">Buffer to write to</param>
		/// <param name="canwrite">True if you can write to the buffer</param>
		public RSAWriter(byte[] buf, bool canwrite) : base(buf, canwrite)
		{
		}

		/// <summary>
		/// Constructor
		/// </summary>
		/// <param name="buf">Buffer to write to</param>
		/// <param name="start">Starting index into buf</param>
		/// <param name="size"></param>
		public RSAWriter(byte[] buf, int start, int size) : base(buf, start, size)
		{
		}

		/// <summary>
		/// Constructor
		/// </summary>
		/// <param name="buf">Buffer to write to</param>
		/// <param name="start">Starting index into buf</param>
		/// <param name="size">Size of the internal buffer</param>
		/// <param name="canwrite">True if you can write to the buffer</param>
		public RSAWriter(byte[] buf, int start, int size, bool canwrite) : base(buf, start, size, canwrite)
		{
		}

		/// <summary>
		/// Constructor
		/// </summary>
		/// <param name="buf">Buffer to write to</param>
		/// <param name="start">Starting index into buf</param>
		/// <param name="size">Size of the internal buffer</param>
		/// <param name="canwrite">True if you can write to the buffer</param>
		/// <param name="getbuf">True if you can retrieve the internal buffer</param>
		public RSAWriter(byte[] buf, int start, int size, bool canwrite, bool getbuf) : base(buf, start, size, canwrite, getbuf)
		{
		}

		/// <summary>
		/// Writes a 2 byte (short) value to the stream in network byte order
		/// </summary>
		/// <param name="val">Value to write</param>
		public virtual void WriteShort(ushort val)
		{
			WriteByte((byte)(val >> 8));
			WriteByte((byte)(val & 0xff));
		}

		/// <summary>
		/// Writes a 2 byte (short) value to the stream in host byte order
		/// </summary>
		/// <param name="val">Value to write</param>
		public virtual void WriteShortLowEndian(ushort val)
		{
			WriteByte((byte)(val & 0xff));
			WriteByte((byte)(val >> 8));
		}

		/// <summary>
		/// Writes a 4 byte value to the stream in host byte order
		/// </summary>
		/// <param name="val">Value to write</param>
		public virtual void WriteInt(uint val)
		{
			WriteByte((byte)(val >> 24));
			WriteByte((byte)((val >> 16) & 0xff));
			WriteByte((byte)((val & 0xffff) >> 8));
			WriteByte((byte)((val & 0xffff) & 0xff));
		}

		/// <summary>
		/// Calculates the checksum for the internal buffer
		/// </summary>
		/// <returns>The checksum of the internal buffer</returns>
		public unsafe virtual byte CalcChecksum()
		{
			byte val = 0;

			fixed(byte *pin = GetBuffer())
			{
				byte *start = pin + 8;

				for(int i = 0; i < this.Position - 6; ++i)
				{
					val += *start++;
				}
			}

			return val;
		}

		/// <summary>
		/// Writes the supplied value to the stream for a specified number of bytes
		/// </summary>
		/// <param name="val">Value to write</param>
		/// <param name="num">Number of bytes to write</param>
		public virtual void Fill(byte val, int num)
		{
			for(int i = 0; i < num; ++i)
			{
				WriteByte(val);
			}
		}

		/// <summary>
		/// write a bignum formated number for RSA
		/// </summary>
		/// <param name="val">the bignum to write</param>
		public void WriteBignum(byte[] val)
		{
			this.WriteInt((uint)val.Length);
			this.Write(val,0,val.Length);
		}
	}
}
