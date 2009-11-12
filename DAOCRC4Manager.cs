using System;
using System.IO;
using System.Security.Cryptography;

namespace DOL.Crypt
{
	/// <summary>
	/// this is mostly code of RC4 of libtomcrypt
	/// with small change for daoc crypt
	/// </summary>
	public abstract class DAOCRC4Manager
	{
		static int SYMKEY_SIZE = 256;

		public static byte[] EncodeMythicRC4Packet(byte[] buf, byte[] sbox, bool udpPacket)
		{
			if(buf==null) return null;
			if(sbox==null) return null;
			byte[] tmpsbox=new byte[SYMKEY_SIZE];
			Array.Copy(sbox,0, tmpsbox, 0, sbox.Length);
			byte i = 0;
			byte j = 0;
			ushort len = (ushort)((buf[0]<<8)|buf[1]);
			len+=1; // +1 byte for packet code
			if(udpPacket)
				len+=2; //+2 byte for packet-count
			
			int k;
			for(k=(len/2)+2;k<len+2;k++)
			{
				i++;
				byte tmp = tmpsbox[i];
				j += tmp;
				tmpsbox[i]=tmpsbox[j];
				tmpsbox[j]=tmp;
				byte xorKey = tmpsbox[(byte)(tmpsbox[i]+tmpsbox[j])];
				j+=buf[k];
				buf[k]^= xorKey;
			}
			for(k=2;k<(len/2)+2;k++)
			{
				i++;
				byte tmp = tmpsbox[i];
				j += tmp;
				tmpsbox[i]=tmpsbox[j];
				tmpsbox[j]=tmp;
				byte xorKey = tmpsbox[(byte)(tmpsbox[i]+tmpsbox[j])];
				j+=buf[k];
				buf[k]^= xorKey;
			}
			return buf;
		}

		public static byte[] DecodeMythicRC4Packet(byte[] buf, byte[] sbox)
		{
			if(buf==null) return null;
			if(sbox==null) return null;
			byte[] tmpsbox = new byte[SYMKEY_SIZE];
			Array.Copy(sbox,0, tmpsbox, 0, sbox.Length);
			byte i = 0;
			byte j = 0;
			ushort len =(ushort)( (buf[0]<<8)|buf[1] + 10); //+10 byte for packet#,session,param,code,checksum
			int k;
			for(k=(len/2)+2;k<len+2;k++)
			{
				i++;
				byte tmp = tmpsbox[i];
				j += tmp;
				tmpsbox[i]=tmpsbox[j];
				tmpsbox[j]=tmp;
				byte xorKey = tmpsbox[(byte)(tmpsbox[i]+tmpsbox[j])];
				buf[k]^= xorKey;
				j+=buf[k];
			}
			for(k=2;k<(len/2)+2;k++)
			{
				i++;
				byte tmp = tmpsbox[i];
				j += tmp;
				tmpsbox[i]=tmpsbox[j];
				tmpsbox[j]=tmp;
				byte xorKey = tmpsbox[(byte)(tmpsbox[i]+tmpsbox[j])];
				buf[k]^= xorKey;
				j+=buf[k];
			}
			return buf;
		}
	}
}