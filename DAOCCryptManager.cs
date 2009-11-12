using System;
using System.IO;
using System.Security.Cryptography;
using Mono.Math;
using Mono.Security.Cryptography;

namespace DOL.Crypt
{
	/// <summary>
	/// DAOC RSA MANAGER make the key 
	/// </summary>
	public class DAOCRSAManager : Mono.Security.Cryptography.RSAManaged
	{
		//public const int  KEY_LEN=512;
		public const int RSA_KEY_BITS=1536;
		public const int BLOCKLEN = RSA_KEY_BITS / 8 / 3 - 1;

		public enum eRSAKeyFormat : int
		{
		PK_PRIVATE				= 0,/* PK private keys */
		PK_PUBLIC				= 1,/* PK public keys */
		PK_PRIVATE_OPTIMIZED	= 2/* PK private key [rsa optimized] */
		}

		public DAOCRSAManager() : base()
		{
			this.KeySize=RSA_KEY_BITS/8;//modulus 192
			//size exp 65537
		}
		public DAOCRSAManager(int dwKeySize) : base(dwKeySize)
		{

		}

		#region generate rsa key

		public bool GenerateRSAKey()
		{
			FileStream writer=null;
			try
			{
				writer = new FileStream( "rsakey.dat", FileMode.Open);
				ulong exportedKeyLength = (ulong)writer.Length;

				if(exportedKeyLength > 0)
				{
					
					byte[] exportedKey = new byte[exportedKeyLength];
					writer.Read(exportedKey,0,(int)exportedKeyLength);

					return this.Import(exportedKey);//TODO IMPORT
				}
				return false;
			}
			catch(FileNotFoundException e)
			{
				if (e.GetType().Equals(typeof(FileNotFoundException)))
				{
					writer = new FileStream( "rsakey.dat", FileMode.CreateNew);
					this.GenerateKeyPair();
					ulong exportedKeyLength = RSA_KEY_BITS;
					byte[] exportedKey = new byte[exportedKeyLength];
					exportedKey = Export(eRSAKeyFormat.PK_PRIVATE_OPTIMIZED);
					writer.Write(exportedKey,0,(int)exportedKeyLength);
					writer.Close();
					return true;
				}
				return false;
			}
			catch (Exception e)
			{
				Console.WriteLine("error in RSA generation");
				return false;
			}
		}
		#endregion
		
		#region Import

		public bool Import(byte[] exportedkey)
		{
			RSAReader reader = new RSAReader(exportedkey);

			reader.Skip(6);//skip the header
			ushort len = reader.ReadShort();
			reader.Skip(2);//you have the len byte 2 time
			byte[] key = new byte[len];
			reader.Read(key,0,len);

			return (RSAImport(key));
		}

		public bool RSAImport(byte[] exportedkey)
		{
			RSAReader reader = new RSAReader(exportedkey);
			
			eRSAKeyFormat format =(eRSAKeyFormat)reader.ReadByte();
			RSAParam key = new RSAParam();

			/* input modulus  and exponent*/
			key.Modulus = reader.ReadBignum();
			key.Exponent = reader.ReadBignum();

			if (format == eRSAKeyFormat.PK_PRIVATE_OPTIMIZED || format == eRSAKeyFormat.PK_PRIVATE) 
			{
				key.D = reader.ReadBignum();
			}

			if (format == eRSAKeyFormat.PK_PRIVATE_OPTIMIZED) 
			{
				key.DQ = reader.ReadBignum();
				key.DP = reader.ReadBignum();
				key.pQ = reader.ReadBignum();
				key.qP = reader.ReadBignum();
				key.P = reader.ReadBignum();
				key.Q = reader.ReadBignum();
			}

			//skip version at end of buffer

			this.ImportParam(key);
			
			return true;
		}

		#endregion Import

		#region Export

		public byte[] Export(eRSAKeyFormat type)
		{
			RSAWriter writer = new RSAWriter();
			byte[] exported_key_buffer;

			/* store packet header */
			/* store version number */
			writer.WriteByte(0x91);
			writer.WriteByte(0x00);//low endian of version

			/* store section and subsection */
			writer.WriteByte(0x00);
			writer.WriteByte(0x00);

			RSAParam param = this.ExportParam(false);

			exported_key_buffer = RSAExport(param,eRSAKeyFormat.PK_PRIVATE_OPTIMIZED);
			int outlen = exported_key_buffer.Length;
			writer.WriteShort((ushort)outlen);
			writer.WriteShort((ushort)outlen);//need to be get out?


			writer.Write(exported_key_buffer, 0, exported_key_buffer.Length);
			
			//protocole version
			writer.WriteByte(0);
			writer.WriteByte(0);
			writer.WriteByte(0);
			writer.WriteByte(1);
			writer.WriteByte(0);
			writer.WriteByte(1);

			return writer.GetBuffer();
		}
		
		private byte[] RSAExport(RSAParam key,eRSAKeyFormat format)
		{
			RSAWriter writer = new RSAWriter();
			
			/* output key type */
			writer.WriteByte((byte)format);

			/* output modulus  and exponent*/
			writer.WriteBignum(key.Modulus);
			writer.WriteBignum(key.Exponent);

			if (format == eRSAKeyFormat.PK_PRIVATE_OPTIMIZED || format == eRSAKeyFormat.PK_PRIVATE) 
			{
				writer.WriteBignum(key.D);
			}

			if (format == eRSAKeyFormat.PK_PRIVATE_OPTIMIZED) 
			{
				writer.WriteBignum(key.DQ);
				writer.WriteBignum(key.DP);
				writer.WriteBignum(key.pQ);
                writer.WriteBignum(key.qP);
				writer.WriteBignum(key.P);
				writer.WriteBignum(key.Q);
			}

			return writer.GetBuffer();
		}
		#endregion

		#region encode mythic RSA packet
			
		public byte[] EncodeMythicRSAPacket(byte[] inMessage)
		{
			if(inMessage.Length==0) return null;

			int curInPtr = 2; //Input starts at byte 3
			int curOutPtr = 2; //Output starts at byte 3 too
			
			RSAWriter writer = new RSAWriter();
			writer.WriteByte(0);
			writer.WriteByte(0);//add length at end

			int blockLen = BLOCKLEN;
			byte[] paddedBlock = new byte[200];//normaly it s 189 byte....
			int cryptedBlockLen;
			while(curInPtr < inMessage.Length)
			{
				blockLen = BLOCKLEN;
				if(curInPtr+blockLen > inMessage.Length)
					blockLen = inMessage.Length - curInPtr;
				
				//Pad a block of data
				MemoryStream stream = new MemoryStream();
				stream.Write(inMessage,curInPtr,blockLen);
				paddedBlock =RSAPad(stream.GetBuffer());

				
				curInPtr += blockLen;
				
				cryptedBlockLen = paddedBlock.Length - curOutPtr - 2;
				
				byte[] packet = RSAExptmod( paddedBlock,eRSAKeyFormat.PK_PUBLIC);

				writer.WriteShort((ushort)cryptedBlockLen);
				writer.Write( packet,0,cryptedBlockLen);

				curOutPtr += cryptedBlockLen + 2;
	
			}
			writer.Seek(0, SeekOrigin.Begin);
			writer.WriteShort((ushort)curOutPtr);

			return writer.GetBuffer();
		}
		#endregion

		#region decode mythic RSA packet

		public byte[] DecodeMythicRSAPacket(byte[]inMessage)
		{
			if(inMessage==null) return null;

			int curInPtr = 2;

			byte[]decryptedBlock = new byte[500];
			byte[]depaddedBlock = new byte[500];

			RSAWriter writer = new RSAWriter();
			writer.WriteByte(0);
			writer.WriteByte(0);//add length at end

			while(curInPtr < inMessage.Length)
			{
				if(curInPtr+2 > inMessage.Length)
					return null;
				int curBlockLen = (inMessage[curInPtr]<<8)+inMessage[curInPtr+1];
				curInPtr+=2;
				if(curBlockLen>0)
				{
					MemoryStream stream = new MemoryStream();
					stream.Write(inMessage,curInPtr,curBlockLen);
					decryptedBlock = RSAExptmod( stream.GetBuffer(),eRSAKeyFormat.PK_PRIVATE);
					
					depaddedBlock = RSADepad(decryptedBlock);

					writer.Write(depaddedBlock,0,depaddedBlock.Length);
				}
				curInPtr+=curBlockLen;
			}

			writer.Seek(0, SeekOrigin.Begin);
			writer.WriteShort((ushort)writer.Length);

			return writer.GetBuffer();
		}	


		#endregion

		#region padding
		
		public byte[] RSAPad(byte[] Packetin)
		{

			if (Packetin.Length > 512) 
			{
				return null;
			}

			RSAWriter writer = new RSAWriter(Packetin.Length*3);

			writer.WriteByte(0xFF);

			byte[] buf =new byte[Packetin.Length*2];
			Random m_random = new Random((int)DateTime.Now.Ticks);
			m_random.NextBytes(buf);

			writer.Write(buf,0,Packetin.Length-1);
			writer.Write(Packetin,0,Packetin.Length);
			writer.Write(buf,Packetin.Length-1,Packetin.Length-1);
			writer.WriteByte(0xFF);

			return writer.GetBuffer();
		}

		public byte[] RSADepad(byte[] Packetin)
		{
			RSAWriter writer = new RSAWriter(Packetin.Length/3);
			writer.Write(Packetin,Packetin.Length/3,Packetin.Length/3);
			return writer.GetBuffer();
		}

		#endregion

		#region exptmod
		//for that it s strange because it s a quite different of DecryptValue and encryptvalue
		//but maybe it s the same thanks to math ;)
		//so need to do some math to check...
		public byte[] RSAExptmod(byte[] PacketIn, eRSAKeyFormat format)
		{
			BigInteger tmp, tmpa, tmpb;

			//todo more check key generate format packet in and out null...

			tmp = new BigInteger(PacketIn);

			/* are we using the private exponent */
			if (format == eRSAKeyFormat.PK_PRIVATE ) 
			{
				// m1 = c^dp mod p
				tmpa = tmp.ModPow (dp, p);
				tmpb = tmp.ModPow (dq, q);
				tmp = (tmpa * qP + tmpb*pQ).ModPow (0, n);
			} 
			else 
			{
				tmp = tmp.ModPow (e, n);
			}

			/* convert it */
			return tmp.GetBytes();
		}		
		#endregion
	}
}
