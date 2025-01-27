using System;
using System.IO;
using System.Linq;
using System.Numerics;
using Miningcore.Contracts;
using Miningcore.Crypto;
using Miningcore.Crypto.Hashing.Algorithms;
using Miningcore.Extensions;
using Miningcore.Native;
using Miningcore.Stratum;
using Miningcore.Util;
using NBitcoin;
using kaspad = Miningcore.Blockchain.Kaspa.Kaspad;

namespace Miningcore.Blockchain.Kaspa.Custom.Cryptix;

public class CryptixJob : KaspaJob
{
    public CryptixJob(IHashAlgorithm customBlockHeaderHasher, IHashAlgorithm customCoinbaseHasher, IHashAlgorithm customShareHasher)
        : base(customBlockHeaderHasher, customCoinbaseHasher, customShareHasher)
    {
    }

    protected override virtual Span<byte> ComputeCoinbase(Span<byte> prePowHash, Span<byte> data)
    {

        ushort[][] matrix = GenerateMatrix(prePowHash);

        // Nibbles
        byte[] nibbles = new byte[64];
        for (int i = 0; i < 32; i++)
        {
            nibbles[2 * i] = (byte)(data[i] >> 4);
            nibbles[2 * i + 1] = (byte)(data[i] & 0x0F);
        }

        // Product-Array
        byte[] product = new byte[32];
        
        for (int i = 0; i < 32; i++)
        {
            ushort sum1 = 0;
            ushort sum2 = 0;
            
            // Matrix Multi
            for (int j = 0; j < 64; j++)
            {
                ushort elem = (ushort)nibbles[j];
                sum1 += (ushort)(matrix[2 * i][j] * elem);
                sum2 += (ushort)(matrix[2 * i + 1][j] * elem);
            }

            // Nibbles 
            byte aNibble = (byte)((sum1 & 0xF) ^ ((sum2 >> 4) & 0xF) ^ ((sum1 >> 8) & 0xF));
            byte bNibble = (byte)((sum2 & 0xF) ^ ((sum1 >> 4) & 0xF) ^ ((sum2 >> 8) & 0xF));

            // Komb
            product[i] = (byte)((aNibble << 4) | bNibble);
        }

        // XOR 
        for (int i = 0; i < 32; i++)
        {
            product[i] ^= data[i];
        }

        // final_x 
        byte[] final_x = new byte[32]
        {
            0x3F, 0xC2, 0xF2, 0xE2, 0xD1, 0x55, 0x81, 0x92,
            0xA0, 0x6B, 0xF5, 0x3F, 0x5A, 0x70, 0x32, 0xB4,
            0xE4, 0x84, 0xE4, 0xCB, 0x81, 0x73, 0xE7, 0xE0,
            0xD2, 0x7F, 0x8C, 0x55, 0xAD, 0x8C, 0x60, 0x8F
        };

        // XOR  final_x
        for (int i = 0; i < 32; i++)
        {
            product[i] ^= final_x[i];
        }

        // return
        return new Span<byte>(product);
    }


    protected override virtual Span<byte> SerializeHeader(kaspad.RpcBlockHeader header, bool isPrePow = true)
    {
        ulong nonce = isPrePow ? 0 : header.Nonce;
        long timestamp = isPrePow ? 0 : header.Timestamp;
        Span<byte> hashBytes = stackalloc byte[32];
        
        using (var stream = new MemoryStream())
        {
            var versionBytes = (!BitConverter.IsLittleEndian) ? BitConverter.GetBytes((ushort) header.Version).ReverseInPlace() : BitConverter.GetBytes((ushort) header.Version);
            stream.Write(versionBytes);
            var parentsBytes = (!BitConverter.IsLittleEndian) ? BitConverter.GetBytes((ulong) header.Parents.Count).ReverseInPlace() : BitConverter.GetBytes((ulong) header.Parents.Count);
            stream.Write(parentsBytes);

            foreach (var parent in header.Parents)
            {
                var parentHashesBytes = (!BitConverter.IsLittleEndian) ? BitConverter.GetBytes((ulong) parent.ParentHashes.Count).ReverseInPlace() : BitConverter.GetBytes((ulong) parent.ParentHashes.Count);
                stream.Write(parentHashesBytes);

                foreach (var parentHash in parent.ParentHashes)
                {
                    stream.Write(parentHash.HexToByteArray());
                }
            }

            stream.Write(header.HashMerkleRoot.HexToByteArray());
            stream.Write(header.AcceptedIdMerkleRoot.HexToByteArray());
            stream.Write(header.UtxoCommitment.HexToByteArray());

            var timestampBytes = (!BitConverter.IsLittleEndian) ? BitConverter.GetBytes((ulong) timestamp).ReverseInPlace() : BitConverter.GetBytes((ulong) timestamp);
            stream.Write(timestampBytes);
            var bitsBytes = (!BitConverter.IsLittleEndian) ? BitConverter.GetBytes(header.Bits).ReverseInPlace() : BitConverter.GetBytes(header.Bits);
            stream.Write(bitsBytes);
            var nonceBytes = (!BitConverter.IsLittleEndian) ? BitConverter.GetBytes(nonce).ReverseInPlace() : BitConverter.GetBytes(nonce);
            stream.Write(nonceBytes);
            var daaScoreBytes = (!BitConverter.IsLittleEndian) ? BitConverter.GetBytes(header.DaaScore).ReverseInPlace() : BitConverter.GetBytes(header.DaaScore);
            stream.Write(daaScoreBytes);
            var blueScoreBytes = (!BitConverter.IsLittleEndian) ? BitConverter.GetBytes(header.BlueScore).ReverseInPlace() : BitConverter.GetBytes(header.BlueScore);
            stream.Write(blueScoreBytes);

            var blueWork = header.BlueWork.PadLeft(header.BlueWork.Length + (header.BlueWork.Length % 2), '0');
            var blueWorkBytes = blueWork.HexToByteArray();

            var blueWorkLengthBytes = (!BitConverter.IsLittleEndian) ? BitConverter.GetBytes((ulong) blueWorkBytes.Length).ReverseInPlace() : BitConverter.GetBytes((ulong) blueWorkBytes.Length);
            stream.Write(blueWorkLengthBytes);
            stream.Write(blueWorkBytes);

            stream.Write(header.PruningPoint.HexToByteArray());

            // First Hash
            blockHeaderHasher.Digest(stream.ToArray(), hashBytes);

            // Sha3
            using (var sha3 = new SHA3Managed(256))
            {
                var sha3Hash = sha3.ComputeHash(hashBytes.ToArray());

                // return
                return (Span<byte>)sha3Hash.ToArray();
            }
        }
    }
    
}
