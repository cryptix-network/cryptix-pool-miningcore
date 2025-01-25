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

    protected override ushort[][] GenerateMatrix(Span<byte> prePowHash)
    {
        ushort[][] matrix = new ushort[64][];
        for (int i = 0; i < 64; i++)
        {
            matrix[i] = new ushort[64];
        }

        var generator = new KaspaXoShiRo256PlusPlus(prePowHash);
        while (true)
        {
            for (int i = 0; i < 64; i++)
            {
                for (int j = 0; j < 64; j += 16)
                {
                    ulong val = generator.Uint64();
                    for (int shift = 0; shift < 16; shift++)
                    {
                        matrix[i][j + shift] = (ushort)((val >> (4 * shift)) & 0x0F);
                    }
                }
            }

            byte[] final_x = new byte[32]
            {
                0x3F, 0xC2, 0xF2, 0xE2, 0xD1, 0x55, 0x81, 0x92,
                0xA0, 0x6B, 0xF5, 0x3F, 0x5A, 0x70, 0x32, 0xB4,
                0xE4, 0x84, 0xE4, 0xCB, 0x81, 0x73, 0xE7, 0xE0,
                0xD2, 0x7F, 0x8C, 0x55, 0xAD, 0x8C, 0x60, 0x8F
            };

            for (int i = 0; i < 32; i++)
            {
                for (int j = 0; j < 64; j++)
                {
                    matrix[i][j] ^= (ushort)(final_x[i] & 0xFF);
                }
            }

            if (ComputeRank(matrix) == 64)
                return matrix;
        }
    }

    protected override int ComputeRank(ushort[][] matrix)
    {
        double Eps = 0.000000001;
        double[][] B = matrix.Select(row => row.Select(val => (double)val).ToArray()).ToArray();
        int rank = 0;
        bool[] rowSelected = new bool[64];
        for (int i = 0; i < 64; i++)
        {
            int j;
            for (j = 0; j < 64; j++)
            {
                if (!rowSelected[j] && Math.Abs(B[j][i]) > Eps)
                    break;
            }
            if (j != 64)
            {
                rank++;
                rowSelected[j] = true;
                double pivot = B[j][i];
                for (int p = i + 1; p < 64; p++)
                {
                    B[j][p] /= pivot;
                }
                for (int k = 0; k < 64; k++)
                {
                    if (k != j && Math.Abs(B[k][i]) > Eps)
                    {
                        for (int p = i + 1; p < 64; p++)
                        {
                            B[k][p] -= B[j][p] * B[k][i];
                        }
                    }
                }
            }
        }
        return rank;
    }

    protected override Span<byte> ComputeCoinbase(Span<byte> prePowHash, Span<byte> data)
    {
        ushort[][] matrix = GenerateMatrix(prePowHash);

        ushort[] vector = new ushort[64];
        for (int i = 0; i < 32; i++)
        {
            vector[2 * i] = (ushort)(data[i] >> 4);
            vector[2 * i + 1] = (ushort)(data[i] & 0x0F);
        }

        ushort[] product = new ushort[64];
        for (int i = 0; i < 64; i++)
        {
            ushort sum = 0;
            for (int j = 0; j < 64; j++)
            {
                sum += (ushort)(matrix[i][j] * vector[j]);
            }
            product[i] = (ushort)(sum >> 10);
        }

        byte[] res = new byte[32];
        for (int i = 0; i < 32; i++)
        {
            res[i] = (byte)(data[i] ^ ((byte)(product[2 * i] << 4) | (byte)product[2 * i + 1]));
        }

        return res.AsSpan(); 
    }

    private byte[] Sha3_256Hash(Span<byte> input)
    {
        var sha3Hasher = new Sha3_256();
        byte[] result = new byte[32];
        sha3Hasher.Digest(input, result); 
        return result;  
    }


    private void heavyHash(Span<byte> input, Span<byte> output)
    {
        using (var sha256 = System.Security.Cryptography.SHA256.Create())
        {
            byte[] hash = sha256.ComputeHash(input.ToArray());
            hash.CopyTo(output);
        }
    }

    protected override Span<byte> SerializeCoinbase(Span<byte> prePowHash, long timestamp, ulong nonce)
    {
        byte[] hashBytes = new byte[32];

        using (var stream = new MemoryStream())
        {
            stream.Write(prePowHash);
            stream.Write(BitConverter.GetBytes((ulong)timestamp));
            stream.Write(new byte[32]);
            stream.Write(BitConverter.GetBytes(nonce));

            coinbaseHasher.Digest(stream.ToArray(), hashBytes);
        }

        byte[] sha3HashBytes = Sha3_256Hash(hashBytes);


        byte[] finalHashBytes = new byte[32];
        heavyHash(sha3HashBytes, finalHashBytes);

        return finalHashBytes.AsSpan();  
    }

    protected override Span<byte> SerializeHeader(kaspad.RpcBlockHeader header, bool isPrePow = true)
    {
        ulong nonce = isPrePow ? 0 : header.Nonce;
        long timestamp = isPrePow ? 0 : header.Timestamp;
        byte[] hashBytes = new byte[32];

        using (var stream = new MemoryStream())
        {
            var versionBytes = (!BitConverter.IsLittleEndian) ? BitConverter.GetBytes((ushort)header.Version).ReverseInPlace() : BitConverter.GetBytes((ushort)header.Version);
            stream.Write(versionBytes);
            var parentsBytes = (!BitConverter.IsLittleEndian) ? BitConverter.GetBytes((ulong)header.Parents.Count).ReverseInPlace() : BitConverter.GetBytes((ulong)header.Parents.Count);
            stream.Write(parentsBytes);

            foreach (var parent in header.Parents)
            {
                var parentHashesBytes = (!BitConverter.IsLittleEndian) ? BitConverter.GetBytes((ulong)parent.ParentHashes.Count).ReverseInPlace() : BitConverter.GetBytes((ulong)parent.ParentHashes.Count);
                stream.Write(parentHashesBytes);

                foreach (var parentHash in parent.ParentHashes)
                {
                    stream.Write(parentHash.HexToByteArray());
                }
            }

            stream.Write(header.HashMerkleRoot.HexToByteArray());
            stream.Write(header.AcceptedIdMerkleRoot.HexToByteArray());
            stream.Write(header.UtxoCommitment.HexToByteArray());

            var timestampBytes = (!BitConverter.IsLittleEndian) ? BitConverter.GetBytes((ulong)timestamp).ReverseInPlace() : BitConverter.GetBytes((ulong)timestamp);
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

            var blueWorkLengthBytes = (!BitConverter.IsLittleEndian) ? BitConverter.GetBytes((ulong)blueWorkBytes.Length).ReverseInPlace() : BitConverter.GetBytes((ulong)blueWorkBytes.Length);
            stream.Write(blueWorkLengthBytes);
            stream.Write(blueWorkBytes);

            stream.Write(header.PruningPoint.HexToByteArray());

            blockHeaderHasher.Digest(stream.ToArray(), hashBytes);
        }

        byte[] finalHashBytes = new byte[32];
        heavyHash(hashBytes, finalHashBytes);

        return finalHashBytes.AsSpan();  
    }
}
