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

    protected Sha3_256 sha3_256Hasher;

    public CryptixJob(IHashAlgorithm customBlockHeaderHasher, IHashAlgorithm customCoinbaseHasher, IHashAlgorithm customShareHasher)
        : base(customBlockHeaderHasher, customCoinbaseHasher, customShareHasher)
    {
    }

    protected override Span<byte> ComputeCoinbase(Span<byte> prePowHash, Span<byte> data)
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

    protected virtual Span<byte> SerializeCoinbase(Span<byte> prePowHash, long timestamp, ulong nonce)
    {
        Span<byte> hashBytes = stackalloc byte[32];
        
        using(var stream = new MemoryStream())
        {
            stream.Write(prePowHash);
            stream.Write(BitConverter.GetBytes((ulong) timestamp));
            stream.Write(new byte[32]); 
            stream.Write(BitConverter.GetBytes(nonce));
            
            
            coinbaseHasher.Digest(stream.ToArray(), hashBytes);
            
            // SHA3-256 
            using (SHA3Managed sha3 = new SHA3Managed(256))
            {
                byte[] sha3Hash = sha3.ComputeHash(hashBytes.ToArray());
                sha3Hash.CopyTo(hashBytes); 
            }
            
            return (Span<byte>) hashBytes.ToArray();
        }
    }


    protected override Share ProcessShareInternal(StratumConnection worker, string nonce)
    {
        var context = worker.ContextAs<KaspaWorkerContext>();

        BlockTemplate.Header.Nonce = Convert.ToUInt64(nonce, 16);

        var prePowHashBytes = SerializeHeader(BlockTemplate.Header, true);
        var coinbaseRawBytes = SerializeCoinbase(prePowHashBytes, BlockTemplate.Header.Timestamp, BlockTemplate.Header.Nonce);

        Span<byte> coinbaseBytes = stackalloc byte[32];
        coinbaseHasher.Digest(coinbaseRawBytes, coinbaseBytes);

        Span<byte> astroBWTv3Bytes = stackalloc byte[32];
        astroBWTv3Hasher.Digest(coinbaseBytes, astroBWTv3Bytes);

        Span<byte> hashCoinbaseBytes = stackalloc byte[32];
        shareHasher.Digest(ComputeCoinbase(coinbaseRawBytes, astroBWTv3Bytes), hashCoinbaseBytes);

        var targetHashCoinbaseBytes = new Target(new BigInteger(hashCoinbaseBytes.ToNewReverseArray(), true, true));
        var hashCoinbaseBytesValue = targetHashCoinbaseBytes.ToUInt256();
        //throw new StratumException(StratumError.LowDifficultyShare, $"nonce: {nonce} ||| hashCoinbaseBytes: {hashCoinbaseBytes.ToHexString()} ||| BigInteger: {targetHashCoinbaseBytes.ToBigInteger()} ||| Target: {hashCoinbaseBytesValue} - [stratum: {KaspaUtils.DifficultyToTarget(context.Difficulty)} - blockTemplate: {blockTargetValue}] ||| BigToCompact: {KaspaUtils.BigToCompact(targetHashCoinbaseBytes.ToBigInteger())} - [stratum: {KaspaUtils.BigToCompact(KaspaUtils.DifficultyToTarget(context.Difficulty))} - blockTemplate: {BlockTemplate.Header.Bits}] ||| shareDiff: {(double) new BigRational(SpectreConstants.Diff1b, targetHashCoinbaseBytes.ToBigInteger()) * shareMultiplier} - [stratum: {context.Difficulty} - blockTemplate: {KaspaUtils.TargetToDifficulty(KaspaUtils.CompactToBig(BlockTemplate.Header.Bits)) * (double) SpectreConstants.MinHash}]");

        // calc share-diff
        var shareDiff = (double) new BigRational(SpectreConstants.Diff1b, targetHashCoinbaseBytes.ToBigInteger()) * shareMultiplier;

        // diff check
        var stratumDifficulty = context.Difficulty;
        var ratio = shareDiff / stratumDifficulty;

        // check if the share meets the much harder block difficulty (block candidate)
        var isBlockCandidate = hashCoinbaseBytesValue <= blockTargetValue;
        //var isBlockCandidate = true;

        // test if share meets at least workers current difficulty
        if(!isBlockCandidate && ratio < 0.99)
        {
            // check if share matched the previous difficulty from before a vardiff retarget
            if(context.VarDiff?.LastUpdate != null && context.PreviousDifficulty.HasValue)
            {
                ratio = shareDiff / context.PreviousDifficulty.Value;

                if(ratio < 0.99)
                    throw new StratumException(StratumError.LowDifficultyShare, $"low difficulty share ({shareDiff})");

                // use previous difficulty
                stratumDifficulty = context.PreviousDifficulty.Value;
            }

            else
                throw new StratumException(StratumError.LowDifficultyShare, $"low difficulty share ({shareDiff})");
        }

        var result = new Share
        {
            BlockHeight = (long) BlockTemplate.Header.DaaScore,
            NetworkDifficulty = Difficulty,
            Difficulty = context.Difficulty / shareMultiplier
        };

        if(isBlockCandidate)
        {
            var hashBytes = SerializeHeader(BlockTemplate.Header, false);

            result.IsBlockCandidate = true;
            result.BlockHash = hashBytes.ToHexString();
        }

        return result;
    }

