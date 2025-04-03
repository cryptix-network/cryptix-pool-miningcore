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
    protected Blake3 blake3Hasher;
    protected Sha3_256 sha3_256Hasher;

    public CryptixJob(IHashAlgorithm customBlockHeaderHasher, IHashAlgorithm customCoinbaseHasher, IHashAlgorithm customShareHasher)
        : base(customBlockHeaderHasher, customCoinbaseHasher, customShareHasher)
    {

         this.sha3_256Hasher = new Sha3_256();
         this.blake3Hasher = new Blake3();
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

        // Product-Arrays
        byte[] product = new byte[32];
        byte[] nibbleProduct = new byte[32];

        for (int i = 0; i < 32; i++)
        {
            uint sum1 = 0, sum2 = 0, sum3 = 0, sum4 = 0;
            
            // Matrix Multiplication
            for (int j = 0; j < 64; j++)
            {
                uint elem = nibbles[j];
                sum1 += (uint)(matrix[2 * i][j] * elem);
                sum2 += (uint)(matrix[2 * i + 1][j] * elem);
                sum3 += (uint)(matrix[1 * i + 2][j] * elem);
                sum4 += (uint)(matrix[1 * i + 3][j] * elem);
            }

            // A Nibble
            byte aNibble = (byte)((sum1 & 0xF) ^ ((sum2 >> 4) & 0xF) ^ ((sum3 >> 8) & 0xF)
                ^ ((sum1 * 0xABCD >> 12) & 0xF)
                ^ ((sum1 * 0x1234 >> 8) & 0xF)
                ^ ((sum2 * 0x5678 >> 16) & 0xF)
                ^ ((sum3 * 0x9ABC >> 4) & 0xF)
                ^ ((sum1 << 3 & 0xF) ^ (sum3 >> 5 & 0xF)));

            // B Nibble
            byte bNibble = (byte)((sum2 & 0xF) ^ ((sum1 >> 4) & 0xF) ^ ((sum4 >> 8) & 0xF)
                ^ ((sum2 * 0xDCBA >> 14) & 0xF)
                ^ ((sum2 * 0x8765 >> 10) & 0xF)
                ^ ((sum1 * 0x4321 >> 6) & 0xF)
                ^ ((sum4 << 2 ^ sum1 >> 1) & 0xF));

            // C Nibble
            byte cNibble = (byte)((sum3 & 0xF) ^ ((sum2 >> 4) & 0xF) ^ ((sum2 >> 8) & 0xF)
                ^ ((sum3 * 0xF135 >> 10) & 0xF)
                ^ ((sum3 * 0x2468 >> 12) & 0xF)
                ^ ((sum4 * 0xACEF >> 8) & 0xF)
                ^ ((sum2 * 0x1357 >> 4) & 0xF)
                ^ ((sum3 << 5 & 0xF) ^ (sum1 >> 7 & 0xF)));

            // D Nibble
            byte dNibble = (byte)((sum1 & 0xF) ^ ((sum4 >> 4) & 0xF) ^ ((sum1 >> 8) & 0xF)
                ^ ((sum4 * 0x57A3 >> 6) & 0xF)
                ^ ((sum3 * 0xD4E3 >> 12) & 0xF)
                ^ ((sum1 * 0x9F8B >> 10) & 0xF)
                ^ ((sum4 << 4 ^ (sum1 + sum2)) & 0xF));

            // Combine into final products
            nibbleProduct[i] = (byte)((cNibble << 4) | dNibble);
            product[i] = (byte)((aNibble << 4) | bNibble);
        }

        // XOR with original data
        for (int i = 0; i < 32; i++)
        {
            product[i] ^= data[i];
            nibbleProduct[i] ^= data[i];
        }

        // return
        return new Span<byte>(product);
    }

 protected override Share ProcessShareInternal(StratumConnection worker, string nonce)
    {
        var context = worker.ContextAs<KaspaWorkerContext>();

        BlockTemplate.Header.Nonce = Convert.ToUInt64(nonce, 16);

        var prePowHashBytes = SerializeHeader(BlockTemplate.Header, true);
        var coinbaseBytes = SerializeCoinbase(prePowHashBytes, BlockTemplate.Header.Timestamp, BlockTemplate.Header.Nonce);


        Span<byte> sha3_256Bytes = stackalloc byte[32];
        sha3_256Hasher.Digest(coinbaseBytes, sha3_256Bytes);


        Span<byte> hashCoinbaseBytes = stackalloc byte[32];
        shareHasher.Digest(ComputeCoinbase(prePowHashBytes, sha3_256Bytes), hashCoinbaseBytes);

        var targetHashCoinbaseBytes = new Target(new BigInteger(hashCoinbaseBytes.ToNewReverseArray(), true, true));
        var hashCoinbaseBytesValue = targetHashCoinbaseBytes.ToUInt256();
        //throw new StratumException(StratumError.LowDifficultyShare, $"nonce: {nonce} ||| hashCoinbaseBytes: {hashCoinbaseBytes.ToHexString()} ||| BigInteger: {targetHashCoinbaseBytes.ToBigInteger()} ||| Target: {hashCoinbaseBytesValue} - [stratum: {KaspaUtils.DifficultyToTarget(context.Difficulty)} - blockTemplate: {blockTargetValue}] ||| BigToCompact: {KaspaUtils.BigToCompact(targetHashCoinbaseBytes.ToBigInteger())} - [stratum: {KaspaUtils.BigToCompact(KaspaUtils.DifficultyToTarget(context.Difficulty))} - blockTemplate: {BlockTemplate.Header.Bits}] ||| shareDiff: {(double) new BigRational(KaspaConstants.Diff1b, targetHashCoinbaseBytes.ToBigInteger()) * shareMultiplier} - [stratum: {context.Difficulty} - blockTemplate: {KaspaUtils.TargetToDifficulty(KaspaUtils.CompactToBig(BlockTemplate.Header.Bits)) * (double) KaspaConstants.MinHash}]");

        // calc share-diff
        var shareDiff = (double) new BigRational(KaspaConstants.Diff1b, targetHashCoinbaseBytes.ToBigInteger()) * shareMultiplier;

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

}

    

