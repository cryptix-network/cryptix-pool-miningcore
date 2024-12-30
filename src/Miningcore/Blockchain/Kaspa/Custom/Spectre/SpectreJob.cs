using System;
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

namespace Miningcore.Blockchain.Kaspa.Custom.Spectre;

public class SpectreJob : KaspaJob
{
    protected AstroBWTv3 astroBWTv3Hasher;

    public SpectreJob(IHashAlgorithm customBlockHeaderHasher, IHashAlgorithm customCoinbaseHasher, IHashAlgorithm customShareHasher) : base(customBlockHeaderHasher, customCoinbaseHasher, customShareHasher)
    {
        this.astroBWTv3Hasher = new AstroBWTv3();
    }

    protected override Span<byte> SerializeCoinbase(Span<byte> prePowHash, long timestamp, ulong nonce)
    {
        using(var stream = new MemoryStream())
        {
            stream.Write(prePowHash);
            stream.Write(BitConverter.GetBytes((ulong) timestamp));
            stream.Write(new byte[32]); // 32 zero bytes padding
            stream.Write(BitConverter.GetBytes(nonce));

            return (Span<byte>) stream.ToArray();
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

    public override void Init(kaspad.RpcBlock blockTemplate, string jobId, double shareMultiplier)
    {
        Contract.RequiresNonNull(blockTemplate);
        Contract.RequiresNonNull(jobId);
        
        JobId = jobId;
        this.shareMultiplier = shareMultiplier;

        var target = new Target(KaspaUtils.CompactToBig(blockTemplate.Header.Bits));
        Difficulty = KaspaUtils.TargetToDifficulty(target.ToBigInteger()) * (double) SpectreConstants.MinHash;
        blockTargetValue = target.ToUInt256();
        BlockTemplate = blockTemplate;
        
        var (largeJob, regularJob) = SerializeJobParamsData(SerializeHeader(blockTemplate.Header));
        jobParams = new object[]
        {
            JobId,
            largeJob + BitConverter.GetBytes(blockTemplate.Header.Timestamp).ToHexString().PadLeft(16, '0'),
            regularJob,
            blockTemplate.Header.Timestamp,
        };
    }
}