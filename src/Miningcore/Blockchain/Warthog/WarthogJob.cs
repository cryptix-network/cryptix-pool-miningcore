using System;
using System.Collections.Concurrent;
using System.Globalization;
using System.Linq;
using System.Text;
using VeruscoinConstants = Miningcore.Blockchain.Equihash.VeruscoinConstants;
using Miningcore.Blockchain.Warthog.DaemonResponses;
using Miningcore.Contracts;
using Miningcore.Crypto;
using Miningcore.Crypto.Hashing.Algorithms;
using Miningcore.Extensions;
using Miningcore.Native;
using Miningcore.Stratum;
using Miningcore.Time;

namespace Miningcore.Blockchain.Warthog;

public class WarthogJob
{
    protected IMasterClock clock;
    protected readonly IHashAlgorithm sha256S = new Sha256S();
    protected readonly IHashAlgorithm sha256D = new Sha256D();
    protected readonly Verushash verusHash = new Verushash();

    protected readonly ConcurrentDictionary<string, bool> submissions = new(StringComparer.OrdinalIgnoreCase);
    protected WarthogTarget blockTargetValue;
    protected byte[] prevHashBytes;
    protected byte[] merklePrefixBytes;
    //protected byte[] merkleRootBytes;
    protected byte[] versionBytes;
    protected byte[] nBitsBytes;
    protected byte[] nTimeBytes;

    protected object[] jobParams;

    #region API-Surface

    public WarthogBlockTemplate BlockTemplate { get; protected set; }
    public double Difficulty { get; protected set; }
    public WarthogNetworkType network { get; protected set; }
    public bool IsJanusHash { get; protected set; }

    public string JobId { get; protected set; }

    protected virtual byte[] SerializeHeader(byte[] extraNonce, uint nTime, uint nonce)
    {
        var merkleRootBytes = SerializeMerkleRoot(extraNonce);

        using(var stream = new MemoryStream(WarthogConstants.HeaderByteSize))
        {
            var bw = new BinaryWriter(stream);

            bw.Write(prevHashBytes);
            bw.Write(nBitsBytes);
            bw.Write(merkleRootBytes);
            bw.Write(versionBytes);
            bw.Write((BitConverter.IsLittleEndian ? BitConverter.GetBytes(nTime).ReverseInPlace() : BitConverter.GetBytes(nTime))); // wart-node expects a big endian format.
            bw.Write((BitConverter.IsLittleEndian ? BitConverter.GetBytes(nonce).ReverseInPlace() : BitConverter.GetBytes(nonce))); // wart-node expects a big endian format.

            return stream.ToArray();
        }
    }

    protected virtual byte[] SerializeMerkleRoot(byte[] extraNonce)
    {
        // Merkle root computation
        Span<byte> merklePrefixExtraNonceBytes = stackalloc byte[merklePrefixBytes.Length + extraNonce.Length];
        merklePrefixBytes.CopyTo(merklePrefixExtraNonceBytes);
        extraNonce.CopyTo(merklePrefixExtraNonceBytes[merklePrefixBytes.Length..]);

        Span<byte> merkleRootBytes = stackalloc byte[32];
        sha256S.Digest(merklePrefixExtraNonceBytes, merkleRootBytes);

        return merkleRootBytes.ToArray();
    }

    protected virtual byte[] SerializeExtranonce(string extraNonce1, string extraNonce2)
    {
        var extraNonce1Bytes = extraNonce1.HexToByteArray();
        var extraNonce2Bytes = extraNonce2.HexToByteArray();

        Span<byte> extraNonceBytes = stackalloc byte[extraNonce1Bytes.Length + extraNonce2Bytes.Length];
        extraNonce1Bytes.CopyTo(extraNonceBytes);
        extraNonce2Bytes.CopyTo(extraNonceBytes[extraNonce1Bytes.Length..]);

        return extraNonceBytes.ToArray();
    }

    protected virtual byte[] SerializeBody(byte[] extraNonce)
    {
        var bodyBytes = BlockTemplate.Data.Body.HexToByteArray();
        var bodyBytesLength = bodyBytes.Length;
        bodyBytes = bodyBytes.Skip(extraNonce.Length).Take(bodyBytesLength - extraNonce.Length).ToArray();

        Span<byte> extraNonceBodyBytes = stackalloc byte[extraNonce.Length + bodyBytes.Length];
        extraNonce.CopyTo(extraNonceBodyBytes);
        bodyBytes.CopyTo(extraNonceBodyBytes[extraNonce.Length..]);

        return extraNonceBodyBytes.ToArray();
    }

    protected virtual (Share Share, string HeaderHex) ProcessShareInternal(
        StratumConnection worker, string extraNonce2, uint nTime, uint nonce)
    {
        var context = worker.ContextAs<WarthogWorkerContext>();
        var extraNonceBytes = SerializeExtranonce(context.ExtraNonce1, extraNonce2);
        var headerSolutionBytes = SerializeHeader(extraNonceBytes, nTime, nonce);

        WarthogCustomFloat headerSolutionValue;
        bool isBlockCandidate;
        uint version = uint.Parse(versionBytes.ToHexString(), NumberStyles.HexNumber);
        string verusHashVersion = version > 2 ? VeruscoinConstants.HashVersion2b2o : VeruscoinConstants.HashVersion2b1;

        // hash block-header with sha256D
        Span<byte> headerSolutionSha256D = stackalloc byte[32];
        sha256D.Digest(headerSolutionBytes, headerSolutionSha256D);

        // hash block-header with sha256S
        Span<byte> headerSolutionSha256T = stackalloc byte[32];
        sha256S.Digest(headerSolutionSha256D, headerSolutionSha256T);
        
        WarthogCustomFloat sha256TFloat = new WarthogCustomFloat(headerSolutionSha256T);

        // hash block-header with Verushash
        Span<byte> headerSolutionVerusHash = stackalloc byte[32];
        verusHash.Digest(headerSolutionBytes, headerSolutionVerusHash, verusHashVersion);

        WarthogCustomFloat verusFloat = new WarthogCustomFloat(headerSolutionVerusHash);

        // I know the following looks incredibly overwhelming but it's the harsh reality about WARTHOG. And CODE is LAW, so we must follow it.
        // https://github.com/warthog-network/Warthog/blob/master/src/shared/src/block/header/view.cpp
        // Testnet
        if(network == WarthogNetworkType.Testnet)
        {
            // The Sha256t hash must not be too small. We will adjust that if better miner(s) are available
            if(sha256TFloat < WarthogConstants.ProofOfBalancedWorkC)
                sha256TFloat = WarthogConstants.ProofOfBalancedWorkC;

            headerSolutionValue = verusFloat * WarthogCustomFloat.Pow(sha256TFloat, WarthogConstants.ProofOfBalancedWorkExponent);
            
            // check if the share meets the much harder block difficulty (block candidate)
            isBlockCandidate = headerSolutionValue < blockTargetValue;
        }
        // Mainnet
        else
        {
            // JanusHash activated
            if(IsJanusHash && BlockTemplate.Data.Height > WarthogConstants.JanusHashRetargetBlockHeight)
            {
                // new JanusHash
                if(BlockTemplate.Data.Height > WarthogConstants.JanusHashV2RetargetBlockHeight)
                {
                    if(BlockTemplate.Data.Height > WarthogConstants.JanusHashV6RetargetBlockHeight)
                    {
                        // The Sha256t hash must not be too small. We will adjust that if better miner(s) are available
                        if(sha256TFloat < WarthogConstants.ProofOfBalancedWorkC)
                            sha256TFloat = WarthogConstants.ProofOfBalancedWorkC;
                    }

                    headerSolutionValue = verusFloat * WarthogCustomFloat.Pow(sha256TFloat, WarthogConstants.ProofOfBalancedWorkExponent);
                }
                // old JanusHash
                else
                    headerSolutionValue = verusFloat * sha256TFloat;

                // check if the share meets the much harder block difficulty (block candidate)
                isBlockCandidate = headerSolutionValue < blockTargetValue;
            }
            // JanusHash not activated
            else
            {
                headerSolutionValue = verusFloat * WarthogCustomFloat.Pow(sha256TFloat, WarthogConstants.ProofOfBalancedWorkExponent);

                // check if the share meets the much harder block difficulty (block candidate)
                isBlockCandidate = headerSolutionSha256D < blockTargetValue;
            }
        }

        // Miner must meet the target "1/difficulty" or "1/janush_number" to mine a share - https://www.warthog.network/docs/developers/integrations/pools/stratum/#notable-differences-from-bitcoins-stratum-protocol-1
        // calc share-diff
        var shareDiff = WarthogConstants.Diff1 / (double)headerSolutionValue;

        //throw new StratumException(StratumError.LowDifficultyShare, $"nonce: {nonce} - headerSolutionBytes: {headerSolutionBytes.ToHexString()} - headerSolutionVerusHash: {headerSolutionVerusHash.ToHexString()} - proofOfBalancedWorkC: {(double)WarthogConstants.ProofOfBalancedWorkC} - ProofOfBalancedWorkExponent: {(double)WarthogConstants.ProofOfBalancedWorkExponent} - sha256TFloat: {(double)sha256TFloat} - verusFloat: {(double)verusFloat} - CalculateHashrate: {WarthogUtils.CalculateHashrate(sha256TFloat, verusFloat)} ||| headerSolutionValue: {(double)headerSolutionValue} - exponent => (wcf: [{headerSolutionValue._exponent}, {(uint)(headerSolutionValue._exponent < 0 ? -headerSolutionValue._exponent : headerSolutionValue._exponent)}]), mantissa => (wcf: {headerSolutionValue._mantissa}) [stratum: {new WarthogTarget(context.Difficulty, IsJanusHash).data} - exponent => (wt: {new WarthogTarget(context.Difficulty, IsJanusHash).Zeros10()}), mantissa => (wt: {(new WarthogTarget(context.Difficulty, IsJanusHash).Bits22() << 10)}) - validShare: {(headerSolutionValue < new WarthogTarget(context.Difficulty, IsJanusHash))} - blockTemplate: {blockTargetValue.data} - exponent => (wt: {blockTargetValue.Zeros10()}), mantissa => (wt: {(blockTargetValue.Bits22() << 10)}) - blockCandidate: {isBlockCandidate}] ||| shareDiff: {shareDiff} [stratum: {context.Difficulty} - blockTemplate: {Difficulty}]");

        var stratumDifficulty = context.Difficulty;
        var ratio = shareDiff / stratumDifficulty;

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
            BlockHeight = BlockTemplate.Data.Height,
            NetworkDifficulty = Difficulty,
            Difficulty = stratumDifficulty,
        };

        if(isBlockCandidate)
        {
            result.IsBlockCandidate = true;

            result.BlockHash = headerSolutionSha256D.ToHexString();
            
            var headerHex = headerSolutionBytes.ToHexString();
            
            var extranonceBodyBytes = SerializeBody(extraNonceBytes);
            BlockTemplate.Data.Body = extranonceBodyBytes.ToHexString();

            return (result, headerHex);
        }

        return (result, null);
    }

    protected virtual byte[] SerializeBlock(byte[] header)
    {
        var height = BlockTemplate.Data.Height;
        var bodyBytes = BlockTemplate.Data.Body.HexToByteArray();

        using(var stream = new MemoryStream())
        {
            var bw = new BinaryWriter(stream);

            bw.Write(height);
            bw.Write(header);
            bw.Write(bodyBytes);

            return stream.ToArray();
        }
    }

    public virtual void Init(WarthogBlockTemplate blockTemplate, string jobId, IMasterClock clock, WarthogNetworkType network, bool isJanusHash)
    {
        Contract.RequiresNonNull(blockTemplate);
        Contract.RequiresNonNull(clock);
        Contract.RequiresNonNull(network);
        Contract.Requires<ArgumentException>(!string.IsNullOrEmpty(jobId));

        this.clock = clock;
        BlockTemplate = blockTemplate;
        JobId = jobId;
        
        this.network = network;
        IsJanusHash = isJanusHash;

        Difficulty = BlockTemplate.Data.Difficulty;

        var headerBytes = BlockTemplate.Data.Header.HexToByteArray();
        prevHashBytes = headerBytes.Take(WarthogConstants.HeaderOffsetTarget - WarthogConstants.HeaderOffsetPrevHash).ToArray();
        nBitsBytes = headerBytes.Skip(WarthogConstants.HeaderOffsetTarget).Take(WarthogConstants.HeaderOffsetMerkleRoot - WarthogConstants.HeaderOffsetTarget).ToArray();
        //merkleRootBytes = headerBytes.Skip(WarthogConstants.HeaderOffsetMerkleRoot).Take(WarthogConstants.HeaderOffsetVersion - WarthogConstants.HeaderOffsetMerkleRoot).ToArray();
        versionBytes = headerBytes.Skip(WarthogConstants.HeaderOffsetVersion).Take(WarthogConstants.HeaderOffsetTimestamp - WarthogConstants.HeaderOffsetVersion).ToArray();
        nTimeBytes = headerBytes.Skip(WarthogConstants.HeaderOffsetTimestamp).Take(WarthogConstants.HeaderOffsetNonce - WarthogConstants.HeaderOffsetTimestamp).ToArray();

        merklePrefixBytes = BlockTemplate.Data.MerklePrefix.HexToByteArray();

        blockTargetValue = new WarthogTarget(Difficulty, IsJanusHash);

        jobParams = new object[]
        {
            JobId,
            prevHashBytes.ToHexString(),
            BlockTemplate.Data.MerklePrefix,
            //uint.Parse(versionBytes.ToHexString(), NumberStyles.HexNumber),
            versionBytes.ToHexString(),
            nBitsBytes.ToHexString(),
            nTimeBytes.ToHexString(),
            false
        };
    }

    public virtual object GetJobParams(bool isNew)
    {
        jobParams[^1] = isNew;
        return jobParams;
    }

    protected virtual bool RegisterSubmit(string extraNonce1, string extraNonce2, string nTime, string nonce)
    {
        var key = new StringBuilder()
            .Append(extraNonce1)
            .Append(extraNonce2) // lowercase as we don't want to accept case-sensitive values as valid.
            .Append(nTime)
            .Append(nonce) // lowercase as we don't want to accept case-sensitive values as valid.
            .ToString();

        return submissions.TryAdd(key, true);
    }

    public virtual (Share Share, string HeaderHex) ProcessShare(StratumConnection worker,
        string extraNonce2, string nTime, string nonce)
    {
        Contract.Requires<ArgumentException>(!string.IsNullOrEmpty(extraNonce2));
        Contract.Requires<ArgumentException>(!string.IsNullOrEmpty(nTime));
        Contract.Requires<ArgumentException>(!string.IsNullOrEmpty(nonce));

        var context = worker.ContextAs<WarthogWorkerContext>();

        // validate nTime
        if(nTime.Length != 8)
            throw new StratumException(StratumError.Other, "incorrect size of ntime");

        var nTimeInt = uint.Parse(nTime, NumberStyles.HexNumber);
        if(nTimeInt < uint.Parse(nTimeBytes.ToHexString(), NumberStyles.HexNumber) || nTimeInt > ((DateTimeOffset) clock.Now).ToUnixTimeSeconds() + WarthogConstants.TimeTolerance)
            throw new StratumException(StratumError.Other, "ntime out of range");

        // validate nonce
        if(nonce.Length != WarthogConstants.NonceLength)
            throw new StratumException(StratumError.Other, "incorrect size of nonce");

        var nonceInt = uint.Parse(nonce, NumberStyles.HexNumber);

        // dupe check
        if(!RegisterSubmit(context.ExtraNonce1, extraNonce2, nTime, nonce))
            throw new StratumException(StratumError.DuplicateShare, "duplicate");

        return ProcessShareInternal(worker, extraNonce2, nTimeInt, nonceInt);
    }

    #endregion // API-Surface
}