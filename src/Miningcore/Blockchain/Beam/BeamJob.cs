using System;
using System.Collections.Concurrent;
using System.Globalization;
using System.Numerics;
using System.Reflection;
using System.Text;
using Miningcore.Blockchain.Bitcoin;
using Miningcore.Blockchain.Beam.DaemonResponses;
using Miningcore.Configuration;
using Miningcore.Contracts;
using Miningcore.Crypto;
using Miningcore.Crypto.Hashing.Algorithms;
using Miningcore.Extensions;
using Miningcore.Native;
using Miningcore.Stratum;
using Miningcore.Time;
using Miningcore.Util;
using NBitcoin;
using NBitcoin.DataEncoders;
using NBitcoin.Zcash;

namespace Miningcore.Blockchain.Beam;

public class BeamJob
{
    protected IMasterClock clock;
    protected BeamCoinTemplate coin;
    
    protected readonly ConcurrentDictionary<string, bool> submissions = new(StringComparer.OrdinalIgnoreCase);

    protected BeamHash solver;
    protected readonly IHashAlgorithm sha256S = new Sha256S();

    private (Share Share, string BlockHex, short stratumError) ProcessShareInternal(StratumConnection worker, string nonce,
        string solution)
    {
        var context = worker.ContextAs<BeamWorkerContext>();
        
        var headerBytes = (Span<byte>) BlockTemplate.Input.HexToByteArray();
        var solutionBytes = (Span<byte>) solution.HexToByteArray();
        var nonceBytes = (Span<byte>) nonce.HexToByteArray();

        // verify solution
        if(!solver.Verify(headerBytes, solutionBytes, nonceBytes, BlockTemplate.PowType))
            return (new Share {}, null, BeamConstants.BeamRpcInvalidShare);
        
        // hash block-solution
        Span<byte> solutionHash = stackalloc byte[32];
        sha256S.Digest(solutionBytes, solutionHash);
        BigInteger solutionHashValue = new BigInteger(solutionHash, true, true);
        
        // calc share-diff
        var shareDiff = (double) new BigRational(BeamConstants.BigMaxValue, solutionHashValue);
        var stratumDifficulty = context.Difficulty;
        var ratio = shareDiff / stratumDifficulty;
        
        //throw new StratumException(StratumError.Other, $"Job difficulty: {BlockTemplate.Difficulty}, Job packed difficulty: {BlockTemplate.PackedDifficulty}, stratum difficulty: {stratumDifficulty}, shareDiff: {shareDiff}, BigMaxValue: {BeamConstants.BigMaxValue}, solutionHashValue: {solutionHashValue}");
        
        // check if the share meets the much harder block difficulty (block candidate)
        var isBlockCandidate = shareDiff >= BlockTemplate.Difficulty;

        // test if share meets at least workers current difficulty
        if(!isBlockCandidate && ratio < 0.99)
        {
            // check if share matched the previous difficulty from before a vardiff retarget
            if(context.VarDiff?.LastUpdate != null && context.PreviousDifficulty.HasValue)
            {
                ratio = shareDiff / context.PreviousDifficulty.Value;

                if(ratio < 0.99)
                    return (new Share { Difficulty = shareDiff }, null, BeamConstants.BeamRpcLowDifficultyShare);

                // use previous difficulty
                stratumDifficulty = context.PreviousDifficulty.Value;
            }

            else
                return (new Share { Difficulty = shareDiff }, null, BeamConstants.BeamRpcLowDifficultyShare);
        }

        var result = new Share
        {
            BlockHeight = (long) BlockTemplate.Height,
            NetworkDifficulty = Difficulty,
            Difficulty = stratumDifficulty
        };

        if(isBlockCandidate)
        {
            result.IsBlockCandidate = true;
            //result.BlockHash = solution + nonce;
            result.BlockHash = solutionHash.ToHexString();
        }

        return (result, null, BeamConstants.BeamRpcShareAccepted);
    }

    private bool RegisterSubmit(string nonce, string solution)
    {
        var key = nonce + solution;

        return submissions.TryAdd(key, true);
    }

    #region API-Surface

    public void Init(BeamBlockTemplate blockTemplate, string jobId,
        PoolConfig poolConfig, ClusterConfig clusterConfig, IMasterClock clock,
        BeamHash solver)
    {
        Contract.RequiresNonNull(blockTemplate);
        Contract.RequiresNonNull(poolConfig);
        Contract.RequiresNonNull(clusterConfig);
        Contract.RequiresNonNull(clock);
        Contract.RequiresNonNull(solver);
        Contract.Requires<ArgumentException>(!string.IsNullOrEmpty(jobId));

        this.clock = clock;
        coin = poolConfig.Template.As<BeamCoinTemplate>();
        BlockTemplate = blockTemplate;
        JobId = jobId;
        blockTemplate.Difficulty = BeamUtils.UnpackedDifficulty(blockTemplate.PackedDifficulty);
        Difficulty = blockTemplate.Difficulty;

        // Misc
        this.solver = solver;
    }

    public BeamBlockTemplate BlockTemplate { get; protected set; }
    public double Difficulty { get; protected set; }

    public string JobId { get; protected set; }

    public (Share Share, string BlockHex, short stratumError) ProcessShare(StratumConnection worker, string nonce, string solution)
    {
        Contract.RequiresNonNull(worker);
        Contract.Requires<ArgumentException>(!string.IsNullOrEmpty(nonce));
        Contract.Requires<ArgumentException>(!string.IsNullOrEmpty(solution));

        var context = worker.ContextAs<BeamWorkerContext>();

        // validate nonce
        if(nonce.Length != BeamConstants.NonceSize)
            return (new Share {}, null, BeamConstants.BeamRpcShareBadNonce);

        // validate solution
        if(solution.Length != BeamConstants.SolutionSize)
            return (new Share {}, null, BeamConstants.BeamRpcShareBadSolution);

        // dupe check
        if(!RegisterSubmit(nonce, solution))
            return (new Share {}, null, BeamConstants.BeamRpcDuplicateShare);

        return ProcessShareInternal(worker, nonce, solution);
    }
    
    public object[] GetJobParamsForStratum()
    {
        return new object[]
        {
            JobId,
            BlockTemplate.Height,
            BlockTemplate.Difficulty,
            BlockTemplate.PackedDifficulty,
            BlockTemplate.Input,
            BlockTemplate.PowType,
            true
        };
    }

    #endregion // API-Surface
}