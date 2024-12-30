using System.Collections.Concurrent;
using System.Globalization;
using System.Text;
using Miningcore.Blockchain.Bitcoin.DaemonResponses;
using Miningcore.Blockchain.Nexa.DaemonResponses;
using Miningcore.Configuration;
using Miningcore.Crypto;
using Miningcore.Extensions;
using Miningcore.Stratum;
using Miningcore.Time;
using Miningcore.Util;
using Miningcore.Blockchain.Bitcoin;
using NBitcoin;
using Contract = Miningcore.Contracts.Contract;

namespace Miningcore.Blockchain.Nexa;

public class NexaJob
{
    private IMasterClock clock;
    private IHashAlgorithm headerHasher;
    private double shareMultiplier;
    private BitcoinTemplate coin;
    private readonly ConcurrentDictionary<string, bool> submissions = new(StringComparer.OrdinalIgnoreCase);
    private uint256 blockTargetValue;
    private object[] jobParams;

    private BlockTemplate BlockTemplate { get; set; }
    public MiningCandidate MiningCandidate { get; private set; }
    private byte[] headerCommitmentRev;
    public double Difficulty { get; private set; }
    public string JobId { get; private set; }

    protected virtual (Share Share, object submitParams) ProcessShareInternal(
        StratumConnection worker, string nonce, string extraNonce1)
    {
        var context = worker.ContextAs<BitcoinWorkerContext>();
        var extraNonce1Bytes = extraNonce1.HexToByteArray();
        var nonceBytes = nonce.HexToByteArray();

        Span<byte> nonceFinal = stackalloc byte[12]; // 4 bytes extra nonce + 8 bytes nonce
        using(var stream = new MemoryStream())
        {
            stream.Write(extraNonce1Bytes);
            stream.Write(nonceBytes);

            nonceFinal = stream.ToArray();
        }

        Span<byte> miningHashBytes = stackalloc byte[44]; // 32 bytes commitment + 4 bytes extra nonce + 8 bytes nonce
        using(var stream = new MemoryStream())
        {
            stream.Write(headerCommitmentRev);
            stream.Write(new byte[] {0x0c}); // nonceFinal.Length
            stream.Write(nonceFinal);

            miningHashBytes = stream.ToArray();
        }

        Span<byte> powHash = stackalloc byte[32];
        headerHasher.Digest(miningHashBytes, powHash);
        var miningValue = new uint256(powHash);

        var shareDiff = (double) new BigRational(BitcoinConstants.Diff1, powHash.ToBigInteger()) * shareMultiplier;
        var stratumDifficulty = context.Difficulty;
        var ratio = shareDiff / stratumDifficulty;

        // check if the share meets the much harder block difficulty (block candidate)
        var isBlockCandidate = miningValue <= blockTargetValue;

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

        var submitParams = new object[]
        {
            new
            {
                id = this.MiningCandidate.Id,
                nonce = nonceFinal.ToHexString()
            }
        };

        var share = new Share
        {
            BlockHeight = BlockTemplate.Height,
            NetworkDifficulty = Difficulty,
            Difficulty = stratumDifficulty / shareMultiplier,
            IsBlockCandidate = isBlockCandidate,
        };

        return (share, submitParams);
    }

    public void Init(MiningCandidate miningCandidate, BlockTemplate blockTemplate,
        string jobId, PoolConfig pc, IMasterClock clock, double shareMultiplier, IHashAlgorithm headerHasher)
    {
        Contract.RequiresNonNull(miningCandidate);
        Contract.RequiresNonNull(blockTemplate);
        Contract.RequiresNonNull(pc);
        Contract.RequiresNonNull(clock);
        Contract.RequiresNonNull(headerHasher);
        Contract.Requires<ArgumentException>(!string.IsNullOrEmpty(jobId));

        coin = pc.Template.As<BitcoinTemplate>();
        MiningCandidate = miningCandidate;
        BlockTemplate = blockTemplate;
        this.shareMultiplier = shareMultiplier;
        JobId = jobId;
        this.headerHasher = headerHasher;
        this.clock = clock;
        Difficulty = new Target(System.Numerics.BigInteger.Parse(BlockTemplate.Target, NumberStyles.HexNumber)).Difficulty;
        headerCommitmentRev = miningCandidate.HeaderCommitment.HexToReverseByteArray();

        if(!string.IsNullOrEmpty(BlockTemplate.Target))
            blockTargetValue = new uint256(BlockTemplate.Target);
        else
        {
            var tmp = new Target(BlockTemplate.Bits.HexToByteArray());
            blockTargetValue = tmp.ToUInt256();
        }

        jobParams = new object[]
        {
            JobId,
            headerCommitmentRev.ToHexString(),
            blockTemplate.Height,
            miningCandidate.NBits,
        };
    }

    public object GetJobParams()
    {
        return jobParams;
    }

    private bool RegisterSubmit(string headerCommitment, string extraNonce1, string nonce)
    {
        var key = new StringBuilder()
            .Append(headerCommitment)
            .Append(extraNonce1)
            .Append(nonce)
            .ToString();

        return submissions.TryAdd(key, true);
    }

    public (Share Share, object param) ProcessShare(StratumConnection worker, string nonce, string extraNonce1)
    {
        Contract.Requires<ArgumentException>(!string.IsNullOrEmpty(nonce));
        Contract.Requires<ArgumentException>(!string.IsNullOrEmpty(extraNonce1));

        // validate nonce. must be 8 bytes (16 hex chars without prefix)
        if(nonce.Length != 16)
            throw new StratumException(StratumError.Other, "incorrect size of nonce");

        // dupe check
        if(!RegisterSubmit(this.MiningCandidate.HeaderCommitment, extraNonce1, nonce))
            throw new StratumException(StratumError.DuplicateShare, "duplicate share");

        return ProcessShareInternal(worker, nonce, extraNonce1);
    }
}
