using System.Globalization;
using Miningcore.Blockchain.Bitcoin;
using Miningcore.Blockchain.Equihash.DaemonResponses;
using Miningcore.Configuration;
using Miningcore.Contracts;
using Miningcore.Crypto.Hashing.Equihash;
using Miningcore.Extensions;
using Miningcore.Native;
using Miningcore.Stratum;
using Miningcore.Time;
using Miningcore.Util;
using NBitcoin;
using NBitcoin.DataEncoders;
using NBitcoin.Zcash;

namespace Miningcore.Blockchain.Equihash.Custom.Veruscoin;

public class VeruscoinJob : EquihashJob
{
    // PBaaS
    public bool isPBaaSActive;
    
    protected override void BuildCoinbase()
    {
        // output transaction
        txOut = CreateOutputTransaction();
        
        // when PBaaS activates we must use the coinbasetxn from daemon to get proper fee pool calculations in coinbase
        var solutionVersion = BlockTemplate.Solution.Substring(0, 8);
        var reversedSolutionVersion = uint.Parse(solutionVersion.HexToReverseByteArray().ToHexString(), NumberStyles.HexNumber);
        isPBaaSActive = (reversedSolutionVersion > 6);
        
        if(!isPBaaSActive)
        {
            var script = TxIn.CreateCoinbase((int) BlockTemplate.Height).ScriptSig;

            /* var blockHeight = (int) BlockTemplate.Height;
            var blockHeightSerial = blockHeight.ToString();
            if (blockHeightSerial.Length % 2 != 0)
                blockHeightSerial = "0" + blockHeightSerial;

            int shiftedHeight = blockHeight << 1;
            int height = (int) Math.Ceiling((double) shiftedHeight.ToString().Length / 8);
            int lengthDiff = blockHeightSerial.Length / 2 - height;
            for (int i = 0; i < lengthDiff; i++) {
                blockHeightSerial += "00";
            }

            var length = "0" + height.ToString();

            var lengthBytes = (Span<byte>) length.HexToByteArray();
            var blockHeightSerialBytes = (Span<byte>) blockHeightSerial.HexToReverseByteArray();
            var opBytes = (Span<byte>) new byte[] { 0x00 };
            var poolHexBytes = (Span<byte>) poolHex.HexToByteArray();

            // concat length, blockHeightSerial, OP_0 and poolHex
            Span<byte> serializedBlockHeightBytes = stackalloc byte[lengthBytes.Length + blockHeightSerialBytes.Length + opBytes.Length + poolHexBytes.Length];
            lengthBytes.CopyTo(serializedBlockHeightBytes);
            var offset = lengthBytes.Length;
            blockHeightSerialBytes.CopyTo(serializedBlockHeightBytes[offset..]);
            offset += blockHeightSerialBytes.Length;
            opBytes.CopyTo(serializedBlockHeightBytes[offset..]);
            offset += opBytes.Length;
            poolHexBytes.CopyTo(serializedBlockHeightBytes[offset..]); */
            
            using(var stream = new MemoryStream())
            {
                var bs = new ZcashStream(stream, true);

                bs.Version = txVersion;
                bs.Overwintered = isOverwinterActive;

                /* if(isOverwinterActive)
                {
                    uint mask = (isOverwinterActive ? 1u : 0u );
                    uint shiftedMask = mask << 31;
                    uint versionWithOverwinter = txVersion | shiftedMask;

                    // version
                    bs.ReadWrite(ref versionWithOverwinter);
                }
                else
                {
                    // version
                    bs.ReadWrite(ref txVersion);
                }

                if(isOverwinterActive || isSaplingActive)
                {
                    bs.ReadWrite(ref txVersionGroupId);
                } */

                // serialize (simulated) input transaction
                bs.ReadWriteAsVarInt(ref txInputCount);
                bs.ReadWrite(sha256Empty);
                bs.ReadWrite(ref coinbaseIndex);
                // bs.ReadWrite(serializedBlockHeightBytes);
                bs.ReadWrite(ref script);
                bs.ReadWrite(ref coinbaseSequence);

                // serialize output transaction
                var txOutBytes = SerializeOutputTransaction(txOut);
                bs.ReadWrite(txOutBytes);

                // misc
                bs.ReadWrite(ref txLockTime);

                if(isOverwinterActive || isSaplingActive)
                {
                    bs.ReadWrite(ref txExpiryHeight);
                }

                if(isSaplingActive)
                {
                    bs.ReadWrite(ref txBalance);
                    bs.ReadWriteAsVarInt(ref txVShieldedSpend);
                    bs.ReadWriteAsVarInt(ref txVShieldedOutput);
                }

                if(isOverwinterActive || isSaplingActive)
                {
                    bs.ReadWriteAsVarInt(ref txJoinSplits);
                }

                // done
                coinbaseInitial = stream.ToArray();
                coinbaseInitialHash = new byte[32];
                sha256D.Digest(coinbaseInitial, coinbaseInitialHash);
            }
        }
        else
        {
            coinbaseInitial = BlockTemplate.CoinbaseTx.Data.HexToByteArray();
            coinbaseInitialHash = BlockTemplate.CoinbaseTx.Hash.HexToReverseByteArray();
        }
    }
    
    protected override byte[] SerializeOutputTransaction(Transaction tx)
    {
        var withDefaultWitnessCommitment = !string.IsNullOrEmpty(BlockTemplate.DefaultWitnessCommitment);

        var outputCount = (uint) tx.Outputs.Count;
        if(withDefaultWitnessCommitment)
            outputCount++;

        using(var stream = new MemoryStream())
        {
            var bs = new BitcoinStream(stream, true);

            // write output count
            bs.ReadWriteAsVarInt(ref outputCount);

            long amount;
            byte[] raw;
            uint rawLength;
            
            // serialize outputs
            foreach(var output in tx.Outputs)
            {
                amount = output.Value.Satoshi;
                var outScript = output.ScriptPubKey;
                raw = outScript.ToBytes(true);
                rawLength = (uint) raw.Length;

                bs.ReadWrite(ref amount);
                bs.ReadWriteAsVarInt(ref rawLength);
                bs.ReadWrite(raw);
            }

            // serialize witness (segwit)
            if(withDefaultWitnessCommitment)
            {
                amount = 0;
                raw = BlockTemplate.DefaultWitnessCommitment.HexToByteArray();
                rawLength = (uint) raw.Length;

                bs.ReadWrite(ref amount);
                bs.ReadWriteAsVarInt(ref rawLength);
                bs.ReadWrite(raw);
            }

            return stream.ToArray();
        }
    }

    protected override byte[] SerializeBlock(Span<byte> header, Span<byte> coinbase, Span<byte> solution)
    {
        var transactionCount = (uint) BlockTemplate.Transactions.Length + 1; // +1 for prepended coinbase tx
        var rawTransactionBuffer = BuildRawTransactionBuffer();

        using(var stream = new MemoryStream())
        {
            var bs = new BitcoinStream(stream, true);

            bs.ReadWrite(header);
            bs.ReadWrite(solution);
            
            /* var txCount = transactionCount.ToString();
            if (Math.Abs(txCount.Length % 2) == 1)
                txCount = "0" + txCount;
            
            if (transactionCount <= 0x7f)
            {
                var simpleVarIntBytes = (Span<byte>) txCount.HexToByteArray();
                
                bs.ReadWrite(simpleVarIntBytes);
            }
            else if (transactionCount <= 0x7fff)
            {
                if (txCount.Length == 2)
                    txCount = "00" + txCount;
                
                var complexHeader = (Span<byte>) new byte[] { 0xFD };
                var complexVarIntBytes = (Span<byte>) txCount.HexToReverseByteArray();
                
                // concat header and varInt
                Span<byte> complexHeaderVarIntBytes = stackalloc byte[complexHeader.Length + complexVarIntBytes.Length];
                complexHeader.CopyTo(complexHeaderVarIntBytes);
                complexVarIntBytes.CopyTo(complexHeaderVarIntBytes[complexHeader.Length..]);
                
                bs.ReadWrite(complexHeaderVarIntBytes);
            } */
            
            bs.ReadWriteAsVarInt(ref transactionCount);
            bs.ReadWrite(coinbase);
            bs.ReadWrite(rawTransactionBuffer);

            return stream.ToArray();
        }
    }
    
    protected override (Share Share, string BlockHex) ProcessShareInternal(StratumConnection worker, string nonce,
        uint nTime, string solution)
    {
        var context = worker.ContextAs<BitcoinWorkerContext>();
        var solutionBytes = (Span<byte>) solution.HexToByteArray();

        // serialize block-header
        var headerBytes = SerializeHeader(nTime, nonce);

        // concat header and solution
        Span<byte> headerSolutionBytes = stackalloc byte[headerBytes.Length + solutionBytes.Length];
        headerBytes.CopyTo(headerSolutionBytes);

        solutionBytes.CopyTo(headerSolutionBytes[headerBytes.Length..]);

        // hash block-header
        Span<byte> headerHash = stackalloc byte[32];
        
        Verushash headerHasherVerus = new Verushash();
        
        if (BlockTemplate.Version > 4 && !string.IsNullOrEmpty(BlockTemplate.Solution))
        {
            // make sure verus solution version matches expected version
            if (solution.Substring(VeruscoinConstants.SolutionSlice, 2) != BlockTemplate.Solution.Substring(0, 2))
                throw new StratumException(StratumError.Other, $"invalid solution - expected solution header: {BlockTemplate.Solution.Substring(0, 2)}");
            
            if (solution.Substring(VeruscoinConstants.SolutionSlice, 2) == "03")
                headerHasherVerus.Digest(headerSolutionBytes, headerHash, VeruscoinConstants.HashVersion2b1);
            else
                headerHasherVerus.Digest(headerSolutionBytes, headerHash, VeruscoinConstants.HashVersion2b2);
        }
        else if (BlockTemplate.Version > 4)
            headerHasherVerus.Digest(headerSolutionBytes, headerHash, VeruscoinConstants.HashVersion2b);
        else
            headerHasherVerus.Digest(headerSolutionBytes, headerHash);
        
        var headerValue = new uint256(headerHash);

        // calc share-diff
        var shareDiff = (double) new BigRational(networkParams.Diff1BValue, headerHash.ToBigInteger());
        var stratumDifficulty = context.Difficulty;
        var ratio = shareDiff / stratumDifficulty;

        // check if the share meets the much harder block difficulty (block candidate)
        var isBlockCandidate = headerValue <= blockTargetValue;

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
            BlockHeight = BlockTemplate.Height,
            NetworkDifficulty = Difficulty,
            Difficulty = stratumDifficulty,
        };

        if(isBlockCandidate)
        {
            var headerHashReversed = headerHash.ToNewReverseArray();
            
            result.IsBlockCandidate = true;
            result.BlockReward = rewardToPool.ToDecimal(MoneyUnit.BTC);
            result.BlockHash = headerHashReversed.ToHexString();
            var blockBytes = SerializeBlock(headerBytes, coinbaseInitial, solutionBytes);
            var blockHex = blockBytes.ToHexString();

            return (result, blockHex);
        }

        return (result, null);
    }
    
    private bool RegisterVersucoinSubmit(string nonce, string solution)
    {
        var key = nonce + solution;

        return submissions.TryAdd(key, true);
    }

    #region API-Surface

    public override void Init(EquihashBlockTemplate blockTemplate, string jobId,
        PoolConfig poolConfig, ClusterConfig clusterConfig, IMasterClock clock,
        IDestination poolAddressDestination, Network network,
        EquihashSolver solver)
    {
        Contract.RequiresNonNull(blockTemplate);
        Contract.RequiresNonNull(poolConfig);
        Contract.RequiresNonNull(clusterConfig);
        Contract.RequiresNonNull(clock);
        Contract.RequiresNonNull(poolAddressDestination);
        Contract.RequiresNonNull(solver);
        Contract.Requires<ArgumentException>(!string.IsNullOrEmpty(jobId));

        this.clock = clock;
        this.poolAddressDestination = poolAddressDestination;
        coin = poolConfig.Template.As<EquihashCoinTemplate>();
        networkParams = coin.GetNetwork(network.ChainName);
        this.network = network;
        BlockTemplate = blockTemplate;
        JobId = jobId;
        Difficulty = (double) new BigRational(networkParams.Diff1BValue, BlockTemplate.Target.HexToReverseByteArray().AsSpan().ToBigInteger());

        // ZCash Sapling & Overwinter support
        isSaplingActive = networkParams.SaplingActivationHeight.HasValue &&
            networkParams.SaplingTxVersion.HasValue &&
            networkParams.SaplingTxVersionGroupId.HasValue &&
            networkParams.SaplingActivationHeight.Value > 0 &&
            blockTemplate.Height >= networkParams.SaplingActivationHeight.Value;

        isOverwinterActive = isSaplingActive ||
            networkParams.OverwinterTxVersion.HasValue &&
            networkParams.OverwinterTxVersionGroupId.HasValue &&
            networkParams.OverwinterActivationHeight.HasValue &&
            networkParams.OverwinterActivationHeight.Value > 0 &&
            blockTemplate.Height >= networkParams.OverwinterActivationHeight.Value;

        if(isSaplingActive)
        {
            txVersion = networkParams.SaplingTxVersion.Value;
            txVersionGroupId = networkParams.SaplingTxVersionGroupId.Value;
        }

        else if(isOverwinterActive)
        {
            txVersion = networkParams.OverwinterTxVersion.Value;
            txVersionGroupId = networkParams.OverwinterTxVersionGroupId.Value;
        }

        // Misc
        isPBaaSActive = false;
        this.solver = solver;
        
         // pbaas minimal merged mining target
        if(!string.IsNullOrEmpty(BlockTemplate.MergedBits))
        {
            var tmpMergedBits = new Target(BlockTemplate.MergedBits.HexToByteArray());
            blockTargetValue = tmpMergedBits.ToUInt256();
        }
        else if(!string.IsNullOrEmpty(BlockTemplate.MergeMineBits))
        {
            var tmpMergeMineBits = new Target(BlockTemplate.MergeMineBits.HexToByteArray());
            blockTargetValue = tmpMergeMineBits.ToUInt256();
        }
        else if(!string.IsNullOrEmpty(BlockTemplate.Target))
            blockTargetValue = new uint256(BlockTemplate.Target);
        else
        {
            var tmpBits = new Target(BlockTemplate.Bits.HexToByteArray());
            blockTargetValue = tmpBits.ToUInt256();
        }

        previousBlockHashReversedHex = BlockTemplate.PreviousBlockhash
            .HexToByteArray()
            .ReverseInPlace()
            .ToHexString();

        if(blockTemplate.Subsidy != null)
            blockReward = blockTemplate.Subsidy.Miner * BitcoinConstants.SatoshisPerBitcoin;
        else
            blockReward = BlockTemplate.CoinbaseValue;

        if(networkParams?.PayFundingStream == true)
        {
            decimal fundingstreamTotal = 0;
            fundingstreamTotal = blockTemplate.Subsidy.FundingStreams.Sum(x => x.Value);
            blockReward = (blockTemplate.Subsidy.Miner + fundingstreamTotal) * BitcoinConstants.SatoshisPerBitcoin;
        }
        else if(networkParams?.vOuts == true)
        {
            blockReward = (decimal) ((blockTemplate.Subsidy.Miner + blockTemplate.Subsidy.Community + blockTemplate.Subsidy.Securenodes + blockTemplate.Subsidy.Supernodes) * BitcoinConstants.SatoshisPerBitcoin);
        }
        else if(networkParams?.PayFoundersReward == true)
        {
            var founders = blockTemplate.Subsidy.Founders ?? blockTemplate.Subsidy.Community;

            if(!founders.HasValue)
                throw new Exception("Error, founders reward missing for block template");

            blockReward = (blockTemplate.Subsidy.Miner + founders.Value) * BitcoinConstants.SatoshisPerBitcoin;
        }

        rewardFees = blockTemplate.Transactions.Sum(x => x.Fee);
        
        BuildCoinbase();
        
        // build tx hashes
        var txHashes = new List<uint256> { new(coinbaseInitialHash) };
        txHashes.AddRange(BlockTemplate.Transactions.Select(tx => new uint256(tx.Hash.HexToReverseByteArray())));

        // build merkle root
        merkleRoot = MerkleNode.GetRoot(txHashes).Hash.ToBytes().ReverseInPlace();
        merkleRootReversed = merkleRoot.ReverseInPlace();
        merkleRootReversedHex = merkleRootReversed.ToHexString();

        // misc
        var hashReserved = isSaplingActive && !string.IsNullOrEmpty(blockTemplate.FinalSaplingRootHash) ?
            blockTemplate.FinalSaplingRootHash.HexToReverseByteArray().ToHexString() :
            sha256Empty.ToHexString();

        string solutionIn = null;
        // VerusHash V2.1 activation
        if (!string.IsNullOrEmpty(blockTemplate.Solution))
        {
            char[] charsToTrim = {'0'};
            solutionIn = blockTemplate.Solution.TrimEnd(charsToTrim);
            
            if ((solutionIn.Length % 2) == 1)
                solutionIn += "0";
        }

        jobParams = new object[]
        {
            JobId,
            BlockTemplate.Version.ReverseByteOrder().ToStringHex8(),
            previousBlockHashReversedHex,
            merkleRootReversedHex,
            hashReserved,
            BlockTemplate.CurTime.ReverseByteOrder().ToStringHex8(),
            BlockTemplate.Bits.HexToReverseByteArray().ToHexString(),
            true,
            solutionIn
        };
    }
    
    public override (Share Share, string BlockHex) ProcessShare(StratumConnection worker, string extraNonce2, string nTime, string solution)
    {
        Contract.RequiresNonNull(worker);
        Contract.Requires<ArgumentException>(!string.IsNullOrEmpty(extraNonce2));
        Contract.Requires<ArgumentException>(!string.IsNullOrEmpty(nTime));
        Contract.Requires<ArgumentException>(!string.IsNullOrEmpty(solution));

        var context = worker.ContextAs<BitcoinWorkerContext>();

        // validate nTime
        if(nTime.Length != 8)
            throw new StratumException(StratumError.Other, "incorrect size of ntime");

        var nTimeInt = uint.Parse(nTime.HexToReverseByteArray().ToHexString(), NumberStyles.HexNumber);
        // if(nTimeInt < BlockTemplate.CurTime || nTimeInt > ((DateTimeOffset) clock.Now).ToUnixTimeSeconds() + 7200)
            // throw new StratumException(StratumError.Other, "ntime out of range");
        
        if(nTimeInt != BlockTemplate.CurTime)
            throw new StratumException(StratumError.Other, "ntime out of range");

        var nonce = context.ExtraNonce1 + extraNonce2;

        // validate nonce
        if(nonce.Length != 64)
            throw new StratumException(StratumError.Other, "incorrect size of extraNonce2");
        
        // validate solution
        if(solution.Length != (networkParams.SolutionSize + networkParams.SolutionPreambleSize) * 2)
            throw new StratumException(StratumError.Other, "incorrect size of solution");

        // dupe check
        if(!RegisterVersucoinSubmit(nonce, solution))
            throw new StratumException(StratumError.DuplicateShare, "duplicate share");
        
        // when pbaas activates use block header nonce from daemon, pool/miner can no longer manipulate
        if(isPBaaSActive)
        {
            if(string.IsNullOrEmpty(BlockTemplate.Nonce))
                throw new StratumException(StratumError.Other, "block header nonce not provided by daemon");
            else
                nonce = BlockTemplate.Nonce.HexToReverseByteArray().ToHexString();
            
            // verify pool nonce presence in solution
            var solutionExtraData = solution.Substring(solution.Length - 30);
            if(solutionExtraData.IndexOf(context.ExtraNonce1) < 0)
                throw new StratumException(StratumError.Other, "invalid solution, pool nonce missing");
        }
            
        return ProcessShareInternal(worker, nonce, nTimeInt, solution);
    }
    
    public override object GetJobParams(bool isNew)
    {
        jobParams[^2] = isNew;
        return jobParams;
    }
    
    #endregion // API-Surface
}