using System;
using System.Collections.Concurrent;
using System.Globalization;
using System.Numerics;
using System.Text;
using Miningcore.Blockchain.Bitcoin;
using Miningcore.Blockchain.Bitcoin.Configuration;
using Miningcore.Blockchain.Handshake;
using Miningcore.Blockchain.Handshake.DaemonResponses;
using Miningcore.Configuration;
using Miningcore.Crypto;
using Miningcore.Extensions;
using Miningcore.Stratum;
using Miningcore.Time;
using Miningcore.Util;
using NBitcoin;
using NBitcoin.DataEncoders;
using Newtonsoft.Json.Linq;
using Contract = Miningcore.Contracts.Contract;
using Transaction = NBitcoin.Transaction;

namespace Miningcore.Blockchain.Handshake;

public class HandshakeTransactionOutput
{
    public decimal Amount;
    public string Address;
    public byte Version;
    public uint Type;
}

public class HandshakeJob
{
    protected IHashAlgorithm blockHasher;
    protected IMasterClock clock;
    protected IHashAlgorithm coinbaseHasher;
    protected double shareMultiplier;
    protected int extraNoncePlaceHolderLength;
    protected IHashAlgorithm headerHasher;
    protected string txComment;

    protected Network network;
    protected string poolAddress;
    protected HandshakeBech32Decoder handshakeBech32Decoder = new HandshakeBech32Decoder();
    protected BitcoinTemplate coin;
    private BitcoinTemplate.BitcoinNetworkParams networkParams;
    protected readonly ConcurrentDictionary<string, bool> submissions = new(StringComparer.OrdinalIgnoreCase);
    protected uint256 blockTargetValue;
    protected byte[] coinbaseFinal;
    protected string coinbaseFinalHex;
    protected byte[] coinbaseInitial;
    protected string coinbaseInitialHex;
    protected byte[] coinbaseMerkle;
    protected byte[] merkleRoot;
    protected byte[] coinbaseWitness;
    protected byte[] witnessRoot;
    protected HandshakeMerkleTree merkleTree = new HandshakeMerkleTree();

    ///////////////////////////////////////////
    // GetJobParams related properties

    protected object[] jobParams;
    protected Money rewardToPool;
    protected Transaction txInt;
    protected List<HandshakeTransactionOutput> txOut;
    protected List<Op> scriptSigOutPoint;

    // serialization constants
    protected static byte[] sha256Empty = new byte[32];
    protected uint txVersion = 1u; // transaction version (currently 1) - see https://github.com/handshake-org/hsd/blob/f749f5cccd0fafb3be2e47ea7e717bdb927a6efa/lib/primitives/tx.js#L51

    protected static uint txInPrevOutIndex = (uint) (Math.Pow(2, 32) - 1);
    protected uint txLockTime;

    protected virtual void BuildMerkleBranches()
    {
        var transactionHashes = new List<byte[]>();

        transactionHashes.Add(coinbaseMerkle);

        foreach(var transaction in BlockTemplate.Transactions)
            transactionHashes.Add(transaction.TxId.HexToByteArray());

        // build merkle-root
        merkleRoot = merkleTree.CreateRoot(coin.MerkleTreeHasherValue, transactionHashes);
    }

    protected virtual void BuildWitnessBranches()
    {
        var transactionHashes = new List<byte[]>();

        transactionHashes.Add(coinbaseWitness);

        foreach(var transaction in BlockTemplate.Transactions)
            transactionHashes.Add(transaction.Hash.HexToByteArray());

        // build witness-root
        witnessRoot = merkleTree.CreateRoot(coin.MerkleTreeHasherValue, transactionHashes);
    }

    protected virtual void BuildCoinbase()
    {
        // input transaction
        txInt = CreateInputTransaction();
        // output transaction
        txOut = CreateOutputTransaction();
        // signature script parts
        scriptSigOutPoint = GenerateScriptSig();

        // build coinbase initial
        using(var stream = new MemoryStream())
        {
            var bs = new BitcoinStream(stream, true);

            // version
            bs.ReadWrite(ref txVersion);

            // serialize input transaction
            var txInBytes = SerializeInputTransaction(txInt);
            bs.ReadWrite(txInBytes);

            // serialize output transaction
            var txOutBytes = SerializeOutputTransaction(txOut);
            bs.ReadWrite(txOutBytes);

            // misc
            bs.ReadWrite(ref txLockTime);

            // done
            coinbaseInitial = stream.ToArray();
            coinbaseInitialHex = coinbaseInitial.ToHexString();

            Span<byte> coinbaseInitialBytes = stackalloc byte[32];
            coinbaseHasher.Digest(coinbaseInitial, coinbaseInitialBytes);

            coinbaseMerkle = coinbaseInitialBytes.ToArray();
        }

        // build coinbase final
        using(var stream = new MemoryStream())
        {
            var bs = new BitcoinStream(stream, true);

            // serialize signature script parts
            var scriptBytes = SerializeScriptSig(scriptSigOutPoint);
            bs.ReadWrite(scriptBytes);

            // done
            coinbaseFinal = stream.ToArray();
            coinbaseFinalHex = coinbaseFinal.ToHexString();

            Span<byte> coinbaseFinalBytes = stackalloc byte[32];
            coinbaseHasher.Digest(coinbaseFinal, coinbaseFinalBytes);

            Span<byte> coinbaseMerklCoinbaseFinalBytes = stackalloc byte[coinbaseMerkle.Length + coinbaseFinalBytes.Length];
            coinbaseMerkle.CopyTo(coinbaseMerklCoinbaseFinalBytes);
            coinbaseFinalBytes.CopyTo(coinbaseMerklCoinbaseFinalBytes[coinbaseMerkle.Length..]);

            Span<byte> coinbaseBytes = stackalloc byte[32];
            coinbaseHasher.Digest(coinbaseMerklCoinbaseFinalBytes, coinbaseBytes);

            coinbaseWitness = coinbaseBytes.ToArray();
        }
    }

    protected virtual byte[] SerializeInputTransaction(Transaction tx)
    {
        var inputCount = (uint) tx.Inputs.Count;

        using(var stream = new MemoryStream())
        {
            var bs = new BitcoinStream(stream, true);

            // serialize (simulated) input transaction
            bs.ReadWriteAsVarInt(ref inputCount);

            byte[] hash;
            uint index;
            Script script;
            uint sequence;

            // serialize initial input
            foreach(var input in tx.Inputs)
            {
                hash = input.PrevOut.Hash.ToBytes(false);
                index = input.PrevOut.N;
                script = input.ScriptSig;
                sequence = input.Sequence;
                
                if(script == Script.Empty)
                {
                    bs.ReadWrite(hash);
                    bs.ReadWrite(ref index);
                    // tx in sequence
                    bs.ReadWrite(ref sequence);
                }
                else
                {
                    bs.ReadWrite(ref sequence);
                    bs.ReadWrite(ref script);
                    bs.ReadWrite(ref sequence);
                }
            }

            return stream.ToArray();
        }
    }

    protected virtual byte[] SerializeOutputTransaction(List<HandshakeTransactionOutput> tx)
    {
        var outputCount = (uint) tx.Count;

        using(var stream = new MemoryStream())
        {
            var bs = new BitcoinStream(stream, true);

            // write output count
            bs.ReadWriteAsVarInt(ref outputCount);

            ulong amount;
            byte version;
            byte[] raw;
            byte rawLength;
            byte type;
            uint itemLength = 0;

            // serialize outputs
            foreach(var output in tx)
            {
                amount = (ulong) output.Amount;
                version = output.Version;
                raw = output.Address.HexToByteArray();
                rawLength = (byte) raw.Length;
                type = (byte) output.Type;

                bs.ReadWrite(ref amount);
                bs.ReadWrite(ref version);
                bs.ReadWrite(ref rawLength);
                bs.ReadWrite(raw);
                
                bs.ReadWrite(ref type);
                bs.ReadWriteAsVarInt(ref itemLength);
            }

            return stream.ToArray();
        }
    }

    protected virtual byte[] SerializeScriptSig(List<Op> ops)
    {
        var scriptSigOutPointCount = (uint) ops.Count;
        
        var scriptSigOutPoint = new Script(ops);

        using(var stream = new MemoryStream())
        {
            var bs = new BitcoinStream(stream, true);
            
            // write signature script parts count
            bs.ReadWriteAsVarInt(ref scriptSigOutPointCount);

            byte[] outpoint = scriptSigOutPoint.ToBytes();
            bs.ReadWrite(outpoint);

            return stream.ToArray();
        }
    }

    protected virtual List<Op> GenerateScriptSig()
    {
        // script ops
        var ops = new List<Op>();

        var coinbaseAuxBytes = (Span<byte>) new byte[20] {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
        // optionally push aux-flags
        if(!coin.CoinbaseIgnoreAuxFlags && !string.IsNullOrEmpty(BlockTemplate.CoinbaseAux?.Flags))
        {
            var coinbaseAuxFlagsBytes = (Span<byte>) BlockTemplate.CoinbaseAux.Flags.HexToByteArray();
            coinbaseAuxFlagsBytes.CopyTo(coinbaseAuxBytes);
        }
        ops.Add(Op.GetPushOp(coinbaseAuxBytes.ToArray()));

        var rand = new Random(); 
        var randomBytes = new byte[8]; 
        rand.NextBytes(randomBytes);
        ops.Add(Op.GetPushOp(randomBytes));

         // push placeholder
         ops.Add(Op.GetPushOp(new byte[8] {0, 0, 0, 0, 0, 0, 0, 0}));

        // claims
        foreach(var claim in BlockTemplate.Claims)
        {
            ops.Add(Op.GetPushOp(claim.Blob.HexToByteArray()));
        }

        // airdrops
        foreach(var airdrop in BlockTemplate.Airdrops)
        {
            ops.Add(Op.GetPushOp(airdrop.Blob.HexToByteArray()));
        }

        return ops;
    }

    protected virtual Transaction CreateInputTransaction()
    {
        var tx = Transaction.Create(network);
        // set versions
        tx.Version = txVersion;

        TxIn txIn;

        var rand = new Random(); 
        txIn = new TxIn(new OutPoint(new uint256(ZeroHash), txInPrevOutIndex));
        txIn.Sequence = new Sequence((uint) (rand.Next(1 << 30)) << 2 | (uint) (rand.Next(1 << 2)));
        tx.Inputs.Add(txIn);

        // claims
        foreach(var claim in BlockTemplate.Claims)
        {
            txIn = new TxIn(new OutPoint(new uint256(ZeroHash), txInPrevOutIndex));
            txIn.Sequence = new Sequence(txInPrevOutIndex);
            tx.Inputs.Add(txIn);
        }

        // airdrops
        foreach(var airdrop in BlockTemplate.Airdrops)
        {
            txIn = new TxIn(new OutPoint(new uint256(ZeroHash), txInPrevOutIndex));
            txIn.Sequence = new Sequence(txInPrevOutIndex);
            tx.Inputs.Add(txIn);
        }

        return tx;
    }

    protected virtual List<HandshakeTransactionOutput> CreateOutputTransaction()
    {
        var tx = new List<HandshakeTransactionOutput>();
        
        var (poolAddressHrp, poolAddressVersion, poolAddressHash) = handshakeBech32Decoder.Decode(poolAddress);
        tx.Add(new HandshakeTransactionOutput
        {
            Amount = (decimal) BlockTemplate.CoinbaseValue,
            Address = poolAddressHash.ToHexString(),
            Version = (byte) poolAddressVersion,
            Type = 0
        });

        // claims
        foreach(var claim in BlockTemplate.Claims)
        {
            tx.Add(new HandshakeTransactionOutput
            {
                Amount = (decimal) (claim.Value - claim.Fee),
                Address = claim.Address,
                Version = (byte) claim.Version,
                Type = 1
            });
        }

        // airdrops
        foreach(var airdrop in BlockTemplate.Airdrops)
        {
            tx.Add(new HandshakeTransactionOutput
            {
                Amount = (decimal) (airdrop.Value - airdrop.Fee),
                Address = airdrop.Address,
                Version = (byte) airdrop.Version,
                Type = 0
            });
        }

        return tx;
    }

    #region API-Surface

    public HandshakeBlockTemplate BlockTemplate { get; protected set; }
    public double Difficulty { get; protected set; }

    public string JobId { get; protected set; }

    protected virtual byte[] PaddingPreviousBlockWithTreeRoot(int size)
    {
        var previousBlockhashBytes = BlockTemplate.PreviousBlockhash.HexToByteArray();
        var treeRootBytes = BlockTemplate.TreeRoot.HexToByteArray();

        byte[] paddingPreviousBlockWithTreeRoot = new byte[size];

        for (int i = 0; i < size; i++)
            paddingPreviousBlockWithTreeRoot[i] = (byte)(previousBlockhashBytes[i % 32] ^ treeRootBytes[i % 32]);

        return paddingPreviousBlockWithTreeRoot;
    }

    protected virtual byte[] SerializeHeader(uint nonce, uint nTime, byte[] extraNonce, byte[] commitHash)
    {
        var time = (ulong) nTime;
        var previousBlockhashBytes = BlockTemplate.PreviousBlockhash.HexToByteArray();
        var treeRootBytes = BlockTemplate.TreeRoot.HexToByteArray();
        
        var reservedRootBytes = BlockTemplate.ReservedRoot.HexToByteArray();

        var version = BlockTemplate.Version;
        var bits = (uint) new Target(Encoders.Hex.DecodeData(BlockTemplate.Bits));

        using(var stream = new MemoryStream(HandshakeConstants.BlockHeaderSize))
        {
            var bw = new BinaryWriter(stream);

            // Preheader
            bw.Write(nonce);
            bw.Write(time);
            bw.Write(previousBlockhashBytes);
            bw.Write(treeRootBytes);

            // Subheader
            bw.Write(extraNonce);
            bw.Write(reservedRootBytes);
            bw.Write(witnessRoot);
            bw.Write(merkleRoot);
            bw.Write(version);
            bw.Write(bits);

             // Mask.
            bw.Write(maskBytes);

            return stream.ToArray();
        }
    }

    protected virtual byte[] SerializeShare(uint nonce, uint nTime, byte[] commitHash)
    {
        var time = (ulong) nTime;
        var previousBlockhashBytes = BlockTemplate.PreviousBlockhash.HexToByteArray();
        var treeRootBytes = BlockTemplate.TreeRoot.HexToByteArray();

        using(var stream = new MemoryStream(HandshakeConstants.BlockHeaderSize / 2))
        {
            var bw = new BinaryWriter(stream);

            // Preheader
            bw.Write(nonce);
            bw.Write(time);
            bw.Write(PaddingPreviousBlockWithTreeRoot(20));
            bw.Write(previousBlockhashBytes);
            bw.Write(treeRootBytes);
            bw.Write(commitHash);

            return stream.ToArray();
        }
    }

    protected virtual byte[] SerializeCommitHash(byte[] subHeader)
    {
        Span<byte> subHeaderHashBytes = stackalloc byte[32];
        headerHasher.Digest(subHeader, subHeaderHashBytes);

        var previousBlockhashBytes = BlockTemplate.PreviousBlockhash.HexToByteArray();
        Span<byte> previousBlockhashMaskBytes = stackalloc byte[previousBlockhashBytes.Length + maskBytes.Length];
        previousBlockhashBytes.CopyTo(previousBlockhashMaskBytes);
        maskBytes.CopyTo(previousBlockhashMaskBytes[previousBlockhashBytes.Length..]);
        
        var commitMaskBytes = (Span<byte>) stackalloc byte[32];
        headerHasher.Digest(previousBlockhashMaskBytes, commitMaskBytes);

        Span<byte> subHeaderHashMaskBytes = stackalloc byte[subHeaderHashBytes.Length + commitMaskBytes.Length];
        subHeaderHashBytes.CopyTo(subHeaderHashMaskBytes);
        commitMaskBytes.CopyTo(subHeaderHashMaskBytes[subHeaderHashBytes.Length..]);
        
        var commitHashBytes = (Span<byte>) stackalloc byte[32];
        headerHasher.Digest(subHeaderHashMaskBytes, commitHashBytes);

        return commitHashBytes.ToArray();
    }

    protected virtual byte[] SerializeSubHeader(byte[] extraNonce)
    {
        var reservedRootBytes = (Span<byte>) BlockTemplate.ReservedRoot.HexToByteArray();

        var version = BlockTemplate.Version;
        var bits = (uint) new Target(Encoders.Hex.DecodeData(BlockTemplate.Bits));

        using(var stream = new MemoryStream(HandshakeConstants.BlockHeaderSize / 2))
        {
            var bw = new BinaryWriter(stream);

            // Subheader
            bw.Write(extraNonce);
            bw.Write(reservedRootBytes);
            bw.Write(witnessRoot);
            bw.Write(merkleRoot);
            bw.Write(version);
            bw.Write(bits);

            return stream.ToArray();
        }
    }

    public virtual object[] GetTransactions()
    {
        if(BlockTemplate.Transactions.Length < 1)
            return new object[] {};
        else
        {
            object[] transactions;
            transactions = new object[BlockTemplate.Transactions.Length];

            for (int i = 0; i < BlockTemplate.Transactions.Length; i++)
                transactions[i] = new object[] { BlockTemplate.Transactions[i].Hash.HexToByteArray().ToHexString() };

            return transactions;
        }
    }

    protected virtual byte[] SerializeExtranonce(string extraNonce1, string extraNonce2)
    {
        var extraNonce1Bytes = extraNonce1.HexToByteArray();
        var extraNonce2Bytes = extraNonce2.HexToByteArray();

        using(var stream = new MemoryStream())
        {
            stream.Write(extraNonce1Bytes);
            stream.Write(extraNonce2Bytes);

            var extraNonceBytes = ZeroNonce;
            var tmpExtraNonceBytes = stream.ToArray();
            for (int i = 0; i < tmpExtraNonceBytes.Length; i++)
                extraNonceBytes[i] = tmpExtraNonceBytes[i];

            return extraNonceBytes;
        }
    }

    protected virtual (Share Share, string BlockHex) ProcessShareInternal(
        StratumConnection worker, string extraNonce2, uint nTime, uint nonce)
    {
        var context = worker.ContextAs<BitcoinWorkerContext>();
        var extraNonceBytes = SerializeExtranonce(context.ExtraNonce1, extraNonce2);
        
        var subHeaderBytes = SerializeSubHeader(extraNonceBytes);
        var commitHashBytes = SerializeCommitHash(subHeaderBytes);

        var shareBytes = SerializeShare(nonce, nTime, commitHashBytes);

        Span<byte> shareLeftBytes = stackalloc byte[64];
        blockHasher.Digest(shareBytes, shareLeftBytes);
        
        var rightPaddingBytes = (Span<byte>) PaddingPreviousBlockWithTreeRoot(8);
        Span<byte> shareRightPaddingBytes = stackalloc byte[shareBytes.Length + rightPaddingBytes.Length];
        shareBytes.CopyTo(shareRightPaddingBytes);
        rightPaddingBytes.CopyTo(shareRightPaddingBytes[shareBytes.Length..]);

        Span<byte> shareRightBytes = stackalloc byte[32];
        coin.ShareHasherValue.Digest(shareRightPaddingBytes, shareRightBytes);
        
        var centerPaddingBytes = (Span<byte>) PaddingPreviousBlockWithTreeRoot(32);
        Span<byte> shareLeftCenterPaddingHeaderRighthBytes = stackalloc byte[shareLeftBytes.Length + centerPaddingBytes.Length + shareRightBytes.Length];
        shareLeftBytes.CopyTo(shareLeftCenterPaddingHeaderRighthBytes);
        centerPaddingBytes.CopyTo(shareLeftCenterPaddingHeaderRighthBytes[shareLeftBytes.Length..]);
        shareRightBytes.CopyTo(shareLeftCenterPaddingHeaderRighthBytes[(shareLeftBytes.Length + centerPaddingBytes.Length)..]);
        
        Span<byte> shareHashBytes = stackalloc byte[32];
        blockHasher.Digest(shareLeftCenterPaddingHeaderRighthBytes, shareHashBytes);

        for (int i = 0; i < maskBytes.Length; i++)
            shareHashBytes[i] ^= maskBytes[i];

        var targetShareHashBytes = new Target(new BigInteger(shareHashBytes, true, true));
        var shareHashValue = targetShareHashBytes.ToUInt256();

        // calc share-diff
        var shareDiff = (double) new BigRational(HandshakeConstants.Diff1, targetShareHashBytes.ToBigInteger()) * shareMultiplier;
        var stratumDifficulty = context.Difficulty;
        var ratio = shareDiff / stratumDifficulty;

        // check if the share meets the much harder block difficulty (block candidate)
        var isBlockCandidate = shareHashValue <= blockTargetValue;

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
            Difficulty = stratumDifficulty / shareMultiplier,
        };

        if(isBlockCandidate)
        {
            result.IsBlockCandidate = true;

            result.BlockHash = shareHashBytes.ToHexString();
            
            var headerBytes = SerializeHeader(nonce, nTime, extraNonceBytes, commitHashBytes);
            var coinbaseBytes = SerializeCoinbase();
            var blockBytes = SerializeBlock(headerBytes, coinbaseBytes);
            var blockHex = blockBytes.ToHexString();

            return (result, blockHex);
        }

        return (result, null);
    }

    protected virtual byte[] SerializeCoinbase()
    {
        Span<byte> coinbaseBytes = stackalloc byte[coinbaseInitial.Length + coinbaseFinal.Length];
        coinbaseInitial.CopyTo(coinbaseBytes);
        coinbaseFinal.CopyTo(coinbaseBytes[coinbaseInitial.Length..]);

        return coinbaseBytes.ToArray();
    }

    protected virtual byte[] SerializeBlock(byte[] header, byte[] coinbase)
    {
        var rawTransactionBuffer = BuildRawTransactionBuffer();
        var transactionCount = (uint) (BlockTemplate.Transactions.Length + 1); // +1 for prepended coinbase tx

        using(var stream = new MemoryStream())
        {
            var bs = new BitcoinStream(stream, true);

            bs.ReadWrite(header);
            bs.ReadWriteAsVarInt(ref transactionCount);

            bs.ReadWrite(coinbase);
            bs.ReadWrite(rawTransactionBuffer);

            return stream.ToArray();
        }
    }

    protected virtual byte[] BuildRawTransactionBuffer()
    {
        using(var stream = new MemoryStream())
        {
            foreach(var tx in BlockTemplate.Transactions)
            {
                var txRaw = tx.Data.HexToByteArray();
                stream.Write(txRaw);
            }

            return stream.ToArray();
        }
    }

    protected byte[] maskBytes;
    protected byte[] ZeroHash { get; private set; } = new byte[32] { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
    protected byte[] ZeroNonce { get; private set; } = new byte[24] { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };

    public virtual void Init(HandshakeBlockTemplate blockTemplate, string jobId,
        PoolConfig pc, BitcoinPoolConfigExtra extraPoolConfig,
        ClusterConfig cc, IMasterClock clock,
        string poolAddress, Network network,
        double shareMultiplier, IHashAlgorithm coinbaseHasher,
        IHashAlgorithm headerHasher, IHashAlgorithm blockHasher)
    {
        Contract.RequiresNonNull(blockTemplate);
        Contract.RequiresNonNull(pc);
        Contract.RequiresNonNull(clock);
        Contract.RequiresNonNull(poolAddress);
        Contract.RequiresNonNull(coinbaseHasher);
        Contract.RequiresNonNull(headerHasher);
        Contract.RequiresNonNull(blockHasher);
        Contract.Requires<ArgumentException>(!string.IsNullOrEmpty(jobId));

        coin = pc.Template.As<BitcoinTemplate>();
        networkParams = coin.GetNetwork(network.ChainName);
        this.network = network;
        this.clock = clock;
        this.poolAddress = poolAddress;
        BlockTemplate = blockTemplate;
        JobId = jobId;
        txLockTime = BlockTemplate.Height;
        txVersion = coin?.CoinbaseTxVersion ?? BlockTemplate.Version;
        
        Difficulty = new Target(System.Numerics.BigInteger.Parse(BlockTemplate.Target, NumberStyles.HexNumber)).Difficulty;
        
        extraNoncePlaceHolderLength = BitcoinConstants.ExtranoncePlaceHolderLength;
        this.shareMultiplier = shareMultiplier;

        txComment = !string.IsNullOrEmpty(extraPoolConfig?.CoinbaseTxComment) ?
            extraPoolConfig.CoinbaseTxComment : coin.CoinbaseTxComment;
        
        this.coinbaseHasher = coinbaseHasher;
        this.headerHasher = headerHasher;
        this.blockHasher = blockHasher;

        if(!string.IsNullOrEmpty(BlockTemplate.Target))
            blockTargetValue = new uint256(BlockTemplate.Target);
        else
        {
            var tmp = new Target(BlockTemplate.Bits.HexToByteArray());
            blockTargetValue = tmp.ToUInt256();
        }

        var previousBlockhashBytes = (Span<byte>) BlockTemplate.PreviousBlockhash.HexToByteArray();
        maskBytes = ZeroHash;

        /* maskBytes = new byte[32];
        Span<byte> previousBlockhashMaskBytes = stackalloc byte[previousBlockhashBytes.Length + maskBytes.Length];
        previousBlockhashBytes.CopyTo(previousBlockhashMaskBytes);
        maskBytes.CopyTo(previousBlockhashMaskBytes[previousBlockhashBytes.Length..]);

        Span<byte> puzzleBytes = stackalloc byte[32];
        headerHasher.Digest(previousBlockhashMaskBytes, puzzleBytes); */

        BuildCoinbase();
        BuildMerkleBranches();
        BuildWitnessBranches();

        jobParams = new object[]
        {
            JobId,
            previousBlockhashBytes.ToHexString(),
            merkleRoot.ToHexString(),
            witnessRoot.ToHexString(),
            BlockTemplate.TreeRoot.HexToByteArray().ToHexString(),
            BlockTemplate.ReservedRoot.HexToByteArray().ToHexString(),
            BlockTemplate.Version.ToStringHex8(),
            BlockTemplate.Bits,
            BlockTemplate.CurTime.ToStringHex8()
        };
    }

    public object GetJobParams()
    {
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

    public virtual (Share Share, string BlockHex) ProcessShare(StratumConnection worker,
        string extraNonce2, string nTime, string nonce)
    {
        Contract.Requires<ArgumentException>(!string.IsNullOrEmpty(extraNonce2));
        Contract.Requires<ArgumentException>(!string.IsNullOrEmpty(nTime));
        Contract.Requires<ArgumentException>(!string.IsNullOrEmpty(nonce));

        var context = worker.ContextAs<BitcoinWorkerContext>();

        // validate nTime
        if(nTime.Length != 8)
            throw new StratumException(StratumError.Other, "incorrect size of ntime");

        var nTimeInt = uint.Parse(nTime, NumberStyles.HexNumber);
        if(nTimeInt < BlockTemplate.CurTime || nTimeInt > ((DateTimeOffset) clock.Now).ToUnixTimeSeconds() + 7200)
            throw new StratumException(StratumError.Other, "ntime out of range");

        // validate nonce
        if(nonce.Length != 8)
            throw new StratumException(StratumError.Other, "incorrect size of nonce");

        var nonceInt = uint.Parse(nonce, NumberStyles.HexNumber);

        // dupe check
        if(!RegisterSubmit(context.ExtraNonce1, extraNonce2, nTime, nonce))
            throw new StratumException(StratumError.DuplicateShare, "duplicate");

        return ProcessShareInternal(worker, extraNonce2, nTimeInt, nonceInt);
    }

    #endregion // API-Surface
}