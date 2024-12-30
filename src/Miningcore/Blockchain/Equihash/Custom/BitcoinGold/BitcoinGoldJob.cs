using Miningcore.Blockchain.Equihash.DaemonResponses;
using Miningcore.Configuration;
using Miningcore.Contracts;
using Miningcore.Crypto.Hashing.Equihash;
using Miningcore.Extensions;
using Miningcore.Time;
using Miningcore.Util;
using NBitcoin;
using NBitcoin.DataEncoders;
using Transaction = NBitcoin.Transaction;

namespace Miningcore.Blockchain.Equihash.Custom.BitcoinGold;

public class BitcoinGoldJob : EquihashJob
{
    protected override Transaction CreateOutputTransaction()
    {
        rewardToPool = new Money(BlockTemplate.CoinbaseValue, MoneyUnit.Satoshi);

        var txNetwork = Network.GetNetwork(networkParams.CoinbaseTxNetwork);
        var tx = Transaction.Create(txNetwork);

        // set versions
        tx.Version = txVersion;

        // pool reward (t-addr)
        tx.Outputs.Add(rewardToPool, poolAddressDestination);

        tx.Inputs.Add(TxIn.CreateCoinbase((int) BlockTemplate.Height));

        return tx;
    }

    protected override void BuildCoinbase()
    {
        var script = TxIn.CreateCoinbase((int) BlockTemplate.Height).ScriptSig;

        // output transaction
        txOut = CreateOutputTransaction();

        using(var stream = new MemoryStream())
        {
            var bs = new BitcoinStream(stream, true);

            // version
            bs.ReadWrite(ref txVersion);

            // serialize (simulated) input transaction
            bs.ReadWriteAsVarInt(ref txInputCount);
            bs.ReadWrite(sha256Empty);
            bs.ReadWrite(ref coinbaseIndex);
            bs.ReadWrite(ref script);
            bs.ReadWrite(ref coinbaseSequence);

            // serialize output transaction
            var txOutBytes = SerializeOutputTransaction(txOut);
            bs.ReadWrite(txOutBytes);

            // misc
            bs.ReadWrite(ref txLockTime);

            // done
            coinbaseInitial = stream.ToArray();
            coinbaseInitialHash = new byte[32];
            sha256D.Digest(coinbaseInitial, coinbaseInitialHash);
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

            return stream.ToArray();
        }
    }

    protected override byte[] SerializeHeader(uint nTime, string nonce)
    {
        // BTG requires the blockheight to be encoded in the first 4 bytes of the hashReserved field
        var heightAndReserved = new byte[32];
        BitConverter.TryWriteBytes(heightAndReserved, BlockTemplate.Height);

        var blockHeader = new EquihashBlockHeader
        {
            Version = (int) BlockTemplate.Version,
            Bits = new Target(Encoders.Hex.DecodeData(BlockTemplate.Bits)),
            HashPrevBlock = uint256.Parse(BlockTemplate.PreviousBlockhash),
            HashMerkleRoot = new uint256(merkleRoot),
            HashReserved = heightAndReserved,
            NTime = nTime,
            Nonce = nonce
        };

        return blockHeader.ToBytes();
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
            bs.ReadWriteAsVarInt(ref transactionCount);
            bs.ReadWrite(coinbase);
            bs.ReadWrite(rawTransactionBuffer);

            return stream.ToArray();
        }
    }

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
        Contract.Requires<ArgumentException>(!string.IsNullOrEmpty(jobId));

        this.clock = clock;
        this.poolAddressDestination = poolAddressDestination;
        coin = poolConfig.Template.As<EquihashCoinTemplate>();
        this.network = network;
        var equihashTemplate = poolConfig.Template.As<EquihashCoinTemplate>();
        networkParams = coin.GetNetwork(network.ChainName);
        BlockTemplate = blockTemplate;
        JobId = jobId;
        Difficulty = (double) new BigRational(networkParams.Diff1BValue, BlockTemplate.Target.HexToReverseByteArray().AsSpan().ToBigInteger());

        this.solver = solver;

        if(!string.IsNullOrEmpty(BlockTemplate.Target))
            blockTargetValue = new uint256(BlockTemplate.Target);
        else
        {
            var tmp = new Target(BlockTemplate.Bits.HexToByteArray());
            blockTargetValue = tmp.ToUInt256();
        }

        previousBlockHashReversedHex = BlockTemplate.PreviousBlockhash
            .HexToByteArray()
            .ReverseInPlace()
            .ToHexString();

        BuildCoinbase();

        // build tx hashes
        var txHashes = new List<uint256> { new(coinbaseInitialHash) };
        txHashes.AddRange(BlockTemplate.Transactions.Select(tx => new uint256(tx.TxId.HexToReverseByteArray())));

        // build merkle root
        merkleRoot = MerkleNode.GetRoot(txHashes).Hash.ToBytes().ReverseInPlace();
        merkleRootReversed = merkleRoot.ReverseInPlace();
        merkleRootReversedHex = merkleRootReversed.ToHexString();

        jobParams = new object[]
        {
            JobId,
            BlockTemplate.Version.ReverseByteOrder().ToStringHex8(),
            previousBlockHashReversedHex,
            merkleRootReversedHex,
            BlockTemplate.Height.ReverseByteOrder().ToStringHex8() + sha256Empty.Take(28).ToHexString(), // height + hashReserved
            BlockTemplate.CurTime.ReverseByteOrder().ToStringHex8(),
            BlockTemplate.Bits.HexToReverseByteArray().ToHexString(),
            false
        };
    }
}
