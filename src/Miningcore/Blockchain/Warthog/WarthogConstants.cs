// ReSharper disable InconsistentNaming

namespace Miningcore.Blockchain.Warthog;

public static class WarthogConstants
{
    public const string JanusMiner = "janusminer";

    public const int ExtranoncePlaceHolderLength = 10;
    public static int NonceLength = 8;
    public const int TimeTolerance = 600; // in seconds

    // https://www.warthog.network/docs/developers/integrations/pools/stratum/#miningset_difficulty
    // In contrast to Bitcoin's stratum protocol the target is just the inverse of the difficulty. In Bitcoin there is an additional factor of 2^32 involved for historical reasons.
    // Since Warthog was written from scratch, it does not carry this historical burden. This means the miner must meet the target 1/difficulty to mine a share.
    public static readonly double Diff1 = 1;

    public const byte GenesisDifficultyExponent = 32;
    public const uint HardestTargetHost = 0xFF800000u;
    public const uint GenesisTargetHost = (uint)(GenesisDifficultyExponent << 24) | 0x00FFFFFFu;
    public const uint JanusHashMaxTargetHost = 0xe00fffffu;
    public const byte JanusHashMinDiffExponent = 22;
    public static readonly double Pow2x1 = Math.Pow(2, 1);
    public const uint JanusHashMinTargetHost = (uint)(JanusHashMinDiffExponent << 24) | 0x003FFFFFu;

    public const uint NewMerkleRootBlockHeight = 900000;
    public const uint JanusHashRetargetBlockHeight = 745200;
    public const uint JanusHashV2RetargetBlockHeight = 769680;
    public const uint JanusHashV3RetargetBlockHeight = 776880;
    public const uint JanusHashV4RetargetBlockHeight = 809280;
    public const uint JanusHashV5RetargetBlockHeight = 855000;
    public const uint JanusHashV6RetargetBlockHeight = 879500;
    public const uint JanusHashV7RetargetBlockHeight = 987000;

    public static readonly WarthogCustomFloat ProofOfBalancedWorkC = new WarthogCustomFloat(-7, 2748779069, true); // 0.005
    public static readonly WarthogCustomFloat ProofOfBalancedWorkExponent = new WarthogCustomFloat(0, 3006477107, true); // = 0.7 <-- this can be decreased if necessary

    public const byte HeaderOffsetPrevHash = 0;
    public const byte HeaderOffsetTarget = 32;
    public const byte HeaderOffsetMerkleRoot = 36;
    public const byte HeaderOffsetVersion = 68;
    public const byte HeaderOffsetTimestamp = 72;
    public const byte HeaderOffsetNonce = 76;
    public const byte HeaderByteSize = 80;

    // WART smallest unit is called UNIT: https://github.com/warthog-network/Warthog/blob/master/src/shared/src/general/params.hpp#L5
    public const decimal SmallestUnit = 100000000;

    // Amount in UNIT
    public const decimal MinimumTransactionFees = 1;

    public const byte PinHeightNonceIdFeeByteSize = 19;
    public const byte Zero = 0;
    public const byte ToAddressOffset = 20;
    public const byte AmountByteSize = 8;
    public const byte FullSignatureByteSize = 65;
}

public static class WarthogCommands
{
    public const string DaemonName = "wart-node";
    public const string DataLabel = ":data:";

    public const string Websocket = "/ws/chain_delta";
    public const string WebsocketEventBlockAppend = "blockAppend";
    public const string WebsocketEventRollback = "rollback";

    public const string GetChainInfo = "/chain/head";
    public const string GetPeers = "/peers/connected";
    public const string GetNetworkHashrate = "/chain/hashrate/" + DataLabel;
    public const string GetBlockTemplate = "/chain/mine/" + DataLabel;

    public const string SubmitBlock = "/chain/append";

    public const string GetBlockByHeight = "/chain/block/" + DataLabel;

    public const string GetWallet = "/tools/wallet/from_privkey/" + DataLabel;
    public const string GetBalance = "/account/" + DataLabel + "/balance";
    public const string GetTransaction = "/transaction/lookup/" + DataLabel;
    public const string SendTransaction = "/transaction/add";
    public const string GetFeeE8Encoded = "/tools/encode16bit/from_e8/" + DataLabel;
}

public enum WarthogNetworkType
{
    Testnet,
    Mainnet,
}