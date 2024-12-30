using System.Text.Json.Serialization;

namespace Miningcore.Blockchain.Warthog.DaemonResponses;

public class WarthogBlockTemplateData
{
    [JsonPropertyName("blockRewardE8")]
    public ulong BlockReward { get; set; }

    public string Body { get; set; }
    public double Difficulty { get; set; }
    public string Header { get; set; }
    public uint Height { get; set; }

    [JsonPropertyName("merklePrefix")]
    public string MerklePrefix { get; set; }

    public bool Synced { get; set; }
    public bool Testnet { get; set; }

    [JsonPropertyName("totalTxFeeE8")]
    public ulong TotalTxFee { get; set; }
}

public class WarthogBlockTemplate : WarthogResponseBase
{
    public WarthogBlockTemplateData Data { get; set; }
}
