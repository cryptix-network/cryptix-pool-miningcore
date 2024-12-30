using System.Text.Json.Serialization;

namespace Miningcore.Blockchain.Warthog.DaemonResponses;

public class WarthogBlockDataBodyBlockReward
{
    [JsonPropertyName("amountE8")]
    public ulong Amount { get; set; }

    [JsonPropertyName("toAddress")]
    public string ToAddress { get; set; }

    /// <summary>
    /// Publically searchable transaction hash
    /// </summary>
    [JsonPropertyName("txHash")]
    public string TxHash { get; set; }
}

public class WarthogBlockDataBody
{
    [JsonPropertyName("rewards")]
    public WarthogBlockDataBodyBlockReward[] BlockReward { get; set; }
}

public class WarthogBlockDataTransaction
{
    [JsonPropertyName("amountE8")]
    public ulong Amount { get; set; }

    [JsonPropertyName("feeE8")]
    public ulong Fee { get; set; }

    [JsonPropertyName("fromAddress")]
    public string FromAddress { get; set; }

    [JsonPropertyName("nonceId")]
    public uint NonceId { get; set; }

    [JsonPropertyName("pinHeight")]
    public uint PinHeight { get; set; }

    [JsonPropertyName("toAddress")]
    public string ToAddress { get; set; }

    /// <summary>
    /// Publically searchable transaction hash
    /// </summary>
    [JsonPropertyName("txHash")]
    public string TxHash { get; set; }
}

public class WarthogBlockDataHeader
{
    public double Difficulty { get; set; }
    public string Hash { get; set; }
    
    [JsonPropertyName("merkleroot")]
    public string MerkleRoot { get; set; }

    public string Nonce { get; set; }

    [JsonPropertyName("prevHash")]
    public string PrevHash { get; set; }

    public string Raw { get; set; }
    public string Target { get; set; }
    public ulong Timestamp { get; set; }
    public string Version { get; set; }
}

public class WarthogBlockData
{
    public WarthogBlockDataBody Body { get; set; }
    public WarthogBlockDataTransaction[] Transaction { get; set; }
    public ulong confirmations { get; set; }
    public WarthogBlockDataHeader Header { get; set; }
    public uint Height { get; set; }
    public ulong timestamp { get; set; }
}

public class WarthogBlock : WarthogResponseBase
{
    public WarthogBlockData Data { get; set; }
}
