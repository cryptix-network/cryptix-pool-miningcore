using System.Text.Json.Serialization;

namespace Miningcore.Blockchain.Warthog.DaemonRequests;

public class WarthogSendTransactionRequest
{
    [JsonPropertyName("pinHeight")]
    public uint PinHeight { get; set; }

    [JsonPropertyName("nonceId")]
    public uint NonceId { get; set; }

    [JsonPropertyName("toAddr")]
    public string ToAddress { get; set; }

    [JsonPropertyName("amountE8")]
    public ulong Amount { get; set; }

    [JsonPropertyName("feeE8")]
    public ulong Fee { get; set; }

    [JsonPropertyName("signature65")]
    public string Signature { get; set; }
}