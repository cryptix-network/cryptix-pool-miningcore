using System.Text.Json.Serialization;

namespace Miningcore.Blockchain.Warthog.DaemonResponses;

public class WarthogFeeE8EncodedData
{
    [JsonPropertyName("roundedE8")]
    public ulong Rounded { get; set; }
}

public class WarthogFeeE8EncodedResponse : WarthogResponseBase
{
    public WarthogFeeE8EncodedData Data { get; set; }
}
