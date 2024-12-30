using System.Text.Json.Serialization;

namespace Miningcore.Blockchain.Warthog.DaemonResponses;

public class GetChainInfoData
{
    public double Difficulty { get; set; }
    public string Hash { get; set; }
    public uint Height { get; set; }
    
    [JsonPropertyName("is_janushash")]
    public bool IsJanusHash { get; set; }

    [JsonPropertyName("pinHash")]
    public string PinHash { get; set; }

    [JsonPropertyName("pinHeight")]
    public uint PinHeight { get; set; }

    public bool Synced { get; set; }
    public double Worksum { get; set; }

    [JsonPropertyName("worksumHex")]
    public string WorksumHex { get; set; }
}

public class GetChainInfoResponse : WarthogResponseBase
{
    public GetChainInfoData Data { get; set; }
}
