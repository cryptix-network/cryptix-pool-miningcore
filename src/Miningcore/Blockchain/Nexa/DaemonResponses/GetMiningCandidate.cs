using Newtonsoft.Json;

namespace Miningcore.Blockchain.Nexa.DaemonResponses;

public class MiningCandidate
{
    [JsonProperty("id")]
    public int Id { get; set; }

    [JsonProperty("headerCommitment")]
    public string HeaderCommitment { get; set; }

    [JsonProperty("nBits")]
    public string NBits { get; set; }
}
