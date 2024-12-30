using Newtonsoft.Json;

namespace Miningcore.Blockchain.Beam.StratumRequests;

public class BeamLoginRequest
{
    [JsonProperty("api_key")]
    public string Login { get; set; }

    [JsonProperty("pass")]
    public string Password { get; set; } = null;

    [JsonProperty("agent")]
    public string UserAgent { get; set; } = null;
}