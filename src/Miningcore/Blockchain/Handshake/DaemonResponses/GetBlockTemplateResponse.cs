using Newtonsoft.Json;

namespace Miningcore.Blockchain.Handshake.DaemonResponses;

public class HandshakeClaim
{
    [JsonProperty("data")]
    public string Blob { get; set; }

    public uint Version { get; set; }

    [JsonProperty("hash")]
    public string Address { get; set; }

    public long Value { get; set; }
    public long Fee { get; set; }
}

public class HandshakeAirdrops
{
    [JsonProperty("data")]
    public string Blob { get; set; }

    public uint Version { get; set; }
    public string Address { get; set; }
    public long Value { get; set; }
    public long Fee { get; set; }
}

public class HandshakeBlockTemplate : Bitcoin.DaemonResponses.BlockTemplate
{
    public string MerkleRoot { get; set; }
    public string ReservedRoot { get; set; }
    public string TreeRoot { get; set; }
    public string WitnessRoot { get; set; }

    public HandshakeClaim[] Claims { get; set; }
    public HandshakeAirdrops[] Airdrops { get; set; }
}
