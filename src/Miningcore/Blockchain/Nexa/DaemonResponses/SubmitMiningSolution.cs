using Newtonsoft.Json;

namespace Miningcore.Blockchain.Nexa.DaemonResponses;

public class SubmitMiningSolution
{
    /// <summary>
    /// The height of the block new block.
    /// </summary>
    public long Height { get; set; }

    /// <summary>
    /// The hash of the new block.
    /// </summary>
    public string Hash { get; set; }

    /// <summary>
    /// This should be empty if the solution is correct.
    /// Otherwise it will contain an error message.
    /// </summary>
    public string Result { get; set; }
}
