namespace Miningcore.Blockchain.Warthog.DaemonRequests;

public class WarthogSubmitBlockRequest
{
    public uint Height { get; set; }
    public string Header { get; set; }
    public string Body { get; set; }
}