using System.Reactive;
using System.Reactive.Linq;
using System.Reactive.Threading.Tasks;
using System.Text;
using Autofac;
using Miningcore.Blockchain.Warthog.Configuration;
using Miningcore.Blockchain.Warthog.DaemonRequests;
using Miningcore.Blockchain.Warthog.DaemonResponses;
using Miningcore.Configuration;
using Miningcore.Extensions;
using Miningcore.JsonRpc;
using Miningcore.Messaging;
using Miningcore.Mining;
using Miningcore.Native;
using Miningcore.Notifications.Messages;
using Miningcore.Rest;
using Miningcore.Rpc;
using Miningcore.Stratum;
using Miningcore.Time;
using Miningcore.Util;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using NLog;
using Contract = Miningcore.Contracts.Contract;
using static Miningcore.Util.ActionUtils;

namespace Miningcore.Blockchain.Warthog;

public class WarthogJobManager : JobManagerBase<WarthogJob>
{
    public WarthogJobManager(
        IComponentContext ctx,
        IMasterClock clock,
        IHttpClientFactory httpClientFactory,
        IMessageBus messageBus,
        IExtraNonceProvider extraNonceProvider) :
        base(ctx, messageBus)
    {
        Contract.RequiresNonNull(ctx);
        Contract.RequiresNonNull(clock);
        Contract.RequiresNonNull(messageBus);
        Contract.RequiresNonNull(extraNonceProvider);

        this.clock = clock;
        this.extraNonceProvider = extraNonceProvider;
        this.httpClientFactory = httpClientFactory;
    }

    private WarthogCoinTemplate coin;
    private DaemonEndpointConfig[] daemonEndpoints;
    private IHttpClientFactory httpClientFactory;
    private SimpleRestClient restClient;
    private RpcClient rpc;
    private WarthogNetworkType network;
    private readonly List<WarthogJob> validJobs = new();
    private readonly IExtraNonceProvider extraNonceProvider;
    private readonly IMasterClock clock;
    private WarthogPoolConfigExtra extraPoolConfig;
    private WarthogPaymentProcessingConfigExtra extraPoolPaymentProcessingConfig;
    protected int maxActiveJobs;
    protected bool isJanusHash;

    protected async Task<bool> UpdateJob(CancellationToken ct, string via = null)
    {
        try
        {
            var blockTemplate = await restClient.Get<WarthogBlockTemplate>(WarthogCommands.GetBlockTemplate.Replace(WarthogCommands.DataLabel, poolConfig.Address), ct);
            if(blockTemplate?.Error != null)
                return false;

            var job = currentJob;
            var isNew = currentJob == null ||
                job.BlockTemplate.Data.Height < blockTemplate.Data.Height ||
                job.BlockTemplate.Data.Header != blockTemplate.Data.Header;

            if(isNew)
            {
                messageBus.NotifyChainHeight(poolConfig.Id, blockTemplate.Data.Height, poolConfig.Template);

                // update job
                job = new WarthogJob();
                job.Init(blockTemplate, NextJobId(), clock, network, isJanusHash);

                lock(jobLock)
                {
                    validJobs.Insert(0, job);

                    // trim active jobs
                    while(validJobs.Count > maxActiveJobs)
                        validJobs.RemoveAt(validJobs.Count - 1);
                }

                if(via != null)
                    logger.Info(() => $"Detected new block {blockTemplate.Data.Height} [{via}]");
                else
                    logger.Info(() => $"Detected new block {blockTemplate.Data.Height}");

                // update stats
                if (job.BlockTemplate.Data.Height > BlockchainStats.BlockHeight)
                {
                    BlockchainStats.LastNetworkBlockTime = clock.Now;
                    BlockchainStats.BlockHeight = (ulong) job.BlockTemplate.Data.Height;
                    BlockchainStats.NetworkDifficulty = job.Difficulty;
                }

                currentJob = job;
            }

            else
            {
                if(via != null)
                    logger.Debug(() => $"Template update {blockTemplate.Data.Height} [{via}]");
                else
                    logger.Debug(() => $"Template update {blockTemplate.Data.Height}");
            }

            return isNew;
        }

        catch(OperationCanceledException)
        {
            // ignored
        }

        catch(Exception ex)
        {
            logger.Error(ex, () => $"Error during {nameof(UpdateJob)}");
        }

        return false;
    }

    protected object GetJobParamsForStratum(bool isNew)
    {
        var job = currentJob;
        return job?.GetJobParams(isNew);
    }

    private async Task UpdateNetworkStatsAsync(CancellationToken ct)
    {
        try
        {
            var responseHashrate = await restClient.Get<GetNetworkHashrateResponse>(WarthogCommands.GetNetworkHashrate.Replace(WarthogCommands.DataLabel, "300"), ct);
            if(responseHashrate?.Code == 0)
                BlockchainStats.NetworkHashrate = responseHashrate.Data.Hashrate;

            var responsePeers = await restClient.Get<GetPeersResponse[]>(WarthogCommands.GetPeers, ct);
            BlockchainStats.ConnectedPeers = responsePeers.Length;
        }

        catch(Exception e)
        {
            logger.Error(e);
        }
    }

    protected async Task<bool> SubmitBlockAsync(Share share, string headerHex, WarthogBlockTemplate blockTemplate, CancellationToken ct)
    {
        Contract.RequiresNonNull(blockTemplate);

        try
        {
            var block = new WarthogSubmitBlockRequest
            {
                Height = blockTemplate.Data.Height,
                Header = headerHex,
                Body = blockTemplate.Data.Body
            };

            var response = await restClient.Post<WarthogSubmitBlockResponse>(WarthogCommands.SubmitBlock, block, ct);
            if(response?.Error != null)
            {
                logger.Warn(() => $"Block {share.BlockHeight} submission failed with: {response.Error}");
                messageBus.SendMessage(new AdminNotification("Block submission failed", $"Pool {poolConfig.Id} {(!string.IsNullOrEmpty(share.Source) ? $"[{share.Source.ToUpper()}] " : string.Empty)}failed to submit block {share.BlockHeight}: {response.Error}"));
                return false;
            }

            return response?.Code == 0;
        }

        catch(Exception e)
        {
            logger.Error(e);
            return false;
        }
    }

    #region API-Surface

    public IObservable<object> Jobs { get; private set; }
    public BlockchainStats BlockchainStats { get; } = new();

    public WarthogCoinTemplate Coin => coin;

    public override void Configure(PoolConfig pc, ClusterConfig cc)
    {
        coin = pc.Template.As<WarthogCoinTemplate>();

        extraPoolConfig = pc.Extra.SafeExtensionDataAs<WarthogPoolConfigExtra>();
        extraPoolPaymentProcessingConfig = pc.PaymentProcessing.Extra.SafeExtensionDataAs<WarthogPaymentProcessingConfigExtra>();

        maxActiveJobs = extraPoolConfig?.MaxActiveJobs ?? 4;

        // extract standard daemon endpoints
        daemonEndpoints = pc.Daemons
            .Where(x => string.IsNullOrEmpty(x.Category))
            .ToArray();

        base.Configure(pc, cc);
    }

    public object[] GetSubscriberData(StratumConnection worker)
    {
        Contract.RequiresNonNull(worker);

        var context = worker.ContextAs<WarthogWorkerContext>();
        var extraNonce1Size = GetExtraNonce1Size();

        // assign unique ExtraNonce1 to worker (miner)
        context.ExtraNonce1 = extraNonceProvider.Next();

        // setup response data
        var responseData = new object[]
        {
            context.ExtraNonce1,
            WarthogConstants.ExtranoncePlaceHolderLength - extraNonce1Size,
        };

        return responseData;
    }

    public int GetExtraNonce1Size()
    {
        return extraPoolConfig?.ExtraNonce1Size ?? 4;
    }

    public virtual async ValueTask<Share> SubmitShareAsync(StratumConnection worker, object submission,
        CancellationToken ct)
    {
        Contract.RequiresNonNull(worker);
        Contract.RequiresNonNull(submission);

        if(submission is not object[] submitParams)
            throw new StratumException(StratumError.Other, "invalid params");

        var context = worker.ContextAs<WarthogWorkerContext>();

        // extract params
        var jobId = submitParams[0] as string;
        var extraNonce2 = submitParams[1] as string;
        var nTime = submitParams[2] as string;
        var nonce = submitParams[3] as string;

        WarthogJob job;

        lock(jobLock)
        {
            job = validJobs.FirstOrDefault(x => x.JobId == jobId);
        }

        if(job == null)
            throw new StratumException(StratumError.JobNotFound, "job not found");

        // validate & process
        var (share, headerHex) = job.ProcessShare(worker, extraNonce2, nTime, nonce);

        // enrich share with common data
        share.PoolId = poolConfig.Id;
        share.IpAddress = worker.RemoteEndpoint.Address.ToString();
        share.Miner = context.Miner;
        share.Worker = context.Worker;
        share.UserAgent = context.UserAgent;
        share.Source = clusterConfig.ClusterName;
        share.Created = clock.Now;

        // if block candidate, submit & check if accepted by network
        if(share.IsBlockCandidate)
        {
            logger.Info(() => $"Submitting block {share.BlockHeight} [{share.BlockHash}][{headerHex}]");

            var acceptResponse = await SubmitBlockAsync(share, headerHex, job.BlockTemplate, ct);

            // is it still a block candidate?
            share.IsBlockCandidate = acceptResponse;

            if(share.IsBlockCandidate)
            {
                logger.Info(() => $"Daemon accepted block {share.BlockHeight} [{share.BlockHash}] submitted by {context.Miner}");

                OnBlockFound();

                // persist the nonce to make block unlocking a bit more reliable
                share.TransactionConfirmationData = nonce;
            }

            else
            {
                // clear fields that no longer apply
                share.TransactionConfirmationData = null;
            }
        }

        return share;
    }

    public async Task<bool> ValidateAddressAsync(string address, CancellationToken ct)
    {
        if(string.IsNullOrEmpty(address))
            return false;

        try
        {
            var response = await restClient.Get<WarthogBlockTemplate>(WarthogCommands.GetBlockTemplate.Replace(WarthogCommands.DataLabel, address), ct);
            if(response?.Error != null)
            {
                logger.Warn(() => $"'{address}': {response.Error} (Code {response?.Code})");
                return false;
            }

            return response?.Code == 0;
        }

        catch(Exception)
        {
            logger.Warn(() => $"'{WarthogCommands.DaemonName}' daemon does not seem to be running...");
            return false;
        }
    }

    #endregion // API-Surface

    #region Overrides

    protected override void ConfigureDaemons()
    {
        var jsonSerializerSettings = ctx.Resolve<JsonSerializerSettings>();

        restClient = new SimpleRestClient(httpClientFactory, "http://" + daemonEndpoints.First().Host.ToString() + ":" + daemonEndpoints.First().Port.ToString());
        rpc = new RpcClient(daemonEndpoints.First(), jsonSerializerSettings, messageBus, poolConfig.Id);
    }

    protected override async Task<bool> AreDaemonsHealthyAsync(CancellationToken ct)
    {
        logger.Debug(() => $"Checking if '{WarthogCommands.DaemonName}' daemon is healthy...");

        // test daemon
        try
        {
            var response = await restClient.Get<GetChainInfoResponse>(WarthogCommands.GetChainInfo, ct);
            if(response?.Error != null)
            {
                logger.Warn(() => $"'{WarthogCommands.GetChainInfo}': {response.Error} (Code {response?.Code})");
                return false;
            }

            return response?.Code == 0;
        }

        catch(Exception)
        {
            logger.Warn(() => $"'{WarthogCommands.DaemonName}' daemon does not seem to be running...");
            return false;
        }
    }

    protected override async Task<bool> AreDaemonsConnectedAsync(CancellationToken ct)
    {
        logger.Debug(() => $"Checking if '{WarthogCommands.DaemonName}' daemon is connected...");

        try
        {
            var response = await restClient.Get<GetPeersResponse[]>(WarthogCommands.GetPeers, ct);

            if(network == WarthogNetworkType.Testnet)
                return response?.Length >= 0;
            else
                return response?.Length > 0;
        }
        
        catch(Exception)
        {
            logger.Warn(() => $"'{WarthogCommands.DaemonName}' daemon does not seem to be running...");
            return false;
        }
    }

    protected override async Task EnsureDaemonsSynchedAsync(CancellationToken ct)
    {
        using var timer = new PeriodicTimer(TimeSpan.FromSeconds(5));
        
        logger.Debug(() => $"Checking if '{WarthogCommands.DaemonName}' daemon is synched...");

        do
        {
            try
            {
                var response = await restClient.Get<GetChainInfoResponse>(WarthogCommands.GetChainInfo, ct);
                if(response?.Code == null)
                    logger.Debug(() => $"'{WarthogCommands.DaemonName}' daemon did not responded...");

                if(response?.Error != null)
                    logger.Debug(() => $"'{WarthogCommands.GetChainInfo}': {response.Error} (Code {response?.Code})");

                if(response.Data.Synced)
                {
                    logger.Info(() => $"'{WarthogCommands.DaemonName}' daemon synched with blockchain");
                    break;
                }

                logger.Info(() => $"Daemon is still syncing with network. Current height: {response?.Data.Height}. Manager will be started once synced.");
            }

            catch(Exception)
            {
                logger.Warn(() => $"'{WarthogCommands.DaemonName}' daemon does not seem to be running...");
            }
        } while(await timer.WaitForNextTickAsync(ct));
    }

    protected override async Task PostStartInitAsync(CancellationToken ct)
    {
        // validate pool address
        if(string.IsNullOrEmpty(poolConfig.Address))
            throw new PoolStartupException("Pool address is not configured", poolConfig.Id);

        // test daemon
        try
        {
            var responseChain = await restClient.Get<GetChainInfoResponse>(WarthogCommands.GetChainInfo, ct);
            if(responseChain?.Code == null)
                throw new PoolStartupException("Init RPC failed...", poolConfig.Id);
            
            isJanusHash = responseChain.Data.IsJanusHash;
            if(isJanusHash)
                logger.Info(() => "JanusHash activated");
        }

        catch(Exception)
        {
            logger.Warn(() => $"'{WarthogCommands.DaemonName} - {WarthogCommands.GetChainInfo}' daemon does not seem to be running...");
            throw new PoolStartupException("Init RPC failed...", poolConfig.Id);
        }

        try
        {
            var responsePoolAddress = await restClient.Get<WarthogBlockTemplate>(WarthogCommands.GetBlockTemplate.Replace(WarthogCommands.DataLabel, poolConfig.Address), ct);
            if(responsePoolAddress?.Error != null)
                throw new PoolStartupException($"Pool address '{poolConfig.Address}': {responsePoolAddress.Error} (Code {responsePoolAddress?.Code})", poolConfig.Id);

            network = responsePoolAddress.Data.Testnet ? WarthogNetworkType.Testnet : WarthogNetworkType.Mainnet;

            // update stats
            BlockchainStats.RewardType = "POW";
            BlockchainStats.NetworkType = $"{network}";
        }

        catch(Exception)
        {
            logger.Warn(() => $"'{WarthogCommands.DaemonName} - {WarthogCommands.GetBlockTemplate}' daemon does not seem to be running...");
            throw new PoolStartupException($"Pool address check failed...", poolConfig.Id);
        }

        if(clusterConfig.PaymentProcessing?.Enabled == true && poolConfig.PaymentProcessing?.Enabled == true)
        {
            // validate pool address privateKey
            if(string.IsNullOrEmpty(extraPoolPaymentProcessingConfig?.WalletPrivateKey))
                throw new PoolStartupException("Pool address private key is not configured", poolConfig.Id);

            try
            {
                var responsePoolAddressWalletPrivateKey = await restClient.Get<WarthogWalletResponse>(WarthogCommands.GetWallet.Replace(WarthogCommands.DataLabel, extraPoolPaymentProcessingConfig?.WalletPrivateKey), ct);
                if(responsePoolAddressWalletPrivateKey?.Error != null)
                    throw new PoolStartupException($"Pool address private key '{extraPoolPaymentProcessingConfig?.WalletPrivateKey}': {responsePoolAddressWalletPrivateKey.Error} (Code {responsePoolAddressWalletPrivateKey?.Code})", poolConfig.Id);

                if(responsePoolAddressWalletPrivateKey.Data.Address != poolConfig.Address)
                    throw new PoolStartupException($"Pool address private key '{extraPoolPaymentProcessingConfig?.WalletPrivateKey}' [{responsePoolAddressWalletPrivateKey.Data.Address}] does not match pool address: {poolConfig.Address}", poolConfig.Id);
            }

            catch(Exception)
            {
                logger.Warn(() => $"'{WarthogCommands.DaemonName} - {WarthogCommands.GetWallet}' daemon does not seem to be running...");
                throw new PoolStartupException($"Pool address private key check failed...", poolConfig.Id);
            }
        }

        await UpdateNetworkStatsAsync(ct);

        // Periodically update network stats
        Observable.Interval(TimeSpan.FromMinutes(1))
            .Select(via => Observable.FromAsync(() =>
                Guard(()=> UpdateNetworkStatsAsync(ct),
                    ex=> logger.Error(ex))))
            .Concat()
            .Subscribe();

        SetupJobUpdates(ct);
    }

    protected virtual void SetupJobUpdates(CancellationToken ct)
    {
        var pollingInterval = poolConfig?.BlockRefreshInterval ?? 0;

        var blockSubmission = blockFoundSubject.Synchronize();
        var pollTimerRestart = blockFoundSubject.Synchronize();

        var triggers = new List<IObservable<(string Via, string Data)>>
        {
            blockSubmission.Select(_ => (JobRefreshBy.BlockFound, (string) null))
        };

        var endpointExtra = daemonEndpoints
            .Where(x => x.Extra.SafeExtensionDataAs<WarthogDaemonEndpointConfigExtra>() != null)
            .Select(x=> Tuple.Create(x, x.Extra.SafeExtensionDataAs<WarthogDaemonEndpointConfigExtra>()))
            .FirstOrDefault();

        if(endpointExtra?.Item2?.PortWs.HasValue == true)
        {
            var (endpointConfig, extra) = endpointExtra;

            var wsEndpointConfig = new DaemonEndpointConfig
            {
                Host = endpointConfig.Host,
                Port = extra.PortWs!.Value,
                HttpPath = extra.HttpPathWs,
                Ssl = extra.SslWs
            };

            logger.Info(() => $"Subscribing to WebSocket {(wsEndpointConfig.Ssl ? "wss" : "ws")}://{wsEndpointConfig.Host}:{wsEndpointConfig.Port}");

            // stream work updates
            var getWorkObs = rpc.WebsocketSubscribe(logger, ct, wsEndpointConfig, WarthogCommands.Websocket, new[] { WarthogCommands.WebsocketEventBlockAppend })
                .Publish()
                .RefCount();

            var websocketNotify = getWorkObs.Where(x => x != null)
                .Publish()
                .RefCount();

            pollTimerRestart = blockSubmission.Merge(websocketNotify.Select(_ => Unit.Default))
                .Publish()
                .RefCount();

            triggers.Add(websocketNotify.Select(_ => (JobRefreshBy.WebSocket, (string) null)));

            if(pollingInterval > 0)
            {
                triggers.Add(Observable.Timer(TimeSpan.FromMilliseconds(pollingInterval))
                    .TakeUntil(pollTimerRestart)
                    .Select(_ => (JobRefreshBy.Poll, (string) null))
                    .Repeat());
            }

            else
            {
                // get initial blocktemplate
                triggers.Add(Observable.Interval(TimeSpan.FromMilliseconds(1000))
                    .Select(_ => (JobRefreshBy.Initial, (string) null))
                    .TakeWhile(_ => !hasInitialBlockTemplate));
            }
        }

        else
        {
            pollingInterval = pollingInterval > 0 ? pollingInterval : 1000;

            // ordinary polling (avoid this at all cost)
            triggers.Add(Observable.Timer(TimeSpan.FromMilliseconds(pollingInterval))
                .TakeUntil(pollTimerRestart)
                .Select(_ => (JobRefreshBy.Poll, (string) null))
                .Repeat());
        }

        Jobs = triggers.Merge()
            .Select(x => Observable.FromAsync(() => UpdateJob(ct, x.Via)))
            .Concat()
            .Where(x => x)
            .Do(x =>
            {
                if(x)
                    hasInitialBlockTemplate = true;
            })
            .Select(x => GetJobParamsForStratum(x))
            .Publish()
            .RefCount();
    }

    #endregion // Overrides
}
