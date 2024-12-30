using static System.Array;
using System.Globalization;
using System.Reactive;
using System.Reactive.Disposables;
using System.Reactive.Linq;
using System.Security.Cryptography;
using System.Text;
using System.IO;
using System.Net;
using System.Net.Sockets;
using Autofac;
using Miningcore.Blockchain.Bitcoin;
using Miningcore.Blockchain.Beam.Configuration;
using Miningcore.Blockchain.Beam.DaemonRequests;
using Miningcore.Blockchain.Beam.DaemonResponses;
using Miningcore.Blockchain.Beam.StratumRequests;
using Miningcore.Blockchain.Beam.StratumResponses;
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

namespace Miningcore.Blockchain.Beam;

public class BeamJobManager : JobManagerBase<BeamJob>
{
    public BeamJobManager(
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
        this.httpClientFactory = httpClientFactory;
        this.extraNonceProvider = extraNonceProvider;
    }

    private DaemonEndpointConfig[] daemonEndpoints;
    private DaemonEndpointConfig[] explorerDaemonEndpoints;
    private DaemonEndpointConfig[] walletDaemonEndpoints;
    private RpcClient walletRpc;
    private IHttpClientFactory httpClientFactory;
    private SimpleRestClient explorerRestClient;
    private BeamHash solver = new BeamHash();
    private readonly IMasterClock clock;
    private readonly IExtraNonceProvider extraNonceProvider;
    protected int maxActiveJobs = 4;
    private readonly List<BeamJob> validJobs = new();
    private BeamPoolConfigExtra extraPoolConfig;
    public ulong? Forkheight;
    public ulong? Forkheight2;
    protected string PoolNoncePrefix;
    private BeamCoinTemplate coin;
    
    protected IObservable<string> BeamSubscribeStratumApiSocketClient(CancellationToken ct, DaemonEndpointConfig endPoint,
        object request, object payload = null,
        JsonSerializerSettings payloadJsonSerializerSettings = null)
    {
        Contract.RequiresNonNull(request);
        
        return Observable.Defer(() => Observable.Create<string>(obs =>
        {
            var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);

            Task.Run(async () =>
            {
                using(cts)
                {
                    retry:
                        byte[] receiveBuffer = new byte[1024];

                        try
                        {
                            int port = endPoint.Port;
                            IPAddress[] iPAddress = await Dns.GetHostAddressesAsync(endPoint.Host, AddressFamily.InterNetwork, cts.Token);
                            IPEndPoint ipEndPoint = new IPEndPoint(iPAddress.First(), port);
                            using Socket client = new(SocketType.Stream, ProtocolType.Tcp);
                            client.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.KeepAlive, true);
                            client.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.SendTimeout, 1);
                            client.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.ReceiveTimeout, 1);
                            client.SetSocketOption(SocketOptionLevel.Tcp, SocketOptionName.NoDelay, true);
                            logger.Debug(() => $"Establishing socket connection with `{iPAddress.First().ToString()}:{port}`");
                            await client.ConnectAsync(ipEndPoint, cts.Token);
                            if (client.Connected)
                                logger.Debug(() => $"Socket connection succesffuly established");

                            using NetworkStream stream = new NetworkStream(client, false);
                            string json = JsonConvert.SerializeObject(request, payloadJsonSerializerSettings);
                            byte[] requestData = Encoding.UTF8.GetBytes($"{json}\r\n");
                            string data = null;
                            int receivedBytes;

                            logger.Debug(() => $"Sending request `{json}`");
                            // send
                            await stream.WriteAsync(requestData, 0, requestData.Length, cts.Token);

                            logger.Debug(() => $"Waiting for data");
                            // receive
                            while(!cts.IsCancellationRequested && (receivedBytes = await stream.ReadAsync(receiveBuffer, 0, receiveBuffer.Length, cts.Token)) != 0)
                            {
                                logger.Debug(() => $"{receivedBytes} byte(s) of data have been received");

                                // Translate data bytes to an UTF8 string.
                                data = Encoding.UTF8.GetString(receiveBuffer, 0, receivedBytes);
                                logger.Debug(() => $"Received Socket message: {data}");

                                // detect new lines
                                string[] lines = data.Split(
                                    new string[] { "\r\n", "\r", "\n" },
                                    StringSplitOptions.None
                                );
                                logger.Debug(() => $"Message contains {lines.Length} line(s)");

                                // digest all the lines
                                foreach (string line in lines)
                                {
                                    if (!string.IsNullOrEmpty(line))
                                    {
                                        if (!line.Contains("job"))
                                        {
                                            var loginResponse = JsonConvert.DeserializeObject<BeamLoginResponse>(line);
                                            logger.Debug(() => $"Updating pool Nonceprefix");
                                            PoolNoncePrefix = loginResponse?.Nonceprefix;
                                            logger.Debug(() => $"Updating Forkheight values");
                                            Forkheight = (loginResponse?.Forkheight > 0) ? loginResponse.Forkheight : null;
                                            Forkheight2 = (loginResponse?.Forkheight2 > 0) ? loginResponse.Forkheight2 : null;
                                        }

                                        else
                                        {
                                            // publish
                                            obs.OnNext(line);
                                        }
                                    }
                                }
                            }

                            logger.Debug(() => $"No more data received. Bye!");
                            client.Shutdown(SocketShutdown.Both);
                            client.Close();
                        }

                        catch(OperationCanceledException)
                        {
                            // ignored
                        }

                        catch(Exception ex)
                        {
                            logger.Error(() => $"{ex.GetType().Name} '{ex.Message}' while streaming socket responses. Reconnecting in 10s");
                        }
                        
                        if(!cts.IsCancellationRequested)
                        {
                            await Task.Delay(TimeSpan.FromSeconds(10), cts.Token);
                            goto retry;
                        }
                }
            }, cts.Token);
            
            return Disposable.Create(() => { cts.Cancel(); });
        }));
    }
    
    protected async Task<bool> UpdateJob(CancellationToken ct, string via = null, string json = null)
    {
        try
        {
            var responseExplorerRestClient = await explorerRestClient.Get<GetStatusResponse>(BeamExplorerCommands.GetStatus, ct);
            BeamBlockTemplate blockTemplate;
            
            if (!string.IsNullOrEmpty(json))
            {
                blockTemplate = GetBlockTemplateFromJson(json);
            }
            
            else
            {
                blockTemplate = new BeamBlockTemplate
                {
                    Height = responseExplorerRestClient.Height
                };
            }
            
            if (Forkheight2 > 0 && blockTemplate.Height >= Forkheight2)
            {
                blockTemplate.PowType = 2;
            }

            else if (Forkheight > 0 && blockTemplate.Height >= Forkheight)
            {
                blockTemplate.PowType = 1;
            }

            logger.Debug(() => $"POW applied: BEAMHASH{blockTemplate.PowType+1}");

            var job = currentJob;

            var isNew = job == null || (blockTemplate != null && blockTemplate.Input != null && (blockTemplate.JobId != job.BlockTemplate?.JobId || blockTemplate.Height > job.BlockTemplate?.Height));

            if(isNew)
            {
                messageBus.NotifyChainHeight(poolConfig.Id, blockTemplate.Height, poolConfig.Template);

                // init job
                job = new BeamJob();

                job.Init(blockTemplate, blockTemplate.JobId, poolConfig, clusterConfig, clock, solver);

                lock(jobLock)
                {
                    validJobs.Insert(0, job);

                    // trim active jobs
                    while(validJobs.Count > maxActiveJobs)
                        validJobs.RemoveAt(validJobs.Count - 1);
                }
                
                currentJob = job;

                if(via != null)
                    logger.Info(() => $"Detected new block {blockTemplate.Height} [{via}]");
                else
                    logger.Info(() => $"Detected new block {blockTemplate.Height}");

                // update stats
                if (blockTemplate.Height > BlockchainStats.BlockHeight)
                {
                    BlockchainStats.LastNetworkBlockTime = clock.Now;
                    BlockchainStats.BlockHeight = blockTemplate.Height;
                }
                BlockchainStats.NetworkDifficulty = (double) job.BlockTemplate.Difficulty;
            }

            else
            {
                if(via != null)
                    logger.Debug(() => $"Template update {blockTemplate.Height} [{via}]");
                else
                    logger.Debug(() => $"Template update {blockTemplate.Height}");
            }

            return isNew;
        }

        catch(OperationCanceledException)
        {
            // ignored
        }

        catch(Exception ex)
        {
            logger.Error(() => $"{ex.GetType().Name} '{ex.Message}' while updating new job");
        }

        return false;
    }

    private BeamBlockTemplate GetBlockTemplateFromJson(string json)
    {
        return JsonConvert.DeserializeObject<BeamBlockTemplate>(json);
    }

    private async Task ShowDaemonSyncProgressAsync(CancellationToken ct)
    {
        var responseExplorerRestClient = await explorerRestClient.Get<GetStatusResponse>(BeamExplorerCommands.GetStatus, ct);
        var responseWalletRpc = await walletRpc.ExecuteAsync<GetBalanceResponse>(logger, BeamWalletCommands.GetBalance, ct);

        if(responseWalletRpc.Error == null)
        {
            var lowestHeight = (responseExplorerRestClient.Height > responseWalletRpc.Response.Height) ? responseWalletRpc.Response.Height : responseExplorerRestClient.Height;

            var higherHeight = (responseExplorerRestClient.Height > responseWalletRpc.Response.Height) ? responseExplorerRestClient.Height : responseWalletRpc.Response.Height;
            var blocksPercent = (double) lowestHeight / (higherHeight > 0 ? higherHeight : 1 ) * 100;

            logger.Info(() => $"Daemon has downloaded {blocksPercent:0.00}% of blocks from {responseExplorerRestClient.PeersCount} peer(s)");
        }
    }

    private async Task UpdateNetworkStatsAsync(CancellationToken ct)
    {
        try
        {
            var latestBlock = await explorerRestClient.Get<GetStatusResponse>(BeamExplorerCommands.GetStatus, ct);
            
            var latestBlockHeaderRequest = new GetBlockHeaderRequest
            {
                Height = latestBlock.Height
            };

            var responseWalletRpc = await walletRpc.ExecuteAsync<GetBlockHeaderResponse>(logger, BeamWalletCommands.GetBlockHeaders, ct, latestBlockHeaderRequest);

            // extract results
            var peerCount = latestBlock.PeersCount;

            var latestBlockHeight = latestBlock.Height;
            var latestBlockTimestamp = latestBlock.Timestamp;
            var latestBlockDifficulty = responseWalletRpc.Response.Difficulty;

            var sampleSize = (ulong) 300;
            var sampleBlockNumber = latestBlockHeight - sampleSize;
            
            var sampleBlockHeaderRequest = new GetBlockHeaderRequest
            {
                Height = sampleBlockNumber
            };
            
            var responseSampleBlocks = await walletRpc.ExecuteAsync<GetBlockHeaderResponse>(logger, BeamWalletCommands.GetBlockHeaders, ct, sampleBlockHeaderRequest);
            var sampleBlockTimestamp = responseSampleBlocks.Response.Timestamp;

            var blockTime = (double) (latestBlockTimestamp - sampleBlockTimestamp) / sampleSize;
            var networkHashrate = latestBlockDifficulty / blockTime;
            
            BlockchainStats.BlockHeight = latestBlockHeight;
            BlockchainStats.NetworkHashrate = blockTime > 0 ? networkHashrate : 0;
            BlockchainStats.ConnectedPeers = peerCount;
        }

        catch(Exception ex)
        {
            logger.Error(() => $"{ex.GetType().Name} '{ex.Message}' while updating network stats");
        }
    }
    
    public string GetSubscriberData(StratumConnection worker)
    {
        Contract.RequiresNonNull(worker);

        var context = worker.ContextAs<BeamWorkerContext>();

        // assign unique ExtraNonce1 to worker (miner)
        context.ExtraNonce1 = extraNonceProvider.Next();
        
        return context.ExtraNonce1;
    }

    private void SubmitBlock(CancellationToken ct, DaemonEndpointConfig endPoint, object request, Share share, object payload = null, JsonSerializerSettings payloadJsonSerializerSettings = null)
    {
        Contract.RequiresNonNull(request);
        Contract.RequiresNonNull(share);
        
        var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);

        Task.Run(async () =>
        {
            using(cts)
            {
                byte[] receiveBuffer = new byte[1024];

                try
                {
                    int port = endPoint.Port;
                    IPAddress[] iPAddress = await Dns.GetHostAddressesAsync(endPoint.Host, AddressFamily.InterNetwork, cts.Token);
                    IPEndPoint ipEndPoint = new IPEndPoint(iPAddress.First(), port);
                    using Socket client = new(SocketType.Stream, ProtocolType.Tcp);
                    //client.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.KeepAlive, true);
                    client.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.SendTimeout, 1);
                    client.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.ReceiveTimeout, 1);
                    client.SetSocketOption(SocketOptionLevel.Tcp, SocketOptionName.NoDelay, true);
                    logger.Debug(() => $"[Submit Block] - Establishing socket connection with `{iPAddress.First().ToString()}:{port}`");
                    await client.ConnectAsync(ipEndPoint, cts.Token);
                    if (client.Connected)
                        logger.Debug(() => $"[Submitting block] - Socket connection succesffuly established");

                    using NetworkStream stream = new NetworkStream(client, false);
                    string json = JsonConvert.SerializeObject(request, payloadJsonSerializerSettings);
                    byte[] requestData = Encoding.UTF8.GetBytes($"{json}\r\n");

                    logger.Debug(() => $"[Submitting block] - Sending request `{json}`");
                    // send
                    await stream.WriteAsync(requestData, 0, requestData.Length, cts.Token);

                    client.Shutdown(SocketShutdown.Both);
                }

                catch(Exception)
                {
                    // We lost that battle
                    messageBus.SendMessage(new AdminNotification("Block submission failed", $"Pool {poolConfig.Id} {(!string.IsNullOrEmpty(share.Source) ? $"[{share.Source.ToUpper()}] " : string.Empty)}failed to submit block {share.BlockHeight}"));
                }
                
                if(!cts.IsCancellationRequested)
                    await Task.Delay(TimeSpan.FromSeconds(5), cts.Token);
            }
        }, cts.Token);
    }
    
    public object[] GetJobParamsForStratum()
    {
        var job = currentJob;

        return job?.GetJobParamsForStratum() ?? Array.Empty<object>();
    }

    #region API-Surface
    
    public IObservable<object[]> Jobs { get; private set; }

    public override void Configure(PoolConfig pc, ClusterConfig cc)
    {
        Contract.RequiresNonNull(pc);
        Contract.RequiresNonNull(cc);

        logger = LogUtil.GetPoolScopedLogger(typeof(JobManagerBase<BeamJob>), pc);
        poolConfig = pc;
        clusterConfig = cc;
        extraPoolConfig = pc.Extra.SafeExtensionDataAs<BeamPoolConfigExtra>();
        
        if(extraPoolConfig?.MaxActiveJobs.HasValue == true)
            maxActiveJobs = extraPoolConfig.MaxActiveJobs.Value;
        
        coin = pc.Template.As<BeamCoinTemplate>();
        
        // extract standard daemon endpoints
        daemonEndpoints = pc.Daemons
            .Where(x => string.IsNullOrEmpty(x.Category))
            .ToArray();
        
        // extract explorer daemon endpoints
        explorerDaemonEndpoints = pc.Daemons
            .Where(x => x.Category?.ToLower() == BeamConstants.ExplorerDaemonCategory)
            .ToArray();

        if(explorerDaemonEndpoints.Length == 0)
            throw new PoolStartupException("Explorer-RPC daemon is not configured (Daemon configuration for beam-pools require an additional entry of category \'" + BeamConstants.ExplorerDaemonCategory + "' pointing to the explorer daemon)", pc.Id);
        
        if(cc.PaymentProcessing?.Enabled == true && pc.PaymentProcessing?.Enabled == true)
        {
            // extract wallet daemon endpoints
            walletDaemonEndpoints = pc.Daemons
                .Where(x => x.Category?.ToLower() == BeamConstants.WalletDaemonCategory)
                .Select(x =>
                {
                    if(string.IsNullOrEmpty(x.HttpPath))
                        x.HttpPath = BeamConstants.WalletDaemonRpcLocation;

                    return x;
                })
                .ToArray();

            if(walletDaemonEndpoints.Length == 0)
                throw new PoolStartupException("Wallet-RPC daemon is not configured (Daemon configuration for beam-pools require an additional entry of category \'" + BeamConstants.WalletDaemonCategory + "' pointing to the wallet daemon)", pc.Id);
        }

        ConfigureDaemons();
    }

    public async Task<bool> ValidateAddressAsync(string address, CancellationToken ct)
    {
        if(string.IsNullOrEmpty(address))
            return false;

        var request = new ValidateAddressRequest
        {
            Address = address
        };
        
        // address validation
        var responseWalletRpc = await walletRpc.ExecuteAsync<ValidateAddressResponse>(logger, BeamWalletCommands.ValidateAddress, ct, request);
        
        // Beam wallets come with a lot of flavors
        // I tried to enable payments for most of them but there could be some margin for errors
        // https://github.com/BeamMW/beam/wiki/Beam-wallet-protocol-API-v7.1#create_address
        if (responseWalletRpc.Response?.IsValid == false)
            return false;
        
        if (responseWalletRpc.Response?.Type.ToLower() == "max_privacy")
        {
            logger.Warn(() => $"Worker {address} uses a 'Max Privacy' wallet, intended to be used only one time");
        }
        
        else if (responseWalletRpc.Response?.Type.ToLower() == "offline")
        {
            logger.Info(() => $"Worker {address} uses an 'Offline' wallet. Number of offline payments left: {responseWalletRpc.Response?.Payments}");
            return (responseWalletRpc.Response?.Payments > 0);
        }

        return responseWalletRpc.Response?.IsValid == true;
    }

    public (Share share, short stratumError) SubmitShare(StratumConnection worker,
        string JobId, string nonce, string solution, CancellationToken ct)
    {
        Contract.RequiresNonNull(worker);
        Contract.RequiresNonNull(JobId);
        Contract.RequiresNonNull(nonce);
        Contract.RequiresNonNull(solution);
        
        BeamJob job;

        lock(jobLock)
        {
            job = validJobs.FirstOrDefault(x => x.JobId == JobId);
        }

        if(job == null)
            return (new Share {}, BeamConstants.BeamRpcJobNotFound);

        // validate & process
        var (share, blockHex, stratumError) = job.ProcessShare(worker, nonce, solution);
        
        if (stratumError != BeamConstants.BeamRpcShareAccepted)
            return (share, stratumError);
        
        var context = worker.ContextAs<BeamWorkerContext>();
        
        // enrich share with common data
        share.PoolId = poolConfig.Id;
        share.IpAddress = worker.RemoteEndpoint.Address.ToString();
        share.Miner = context.Miner;
        share.Worker = context.Worker;
        share.UserAgent = context.UserAgent;
        share.Source = clusterConfig.ClusterName;
        share.Created = clock.Now;
        share.TransactionConfirmationData = null;

        // if block candidate, submit & check if accepted by network
        if(share.IsBlockCandidate)
        {
            logger.Info(() => $"Submitting block {share.BlockHeight} [{share.BlockHash}]");
            
            var shareSubmitRequest = new BeamSubmitRequest
            {
                Id = JobId,
                Nonce = (!string.IsNullOrEmpty(PoolNoncePrefix)) ? PoolNoncePrefix : nonce,
                Output = solution
            };
            
            SubmitBlock(ct, daemonEndpoints.First(), shareSubmitRequest, share);
            
            logger.Info(() => $"Daemon accepted block {share.BlockHeight} [{share.BlockHash}] submitted by {context.Miner}");
                            
            // persist the coinbase transaction-hash to allow the payment processor
            // Be aware for BEAM, the block verification and confirmation must be performed with `share.BlockHash` if the socket did not return a `Nonceprefix` after login
            share.TransactionConfirmationData = (!string.IsNullOrEmpty(PoolNoncePrefix)) ? share.BlockHash : share.BlockHeight.ToString();
            share.BlockHash = (!string.IsNullOrEmpty(PoolNoncePrefix)) ? null : solution + nonce;
            
            OnBlockFound();
        }

        return (share, stratumError);
    }
    
    public BlockchainStats BlockchainStats { get; } = new();

    #endregion // API-Surface

    #region Overrides

    protected override void ConfigureDaemons()
    {
        var jsonSerializerSettings = ctx.Resolve<JsonSerializerSettings>();
        
        explorerRestClient = new SimpleRestClient(httpClientFactory, "http://" + explorerDaemonEndpoints.First().Host.ToString() + ":" + explorerDaemonEndpoints.First().Port.ToString() + "/");
        logger.Debug(() => $"`beam-node-explorer` URL: http://{explorerDaemonEndpoints.First().Host.ToString()}:{explorerDaemonEndpoints.First().Port.ToString()}/");
        
        if(clusterConfig.PaymentProcessing?.Enabled == true && poolConfig.PaymentProcessing?.Enabled == true)
        {
            walletRpc = new RpcClient(walletDaemonEndpoints.First(), jsonSerializerSettings, messageBus, poolConfig.Id);
        }
    }

    protected override async Task<bool> AreDaemonsHealthyAsync(CancellationToken ct)
    {
        try
        {
            var responseExplorerRestClient = await explorerRestClient.Get<GetStatusResponse>(BeamExplorerCommands.GetStatus, ct);
            
            if(clusterConfig.PaymentProcessing?.Enabled == true && poolConfig.PaymentProcessing?.Enabled == true)
            {
                var responseWalletRpc = await walletRpc.ExecuteAsync<GetBalanceResponse>(logger, BeamWalletCommands.GetBalance, ct);

                return responseWalletRpc.Error == null;
            }
            
            return true;
        }
        
        catch(Exception)
        {
            logger.Debug(() => $"`beam-node-explorer` daemon does not seem to be running...");
            return false;
        }
    }

    protected override async Task<bool> AreDaemonsConnectedAsync(CancellationToken ct)
    {
        logger.Debug(() => "Checking if `beam-node-explorer` daemon is connected...");
        
        try
        {
            var responseExplorerRestClient = await explorerRestClient.Get<GetStatusResponse>(BeamExplorerCommands.GetStatus, ct);
            logger.Debug(() => $"`beam-node-explorer` is connected to {responseExplorerRestClient?.PeersCount} peer(s): Latest blockHeight known: {responseExplorerRestClient?.Height}");
            
            return (responseExplorerRestClient?.PeersCount > 0);
        }
        
        catch(Exception)
        {
            logger.Debug(() => $"`beam-node-explorer` daemon does not seem to be running...");
            return false;
        }
    }

    protected override async Task EnsureDaemonsSynchedAsync(CancellationToken ct)
    {
        using var timer = new PeriodicTimer(TimeSpan.FromSeconds(5));

        var syncPendingNotificationShown = false;

        do
        {
            var responseExplorerRestClient = await explorerRestClient.Get<GetStatusResponse>(BeamExplorerCommands.GetStatus, ct);
            
            // It's only possible to know if the node is synchronized when using both daemons
            if(clusterConfig.PaymentProcessing?.Enabled == true && poolConfig.PaymentProcessing?.Enabled == true)
            {
                var responseWalletRpc = await walletRpc.ExecuteAsync<GetBalanceResponse>(logger, BeamWalletCommands.GetBalance, ct);

                if(responseWalletRpc.Error != null)
                {
                    logger.Debug(() => $"`wallet-api` daemon response: {responseWalletRpc.Error.Message} (Code {responseWalletRpc.Error.Code})");
                }

                else
                {
                    var isSynched = (responseExplorerRestClient.Height == responseWalletRpc.Response.Height);

                    if(isSynched)
                    {
                        logger.Info(() => "All daemons synched with blockchain");
                        break;
                    }

                    if(!syncPendingNotificationShown)
                    {
                        logger.Info(() => "Daemon is still syncing with network. Manager will be started once synced.");
                        syncPendingNotificationShown = true;
                    }
                }
            }
            else
                break;
            
            await ShowDaemonSyncProgressAsync(ct);
        } while(await timer.WaitForNextTickAsync(ct));
    }

    protected override async Task PostStartInitAsync(CancellationToken ct)
    {
        // coin config
        var coin = poolConfig.Template.As<BeamCoinTemplate>();
        
        try
        {
            var responseExplorerRestClient = await explorerRestClient.Get<GetStatusResponse>(BeamExplorerCommands.GetStatus, ct);
        }
        
        catch(Exception)
        {
            throw new PoolStartupException($"Init RPC failed...", poolConfig.Id);
        }
        
        
        var request = new ValidateAddressRequest
        {
            Address = poolConfig.Address
        };
        
        // address validation
        var responseWalletRpc = await walletRpc.ExecuteAsync<ValidateAddressResponse>(logger, BeamWalletCommands.ValidateAddress, ct, request);
        if(responseWalletRpc.Response?.IsValid == false)
            throw new PoolStartupException("Invalid pool address", poolConfig.Id);
        
        if(responseWalletRpc.Response?.Type.ToLower() != "regular")
            throw new PoolStartupException("Pool address must be {'type': 'regular', 'expiration': 'never'}", poolConfig.Id);

        if(clusterConfig.PaymentProcessing?.Enabled == true && poolConfig.PaymentProcessing?.Enabled == true)
        {
            var responseWalletRpc2 = await walletRpc.ExecuteAsync<ValidateAddressResponse>(logger, BeamWalletCommands.ValidateAddress, ct, request);

            // ensure pool owns wallet
            if(responseWalletRpc2.Response?.IsMine == false)
                throw new PoolStartupException($"Wallet-Daemon does not own pool address '{poolConfig.Address}'", poolConfig.Id);
        }

        // update stats
        BlockchainStats.RewardType = "POW";
        
        // method available only since wallet API v6.1, so upgrade your node in order to enjoy that feature
        // https://github.com/BeamMW/beam/wiki/Beam-wallet-protocol-API-v6.1
        var responseNetwork = await walletRpc.ExecuteAsync<GetVersionResponse>(logger, BeamWalletCommands.GetVersion, ct, new {});
        if(responseNetwork.Error == null)
        {
            BlockchainStats.NetworkType = responseNetwork.Response?.Network;
        }
        
        else
        {
            BlockchainStats.NetworkType = "N/A [Wallet API >= 6.1]";
        }
        
        // update stats
        if(!string.IsNullOrEmpty(responseNetwork.Response?.BeamVersion))
            BlockchainStats.NodeVersion = responseNetwork.Response?.BeamVersion;
        
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
        // Prepare data for the stratum API socket
        var daemonEndpoint = daemonEndpoints.First();
        var extraDaemonEndpoint = daemonEndpoint.Extra.SafeExtensionDataAs<BeamDaemonEndpointConfigExtra>();
        
        if(string.IsNullOrEmpty(extraDaemonEndpoint?.ApiKey))
            throw new PoolStartupException("Beam-node daemon `apiKey` not provided", poolConfig.Id);

        var blockFound = blockFoundSubject.Synchronize();
        
        var triggers = new List<IObservable<(string Via, string Data)>>
        {
            blockFound.Select(_ => (JobRefreshBy.BlockFound, (string) null))
        };
        
        var loginRequest = new GetLoginRequest
        {
            ApiKey = extraDaemonEndpoint.ApiKey
        };
        
        // Listen to the stratum API socket
        var getWorkSocket = BeamSubscribeStratumApiSocketClient(ct, daemonEndpoint, loginRequest)
            .Publish()
            .RefCount();
            
        triggers.Add(getWorkSocket
            .Select(json => (JobRefreshBy.Socket, json))
            .Publish()
            .RefCount());
            
        // get initial blocktemplate
        triggers.Add(Observable.Interval(TimeSpan.FromMilliseconds(1000))
            .Select(_ => (JobRefreshBy.Initial, (string) null))
            .TakeWhile(_ => !hasInitialBlockTemplate));

        Jobs = triggers.Merge()
            .Select(x => Observable.FromAsync(() => UpdateJob(ct, x.Via, x.Data)))
            .Concat()
            .Where(x => x)
            .Do(x =>
            {
                if(x)
                    hasInitialBlockTemplate = true;
            })
            .Select(x => GetJobParamsForStratum())
            .Publish()
            .RefCount();
    }

    #endregion // Overrides
}