using System;
using static System.Array;
using System.Globalization;
using System.Numerics;
using System.Reactive;
using System.Reactive.Disposables;
using System.Reactive.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using System.IO;
using System.Net;
using System.Net.Sockets;
using Autofac;
using Miningcore.Blockchain.Alephium.Configuration;
using NLog;
using Miningcore.Configuration;
using Miningcore.Extensions;
using Miningcore.Messaging;
using Miningcore.Mining;
using Miningcore.Notifications.Messages;
using Miningcore.Stratum;
using Miningcore.Time;
using Newtonsoft.Json;
using Contract = Miningcore.Contracts.Contract;
using static Miningcore.Util.ActionUtils;

namespace Miningcore.Blockchain.Alephium;

public class AlephiumJobManager : JobManagerBase<AlephiumJob>
{
    public AlephiumJobManager(
        IComponentContext ctx,
        IMessageBus messageBus,
        IMasterClock clock,
        IExtraNonceProvider extraNonceProvider) :
        base(ctx, messageBus)
    {
        Contract.RequiresNonNull(clock);
        Contract.RequiresNonNull(extraNonceProvider);

        this.clock = clock;
        this.extraNonceProvider = extraNonceProvider;
    }
    
    private DaemonEndpointConfig[] daemonEndpoints;
    private AlephiumCoinTemplate coin;
    private AlephiumClient rpc;
    private string network;
    private readonly List<AlephiumJob> validJobs = new();
    private readonly IExtraNonceProvider extraNonceProvider;
    private readonly IMasterClock clock;
    private AlephiumPoolConfigExtra extraPoolConfig;
    private AlephiumPaymentProcessingConfigExtra extraPoolPaymentProcessingConfig;
    protected int maxActiveJobs;
    private int socketJobMessageBufferSize;
    private int socketMiningProtocol = 0;
    
    protected IObservable<AlephiumBlockTemplate[]> AlephiumSubscribeStratumApiSocketClient(CancellationToken ct, DaemonEndpointConfig endPoint,
        AlephiumDaemonEndpointConfigExtra extraDaemonEndpoint, object payload = null,
        JsonSerializerSettings payloadJsonSerializerSettings = null)
    {
        return Observable.Defer(() => Observable.Create<AlephiumBlockTemplate[]>(obs =>
        {
            var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);

            Task.Run(async () =>
            {
                using(cts)
                {
                    socket_connexion:
                        byte[] receiveBuffer = new byte[socketJobMessageBufferSize];
                        List<byte> dynamicBuffer = new List<byte>();

                        try
                        {
                            int port = extraDaemonEndpoint.MinerApiPort;
                            IPAddress[] iPAddress = await Dns.GetHostAddressesAsync(endPoint.Host, AddressFamily.InterNetwork, cts.Token);
                            IPEndPoint ipEndPoint = new IPEndPoint(iPAddress.First(), port);
                            using Socket client = new Socket(SocketType.Stream, ProtocolType.Tcp);
                            client.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.KeepAlive, true);
                            client.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.SendTimeout, 1);
                            client.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.ReceiveTimeout, 1);
                            client.SetSocketOption(SocketOptionLevel.Tcp, SocketOptionName.NoDelay, true);
                            logger.Debug(() => $"Establishing socket connection with `{iPAddress.First().ToString()}:{port}`");
                            await client.ConnectAsync(ipEndPoint, cts.Token);
                            if (client.Connected)
                                logger.Debug(() => $"Socket connection successfully established");

                            using NetworkStream stream = new NetworkStream(client, false);
                            string hello = "hello";
                            byte[] requestData = Encoding.UTF8.GetBytes($"{hello}\r\n");
                            int receivedBytes;

                            // Message
                            byte messageVersion = AlephiumConstants.MiningProtocolVersion; // only available since node release >= "3.6.0"
                            byte messageType;
                            uint messageLength;

                            // Buffer
                            byte[] bufferArray;
                            MemoryStream memory = new MemoryStream();
                            BinaryReader reader;

                            // Job
                            //int offset;
                            AlephiumBlockTemplate[] alephiumBlockTemplate;
                            uint jobSize;
                            int fromGroup;
                            int toGroup;
                            ulong height = 0;
                            uint headerBlobLength;
                            byte[] headerBlob;
                            uint txsBlobLength;
                            byte[] txsBlob;
                            uint targetLength;
                            byte[] targetBlob;

                            ChainInfo chainInfo;

                            logger.Debug(() => $"Sending request `{hello}`");
                            // send
                            await stream.WriteAsync(requestData, 0, requestData.Length, cts.Token);

                            logger.Debug(() => $"Waiting for data");
                            // receive
                            while(!cts.IsCancellationRequested && (receivedBytes = await stream.ReadAsync(receiveBuffer, 0, receiveBuffer.Length, cts.Token)) != 0)
                            {
                                logger.Debug(() => $"{receivedBytes} byte(s) of data have been received - current buffer size [{receiveBuffer.Length}]");

                                // According to the ALPH reference pool, it's possible to receive more than 16 blockTemplate at once: https://github.com/alephium/mining-pool/commit/e94379b8fbf6f8b75aecb9b8e77b865de3679552
                                // We need to handle properly that case scenario
                                dynamicBuffer.AddRange(receiveBuffer.Take(receivedBytes));

                                while(dynamicBuffer.Count >= AlephiumConstants.MessageHeaderSize)
                                {
                                    bufferArray = dynamicBuffer.ToArray();

                                    using (memory = new MemoryStream(bufferArray))
                                    {
                                        using (reader = new BinaryReader(memory))
                                        {
                                            messageLength = ReadBigEndianUInt32(reader);

                                            if (bufferArray.Length >= messageLength + AlephiumConstants.MessageHeaderSize)
                                            {
                                                if(socketMiningProtocol > 0)
                                                {
                                                    messageVersion = reader.ReadByte();
                                                    logger.Debug(() => $"Message version: {messageVersion}");
                                                }

                                                messageType = reader.ReadByte();
                                                if (messageVersion == AlephiumConstants.MiningProtocolVersion && messageType == AlephiumConstants.JobsMessageType)
                                                {
                                                    jobSize = ReadBigEndianUInt32(reader);
                                                    logger.Debug(() => $"Parsing {jobSize} job(s) :D");

                                                    alephiumBlockTemplate = new AlephiumBlockTemplate[jobSize];

                                                    for (int index = 0; index < jobSize; index++)
                                                    {
                                                        logger.Debug(() => $"Job ({index + 1})");
                                                        fromGroup = (int)ReadBigEndianUInt32(reader);
                                                        toGroup = (int)ReadBigEndianUInt32(reader);
                                                        logger.Debug(() => $"fromGroup: {fromGroup} - toGroup: {toGroup}");

                                                        if(socketMiningProtocol == 0)
                                                        {
                                                            chainInfo = await rpc.GetBlockflowChainInfoAsync(fromGroup, toGroup, cts.Token);
                                                            height = (ulong) chainInfo?.CurrentHeight + 1;
                                                            logger.Debug(() => $"height: {height}");
                                                        }

                                                        headerBlobLength = ReadBigEndianUInt32(reader);
                                                        logger.Debug(() => $"headerBlobLength: {headerBlobLength}");
                                                        headerBlob = reader.ReadBytes((int)headerBlobLength);
                                                        logger.Debug(() => $"headerBlob: {headerBlob.ToHexString()}");

                                                        txsBlobLength = ReadBigEndianUInt32(reader);
                                                        logger.Debug(() => $"txsBlobLength: {txsBlobLength}");
                                                        txsBlob = reader.ReadBytes((int)txsBlobLength);
                                                        logger.Debug(() => $"txsBlob: {txsBlob.ToHexString()}");

                                                        targetLength = ReadBigEndianUInt32(reader);
                                                        logger.Debug(() => $"targetLength: {targetLength}");
                                                        targetBlob = reader.ReadBytes((int)targetLength);
                                                        logger.Debug(() => $"targetBlob: {targetBlob.ToHexString()}");

                                                        if(socketMiningProtocol > 0)
                                                        {
                                                            height = (ulong)ReadBigEndianUInt32(reader);
                                                            logger.Debug(() => $"height: {height}");
                                                        }

                                                        alephiumBlockTemplate[index] = new AlephiumBlockTemplate
                                                        {
                                                            JobId = NextJobId("X"),
                                                            Height = height,
                                                            Timestamp = clock.Now,
                                                            FromGroup = fromGroup,
                                                            ToGroup = toGroup,
                                                            HeaderBlob = headerBlob.ToHexString(),
                                                            TxsBlob = txsBlob.ToHexString(),
                                                            TargetBlob = targetBlob.ToHexString(),
                                                            ChainIndex = fromGroup * AlephiumConstants.GroupSize + toGroup,
                                                        };
                                                    }

                                                    // publish
                                                    logger.Debug(() => $"Publishing {jobSize} {coin.Symbol} Block Template(s)...");
                                                    obs.OnNext(alephiumBlockTemplate);

                                                    dynamicBuffer = dynamicBuffer.Skip((int)(messageLength + AlephiumConstants.MessageHeaderSize)).ToList();
                                                }
                                                else
                                                {
                                                    logger.Warn(() => $"Message version: {messageVersion}, expects {AlephiumConstants.MiningProtocolVersion} - Message type: {messageType}, expects {AlephiumConstants.JobsMessageType}, wait for more data...");
                                                    break;
                                                }
                                            }
                                            else
                                            {
                                                logger.Debug(() => $"Wait for more data...");
                                                break;
                                            }
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
                            goto socket_connexion;
                        }
                }
            }, cts.Token);
            
            return Disposable.Create(() => { cts.Cancel(); });
        }));
    }
    
    private uint ReadBigEndianUInt32(BinaryReader reader, int count = 4)
    {
        byte[] tmpByte = reader.ReadBytes(count);
        Array.Reverse(tmpByte);
        return BitConverter.ToUInt32(tmpByte, 0);
    }
    
    private void SetupJobUpdates(CancellationToken ct)
    {
        // Prepare data for the stratum API socket
        var daemonEndpoint = daemonEndpoints.First();
        var extraDaemonEndpoint = daemonEndpoint.Extra.SafeExtensionDataAs<AlephiumDaemonEndpointConfigExtra>();
        
        if(extraDaemonEndpoint?.MinerApiPort == null)
            throw new PoolStartupException("Alephium Node's Miner API Port `minerApiPort` not provided", poolConfig.Id);
        
        var blockFound = blockFoundSubject.Synchronize();
        var pollTimerRestart = blockFoundSubject.Synchronize();

        var triggers = new List<IObservable<(string Via, AlephiumBlockTemplate[] Data)>>
        {
            blockFound.Select(_ => (JobRefreshBy.BlockFound, (AlephiumBlockTemplate[]) null))
        };

        // Listen to the stratum API socket
        var getWorkSocket = AlephiumSubscribeStratumApiSocketClient(ct, daemonEndpoint, extraDaemonEndpoint)
            .Publish()
            .RefCount();
            
        triggers.Add(getWorkSocket
            .Select(blockTemplates => (JobRefreshBy.Socket, blockTemplates))
            .Publish()
            .RefCount());

        // get initial blocktemplate
        triggers.Add(Observable.Interval(TimeSpan.FromMilliseconds(1000))
            .Select(_ => (JobRefreshBy.Initial, (AlephiumBlockTemplate[]) null))
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

    private async Task<bool> UpdateJob(CancellationToken ct, string via = null, AlephiumBlockTemplate[] blockTemplates = null)
    {
        var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);

        return await Task.Run(() =>
        {
            using(cts)
            {
                try
                {
                    if(blockTemplates == null)
                        return false;

                    Random randomJob = new Random();
                    var blockTemplate = blockTemplates[randomJob.Next(blockTemplates.Length)];

                    //var chainInfo = await rpc.GetBlockflowChainInfoAsync(blockTemplate.FromGroup, blockTemplate.ToGroup, ct);

                    var job = currentJob;

                    var isNew = job == null ||
                        !string.IsNullOrEmpty(blockTemplate.JobId) &&
                            (job.BlockTemplate?.JobId != blockTemplate.JobId || job.BlockTemplate?.Height < blockTemplate.Height);

                    if(isNew)
                        messageBus.NotifyChainHeight(poolConfig.Id, blockTemplate.Height, poolConfig.Template);

                    if(isNew)
                    {
                        job = new AlephiumJob();

                        job.Init(blockTemplate);

                        lock(jobLock)
                        {
                            validJobs.Insert(0, job);

                            // trim active jobs
                            while(validJobs.Count > maxActiveJobs)
                                validJobs.RemoveAt(validJobs.Count - 1);
                        }

                        if(via != null)
                            logger.Info(() => $"Detected new block {job.BlockTemplate.Height} on chain[{job.BlockTemplate.ChainIndex}] [{via}]");
                        else
                            logger.Info(() => $"Detected new block {job.BlockTemplate.Height} on chain[{job.BlockTemplate.ChainIndex}]");

                        // update stats
                        if ((job.BlockTemplate.Height - 1) > BlockchainStats.BlockHeight)
                        {
                            // update stats
                            BlockchainStats.LastNetworkBlockTime = clock.Now;
                            BlockchainStats.BlockHeight = job.BlockTemplate.Height - 1;
                        }

                        currentJob = job;
                    }

                    else
                    {
                        if(via != null)
                            logger.Debug(() => $"Template update {job.BlockTemplate.Height} on chain[{job.BlockTemplate.ChainIndex}] [{via}]");
                        else
                            logger.Debug(() => $"Template update {job.BlockTemplate.Height} on chain[{job.BlockTemplate.ChainIndex}]");
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
        }, cts.Token);
    }
    
    private async Task UpdateNetworkStatsAsync(CancellationToken ct)
    {
        try
        {
            // update stats
            var info = await rpc.GetInfosInterCliquePeerInfoAsync(ct);
            var infoHashrate = await rpc.GetInfosCurrentHashrateAsync(null, ct);
            var infoDifficulty = await rpc.GetInfosCurrentDifficultyAsync(ct);
            
            BlockchainStats.ConnectedPeers = info.Count;
            BlockchainStats.NetworkDifficulty = (double) infoDifficulty.Difficulty;
            BlockchainStats.NetworkHashrate = AlephiumUtils.TranslateApiHashrate(infoHashrate.Hashrate);
        }

        catch(Exception ex)
        {
            logger.Error(() => $"{ex.GetType().Name} '{ex.Message}' while updating network stats");
        }
    }

    private async Task ShowDaemonSyncProgressAsync(CancellationToken ct)
    {
        var info = await Guard(() => rpc.GetInfosSelfCliqueAsync(ct),
            ex => logger.Debug(ex));

        if(info?.SelfReady != true || info?.Synced != true)
            logger.Info(() => $"Daemon is downloading headers ...");
    }

    private async Task<bool> SubmitBlockAsync(CancellationToken ct, DaemonEndpointConfig endPoint,
        AlephiumDaemonEndpointConfigExtra extraDaemonEndpoint, byte[] coinbase, object payload = null,
        JsonSerializerSettings payloadJsonSerializerSettings = null)
    {
        Contract.RequiresNonNull(coinbase);
        
        bool succeed = false;
        byte[] receiveBuffer = new byte[8192];

        try
        {
            int port = extraDaemonEndpoint.MinerApiPort;
            IPAddress[] iPAddress = await Dns.GetHostAddressesAsync(endPoint.Host, AddressFamily.InterNetwork, ct);
            IPEndPoint ipEndPoint = new IPEndPoint(iPAddress.First(), port);
            using Socket client = new(SocketType.Stream, ProtocolType.Tcp);
            //client.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.KeepAlive, true);
            client.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.SendTimeout, 1);
            client.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.ReceiveTimeout, 1);
            client.SetSocketOption(SocketOptionLevel.Tcp, SocketOptionName.NoDelay, true);
            logger.Debug(() => $"Establishing socket connection with `{iPAddress.First().ToString()}:{port}`");
            await client.ConnectAsync(ipEndPoint, ct);
            if (client.Connected)
                logger.Debug(() => $"[Submitting block] - Socket connection succesffuly established");

            using NetworkStream stream = new NetworkStream(client, false);
            int receivedBytes;

            // Message
            int messageTypeOffset;
            byte messageType;
            int startOffset;
            int succeedIndex;
            byte[] message;

            logger.Debug(() => $"[Submit Block] - Submitting coinbase");
            // send
            await stream.WriteAsync(coinbase, 0, coinbase.Length, ct);

            // receive
            while(!ct.IsCancellationRequested && (receivedBytes = await stream.ReadAsync(receiveBuffer, 0, receiveBuffer.Length, ct)) != 0)
            {
                logger.Debug(() => $"{receivedBytes} byte(s) of data have been received");

                messageTypeOffset = (socketMiningProtocol > 0) ? 1: 0; // socketMiningProtocol: 0 => messageType(1 byte) || socketMiningProtocol: 1 => version(1 byte) + messageType(1 byte)
                messageType = receiveBuffer[AlephiumConstants.MessageHeaderSize + messageTypeOffset];
                if (messageType == AlephiumConstants.SubmitResultMessageType)
                {
                    logger.Debug(() => $"[Submit Block] - Response received :D");
                    startOffset = AlephiumConstants.MessageHeaderSize + messageTypeOffset + 1; // 1 byte
                    message = new byte[receivedBytes - startOffset];
                    Buffer.BlockCopy(receiveBuffer, startOffset, message, 0, receivedBytes - startOffset);

                    succeedIndex = (socketMiningProtocol > 0) ? 40: 8; // socketMiningProtocol: 0 => succeed: index[8] || socketMiningProtocol: 1 => succeed: index[40]
                    succeed = (message[succeedIndex] == 1);
                    break;
                }
            }

            client.Shutdown(SocketShutdown.Both);
        }
        
        catch(Exception)
        {
            // We lost that battle
            messageBus.SendMessage(new AdminNotification("Block submission failed", $"Pool {poolConfig.Id} failed to submit block"));
        }
        
        return succeed;
    }

    #region API-Surface

    public IObservable<AlephiumJobParams> Jobs { get; private set; }
    public BlockchainStats BlockchainStats { get; } = new();
    public string Network => network;

    public AlephiumCoinTemplate Coin => coin;

    public object[] GetSubscriberData(StratumConnection worker)
    {
        Contract.RequiresNonNull(worker);

        var context = worker.ContextAs<AlephiumWorkerContext>();

        // assign unique ExtraNonce1 to worker (miner)
        context.ExtraNonce1 = extraNonceProvider.Next();

        // setup response data
        var responseData = new object[]
        {
            context.ExtraNonce1,
        };

        return responseData;
    }

    public async ValueTask<Share> SubmitShareAsync(StratumConnection worker, AlephiumWorkerSubmitParams submitParams, CancellationToken ct)
    {
        Contract.RequiresNonNull(worker);
        Contract.RequiresNonNull(submitParams);

        var context = worker.ContextAs<AlephiumWorkerContext>();
        
        var jobId = submitParams.JobId;
        var nonce = submitParams.Nonce;

        AlephiumJob job;

        lock(jobLock)
        {
            job = validJobs.FirstOrDefault(x => x.JobId == jobId);
        }

        if(job == null)
            throw new AlephiumStratumException(AlephiumStratumError.JobNotFound, "job not found");

        // validate & process
        var share = job.ProcessShare(worker, nonce);

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
            logger.Info(() => $"Submitting block {share.BlockHeight} [{share.BlockHash}]");
            
            // Prepare data for the stratum API socket
            var daemonEndpoint = daemonEndpoints.First();
            var extraDaemonEndpoint = daemonEndpoint.Extra.SafeExtensionDataAs<AlephiumDaemonEndpointConfigExtra>();
            var jobCoinbase = job.SerializeCoinbase(nonce, socketMiningProtocol);

            var acceptResponse = await SubmitBlockAsync(ct, daemonEndpoint,
                extraDaemonEndpoint, jobCoinbase);

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

    public async Task<bool> ValidateAddress(string address, CancellationToken ct)
    {
        if(string.IsNullOrEmpty(address))
            return false;

        var validity = await Guard(() => rpc.GetAddressesAddressGroupAsync(address, ct),
            ex => logger.Debug(ex));

        return validity?.Group1 >= 0;
    }

    public bool ValidateIsGoldShell(string userAgent)
    {
        if(string.IsNullOrEmpty(userAgent))
            return false;
        
        // Find matches
        MatchCollection matchesUserAgentGoldShell = AlephiumConstants.RegexUserAgentGoldShell.Matches(userAgent);
        return (matchesUserAgentGoldShell.Count > 0);
    }

    public bool ValidateIsIceRiverMiner(string userAgent)
    {
        if(string.IsNullOrEmpty(userAgent))
            return false;
        
        // Find matches
        MatchCollection matchesUserAgentIceRiverMiner = AlephiumConstants.RegexUserAgentIceRiverMiner.Matches(userAgent);
        return (matchesUserAgentIceRiverMiner.Count > 0);
    }

    #endregion // API-Surface

    #region Overrides

    protected override async Task PostStartInitAsync(CancellationToken ct)
    {
        // validate pool address
        if(string.IsNullOrEmpty(poolConfig.Address))
            throw new PoolStartupException($"Pool address is not configured", poolConfig.Id);

        // Payment-processing setup
        if(clusterConfig.PaymentProcessing?.Enabled == true && poolConfig.PaymentProcessing?.Enabled == true)
        {
            // validate pool wallet name
            if(string.IsNullOrEmpty(extraPoolPaymentProcessingConfig.WalletName))
                throw new PoolStartupException($"Pool payment wallet name is not configured", poolConfig.Id);
            
            // check configured pool wallet name belongs to wallet
            var validityWalletName = await Guard(() => rpc.NameAsync(extraPoolPaymentProcessingConfig.WalletName, ct),
                ex=> throw new PoolStartupException($"Error validating pool payment wallet name: {ex}", poolConfig.Id));
            
            // unlocked wallet if locked
            if(validityWalletName.Locked)
            {
                var walletPassword = extraPoolPaymentProcessingConfig.WalletPassword ?? string.Empty;
                
                await Guard(() => rpc.NameUnlockAsync(extraPoolPaymentProcessingConfig.WalletName, new WalletUnlock {Password = walletPassword}, ct),
                    ex=> throw new PoolStartupException($"Error validating pool payment wallet name: {ex}", poolConfig.Id));
                
                logger.Info(() => $"Pool payment wallet is unlocked");
            }
            
            // check configured pool wallet has 4 addresses
            var validityWalletMinerAddresses = await Guard(() => rpc.NameAddressesAsync(extraPoolPaymentProcessingConfig.WalletName, ct),
                ex=> throw new PoolStartupException($"Error validating pool payment wallet name: {ex}", poolConfig.Id));
            
            if (validityWalletMinerAddresses?.Addresses1.Count < 4)
                throw new PoolStartupException($"Pool payment wallet name: {extraPoolPaymentProcessingConfig.WalletName} must have 4 miner's addresses", poolConfig.Id);
            
            // check configured address belongs to wallet
            var walletAddresses = await Guard(() => rpc.NameAddressesAddressAsync(extraPoolPaymentProcessingConfig.WalletName, poolConfig.Address, ct),
                ex=> throw new PoolStartupException($"Pool address: {poolConfig.Address} is not controlled by pool wallet name: {extraPoolPaymentProcessingConfig.WalletName} - Error: {ex}", poolConfig.Id));

            if(walletAddresses.Address != poolConfig.Address)
                throw new PoolStartupException($"Pool address: {poolConfig.Address} is not controlled by pool wallet name: {extraPoolPaymentProcessingConfig.WalletName}", poolConfig.Id);
        }
        
        var infosChainParams = await Guard(() => rpc.GetInfosChainParamsAsync(ct),
            ex=> throw new PoolStartupException($"Daemon reports: {ex.Message}", poolConfig.Id));
        
        switch(infosChainParams?.NetworkId)
        {
            case 0:
                network = "mainnet";
                break;
            case 1:
            case 7:
                network = "testnet";
                break;
            case 4:
                network = "devnet";
                break;
            default:
                throw new PoolStartupException($"Unsupport network type '{infosChainParams?.NetworkId}'", poolConfig.Id);
        }

        // update stats
        BlockchainStats.NetworkType = network;
        BlockchainStats.RewardType = "POW";
        
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

    public override void Configure(PoolConfig pc, ClusterConfig cc)
    {
        coin = pc.Template.As<AlephiumCoinTemplate>();

        extraPoolConfig = pc.Extra.SafeExtensionDataAs<AlephiumPoolConfigExtra>();
        extraPoolPaymentProcessingConfig = pc.PaymentProcessing.Extra.SafeExtensionDataAs<AlephiumPaymentProcessingConfigExtra>();
        
        maxActiveJobs = extraPoolConfig?.MaxActiveJobs ?? 8;
        socketJobMessageBufferSize = extraPoolConfig?.SocketJobMessageBufferSize ?? 131072;
        
        // extract standard daemon endpoints
        daemonEndpoints = pc.Daemons
            .Where(x => string.IsNullOrEmpty(x.Category))
            .ToArray();

        base.Configure(pc, cc);
    }

    protected override void ConfigureDaemons()
    {
        rpc = AlephiumClientFactory.CreateClient(poolConfig, clusterConfig, logger);
    }

    protected override async Task<bool> AreDaemonsHealthyAsync(CancellationToken ct)
    {
        var info = await Guard(() => rpc.GetInfosSelfCliqueAsync(ct),
            ex=> logger.Debug(ex));

        if(info?.SelfReady != true || info?.Synced != true)
            return false;

        return true;
    }

    protected override async Task<bool> AreDaemonsConnectedAsync(CancellationToken ct)
    {
        var infosChainParams = await Guard(() => rpc.GetInfosChainParamsAsync(ct),
            ex=> logger.Debug(ex));

        var info = await Guard(() => rpc.GetInfosInterCliquePeerInfoAsync(ct),
            ex=> logger.Debug(ex));
        
        var nodeInfo = await Guard(() => rpc.GetInfosNodeAsync(ct),
            ex=> logger.Debug(ex));
        
        // update stats
        if(!string.IsNullOrEmpty(nodeInfo?.BuildInfo.ReleaseVersion))
        {
            BlockchainStats.NodeVersion = nodeInfo.BuildInfo.ReleaseVersion;

            // update socket mining protocol
            string numbersOnly = Regex.Replace(nodeInfo.BuildInfo.ReleaseVersion, "[^0-9.]", "");
            string[] numbers = numbersOnly.Split(".");

            // update socket mining protocol
            if(numbers.Length >= 2)
                socketMiningProtocol = ((Convert.ToUInt32(numbers[0]) > 3) || (Convert.ToUInt32(numbers[0]) == 3 && Convert.ToUInt32(numbers[1]) >= 6)) ? 1: 0;
        }

        if(infosChainParams?.NetworkId != 7)
            return info?.Count > 0;

        return true;
    }

    protected override async Task EnsureDaemonsSynchedAsync(CancellationToken ct)
    {
        using var timer = new PeriodicTimer(TimeSpan.FromSeconds(5));

        var syncPendingNotificationShown = false;

        do
        {
            var work = await Guard(() => rpc.GetInfosSelfCliqueAsync(ct),
                ex=> logger.Debug(ex));

            var isSynched = (work?.SelfReady == true && work?.Synced == true);

            if(isSynched)
            {
                logger.Info(() => "Daemon is synced with blockchain");
                break;
            }

            if(!syncPendingNotificationShown)
            {
                logger.Info(() => "Daemon is still syncing with network. Manager will be started once synced.");
                syncPendingNotificationShown = true;
            }

            await ShowDaemonSyncProgressAsync(ct);
        } while(await timer.WaitForNextTickAsync(ct));
    }

    private AlephiumJobParams GetJobParamsForStratum()
    {
        var job = currentJob;
        return job?.GetJobParams();
    }

    #endregion // Overrides
}