using System.Data;
using AutoMapper;
using Dapper;
using Miningcore.Persistence.Model;
using Miningcore.Persistence.Repositories;

namespace Miningcore.Persistence.Postgres.Repositories;

public class BlockRepository : IBlockRepository
{
    public BlockRepository(IMapper mapper)
    {
        this.mapper = mapper;
    }

    private readonly IMapper mapper;

    public async Task InsertAsync(IDbConnection con, IDbTransaction tx, Block block)
    {
        var mapped = mapper.Map<Entities.Block>(block);

        const string query =
            @"INSERT INTO blocks(poolid, blockheight, networkdifficulty, status, type, transactionconfirmationdata,
                miner, reward, effort, minereffort, confirmationprogress, source, hash, created)
            VALUES(@poolid, @blockheight, @networkdifficulty, @status, @type, @transactionconfirmationdata,
                @miner, @reward, @effort, @minereffort, @confirmationprogress, @source, @hash, @created)";

        await con.ExecuteAsync(query, mapped, tx);
    }

    public async Task DeleteBlockAsync(IDbConnection con, IDbTransaction tx, Block block)
    {
        const string query = "DELETE FROM blocks WHERE id = @id";
        await con.ExecuteAsync(query, block, tx);
    }

    public async Task UpdateBlockAsync(IDbConnection con, IDbTransaction tx, Block block)
    {
        var mapped = mapper.Map<Entities.Block>(block);

        const string query = @"UPDATE blocks SET blockheight = @blockheight, status = @status, type = @type,
            reward = @reward, effort = @effort, minereffort = @minereffort, confirmationprogress = @confirmationprogress, hash = @hash WHERE id = @id";

        await con.ExecuteAsync(query, mapped, tx);
    }

    public async Task<Block[]> PageBlocksAsync(IDbConnection con, string poolId, BlockStatus[] status,
        int page, int pageSize, CancellationToken ct)
    {
        const string query = @"SELECT * FROM blocks WHERE poolid = @poolid AND status = ANY(@status)
            ORDER BY created DESC OFFSET @offset FETCH NEXT @pageSize ROWS ONLY";

        return (await con.QueryAsync<Entities.Block>(new CommandDefinition(query, new
        {
            poolId,
            status = status.Select(x => x.ToString().ToLower()).ToArray(),
            offset = page * pageSize,
            pageSize
        }, cancellationToken: ct)))
            .Select(mapper.Map<Block>)
            .ToArray();
    }

    public async Task<Block[]> PageBlocksAsync(IDbConnection con, BlockStatus[] status, int page, int pageSize, CancellationToken ct)
    {
        const string query = @"SELECT * FROM blocks WHERE status = ANY(@status)
            ORDER BY created DESC OFFSET @offset FETCH NEXT @pageSize ROWS ONLY";

        return (await con.QueryAsync<Entities.Block>(new CommandDefinition(query, new
        {
            status = status.Select(x => x.ToString().ToLower()).ToArray(),
            offset = page * pageSize,
            pageSize
        }, cancellationToken: ct)))
            .Select(mapper.Map<Block>)
            .ToArray();
    }

    public async Task<Block[]> PageMinerBlocksAsync(IDbConnection con, string poolId, string address, BlockStatus[] status,
        int page, int pageSize, CancellationToken ct)
    {
        const string query = @"SELECT * FROM blocks WHERE poolid = @poolid AND status = ANY(@status) AND miner = @address
            ORDER BY created DESC OFFSET @offset FETCH NEXT @pageSize ROWS ONLY";

        return (await con.QueryAsync<Entities.Block>(new CommandDefinition(query, new
        {
            poolId,
	    address,
            status = status.Select(x => x.ToString().ToLower()).ToArray(),
            offset = page * pageSize,
            pageSize
        }, cancellationToken: ct)))
            .Select(mapper.Map<Block>)
            .ToArray();
    }

    public async Task<Block[]> GetPendingBlocksForPoolAsync(IDbConnection con, string poolId)
    {
        const string query = @"SELECT * FROM blocks WHERE poolid = @poolid AND status = @status";

        return (await con.QueryAsync<Entities.Block>(query, new { status = BlockStatus.Pending.ToString().ToLower(), poolid = poolId }))
            .Select(mapper.Map<Block>)
            .ToArray();
    }

    public async Task<Block> GetBlockBeforeAsync(IDbConnection con, string poolId, BlockStatus[] status, DateTime before)
    {
        const string query = @"SELECT * FROM blocks WHERE poolid = @poolid AND status = ANY(@status) AND created < @before
            ORDER BY created DESC FETCH NEXT 1 ROWS ONLY";

        return (await con.QueryAsync<Entities.Block>(query, new
        {
            poolId,
            status = status.Select(x => x.ToString().ToLower()).ToArray(),
            before
        }))
            .Select(mapper.Map<Block>)
            .FirstOrDefault();
    }

    public async Task<Block> GetMinerBlockBeforeAsync(IDbConnection con, string poolId, string miner, BlockStatus[] status, DateTime before, CancellationToken ct)
    {
        const string query = @"SELECT * FROM blocks WHERE poolid = @poolid AND miner = @miner AND status = ANY(@status) AND created < @before
            ORDER BY created DESC FETCH NEXT 1 ROWS ONLY";
        return (await con.QueryAsync<Entities.Block>(new CommandDefinition(query, new
        {
            poolId,
            miner,
            before,
            status = status.Select(x => x.ToString().ToLower()).ToArray()
        }, cancellationToken: ct)))
            .Select(mapper.Map<Block>)
            .FirstOrDefault();
    }
    
    public async Task<uint> GetBlockBeforeCountAsync(IDbConnection con, string poolId, BlockStatus[] status, DateTime before)
    {
        const string query = @"SELECT * FROM blocks WHERE poolid = @poolid AND status = ANY(@status) AND created < @before";
        
        return await con.ExecuteScalarAsync<uint>(new CommandDefinition(query, new
        {
            poolId,
            status = status.Select(x => x.ToString().ToLower()).ToArray(),
            before
        }));
    }

    public Task<uint> GetPoolBlockCountAsync(IDbConnection con, string poolId, CancellationToken ct)
    {
        const string query = @"SELECT COUNT(*) FROM blocks WHERE poolid = @poolId";

        return con.ExecuteScalarAsync<uint>(new CommandDefinition(query, new { poolId }, cancellationToken: ct));
    }

    public Task<uint> GetTotalConfirmedBlocksAsync(IDbConnection con, string poolId, CancellationToken ct)
    {
        const string query = @"SELECT COUNT(*) FROM blocks WHERE poolid = @poolId AND status = 'confirmed'";

        return con.ExecuteScalarAsync<uint>(new CommandDefinition(query, new { poolId }, cancellationToken: ct));
    }

    public Task<uint> GetTotalPendingBlocksAsync(IDbConnection con, string poolId, CancellationToken ct)
    {
        const string query = @"SELECT COUNT(*) FROM blocks WHERE poolid = @poolId AND status = 'pending'";

        return con.ExecuteScalarAsync<uint>(new CommandDefinition(query, new { poolId }, cancellationToken: ct));
    }

    public Task<decimal> GetLastConfirmedBlockRewardAsync(IDbConnection con, string poolId, CancellationToken ct)
    {
        const string query = @"SELECT reward FROM blocks WHERE poolid = @poolId AND status = 'confirmed' ORDER BY created DESC LIMIT 1";

        return con.ExecuteScalarAsync<decimal>(new CommandDefinition(query, new { poolId }, cancellationToken: ct));
    }

    public Task<uint> GetMinerBlockCountAsync(IDbConnection con, string poolId, string address, CancellationToken ct)
    {
        const string query = @"SELECT COUNT(*) FROM blocks WHERE poolid = @poolId AND miner = @address";

        return con.ExecuteScalarAsync<uint>(new CommandDefinition(query, new { poolId, address }, cancellationToken: ct));
    }

    public Task<DateTime?> GetLastPoolBlockTimeAsync(IDbConnection con, string poolId, CancellationToken ct)
    {
        const string query = @"SELECT created FROM blocks WHERE poolid = @poolId ORDER BY created DESC LIMIT 1";

        return con.ExecuteScalarAsync<DateTime?>(new CommandDefinition(query, new { poolId }, cancellationToken: ct));
    }

    public Task<DateTime?> GetLastMinerBlockTimeAsync(IDbConnection con, string poolId, string address, CancellationToken ct)
    {
        const string query = @"SELECT created FROM blocks WHERE poolid = @poolId AND miner = @address ORDER BY created DESC LIMIT 1";
        return con.ExecuteScalarAsync<DateTime?>(new CommandDefinition(query, new { poolId, address }, cancellationToken: ct));
    }

    public async Task<Block> GetBlockByPoolHeightAndTypeAsync(IDbConnection con, string poolId, long height, string type)
    {
        const string query = @"SELECT * FROM blocks WHERE poolid = @poolId AND blockheight = @height AND type = @type";

        return (await con.QueryAsync<Entities.Block>(query, new
        { 
            poolId,
            height,
            type
        }))
            .Select(mapper.Map<Block>)
            .FirstOrDefault();
    }
    
    public async Task<uint> GetPoolDuplicateBlockCountByPoolHeightNoTypeAndStatusAsync(IDbConnection con, string poolId, long height, BlockStatus[] status)
    {
        const string query = @"SELECT COUNT(id) FROM blocks WHERE poolid = @poolId AND blockheight = @height AND status = ANY(@status)";
        
        return await con.ExecuteScalarAsync<uint>(new CommandDefinition(query, new
        {
            poolId,
            height,
            status = status.Select(x => x.ToString().ToLower()).ToArray()
        }));
    }
    
    public async Task<uint> GetPoolDuplicateBlockBeforeCountByPoolHeightNoTypeAndStatusAsync(IDbConnection con, string poolId, long height, BlockStatus[] status, DateTime before)
    {
        const string query = @"SELECT COUNT(id) FROM blocks WHERE poolid = @poolId AND blockheight = @height AND status = ANY(@status) AND created < @before";
        
        return await con.ExecuteScalarAsync<uint>(new CommandDefinition(query, new
        {
            poolId,
            height,
            status = status.Select(x => x.ToString().ToLower()).ToArray(),
            before
        }));
    }
    
    public async Task<uint> GetPoolDuplicateBlockAfterCountByPoolHeightNoTypeAndStatusAsync(IDbConnection con, string poolId, long height, BlockStatus[] status, DateTime after)
    {
        const string query = @"SELECT COUNT(id) FROM blocks WHERE poolid = @poolId AND blockheight = @height AND status = ANY(@status) AND created > @after";
        
        return await con.ExecuteScalarAsync<uint>(new CommandDefinition(query, new
        {
            poolId,
            height,
            status = status.Select(x => x.ToString().ToLower()).ToArray(),
            after
        }));
    }

    public async Task<uint> GetPoolDuplicateBlockBeforeCountByPoolHeightAndHashNoTypeAndStatusAsync(IDbConnection con, string poolId, long height, string hash, BlockStatus[] status, DateTime before)
    {
        const string query = @"SELECT COUNT(id) FROM blocks WHERE poolid = @poolId AND blockheight = @height AND hash = @hash AND status = ANY(@status) AND created < @before";
        
        return await con.ExecuteScalarAsync<uint>(new CommandDefinition(query, new
        {
            poolId,
            height,
            hash,
            status = status.Select(x => x.ToString().ToLower()).ToArray(),
            before
        }));
    }

    public async Task<uint> GetPoolDuplicateBlockAfterCountByPoolHeightAndHashNoTypeAndStatusAsync(IDbConnection con, string poolId, long height, string hash, BlockStatus[] status, DateTime after)
    {
        const string query = @"SELECT COUNT(id) FROM blocks WHERE poolid = @poolId AND blockheight = @height AND hash = @hash AND status = ANY(@status) AND created > @after";
        
        return await con.ExecuteScalarAsync<uint>(new CommandDefinition(query, new
        {
            poolId,
            height,
            hash,
            status = status.Select(x => x.ToString().ToLower()).ToArray(),
            after
        }));
    }
}
