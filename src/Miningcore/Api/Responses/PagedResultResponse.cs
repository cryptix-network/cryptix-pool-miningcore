namespace Miningcore.Api.Responses;

public class PagedResultResponse<T> : ResultResponse<T>
{
    public PagedResultResponse(T result, uint itemCount, uint pageCount) : base(result)
    {
        ItemCount = itemCount;
        PageCount = pageCount;
    }

    public uint ItemCount { get; private set; }
    public uint PageCount { get; private set; }
}
