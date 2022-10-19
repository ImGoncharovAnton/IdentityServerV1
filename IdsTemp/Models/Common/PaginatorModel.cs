namespace IdsTemp.Models.Common;

public class PaginatorModel
{
    // Read only properties
    public int TotalItems { get; private set; }
    public int CurrentPage { get; private set; }
    public int PageSize { get; private set; }
    public int TotalPages { get; private set; }
    public int StartPage { get; private set; }
    public int EndPage { get; private set; }
    public int StartRecord { get; private set; }
    public int EndRecord { get; private set; }
    
    // Public properties
    public string Action { get; set; } = "Index";
    public string SearchText { get; set; }
    public string SortExpression { get; set; }

    public PaginatorModel(int totalItems, int currentPage, int pageSize = 5)
    {
        TotalItems = totalItems;
        CurrentPage = currentPage;
        PageSize = pageSize;

        var totalPages = (int)Math.Ceiling(totalItems / (decimal)pageSize);
        TotalPages = totalPages;

        var startPage = currentPage - 5;
        var endPage = currentPage + 4;

        if (startPage <= 0)
        {
            endPage = endPage - (startPage - 1);
            startPage = 1;
        }

        if (endPage > totalPages)
        {
            endPage = totalPages;
            if (endPage > 10)
                startPage = endPage - 9;
        }
        
        StartRecord = (CurrentPage - 1) * PageSize + 1;
        EndRecord = StartRecord - 1 + PageSize;

        if (EndRecord > TotalItems)
            EndRecord = TotalItems;
        if (TotalItems == 0)
        {
            StartPage = 0;
            StartRecord = 0;
            CurrentPage = 0;
            EndRecord = 0;
        }
        else
        {
            StartPage = startPage;
            EndPage = endPage;
        }
    }

}