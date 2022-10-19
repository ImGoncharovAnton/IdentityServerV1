namespace IdsTemp.Models.Common;

public class Paginator
{
    public int TotalItems { get; set; }
    public int CurrentPage { get; set; }
    public int PageSize { get; set; }
    public int TotalPages { get; set; }
    public int StartPage { get; set; }
    public int EndPage { get; set; }
    
    public Paginator() {}

    public Paginator(int totalItems, int page, int pageSize = 10)
    {
        var totalPages = (int)Math.Ceiling(totalItems / (decimal)pageSize);
        var currentPage = page;

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
            {
                startPage = endPage - 9;
            }
        }

        TotalItems = totalItems;
        CurrentPage = currentPage;
        PageSize = pageSize;
        TotalPages = totalPages;
        StartPage = startPage;
        EndPage = endPage;
    }
}