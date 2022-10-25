namespace IdsTemp.Models.Common;

public enum SortOrder { Ascending = 0, Descending = 1}

public class SortModel
{
    private const string UpIcon = "bi bi-arrow-up";
    private const string DownIcon = "bi bi-arrow-down";
    public string SortedProperty { get; set; }
    public SortOrder SortedOrder { get; set; }
    
    public string SortedExpression { get; private set; }
    private List<SortableColumn> _sortableColumns = new List<SortableColumn>();

    public void AddColumn(string colName, bool isDefaultColumn = false)
    {
        var tmp = _sortableColumns.SingleOrDefault(c => c.ColumnName.ToLower() == colName.ToLower());
        if (tmp == null)
            _sortableColumns.Add(new SortableColumn { ColumnName = colName });

        if (isDefaultColumn || _sortableColumns.Count == 1)
        {
            SortedProperty = colName;
            SortedOrder = SortOrder.Ascending;
        }
    }

    public SortableColumn GetColumn(string colName)
    {
        var tmp = _sortableColumns.SingleOrDefault(c => c.ColumnName.ToLower() == colName.ToLower());
        if (tmp == null)
            _sortableColumns.Add(new SortableColumn { ColumnName = colName });
        return tmp;
    }

    public void ApplySort(string sortExpression)
    {
        sortExpression ??= "";
        
        if (sortExpression == "")
            sortExpression = SortedProperty;

        sortExpression = sortExpression.ToLower();
        SortedExpression = sortExpression;

        foreach (var sortableColumn in _sortableColumns)
        {
            sortableColumn.SortIcon = "";
            sortableColumn.SortExpression = sortableColumn.ColumnName;

            if (sortExpression == sortableColumn.ColumnName.ToLower())
            {
                SortedOrder = SortOrder.Ascending;
                SortedProperty = sortableColumn.ColumnName;
                sortableColumn.SortIcon = DownIcon;
                sortableColumn.SortExpression = sortableColumn.ColumnName + "_desc";
            }

            if (sortExpression == sortableColumn.ColumnName.ToLower() + "_desc")
            {
                SortedOrder = SortOrder.Descending;
                SortedProperty = sortableColumn.ColumnName;
                sortableColumn.SortIcon = UpIcon;
                sortableColumn.SortExpression = sortableColumn.ColumnName;
            }
        }
    }
}

public class SortableColumn
{
    public string ColumnName { get; set; }
    public string SortExpression { get; set; }
    public string SortIcon { get; set; }
}