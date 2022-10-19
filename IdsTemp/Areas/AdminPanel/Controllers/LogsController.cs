using IdsTemp.Core.IRepositories;
using IdsTemp.Models.AdminPanel;
using IdsTemp.Models.Common;
using Microsoft.AspNetCore.Mvc;

namespace IdsTemp.Areas.AdminPanel.Controllers;

[Area("AdminPanel")]
public class LogsController : Controller
{
    private readonly ILogsRepository _logsRepository;

    public LogsController(ILogsRepository logsRepository)
    {
        _logsRepository = logsRepository;
    }

    // GET
    public async Task<IActionResult> Index(string sortExpression="", string searchText = "", int pg = 1, int pageSize = 5)
    {
        var sortModel = new SortModel();
        
        sortModel.AddColumn("timestamp");
        sortModel.AddColumn("level");
        sortModel.ApplySort(sortExpression);
        ViewData["sortModel"] = sortModel;
        ViewBag.SearchText = searchText;
        
        
        var logs = await _logsRepository.GetItemsAsync(sortModel.SortedProperty, sortModel.SortedOrder, searchText);

        var paginator = new PaginatorModel(logs.Count, pg, pageSize);
        paginator.SearchText = searchText;
        paginator.SortExpression = sortExpression;
        ViewBag.Paginator = paginator;

        logs = logs.Skip((pg - 1) * pageSize).Take(pageSize).ToList();
        
        var vmLogs = new LogsViewModel
        {
            Logs = logs
        };
      
        return View(vmLogs);
    }

    private SortModel ApplySort(string sortExpression)
    {
        ViewData["SortParamTime"] = "timestamp";
        ViewData["SortParamLevel"] = "level";
        ViewData["SortIconTime"] = "";
        ViewData["SortIconLevel"] = "";

        var sortModel = new SortModel();

        switch (sortExpression.ToLower())
        {
            case "timestamp_desc":
                sortModel.SortedOrder = SortOrder.Descending;
                sortModel.SortedProperty = "timestamp";
                ViewData["SortIconTime"] = "bi bi-arrow-up";
                ViewData["SortParamTime"] = "timestamp";
                break;
            case "level":
                sortModel.SortedOrder = SortOrder.Ascending;
                sortModel.SortedProperty = "level";
                ViewData["SortIconLevel"] = "bi bi-arrow-down";
                ViewData["SortParamLevel"] = "level_desc";
                break;
            case "level_desc":
                sortModel.SortedOrder = SortOrder.Descending;
                sortModel.SortedProperty = "level";
                ViewData["SortIconLevel"] = "bi bi-arrow-up";
                ViewData["SortParamLevel"] = "level";
                break;
            default:
                sortModel.SortedOrder = SortOrder.Ascending;
                sortModel.SortedProperty = "timestamp";
                ViewData["SortIconTime"] = "bi bi-arrow-down";
                ViewData["SortParamTime"] = "timestamp_desc";
                break;
        }

        return sortModel;
    }
}