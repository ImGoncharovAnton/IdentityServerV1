using IdsTemp.Data;
using IdsTemp.Models;
using IdsTemp.Models.AdminPanel;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;

namespace IdsTemp.Areas.AdminPanel.Controllers;

[Area("AdminPanel")]
public class LogsController : Controller
{
    private readonly ApplicationDbContext _dbContext;

    public LogsController(ApplicationDbContext dbContext)
    {
        _dbContext = dbContext;
    }

    // GET
    public async Task<IActionResult> Index(int page = 1 )
    {
        var logs = await _dbContext.logs.ToListAsync();

        const int pageSize = 10;
        if (page < 1)
            page = 1;

        var recsCount = logs.Count;
        var paginator = new Paginator(recsCount, page, pageSize);
        // if page not is 2 and page size is 10 then recskip = (2 - 1) * 10
        var recSkip = (page - 1) * pageSize;
        var data = logs.Skip(recSkip).Take(paginator.PageSize).ToList();

        this.ViewBag.Paginator = paginator;
        
        
        var vmLogs = new LogsViewModel
        {
            Logs = data
        };
      
        return View(vmLogs);
        // return View(data);
    }
}