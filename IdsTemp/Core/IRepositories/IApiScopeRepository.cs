﻿using IdsTemp.Models.AdminPanel;

namespace IdsTemp.Core.IRepositories;

public interface IApiScopeRepository
{
    Task<IEnumerable<ApiScopeSummaryModel>> GetAllAsync(string filter = null);
    Task<ApiScopeModel> GetByIdAsync(string id);
}