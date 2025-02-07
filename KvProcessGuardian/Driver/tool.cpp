#include <pch.h>
#include "tool.h"

BOOL UnloadDriver(const wchar_t* driverName)
{
    // 打开服务控制管理器
    SC_HANDLE hSCManager = OpenSCManager(NULL, NULL, SC_MANAGER_CONNECT);
    if (hSCManager == NULL)
    {
        std::cerr << "OpenSCManager failed with error: " << GetLastError() << std::endl;
        return FALSE;
    }

    // 打开服务
    SC_HANDLE hService = OpenService(hSCManager, driverName, SERVICE_STOP | DELETE);
    if (hService == NULL)
    {
        std::cerr << "OpenService failed with error: " << GetLastError() << std::endl;
        CloseServiceHandle(hSCManager);
        return FALSE;
    }

    // 停止服务
    SERVICE_STATUS serviceStatus;
    if (!ControlService(hService, SERVICE_CONTROL_STOP, &serviceStatus))
    {
        std::cerr << "ControlService failed with error: " << GetLastError() << std::endl;
        CloseServiceHandle(hService);
        CloseServiceHandle(hSCManager);
        return FALSE;
    }

    // 等待服务完全停止
    DWORD dwStartTime = GetTickCount();
    DWORD dwTimeout = 30000; // 30秒超时
    while (QueryServiceStatus(hService, &serviceStatus))
    {
        if (serviceStatus.dwCurrentState == SERVICE_STOPPED)
        {
            break;
        }

        if ((GetTickCount() - dwStartTime) > dwTimeout)
        {
            std::cerr << "Service did not stop in a timely manner." << std::endl;
            CloseServiceHandle(hService);
            CloseServiceHandle(hSCManager);
            return FALSE;
        }

        Sleep(1000);
    }

    // 删除服务
    if (!DeleteService(hService))
    {
        std::cerr << "DeleteService failed with error: " << GetLastError() << std::endl;
        CloseServiceHandle(hService);
        CloseServiceHandle(hSCManager);
        return FALSE;
    }

    // 清理注册表项
    CleanUpRegistry(driverName);

    // 关闭句柄
    CloseServiceHandle(hService);
    CloseServiceHandle(hSCManager);

    return TRUE;
}

void CleanUpRegistry(const wchar_t* driverName)
{
    HKEY hKey;
    DWORD retCode;

    // 打开服务注册表项
    retCode = RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Services", 0, KEY_ALL_ACCESS, &hKey);
    if (retCode == ERROR_SUCCESS)
    {
        // 删除服务的注册表项及其所有子键
        retCode = RegDeleteTreeW(hKey, driverName);
        if (retCode != ERROR_SUCCESS)
        {
            std::cerr << "Failed to delete registry key for service: " << driverName << std::endl;
        }

        RegCloseKey(hKey);
    }
    else
    {
        std::cerr << "Failed to open registry key: " << retCode << std::endl;
    }
}


BOOL LoadDriver(const wchar_t* driverName, const wchar_t* driverPath)
{
    // 打开服务控制管理器
    SC_HANDLE hSCManager = OpenSCManager(NULL, NULL, SC_MANAGER_CREATE_SERVICE);
    if (hSCManager == NULL)
    {
        std::cerr << "OpenSCManager failed with error: " << GetLastError() << std::endl;
        return FALSE;
    }

    // 检查服务是否已经存在
    SC_HANDLE hService = OpenService(hSCManager, driverName, SERVICE_QUERY_STATUS);
    if (hService != NULL)
    {
        // 服务已存在，先卸载
        CloseServiceHandle(hService);
        if (!UnloadDriver(driverName))
        {
            if (!UnloadDriver(driverName))
            {
                CloseServiceHandle(hSCManager);
                return FALSE;

            }
        }
    }

    // 创建服务
    hService = CreateService(
        hSCManager,                   // 服务控制管理器的句柄
        driverName,                   // 服务名称
        driverName,                   // 显示名称
        SERVICE_ALL_ACCESS,           // 访问权限
        SERVICE_KERNEL_DRIVER,        // 服务类型
        SERVICE_DEMAND_START,         // 启动类型
        SERVICE_ERROR_NORMAL,         // 错误控制类型
        driverPath,                   // 驱动程序路径
        NULL,                         // 服务加载组名称
        NULL,                         // 服务标签
        NULL,                         // 依赖项
        NULL,                         // 服务运行的用户账户
        NULL                          // 服务运行的用户密码
    );

    if (hService == NULL)
    {
        std::cerr << "CreateService failed with error: " << GetLastError() << std::endl;
        CloseServiceHandle(hSCManager);
        return FALSE;
    }

    // 启动服务
    if (!StartService(hService, 0, NULL))
    {
        std::cerr << "StartService failed with error: " << GetLastError() << std::endl;
        DeleteService(hService); // 删除创建的服务
        CloseServiceHandle(hService);
        CloseServiceHandle(hSCManager);
        return FALSE;
    }

    // 关闭句柄
    CloseServiceHandle(hService);
    CloseServiceHandle(hSCManager);

    return TRUE;
}
