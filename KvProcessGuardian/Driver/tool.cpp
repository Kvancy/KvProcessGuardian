#include <pch.h>
#include "tool.h"

BOOL UnloadDriver(const wchar_t* driverName)
{
    // �򿪷�����ƹ�����
    SC_HANDLE hSCManager = OpenSCManager(NULL, NULL, SC_MANAGER_CONNECT);
    if (hSCManager == NULL)
    {
        std::cerr << "OpenSCManager failed with error: " << GetLastError() << std::endl;
        return FALSE;
    }

    // �򿪷���
    SC_HANDLE hService = OpenService(hSCManager, driverName, SERVICE_STOP | DELETE);
    if (hService == NULL)
    {
        std::cerr << "OpenService failed with error: " << GetLastError() << std::endl;
        CloseServiceHandle(hSCManager);
        return FALSE;
    }

    // ֹͣ����
    SERVICE_STATUS serviceStatus;
    if (!ControlService(hService, SERVICE_CONTROL_STOP, &serviceStatus))
    {
        std::cerr << "ControlService failed with error: " << GetLastError() << std::endl;
        CloseServiceHandle(hService);
        CloseServiceHandle(hSCManager);
        return FALSE;
    }

    // �ȴ�������ȫֹͣ
    DWORD dwStartTime = GetTickCount();
    DWORD dwTimeout = 30000; // 30�볬ʱ
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

    // ɾ������
    if (!DeleteService(hService))
    {
        std::cerr << "DeleteService failed with error: " << GetLastError() << std::endl;
        CloseServiceHandle(hService);
        CloseServiceHandle(hSCManager);
        return FALSE;
    }

    // ����ע�����
    CleanUpRegistry(driverName);

    // �رվ��
    CloseServiceHandle(hService);
    CloseServiceHandle(hSCManager);

    return TRUE;
}

void CleanUpRegistry(const wchar_t* driverName)
{
    HKEY hKey;
    DWORD retCode;

    // �򿪷���ע�����
    retCode = RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Services", 0, KEY_ALL_ACCESS, &hKey);
    if (retCode == ERROR_SUCCESS)
    {
        // ɾ�������ע�����������Ӽ�
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
    // �򿪷�����ƹ�����
    SC_HANDLE hSCManager = OpenSCManager(NULL, NULL, SC_MANAGER_CREATE_SERVICE);
    if (hSCManager == NULL)
    {
        std::cerr << "OpenSCManager failed with error: " << GetLastError() << std::endl;
        return FALSE;
    }

    // �������Ƿ��Ѿ�����
    SC_HANDLE hService = OpenService(hSCManager, driverName, SERVICE_QUERY_STATUS);
    if (hService != NULL)
    {
        // �����Ѵ��ڣ���ж��
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

    // ��������
    hService = CreateService(
        hSCManager,                   // ������ƹ������ľ��
        driverName,                   // ��������
        driverName,                   // ��ʾ����
        SERVICE_ALL_ACCESS,           // ����Ȩ��
        SERVICE_KERNEL_DRIVER,        // ��������
        SERVICE_DEMAND_START,         // ��������
        SERVICE_ERROR_NORMAL,         // �����������
        driverPath,                   // ��������·��
        NULL,                         // �������������
        NULL,                         // �����ǩ
        NULL,                         // ������
        NULL,                         // �������е��û��˻�
        NULL                          // �������е��û�����
    );

    if (hService == NULL)
    {
        std::cerr << "CreateService failed with error: " << GetLastError() << std::endl;
        CloseServiceHandle(hSCManager);
        return FALSE;
    }

    // ��������
    if (!StartService(hService, 0, NULL))
    {
        std::cerr << "StartService failed with error: " << GetLastError() << std::endl;
        DeleteService(hService); // ɾ�������ķ���
        CloseServiceHandle(hService);
        CloseServiceHandle(hSCManager);
        return FALSE;
    }

    // �رվ��
    CloseServiceHandle(hService);
    CloseServiceHandle(hSCManager);

    return TRUE;
}
