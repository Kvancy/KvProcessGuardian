
// KvProcessGuardianDlg.cpp: 实现文件
//

#include <pch.h>
#include <framework.h>
#include "../resource.h"
#include "KvProcessGuardian.h"
#include "KvProcessGuardianDlg.h"
#include "afxdialogex.h"
#include <TlHelp32.h>
#include <winioctl.h> // 包含 FILE_DEVICE_UNKNOWN 的定义
#include "../Driver/tool.h"
#ifdef _DEBUG
#define new DEBUG_NEW
#endif
#include <iostream>

#define IOCTL_ChangePid CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_UnChangePid CTL_CODE(FILE_DEVICE_UNKNOWN, 0x801, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_HandleCallBack CTL_CODE(FILE_DEVICE_UNKNOWN, 0x802, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_UnHandleCallBack CTL_CODE(FILE_DEVICE_UNKNOWN, 0x803, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_HandleDepower CTL_CODE(FILE_DEVICE_UNKNOWN, 0x804, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_UnHandleDepower CTL_CODE(FILE_DEVICE_UNKNOWN, 0x805, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define SYMBOLICLINKNAME L"\\??\\KvDriver"
typedef struct _ioIn
{
	int pid;
}ioIn, * pioIn;
typedef struct _ioOut
{
	int sum;
	BOOLEAN flag;
}ioOut, * pioOut;
// 用于应用程序“关于”菜单项的 CAboutDlg 对话框

class CAboutDlg : public CDialogEx
{
public:
	CAboutDlg();

// 对话框数据
#ifdef AFX_DESIGN_TIME
	enum { IDD = IDD_ABOUTBOX };
#endif

	protected:
	virtual void DoDataExchange(CDataExchange* pDX);    // DDX/DDV 支持

// 实现
protected:
	DECLARE_MESSAGE_MAP()
public:

};

CAboutDlg::CAboutDlg() : CDialogEx(IDD_ABOUTBOX)
{
}

void CAboutDlg::DoDataExchange(CDataExchange* pDX)
{
	CDialogEx::DoDataExchange(pDX);
}

BEGIN_MESSAGE_MAP(CAboutDlg, CDialogEx)
END_MESSAGE_MAP()


// CKvProcessGuardianDlg 对话框



CKvProcessGuardianDlg::CKvProcessGuardianDlg(CWnd* pParent /*=nullptr*/)
	: CDialogEx(IDD_KVPROCESSGUARDIAN_DIALOG, pParent)
{
	m_hIcon = AfxGetApp()->LoadIcon(IDR_MAINFRAME);
}

void CKvProcessGuardianDlg::DoDataExchange(CDataExchange* pDX)
{
	CDialogEx::DoDataExchange(pDX);
	DDX_Control(pDX, IDC_COMBO1, Combo_ProcessList);
	DDX_Control(pDX, IDC_CHECK4, Check_HidPid);
	DDX_Control(pDX, IDC_CHECK1, Check_HandleCallBack);
	DDX_Control(pDX, IDC_CHECK2, Check_HandleDepower);
}

BEGIN_MESSAGE_MAP(CKvProcessGuardianDlg, CDialogEx)
	ON_WM_SYSCOMMAND()
	ON_WM_PAINT()
	ON_WM_QUERYDRAGICON()
	ON_WM_CLOSE()
	ON_BN_CLICKED(IDC_CHECK1, &CKvProcessGuardianDlg::OnBnClickedHandleCallback)
	ON_BN_CLICKED(IDC_CHECK4, &CKvProcessGuardianDlg::OnBnClickedHidPid)
	ON_BN_CLICKED(IDC_CHECK2, &CKvProcessGuardianDlg::OnBnClickedHandleDepower)
	ON_CBN_DROPDOWN(IDC_COMBO1, &CKvProcessGuardianDlg::OnCbnDropdownCombo)
	ON_BN_CLICKED(IDC_BUTTON3, &CKvProcessGuardianDlg::OnBnClickedButtonConfirmPid)
END_MESSAGE_MAP()


// CKvProcessGuardianDlg 消息处理程序

BOOL CKvProcessGuardianDlg::OnInitDialog()
{
	CDialogEx::OnInitDialog();

	// 将“关于...”菜单项添加到系统菜单中。

	// IDM_ABOUTBOX 必须在系统命令范围内。
	ASSERT((IDM_ABOUTBOX & 0xFFF0) == IDM_ABOUTBOX);
	ASSERT(IDM_ABOUTBOX < 0xF000);

	CMenu* pSysMenu = GetSystemMenu(FALSE);
	if (pSysMenu != nullptr)
	{
		BOOL bNameValid;
		CString strAboutMenu;
		bNameValid = strAboutMenu.LoadString(IDS_ABOUTBOX);
		ASSERT(bNameValid);
		if (!strAboutMenu.IsEmpty())
		{
			pSysMenu->AppendMenu(MF_SEPARATOR);
			pSysMenu->AppendMenu(MF_STRING, IDM_ABOUTBOX, strAboutMenu);
		}
	}

	// 设置此对话框的图标。  当应用程序主窗口不是对话框时，框架将自动
	//  执行此操作
	SetIcon(m_hIcon, TRUE);			// 设置大图标
	SetIcon(m_hIcon, FALSE);		// 设置小图标
		// TODO: 在此添加额外的初始化代码

	WCHAR buffer[30];
	wsprintf(buffer, L"当前保护进程PID:");
	SetWindowText(buffer);

	
	WCHAR driverPath[MAX_PATH];
	GetFullPathName(L"KvDriver.sys", MAX_PATH, driverPath, NULL);
	if (!LoadDriver(L"KvDriver", driverPath))
	{
		if (!LoadDriver(L"KvDriver", driverPath)) //尝试加载两次驱动
		{
			MessageBox(L"驱动加载失败");
			exit(0);
		}
	}
	hDevice = CreateFile(L"\\\\.\\KvDriver", GENERIC_READ | GENERIC_WRITE, FILE_SHARE_WRITE, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	if (!hDevice)
	{
		MessageBox(L"打开设备失败");
		exit(0);

	}
	return TRUE;  // 除非将焦点设置到控件，否则返回 TRUE
}

void CKvProcessGuardianDlg::OnSysCommand(UINT nID, LPARAM lParam)
{
	if ((nID & 0xFFF0) == IDM_ABOUTBOX)
	{
		CAboutDlg dlgAbout;
		dlgAbout.DoModal();
	}
	else
	{
		CDialogEx::OnSysCommand(nID, lParam);
	}
}

// 如果向对话框添加最小化按钮，则需要下面的代码
//  来绘制该图标。  对于使用文档/视图模型的 MFC 应用程序，
//  这将由框架自动完成。

void CKvProcessGuardianDlg::OnPaint()
{
	if (IsIconic())
	{
		CPaintDC dc(this); // 用于绘制的设备上下文

		SendMessage(WM_ICONERASEBKGND, reinterpret_cast<WPARAM>(dc.GetSafeHdc()), 0);

		// 使图标在工作区矩形中居中
		int cxIcon = GetSystemMetrics(SM_CXICON);
		int cyIcon = GetSystemMetrics(SM_CYICON);
		CRect rect;
		GetClientRect(&rect);
		int x = (rect.Width() - cxIcon + 1) / 2;
		int y = (rect.Height() - cyIcon + 1) / 2;

		// 绘制图标
		dc.DrawIcon(x, y, m_hIcon);
	}
	else
	{
		CDialogEx::OnPaint();
	}
}

void CKvProcessGuardianDlg::OnClose()
{
	// 调用卸载驱动的函数
	const wchar_t* driverName = L"KvDriver";
	if (!UnloadDriver(driverName))
	{
		AfxMessageBox(_T("卸载驱动失败"));
	}
	// 调用基类的 OnClose 方法
	CDialog::OnClose();
}

//当用户拖动最小化窗口时系统调用此函数取得光标
//显示。
HCURSOR CKvProcessGuardianDlg::OnQueryDragIcon()
{
	return static_cast<HCURSOR>(m_hIcon);
}


void CKvProcessGuardianDlg::OnCbnDropdownCombo()
{
	Combo_ProcessList.ResetContent();
	HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (hSnapshot != INVALID_HANDLE_VALUE)
	{
		PROCESSENTRY32 pe32;
		pe32.dwSize = sizeof(PROCESSENTRY32);
		if (Process32First(hSnapshot, &pe32))
		{
			do
			{
				CString item;
				item.Format(_T("%s - %d"), pe32.szExeFile, pe32.th32ProcessID);
				Combo_ProcessList.AddString(item);
			} while (Process32Next(hSnapshot, &pe32));
		}
		CloseHandle(hSnapshot);
	}
}


void CKvProcessGuardianDlg::OnBnClickedButtonConfirmPid()
{
	CString selectedText;
	Combo_ProcessList.GetWindowText(selectedText);
	int pos = selectedText.Find(_T('-'));
	if (pos != -1)
	{
		selectedText = selectedText.Mid(pos + 1);
		pid = _ttoi(selectedText);
		WCHAR buffer[30];
		wsprintf(buffer, L"当前保护进程PID:%u", pid);
		SetWindowText(buffer);
	}
	else
	{
		MessageBox(L"没有找到进程PID");
		return;
	}
}


void CKvProcessGuardianDlg::OnBnClickedHandleCallback()
{
	if (pid)
	{
		ioIn in = { pid };
		ULONG retlen = 0;
		if (Check_HandleCallBack.GetCheck()) // 由勾选进入未勾选状态，取消隐藏pid
		{

			BOOL flag = DeviceIoControl(hDevice, IOCTL_HandleDepower, &in, sizeof(ioIn), NULL, NULL, &retlen, 0);
			if (!flag)
			{
				MessageBox(L"DeviceIoControl error");
			}
		}
		else
		{
			BOOL flag = DeviceIoControl(hDevice, IOCTL_UnHandleDepower, &in, sizeof(ioIn), NULL, NULL, &retlen, 0);
			if (!flag)
			{
				MessageBox(L"DeviceIoControl error");
			}
		}
	}
}


void CKvProcessGuardianDlg::OnBnClickedHandleDepower()
{
	if (pid)
	{
		ioIn in = { pid };
		ULONG retlen = 0;
		if (Check_HandleDepower.GetCheck()) // 由勾选进入未勾选状态，取消隐藏pid
		{

			BOOL flag = DeviceIoControl(hDevice, IOCTL_HandleDepower, &in, sizeof(ioIn), NULL, NULL, &retlen, 0);
			if (!flag)
			{
				MessageBox(L"DeviceIoControl error");
			}
		}
		else
		{
			BOOL flag = DeviceIoControl(hDevice, IOCTL_UnHandleDepower, &in, sizeof(ioIn), NULL, NULL, &retlen, 0);
			if (!flag)
			{
				MessageBox(L"DeviceIoControl error");
			}
		}
	}
}

void CKvProcessGuardianDlg::OnBnClickedHidPid()
{
	if (pid)
	{
		ioIn in = { pid };
		ULONG retlen = 0;
		if (Check_HidPid.GetCheck()) // 由勾选进入未勾选状态，取消隐藏pid
		{

			BOOL flag = DeviceIoControl(hDevice, IOCTL_ChangePid, &in, sizeof(ioIn), NULL, NULL, &retlen, 0);
			if (!flag)
			{
				MessageBox(L"DeviceIoControl error");
			}
		}
		else
		{
			BOOL flag = DeviceIoControl(hDevice, IOCTL_UnChangePid, &in, sizeof(ioIn), NULL, NULL, &retlen, 0);
			if (!flag)
			{
				MessageBox(L"DeviceIoControl error");
			}
		}
	}
}
