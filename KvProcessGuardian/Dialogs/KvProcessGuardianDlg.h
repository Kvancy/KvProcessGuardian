
// KvProcessGuardianDlg.h: 头文件
//

#pragma once


// CKvProcessGuardianDlg 对话框
class CKvProcessGuardianDlg : public CDialogEx
{
// 构造
public:
	CKvProcessGuardianDlg(CWnd* pParent = nullptr);	// 标准构造函数

// 对话框数据
#ifdef AFX_DESIGN_TIME
	enum { IDD = IDD_KVPROCESSGUARDIAN_DIALOG };
#endif

	protected:
	virtual void DoDataExchange(CDataExchange* pDX);	// DDX/DDV 支持


// 实现
protected:
	HICON m_hIcon;

	// 生成的消息映射函数
	virtual BOOL OnInitDialog();
	afx_msg void OnSysCommand(UINT nID, LPARAM lParam);
	afx_msg void OnPaint();
	afx_msg void OnClose();
	afx_msg HCURSOR OnQueryDragIcon();
	DECLARE_MESSAGE_MAP()
public:
	UINT pid = 0;
	HANDLE hDevice;
	afx_msg void OnBnClickedHandleDepower();
	afx_msg void OnBnClickedHidPid();
	afx_msg void OnBnClickedHandleCallback();
	afx_msg void OnCbnDropdownCombo();
	CComboBox Combo_ProcessList;
	afx_msg void OnBnClickedButtonConfirmPid();


	CButton Check_HidPid;
	CButton Check_HandleCallBack;
	CButton Check_HandleDepower;
};
