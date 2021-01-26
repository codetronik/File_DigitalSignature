
// DigitalSignatureDlg.h: 헤더 파일
//

#pragma once
#include <openssl/rsa.h>
#include <openssl/pem.h>

// CDigitalSignatureDlg 대화 상자
class CDigitalSignatureDlg : public CDialogEx
{
// 생성입니다.
public:
	CDigitalSignatureDlg(CWnd* pParent = nullptr);	// 표준 생성자입니다.

// 대화 상자 데이터입니다.
#ifdef AFX_DESIGN_TIME
	enum { IDD = IDD_DIGITALSIGNATURE_DIALOG };
#endif

	protected:
	virtual void DoDataExchange(CDataExchange* pDX);	// DDX/DDV 지원입니다.


// 구현입니다.
protected:
	HICON m_hIcon;

	// 생성된 메시지 맵 함수
	virtual BOOL OnInitDialog();
	afx_msg void OnPaint();
	afx_msg HCURSOR OnQueryDragIcon();
	DECLARE_MESSAGE_MAP()
public:
	afx_msg void OnBnClickedButtonMake();

private:
	BOOL LoadRsaKey();
	RSA* m_rsa_public;
	RSA* m_rsa_private;
public:
	afx_msg void OnBnClickedButtonCreate();
	afx_msg void OnBnClickedButtonValidate();
};
