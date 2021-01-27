
// DigitalSignatureDlg.cpp: 구현 파일
//

#include "pch.h"
#include "framework.h"
#include "DigitalSignature.h"
#include "DigitalSignatureDlg.h"
#include "afxdialogex.h"


#ifdef _DEBUG
#define new DEBUG_NEW
#endif


// CDigitalSignatureDlg 대화 상자



CDigitalSignatureDlg::CDigitalSignatureDlg(CWnd* pParent /*=nullptr*/)
	: CDialogEx(IDD_DIGITALSIGNATURE_DIALOG, pParent)
{
	m_hIcon = AfxGetApp()->LoadIcon(IDR_MAINFRAME);
}

void CDigitalSignatureDlg::DoDataExchange(CDataExchange* pDX)
{
	CDialogEx::DoDataExchange(pDX);
}

BEGIN_MESSAGE_MAP(CDigitalSignatureDlg, CDialogEx)
	ON_WM_PAINT()
	ON_WM_QUERYDRAGICON()
	ON_BN_CLICKED(IDC_BUTTON_GENERATE, &CDigitalSignatureDlg::OnBnClickedButtonGenerate)
	ON_BN_CLICKED(IDC_BUTTON_SIGN, &CDigitalSignatureDlg::OnBnClickedButtonSign)
	ON_BN_CLICKED(IDC_BUTTON_VERIFY, &CDigitalSignatureDlg::OnBnClickedButtonVerify)
END_MESSAGE_MAP()


// CDigitalSignatureDlg 메시지 처리기

BOOL CDigitalSignatureDlg::OnInitDialog()
{
	CDialogEx::OnInitDialog();

	// 이 대화 상자의 아이콘을 설정합니다.  응용 프로그램의 주 창이 대화 상자가 아닐 경우에는
	//  프레임워크가 이 작업을 자동으로 수행합니다.
	SetIcon(m_hIcon, TRUE);			// 큰 아이콘을 설정합니다.
	SetIcon(m_hIcon, FALSE);		// 작은 아이콘을 설정합니다.

	// TODO: 여기에 추가 초기화 작업을 추가합니다.

	return TRUE;  // 포커스를 컨트롤에 설정하지 않으면 TRUE를 반환합니다.
}

// 대화 상자에 최소화 단추를 추가할 경우 아이콘을 그리려면
//  아래 코드가 필요합니다.  문서/뷰 모델을 사용하는 MFC 애플리케이션의 경우에는
//  프레임워크에서 이 작업을 자동으로 수행합니다.

void CDigitalSignatureDlg::OnPaint()
{
	if (IsIconic())
	{
		CPaintDC dc(this); // 그리기를 위한 디바이스 컨텍스트입니다.

		SendMessage(WM_ICONERASEBKGND, reinterpret_cast<WPARAM>(dc.GetSafeHdc()), 0);

		// 클라이언트 사각형에서 아이콘을 가운데에 맞춥니다.
		int cxIcon = GetSystemMetrics(SM_CXICON);
		int cyIcon = GetSystemMetrics(SM_CYICON);
		CRect rect;
		GetClientRect(&rect);
		int x = (rect.Width() - cxIcon + 1) / 2;
		int y = (rect.Height() - cyIcon + 1) / 2;

		// 아이콘을 그립니다.
		dc.DrawIcon(x, y, m_hIcon);
	}
	else
	{
		CDialogEx::OnPaint();
	}
}

// 사용자가 최소화된 창을 끄는 동안에 커서가 표시되도록 시스템에서
//  이 함수를 호출합니다.
HCURSOR CDigitalSignatureDlg::OnQueryDragIcon()
{
	return static_cast<HCURSOR>(m_hIcon);
}

BOOL CDigitalSignatureDlg::LoadRsaKey()
{
	int success;
	BIO* bio_public = NULL;
	BIO* bio_private = NULL;
	bio_public = BIO_new(BIO_s_file());
	bio_private = BIO_new(BIO_s_file());

	success = BIO_read_filename(bio_public, "./PublicKey.pem");
	if (success <= 0)
	{
		return FALSE;
	}
	success = BIO_read_filename(bio_private, "./PrivateKey.pem");
	if (success <= 0)
	{
		return FALSE;
	}
	m_rsa_public = PEM_read_bio_RSA_PUBKEY(bio_public, &m_rsa_public, NULL, NULL);	
	m_rsa_private = PEM_read_bio_RSAPrivateKey(bio_private, &m_rsa_private, NULL, NULL);
	if (m_rsa_public == NULL || m_rsa_private == NULL)
	{
		return FALSE;
	}
	return TRUE;
}

void CDigitalSignatureDlg::OnBnClickedButtonGenerate()
{
	int success;
	
	BIO* bio_public = NULL;
	BIO* bio_private = NULL;
	bio_public = BIO_new(BIO_s_file());
	bio_private = BIO_new(BIO_s_file());
	success = BIO_write_filename(bio_public, "./PublicKey.pem");
	if (success <= 0)
	{
		goto EXIT_ERROR;
	}
	success = BIO_write_filename(bio_private, "./PrivateKey.pem");
	if (success <= 0)
	{
		goto EXIT_ERROR;
	}

	// 키 pair 생성
	//RAND_status();
	RSA* rsa = RSA_generate_key(2048, RSA_F4, NULL, NULL);

	//  파일에 pem 형태로 공개키 기록
	success = PEM_write_bio_RSA_PUBKEY(bio_public, rsa);
	if (success <= 0)
	{
		goto EXIT_ERROR;
	}
	// 파일에 pem 형태로 개인키 기록
	success = PEM_write_bio_RSAPrivateKey(bio_private, rsa, NULL, NULL, 0, NULL, NULL);
	if (success <= 0)
	{
		goto EXIT_ERROR;
	}

	if (bio_public) BIO_free_all(bio_public);
	if (bio_private) BIO_free_all(bio_private);
	AfxMessageBox(L"Key generation succeeded.");
	goto EXIT;
EXIT_ERROR:	
	AfxMessageBox(L"There was an error generating the key.");
EXIT:

	return;
}


void CDigitalSignatureDlg::OnBnClickedButtonSign()
{
	WCHAR szFilter[] = L"All Files(*.*)|*.*||";
	CFileDialog dlg(TRUE, NULL, NULL, OFN_HIDEREADONLY, szFilter);
	CString strPathName;
	CString strSigPathName;
	BYTE* byFileBuffer = NULL;
	DWORD dwRead = 0;
	HANDLE hFile = NULL;
	BOOL bSuccess = LoadRsaKey();
	if (FALSE == bSuccess)
	{
		AfxMessageBox(L"There was an error loading the key pair.");		
		goto EXIT_ERROR;
	}
	/*************************
		1. 서명 대상 파일 열기
	**************************/

	// 파일 대화상자 오픈
	if (IDOK != dlg.DoModal())
	{
		// 사용자 캔슬
		return;
	}
	// 대상 파일 경로명
	strPathName = dlg.GetPathName();
	hFile = CreateFile(strPathName, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (INVALID_HANDLE_VALUE == hFile)
	{
		hFile = NULL;
		AfxMessageBox(L"CreateFile() Error");
		goto EXIT_ERROR;
	}
	DWORD nFileSize = GetFileSize(hFile, NULL);
	byFileBuffer = (BYTE*)malloc(nFileSize+1);
	
	bSuccess = ReadFile(hFile, byFileBuffer, nFileSize, &dwRead, NULL);
	if (FALSE == bSuccess)
	{
		AfxMessageBox(L"ReadFile() Error");
		goto EXIT_ERROR;
	}

	CloseHandle(hFile);
	hFile = NULL;
	/*************************
		2. HASH
	**************************/
	BYTE byHash[SHA256_DIGEST_LENGTH] = { 0, };
	SHA256_CTX sha256;
	SHA256_Init(&sha256);
	SHA256_Update(&sha256, byFileBuffer, dwRead);
	SHA256_Final(byHash, &sha256);
	
	// 와이핑
	memset(byFileBuffer, 0, dwRead);
	free(byFileBuffer);
	byFileBuffer = NULL;

	/*************************
		3. 개인키로 hash 암호화
	**************************/
	BYTE byRsaEnc[2048 / 8] = { 0, };
	int enc_size = RSA_private_encrypt(SHA256_DIGEST_LENGTH, byHash, byRsaEnc, m_rsa_private, RSA_PKCS1_PADDING);

	/*************************
		4. 서명을 파일에 저장
	**************************/	
	strSigPathName = strPathName + L".sig";
	hFile = CreateFile(strSigPathName, GENERIC_READ | GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	if (INVALID_HANDLE_VALUE == hFile)
	{
		hFile = NULL;
		AfxMessageBox(L"CreateFile() Error");
		goto EXIT_ERROR;
	}
	DWORD dwWritten = 0;

	bSuccess = WriteFile(hFile, byRsaEnc, 2048 / 8, &dwWritten, NULL);
	if (FALSE == bSuccess)
	{
		AfxMessageBox(L"WriteFile() Error");
		goto EXIT_ERROR;
	}
	
	CloseHandle(hFile);
	hFile = NULL;
	AfxMessageBox(L" Digital signature generation is complete.");

	goto EXIT;
EXIT_ERROR:
EXIT:
	if (hFile != NULL) CloseHandle(hFile);
	if (byFileBuffer != NULL)
	{
		memset(byFileBuffer, 0, dwRead);
		free(byFileBuffer);
		byFileBuffer = NULL;
	}
	return;
}


void CDigitalSignatureDlg::OnBnClickedButtonVerify()
{
	WCHAR szFilter[] = L"Sig Files(*.sig) | *.sig||";
	CFileDialog dlg(TRUE, NULL, NULL, OFN_HIDEREADONLY, szFilter);
	CString strPathName;
	CString strSigPathName;
	BYTE* byFileBuffer = NULL;
	DWORD dwRead = 0;
	HANDLE hFile = NULL;
	BOOL bSuccess = LoadRsaKey();
	if (FALSE == bSuccess)
	{
		AfxMessageBox(L"There was an error loading the key pair.");
		goto EXIT_ERROR;
	}
	/*************************
		1. 원본 파일 열기
	**************************/

	// 파일 대화상자 오픈
	if (IDOK != dlg.DoModal())
	{
		// 사용자 캔슬
		return;
	}
	// 대상 파일 경로명 (.sig 확장자 제거)
	strSigPathName = dlg.GetPathName();
	int nPos = strSigPathName.ReverseFind(L'.sig');
	strPathName = strSigPathName.Left(nPos);

	hFile = CreateFile(strPathName, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (INVALID_HANDLE_VALUE == hFile)
	{
		hFile = NULL;
		AfxMessageBox(L"CreateFile() Error");
		goto EXIT_ERROR;
	}
	DWORD nFileSize = GetFileSize(hFile, NULL);
	byFileBuffer = (BYTE*)malloc(nFileSize + 1);

	bSuccess = ReadFile(hFile, byFileBuffer, nFileSize, &dwRead, NULL);
	if (FALSE == bSuccess)
	{
		AfxMessageBox(L"ReadFile() Error");
		goto EXIT_ERROR;
	}

	CloseHandle(hFile);
	hFile = NULL;

	/*************************
		2. HASH
	**************************/
	BYTE byHash[SHA256_DIGEST_LENGTH] = { 0, };
	SHA256_CTX sha256;
	SHA256_Init(&sha256);
	SHA256_Update(&sha256, byFileBuffer, dwRead);
	SHA256_Final(byHash, &sha256);

	// 와이핑
	memset(byFileBuffer, 0, dwRead);
	free(byFileBuffer);
	byFileBuffer = NULL;

	/*************************
		3. 서명 파일 로딩
	**************************/	
	hFile = CreateFile(strSigPathName, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (INVALID_HANDLE_VALUE == hFile)
	{
		hFile = NULL;
		AfxMessageBox(L"CreateFile() Error");
		goto EXIT_ERROR;
	}
	nFileSize = GetFileSize(hFile, NULL);
	if (nFileSize != 2048 / 8)
	{
		AfxMessageBox(L"This is not a signature file.");
		goto EXIT_ERROR;
	}
	byFileBuffer = (BYTE*)malloc(nFileSize + 1);

	bSuccess = ReadFile(hFile, byFileBuffer, nFileSize, &dwRead, NULL);
	if (FALSE == bSuccess)
	{
		AfxMessageBox(L"ReadFile() Error");
		goto EXIT_ERROR;
	}

	CloseHandle(hFile);
	hFile = NULL;


	/*************************
		4. 공개키로 hash 복호화
	**************************/		
	BYTE byRsaDec[SHA256_DIGEST_LENGTH] = { 0, };
	int dec_size = RSA_public_decrypt(2048/8, byFileBuffer, byRsaDec, m_rsa_public, RSA_PKCS1_PADDING);
	// 와이핑
	memset(byFileBuffer, 0, dwRead);
	free(byFileBuffer);
	byFileBuffer = NULL;

	/*************************
		5. hash 비교
	**************************/
	if (memcmp(byRsaDec, byHash, 32) == 0)
	{		
		AfxMessageBox(L"This file has not been modified.");
	}
	else
	{
		AfxMessageBox(L"This file has been modified.");
	}

	goto EXIT;
EXIT_ERROR:
EXIT:
	if (hFile != NULL) CloseHandle(hFile);
	if (byFileBuffer != NULL)
	{
		memset(byFileBuffer, 0, dwRead);
		free(byFileBuffer);
		byFileBuffer = NULL;
	}
}

