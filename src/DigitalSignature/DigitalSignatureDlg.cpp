
// DigitalSignatureDlg.cpp: 구현 파일
//

#include "pch.h"
#include "framework.h"
#include "DigitalSignature.h"
#include "DigitalSignatureDlg.h"
#include "afxdialogex.h"
#include <vector>

#ifdef _DEBUG
#define new DEBUG_NEW
#endif

#define KEY_SIZE 2048
//#define NOUSE_EVP 


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


BOOL CDigitalSignatureDlg::OnInitDialog()
{
	CDialogEx::OnInitDialog();

	SetIcon(m_hIcon, TRUE);	
	SetIcon(m_hIcon, FALSE);
	return TRUE;
}

void CDigitalSignatureDlg::OnPaint()
{
	if (IsIconic())
	{
		CPaintDC dc(this);
		SendMessage(WM_ICONERASEBKGND, reinterpret_cast<WPARAM>(dc.GetSafeHdc()), 0);
			
		int cxIcon = GetSystemMetrics(SM_CXICON);
		int cyIcon = GetSystemMetrics(SM_CYICON);
		CRect rect;
		GetClientRect(&rect);
		int x = (rect.Width() - cxIcon + 1) / 2;
		int y = (rect.Height() - cyIcon + 1) / 2;
			
		dc.DrawIcon(x, y, m_hIcon);
	}
	else
	{
		CDialogEx::OnPaint();
	}
}

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
	RAND_status();
	RSA* rsa = RSA_generate_key(KEY_SIZE, RSA_F4, NULL, NULL);

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
	
	std::vector<BYTE> FileBuffer;
	DWORD dwRead = 0;
	BYTE bySign[KEY_SIZE / 8] = { 0, };
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
	FileBuffer.resize(nFileSize); // vector 사이즈 재할당
	
	bSuccess = ReadFile(hFile, &FileBuffer.front(), nFileSize, &dwRead, NULL);
	if (FALSE == bSuccess)
	{
		AfxMessageBox(L"ReadFile() Error");
		goto EXIT_ERROR;
	}

	CloseHandle(hFile);
	hFile = NULL;
	
	/*
		서명에는 evp 함수를 사용하는 방법과 평문 hash->rsa_encrypt하는 2가지 방법이 있다.
		다만, 두 가지의 sign값이 다름.
	*/

#if defined(NOUSE_EVP)
	/*************************
		2. HASH
	**************************/	
	BYTE byHash[SHA256_DIGEST_LENGTH] = { 0, };
	SHA256_CTX sha256;
	SHA256_Init(&sha256);
	SHA256_Update(&sha256, &FileBuffer.front(), dwRead);
	SHA256_Final(byHash, &sha256);
	
	/*************************
		3. 개인키로 hash 암호화
	**************************/		
	int enc_size = RSA_private_encrypt(SHA256_DIGEST_LENGTH, byHash, bySign, m_rsa_private, RSA_PKCS1_PADDING);
#else
	/*************************
		2&3. EVP (hash & encrypt)
	**************************/

	EVP_MD_CTX ctx;
	EVP_PKEY* pkey;
	int result;	
	unsigned int signSize = 0;
	pkey = EVP_PKEY_new();
	result = EVP_PKEY_set1_RSA(pkey, m_rsa_private);

	EVP_MD_CTX_init(&ctx);
	result = EVP_SignInit(&ctx, EVP_sha256());
	result = EVP_SignUpdate(&ctx, &FileBuffer.front(), dwRead);
	result = EVP_SignFinal(&ctx, bySign, &signSize, pkey);
	EVP_MD_CTX_cleanup(&ctx);
	EVP_PKEY_free(pkey);

	if ((signSize != KEY_SIZE / 8) || result != 1)
	{
		AfxMessageBox(L"Sign Error");
		goto EXIT_ERROR;
	}
#endif


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

	bSuccess = WriteFile(hFile, bySign, KEY_SIZE / 8, &dwWritten, NULL);
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

	return;
}


void CDigitalSignatureDlg::OnBnClickedButtonVerify()
{
	WCHAR szFilter[] = L"Sig Files(*.sig) | *.sig||";
	CFileDialog dlg(TRUE, NULL, NULL, OFN_HIDEREADONLY, szFilter);
	CString strPathName;
	CString strSigPathName;
	std::vector<BYTE> FileBuffer;
	std::vector<BYTE> SignFileBuffer;

	DWORD dwRead = 0;
	DWORD dwRead2 = 0;

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
	FileBuffer.resize(nFileSize); // vector 사이즈 재할당

	bSuccess = ReadFile(hFile, &FileBuffer.front(), nFileSize, &dwRead, NULL);
	if (FALSE == bSuccess)
	{
		AfxMessageBox(L"ReadFile() Error");
		goto EXIT_ERROR;
	}

	CloseHandle(hFile);
	hFile = NULL;

	/*************************
		2. 서명 파일 로딩
	**************************/	
	hFile = CreateFile(strSigPathName, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (INVALID_HANDLE_VALUE == hFile)
	{
		hFile = NULL;
		AfxMessageBox(L"CreateFile() Error");
		goto EXIT_ERROR;
	}
	nFileSize = GetFileSize(hFile, NULL);
	if (nFileSize != KEY_SIZE / 8)
	{
		AfxMessageBox(L"This is not a signature file.");
		goto EXIT_ERROR;
	}
	SignFileBuffer.resize(nFileSize);

	bSuccess = ReadFile(hFile, &SignFileBuffer.front(), nFileSize, &dwRead2, NULL);
	if (FALSE == bSuccess)
	{
		AfxMessageBox(L"ReadFile() Error");
		goto EXIT_ERROR;
	}

	CloseHandle(hFile);
	hFile = NULL;
		
#if defined(NOUSE_EVP)
	/*************************
		3. 공개키로 hash 복호화
	**************************/		
	BYTE byRsaDec[SHA256_DIGEST_LENGTH] = { 0, };
	int dec_size = RSA_public_decrypt(KEY_SIZE/8, &SignFileBuffer.front(), byRsaDec, m_rsa_public, RSA_PKCS1_PADDING);
	if (dec_size != SHA256_DIGEST_LENGTH)
	{
		AfxMessageBox(L"Decrypt Error");
		goto EXIT_ERROR;
	}
	/*************************
		4. 원본 HASH
	**************************/
	BYTE byHash[SHA256_DIGEST_LENGTH] = { 0, };
	SHA256_CTX sha256;
	SHA256_Init(&sha256);
	SHA256_Update(&sha256, &FileBuffer.front(), dwRead);
	SHA256_Final(byHash, &sha256);

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
#else
	/*************************
		3&4&5. EVP(rsa_decrypt & hash & compare)
	**************************/
	EVP_MD_CTX ctx;
	EVP_PKEY* pubkey;
	int result;
	pubkey = EVP_PKEY_new();
	result = EVP_PKEY_set1_RSA(pubkey, m_rsa_public);
	EVP_MD_CTX_init(&ctx);
	result = EVP_VerifyInit_ex(&ctx, EVP_sha256(), NULL);
	result = EVP_VerifyUpdate(&ctx, &FileBuffer.front(), dwRead);
	result = EVP_VerifyFinal(&ctx, &SignFileBuffer.front(), KEY_SIZE/8 , pubkey);
	EVP_MD_CTX_cleanup(&ctx);
	EVP_PKEY_free(pubkey);
	if (result == 1)
	{
		AfxMessageBox(L"This file has not been modified.");	
	}
	else
	{
		AfxMessageBox(L"This file has been modified.");
	}
#endif
	goto EXIT;
EXIT_ERROR:
EXIT:
	if (hFile != NULL) CloseHandle(hFile);

}

