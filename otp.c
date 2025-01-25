#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <windows.h>
#include <wincrypt.h>
#include <time.h>
#include <stdlib.h>
#include <string.h>
#include <tchar.h>
#include <prsht.h>
#include <commctrl.h>
#include <windowsx.h>

#include "main.h"
#include "options.h"
#include "registry.h"
#include "otp.h"
#include "misc.h"
#include "openvpn-gui-res.h"

/* Common control macros */
#ifndef COMBOBOX_CLASS
#define COMBOBOX_CLASS L"ComboBox"
#endif

#ifndef BUTTON_CLASS
#define BUTTON_CLASS L"Button"
#endif

/* Common control function declarations */
#ifndef ComboBox_AddString
#define ComboBox_AddString(hwndCtl, lpsz) ((int)(DWORD)SendMessage((hwndCtl), CB_ADDSTRING, 0L, (LPARAM)(LPCTSTR)(lpsz)))
#endif

#ifndef ComboBox_SetCurSel
#define ComboBox_SetCurSel(hwndCtl, index) ((int)(DWORD)SendMessage((hwndCtl), CB_SETCURSEL, (WPARAM)(int)(index), 0L))
#endif

#ifndef ComboBox_GetCurSel
#define ComboBox_GetCurSel(hwndCtl) ((int)(DWORD)SendMessage((hwndCtl), CB_GETCURSEL, 0L, 0L))
#endif

#ifndef Button_SetCheck
#define Button_SetCheck(hwndCtl, check) ((void)SendMessage((hwndCtl), BM_SETCHECK, (WPARAM)(int)(check), 0L))
#endif

#ifndef Button_GetCheck
#define Button_GetCheck(hwndCtl) ((int)(DWORD)SendMessage((hwndCtl), BM_GETCHECK, 0L, 0L))
#endif

extern options_t o;
extern connection_t *GetConnByName(const WCHAR *config_name);
extern BOOL SetConfigRegistryValueDWORD(const WCHAR *config_name, const WCHAR *name, DWORD value);
extern DWORD GetConfigRegistryValueDWORD(const WCHAR *config_name, const WCHAR *name, DWORD default_value);

/* Registry keys for OTP settings */
#define OTP_REGISTRY_KEY L"SOFTWARE\\OpenVPN-GUI"
#define OTP_SECRET_DATA L"otp_secret"
#define OTP_ALGO_DATA L"otp_algorithm"
#define OTP_DIGITS_DATA L"otp_digits"
#define OTP_AUTOFILL_DATA L"otp_autofill"

/* OTP Settings Dialog */
#ifndef ID_DLG_OTP
#define ID_DLG_OTP                      600
#define ID_TXT_OTP_SECRET               601
#define ID_EDT_OTP_SECRET               602
#define ID_OTP_SECRET_REVEAL            603
#define ID_TXT_OTP_ALGO                 604
#define ID_CMB_OTP_ALGO                 605
#define ID_TXT_OTP_DIGITS               606
#define ID_CMB_OTP_DIGITS               607
#define ID_CHK_OTP_AUTOFILL             608
#define ID_BTN_TEST_OTP                 609
#define ID_TXT_TEST_OTP                 610
#endif

static void
LoadOTPDlgParams(HWND hwndDlg)
{
    WCHAR debug_buf[512];
    OutputDebugStringW(L"OTP: Loading dialog parameters\n");

    /* Load algorithm options */
    HWND hwndAlgo = GetDlgItem(hwndDlg, ID_CMB_OTP_ALGO);
    ComboBox_AddString(hwndAlgo, L"TOTP (Time-based)");
    ComboBox_AddString(hwndAlgo, L"HOTP (Counter-based)");
    ComboBox_SetCurSel(hwndAlgo, 0);  // Default to TOTP

    /* Load digits options */
    HWND hwndDigits = GetDlgItem(hwndDlg, ID_CMB_OTP_DIGITS);
    ComboBox_AddString(hwndDigits, L"6");
    ComboBox_AddString(hwndDigits, L"8");
    ComboBox_SetCurSel(hwndDigits, 0);  // Default to 6 digits

    /* Load saved settings if available */
    otp_settings_t settings;
    if (LoadOTPSettings(NULL, &settings))
    {
        OutputDebugStringW(L"OTP: Loading saved settings\n");

        /* Set secret */
        SetDlgItemTextW(hwndDlg, ID_EDT_OTP_SECRET, settings.secret);

        /* Set algorithm */
        ComboBox_SetCurSel(hwndAlgo, settings.algorithm);

        /* Set digits */
        ComboBox_SetCurSel(hwndDigits, settings.digits == 8 ? 1 : 0);

        /* Set autofill and auth_pass_concat_otp */
        BOOL autofill = settings.autofill;
        Button_SetCheck(GetDlgItem(hwndDlg, ID_CHK_OTP_AUTOFILL), autofill ? BST_CHECKED : BST_UNCHECKED);

        /* If autofill is enabled, also enable auth_pass_concat_otp */
        if (autofill)
        {
            SaveGlobalRegistryValueDWORD(L"auth_pass_concat_otp", TRUE);
            OutputDebugStringW(L"OTP: auth_pass_concat_otp enabled\n");
        }

        /* Generate initial test code */
        WCHAR otp[16];
        if (GenerateOTP(&settings, otp, _countof(otp)))
        {
            SetDlgItemTextW(hwndDlg, ID_TXT_TEST_OTP, otp);
        }
    }
    else
    {
        OutputDebugStringW(L"OTP: No saved settings found, using defaults\n");
    }
}

INT_PTR CALLBACK
OTPSettingsDlgProc(HWND hwndDlg, UINT msg, WPARAM wParam, LPARAM lParam)
{
    LPPSHNOTIFY psn;
    otp_settings_t settings;
    WCHAR otp[16];
    WCHAR debug_buf[512];

    switch (msg)
    {
        case WM_INITDIALOG:
            LoadOTPDlgParams(hwndDlg);
            break;

        case WM_COMMAND:
            switch (LOWORD(wParam))
            {
                case ID_OTP_SECRET_REVEAL:
                    ChangePasswordVisibility(GetDlgItem(hwndDlg, ID_EDT_OTP_SECRET),
                                          GetDlgItem(hwndDlg, ID_OTP_SECRET_REVEAL),
                                          wParam);
                    break;

                case ID_CHK_OTP_AUTOFILL:
                    if (HIWORD(wParam) == BN_CLICKED)
                    {
                        BOOL autofill = Button_GetCheck(GetDlgItem(hwndDlg, ID_CHK_OTP_AUTOFILL)) == BST_CHECKED;
                        OutputDebugStringW(autofill ? L"OTP: Autofill checkbox checked\n" : L"OTP: Autofill checkbox unchecked\n");
                        
                        /* Update auth_pass_concat_otp in registry */
                        if (autofill)
                        {
                            SaveGlobalRegistryValueDWORD(L"auth_pass_concat_otp", TRUE);
                            OutputDebugStringW(L"OTP: auth_pass_concat_otp enabled\n");
                        }
                        else
                        {
                            SaveGlobalRegistryValueDWORD(L"auth_pass_concat_otp", FALSE);
                            OutputDebugStringW(L"OTP: auth_pass_concat_otp disabled\n");
                        }
                    }
                    break;

                case ID_BTN_TEST_OTP:
                    OutputDebugStringW(L"OTP: Test button clicked\n");
                    /* Get current settings from dialog */
                    GetDlgItemTextW(hwndDlg, ID_EDT_OTP_SECRET, settings.secret, _countof(settings.secret));
                    settings.algorithm = ComboBox_GetCurSel(GetDlgItem(hwndDlg, ID_CMB_OTP_ALGO));
                    settings.digits = ComboBox_GetCurSel(GetDlgItem(hwndDlg, ID_CMB_OTP_DIGITS)) == 1 ? 8 : 6;
                    settings.autofill = Button_GetCheck(GetDlgItem(hwndDlg, ID_CHK_OTP_AUTOFILL)) == BST_CHECKED;

                    swprintf_s(debug_buf, _countof(debug_buf),
                              L"OTP: Test with Secret length: %d, Algorithm: %d, Digits: %d\n",
                              (int)wcslen(settings.secret), settings.algorithm, settings.digits);
                    OutputDebugStringW(debug_buf);

                    /* Generate and display test code */
                    if (GenerateOTP(&settings, otp, _countof(otp)))
                    {
                        swprintf_s(debug_buf, _countof(debug_buf),
                                  L"OTP: Generated test code: %ls\n", otp);
                        OutputDebugStringW(debug_buf);
                        SetDlgItemTextW(hwndDlg, ID_TXT_TEST_OTP, otp);
                    }
                    else
                    {
                        OutputDebugStringW(L"OTP: Failed to generate test code\n");
                        SetDlgItemTextW(hwndDlg, ID_TXT_TEST_OTP, L"Error generating OTP");
                    }
                    break;
            }
            break;

        case WM_NOTIFY:
            psn = (LPPSHNOTIFY)lParam;
            if (psn->hdr.code == PSN_APPLY)
            {
                OutputDebugStringW(L"OTP: Save button clicked (PSN_APPLY received)\n");
                
                /* Get current settings from dialog */
                GetDlgItemTextW(hwndDlg, ID_EDT_OTP_SECRET, settings.secret, _countof(settings.secret));
                settings.algorithm = ComboBox_GetCurSel(GetDlgItem(hwndDlg, ID_CMB_OTP_ALGO));
                settings.digits = ComboBox_GetCurSel(GetDlgItem(hwndDlg, ID_CMB_OTP_DIGITS)) == 1 ? 8 : 6;
                settings.autofill = Button_GetCheck(GetDlgItem(hwndDlg, ID_CHK_OTP_AUTOFILL)) == BST_CHECKED;

                /* Log current dialog state */
                swprintf_s(debug_buf, _countof(debug_buf),
                          L"OTP: Current dialog state:\n  Secret length: %d\n  Algorithm: %d\n  Digits: %d\n  Autofill: %d\n",
                          (int)wcslen(settings.secret), settings.algorithm, settings.digits, settings.autofill);
                OutputDebugStringW(debug_buf);

                if (!SaveOTPSettings(NULL, &settings))
                {
                    DWORD error = GetLastError();
                    swprintf_s(debug_buf, _countof(debug_buf),
                              L"OTP: Failed to save settings - Last Error: %lu\n", error);
                    OutputDebugStringW(debug_buf);
                    MessageBoxW(hwndDlg, L"Failed to save OTP settings", L"Error", MB_OK | MB_ICONERROR);
                    SetWindowLongPtr(hwndDlg, DWLP_MSGRESULT, PSNRET_INVALID);
                    return TRUE;
                }
                OutputDebugStringW(L"OTP: Settings saved successfully\n");

                /* Update auth_pass_concat_otp based on autofill setting */
                SaveGlobalRegistryValueDWORD(L"auth_pass_concat_otp", settings.autofill);
                OutputDebugStringW(settings.autofill ? L"OTP: auth_pass_concat_otp enabled\n" : L"OTP: auth_pass_concat_otp disabled\n");

                /* Generate and display test code after saving */
                if (GenerateOTP(&settings, otp, _countof(otp)))
                {
                    SetDlgItemTextW(hwndDlg, ID_TXT_TEST_OTP, otp);
                }

                SetWindowLongPtr(hwndDlg, DWLP_MSGRESULT, PSNRET_NOERROR);
                return TRUE;
            }
            break;
    }
    return FALSE;
}

static BOOL
SaveGlobalRegistryValueDWORD(const WCHAR *name, DWORD value)
{
    HKEY regkey;
    DWORD status;
    WCHAR debug_buf[512];

    swprintf_s(debug_buf, _countof(debug_buf),
              L"OTP: Attempting to save global value %lu for key '%ls'\n",
              value, name);
    OutputDebugStringW(debug_buf);

    status = RegCreateKeyExW(HKEY_CURRENT_USER,
                           OTP_REGISTRY_KEY,
                           0,
                           NULL,
                           REG_OPTION_NON_VOLATILE,
                           KEY_WRITE,
                           NULL,
                           &regkey,
                           NULL);

    if (status != ERROR_SUCCESS)
    {
        swprintf_s(debug_buf, _countof(debug_buf),
                  L"OTP: Failed to open/create registry key - Error code: %lu\n",
                  status);
        OutputDebugStringW(debug_buf);
        SetLastError(status);
        return FALSE;
    }

    status = RegSetValueExW(regkey, name, 0, REG_DWORD, (BYTE *)&value, sizeof(value));
    RegCloseKey(regkey);

    if (status != ERROR_SUCCESS)
    {
        swprintf_s(debug_buf, _countof(debug_buf),
                  L"OTP: RegSetValueEx failed - Error code: %lu\n",
                  status);
        OutputDebugStringW(debug_buf);
        SetLastError(status);
        return FALSE;
    }

    OutputDebugStringW(L"OTP: Global value saved successfully\n");
    return TRUE;
}

static DWORD
GetGlobalRegistryValueDWORD(const WCHAR *name, DWORD default_value)
{
    HKEY regkey;
    DWORD value = default_value;
    DWORD len = sizeof(value);
    DWORD type = REG_DWORD;
    DWORD status;

    status = RegOpenKeyExW(HKEY_CURRENT_USER,
                         OTP_REGISTRY_KEY,
                         0,
                         KEY_READ,
                         &regkey);

    if (status != ERROR_SUCCESS)
        return default_value;

    if (RegQueryValueExW(regkey, name, NULL, &type, (BYTE *)&value, &len) != ERROR_SUCCESS
        || type != REG_DWORD)
        value = default_value;

    RegCloseKey(regkey);
    return value;
}

static BOOL
SaveGlobalRegistryValueBinary(const WCHAR *name, const BYTE *data, DWORD len)
{
    HKEY regkey;
    DWORD status;
    WCHAR debug_buf[512];

    swprintf_s(debug_buf, _countof(debug_buf),
              L"OTP: Attempting to save global binary data of length %lu for key '%ls'\n",
              len, name);
    OutputDebugStringW(debug_buf);

    status = RegCreateKeyExW(HKEY_CURRENT_USER,
                           OTP_REGISTRY_KEY,
                           0,
                           NULL,
                           REG_OPTION_NON_VOLATILE,
                           KEY_WRITE,
                           NULL,
                           &regkey,
                           NULL);

    if (status != ERROR_SUCCESS)
    {
        swprintf_s(debug_buf, _countof(debug_buf),
                  L"OTP: Failed to open/create registry key - Error code: %lu\n",
                  status);
        OutputDebugStringW(debug_buf);
        SetLastError(status);
        return FALSE;
    }

    status = RegSetValueExW(regkey, name, 0, REG_BINARY, data, len);
    RegCloseKey(regkey);

    if (status != ERROR_SUCCESS)
    {
        swprintf_s(debug_buf, _countof(debug_buf),
                  L"OTP: RegSetValueEx failed - Error code: %lu\n",
                  status);
        OutputDebugStringW(debug_buf);
        SetLastError(status);
        return FALSE;
    }

    OutputDebugStringW(L"OTP: Global binary data saved successfully\n");
    return TRUE;
}

static DWORD
GetGlobalRegistryValueBinary(const WCHAR *name, BYTE *data, DWORD len)
{
    HKEY regkey;
    DWORD type = REG_BINARY;
    DWORD status;

    status = RegOpenKeyExW(HKEY_CURRENT_USER,
                         OTP_REGISTRY_KEY,
                         0,
                         KEY_READ,
                         &regkey);

    if (status != ERROR_SUCCESS)
        return 0;

    if (RegQueryValueExW(regkey, name, NULL, &type, data, &len) != ERROR_SUCCESS
        || type != REG_BINARY)
        len = 0;

    RegCloseKey(regkey);
    return len;
}

BOOL
SaveOTPSettings(const WCHAR *config_name, const otp_settings_t *settings)
{
    WCHAR debug_buf[512];
    DWORD last_error;

    if (!settings)
    {
        OutputDebugStringW(L"OTP: SaveOTPSettings - NULL settings parameter\n");
        return FALSE;
    }

    OutputDebugStringW(L"OTP: SaveOTPSettings called\n");
    swprintf_s(debug_buf, _countof(debug_buf), 
               L"OTP: Settings to save - Secret length: %d\n  Algorithm: %d\n  Digits: %d\n  Autofill: %d\n",
               (int)wcslen(settings->secret), settings->algorithm, settings->digits, settings->autofill);
    OutputDebugStringW(debug_buf);

    /* Save encrypted secret */
    DWORD len = (wcslen(settings->secret) + 1) * sizeof(WCHAR);
    if (!SaveGlobalRegistryValueBinary(OTP_SECRET_DATA, (const BYTE *)settings->secret, len))
    {
        last_error = GetLastError();
        swprintf_s(debug_buf, _countof(debug_buf),
                  L"OTP: Failed to save secret - Error code: %lu\n", last_error);
        OutputDebugStringW(debug_buf);
        return FALSE;
    }
    OutputDebugStringW(L"OTP: Secret saved successfully\n");

    /* Save algorithm */
    if (!SaveGlobalRegistryValueDWORD(OTP_ALGO_DATA, settings->algorithm))
    {
        last_error = GetLastError();
        swprintf_s(debug_buf, _countof(debug_buf),
                  L"OTP: Failed to save algorithm - Error code: %lu\n", last_error);
        OutputDebugStringW(debug_buf);
        return FALSE;
    }
    OutputDebugStringW(L"OTP: Algorithm saved successfully\n");

    /* Save digits */
    if (!SaveGlobalRegistryValueDWORD(OTP_DIGITS_DATA, settings->digits))
    {
        last_error = GetLastError();
        swprintf_s(debug_buf, _countof(debug_buf),
                  L"OTP: Failed to save digits - Error code: %lu\n", last_error);
        OutputDebugStringW(debug_buf);
        return FALSE;
    }
    OutputDebugStringW(L"OTP: Digits saved successfully\n");

    /* Save autofill */
    OutputDebugStringW(L"OTP: Attempting to save autofill setting\n");
    if (!SaveGlobalRegistryValueDWORD(OTP_AUTOFILL_DATA, settings->autofill))
    {
        last_error = GetLastError();
        swprintf_s(debug_buf, _countof(debug_buf),
                  L"OTP: Failed to save autofill - Error code: %lu\n", last_error);
        OutputDebugStringW(debug_buf);
        return FALSE;
    }
    OutputDebugStringW(L"OTP: Autofill saved successfully\n");

    /* Update auth_pass_concat_otp based on autofill setting */
    if (settings->autofill)
    {
        OutputDebugStringW(L"OTP: Attempting to save auth_pass_concat_otp setting\n");
        if (!SaveGlobalRegistryValueDWORD(L"auth_pass_concat_otp", TRUE))
        {
            last_error = GetLastError();
            swprintf_s(debug_buf, _countof(debug_buf),
                      L"OTP: Failed to save auth_pass_concat_otp - Error code: %lu\n", last_error);
            OutputDebugStringW(debug_buf);
            return FALSE;
        }
        OutputDebugStringW(L"OTP: auth_pass_concat_otp enabled and saved\n");
    }

    OutputDebugStringW(L"OTP: All settings saved successfully\n");
    return TRUE;
}

BOOL
LoadOTPSettings(const WCHAR *config_name, otp_settings_t *settings)
{
    DWORD len = sizeof(settings->secret);
    WCHAR debug_buf[256];
    
    OutputDebugStringW(L"OTP: LoadOTPSettings called\n");

    /* Load secret */
    len = GetGlobalRegistryValueBinary(OTP_SECRET_DATA, (BYTE *)settings->secret, len);
    if (len == 0)
    {
        OutputDebugStringW(L"OTP: Failed to load secret\n");
        return FALSE;
    }

    /* Ensure proper null termination */
    settings->secret[_countof(settings->secret) - 1] = L'\0';

    /* Load other settings with defaults */
    settings->algorithm = GetGlobalRegistryValueDWORD(OTP_ALGO_DATA, OTP_ALGO_TOTP);
    settings->digits = GetGlobalRegistryValueDWORD(OTP_DIGITS_DATA, 6);
    settings->autofill = GetGlobalRegistryValueDWORD(OTP_AUTOFILL_DATA, FALSE);

    swprintf_s(debug_buf, _countof(debug_buf), 
               L"OTP: Loaded settings - Algorithm: %d, Digits: %d, Autofill: %d\n",
               settings->algorithm, settings->digits, settings->autofill);
    OutputDebugStringW(debug_buf);

    return TRUE;
}

/* Helper function to convert Base32 string to bytes */
static BOOL base32_decode(const WCHAR *base32, BYTE *bin, size_t *bin_len)
{
    static const BYTE decode_table[256] = {
        80, 80, 80, 80, 80, 80, 80, 80, 80, 80, 80, 80, 80, 80, 80, 80,  /* 0-15 */
        80, 80, 80, 80, 80, 80, 80, 80, 80, 80, 80, 80, 80, 80, 80, 80,  /* 16-31 */
        80, 80, 80, 80, 80, 80, 80, 80, 80, 80, 80, 80, 80, 80, 80, 80,  /* 32-47 */
        80, 80, 26, 27, 28, 29, 30, 31, 80, 80, 80, 80, 80, 80, 80, 80,  /* 48-63 */
        80,  0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14,  /* 64-79 */
        15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 80, 80, 80, 80, 80,  /* 80-95 */
        80,  0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14,  /* 96-111 */
        15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 80, 80, 80, 80, 80   /* 112-127 */
    };

    size_t base32_len = wcslen(base32);
    size_t pad_count = 0;
    BYTE buffer[8] = {0};
    size_t buffer_size = 0;
    size_t out_pos = 0;

    /* Remove padding characters */
    while (base32_len > 0 && base32[base32_len - 1] == L'=') {
        pad_count++;
        base32_len--;
    }

    /* Process input 8 characters at a time */
    for (size_t i = 0; i < base32_len; i++) {
        WCHAR c = base32[i];
        if (c >= 128 || decode_table[c] == 80) {
            return FALSE;  /* Invalid character */
        }

        buffer[buffer_size++] = decode_table[c];

        if (buffer_size == 8) {
            /* Convert 8 base32 characters to 5 bytes */
            if (out_pos + 5 > *bin_len) {
                return FALSE;  /* Output buffer too small */
            }

            bin[out_pos++] = (buffer[0] << 3) | (buffer[1] >> 2);
            bin[out_pos++] = (buffer[1] << 6) | (buffer[2] << 1) | (buffer[3] >> 4);
            bin[out_pos++] = (buffer[3] << 4) | (buffer[4] >> 1);
            bin[out_pos++] = (buffer[4] << 7) | (buffer[5] << 2) | (buffer[6] >> 3);
            bin[out_pos++] = (buffer[6] << 5) | buffer[7];

            buffer_size = 0;
        }
    }

    /* Handle remaining bytes based on padding */
    if (buffer_size > 0) {
        if (buffer_size == 2) {
            bin[out_pos++] = (buffer[0] << 3) | (buffer[1] >> 2);
        } else if (buffer_size == 4) {
            bin[out_pos++] = (buffer[0] << 3) | (buffer[1] >> 2);
            bin[out_pos++] = (buffer[1] << 6) | (buffer[2] << 1) | (buffer[3] >> 4);
        } else if (buffer_size == 5) {
            bin[out_pos++] = (buffer[0] << 3) | (buffer[1] >> 2);
            bin[out_pos++] = (buffer[1] << 6) | (buffer[2] << 1) | (buffer[3] >> 4);
            bin[out_pos++] = (buffer[3] << 4) | (buffer[4] >> 1);
        } else if (buffer_size == 7) {
            bin[out_pos++] = (buffer[0] << 3) | (buffer[1] >> 2);
            bin[out_pos++] = (buffer[1] << 6) | (buffer[2] << 1) | (buffer[3] >> 4);
            bin[out_pos++] = (buffer[3] << 4) | (buffer[4] >> 1);
            bin[out_pos++] = (buffer[4] << 7) | (buffer[5] << 2) | (buffer[6] >> 3);
        }
    }

    *bin_len = out_pos;
    return TRUE;
}

/* HMAC-SHA1 implementation */
#define SHA1_BLOCK_SIZE 64
#define SHA1_DIGEST_SIZE 20

static void hmac_sha1(const BYTE *key, size_t key_len,
                     const BYTE *data, size_t data_len,
                     BYTE *digest)
{
    HCRYPTPROV hProv = 0;
    HCRYPTHASH hHash = 0;
    BYTE k_ipad[SHA1_BLOCK_SIZE];
    BYTE k_opad[SHA1_BLOCK_SIZE];
    BYTE tk[SHA1_DIGEST_SIZE];
    BYTE inner_digest[SHA1_DIGEST_SIZE];
    DWORD hash_len = SHA1_DIGEST_SIZE;
    int i;

    /* If key is longer than block size, hash it */
    if (key_len > SHA1_BLOCK_SIZE) {
        CryptAcquireContext(&hProv, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT);
        CryptCreateHash(hProv, CALG_SHA1, 0, 0, &hHash);
        CryptHashData(hHash, key, (DWORD)key_len, 0);
        CryptGetHashParam(hHash, HP_HASHVAL, tk, &hash_len, 0);
        CryptDestroyHash(hHash);
        CryptReleaseContext(hProv, 0);
        key = tk;
        key_len = SHA1_DIGEST_SIZE;
    }

    /* Create padded keys */
    ZeroMemory(k_ipad, sizeof(k_ipad));
    ZeroMemory(k_opad, sizeof(k_opad));
    memcpy(k_ipad, key, key_len);
    memcpy(k_opad, key, key_len);

    /* XOR keys with ipad and opad values */
    for (i = 0; i < SHA1_BLOCK_SIZE; i++) {
        k_ipad[i] ^= 0x36;
        k_opad[i] ^= 0x5c;
    }

    /* Perform inner SHA1 */
    CryptAcquireContext(&hProv, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT);
    CryptCreateHash(hProv, CALG_SHA1, 0, 0, &hHash);
    CryptHashData(hHash, k_ipad, SHA1_BLOCK_SIZE, 0);
    CryptHashData(hHash, data, (DWORD)data_len, 0);
    CryptGetHashParam(hHash, HP_HASHVAL, inner_digest, &hash_len, 0);
    CryptDestroyHash(hHash);

    /* Perform outer SHA1 */
    CryptCreateHash(hProv, CALG_SHA1, 0, 0, &hHash);
    CryptHashData(hHash, k_opad, SHA1_BLOCK_SIZE, 0);
    CryptHashData(hHash, inner_digest, SHA1_DIGEST_SIZE, 0);
    CryptGetHashParam(hHash, HP_HASHVAL, digest, &hash_len, 0);
    CryptDestroyHash(hHash);
    CryptReleaseContext(hProv, 0);
}

BOOL
GenerateOTP(otp_settings_t *settings, WCHAR *otp, size_t otp_size)
{
    BYTE secret_bin[64];
    size_t secret_bin_len = sizeof(secret_bin);
    BYTE hmac[20];
    BOOL result = FALSE;
    WCHAR debug_buf[512];

    /* Check input parameters */
    if (!settings || !settings->secret[0]) {
        OutputDebugStringW(L"OTP: Error - Empty secret key\n");
        goto cleanup;
    }

    swprintf_s(debug_buf, _countof(debug_buf), 
               L"OTP: Starting generation with secret length: %d, Algorithm: %d, Digits: %d\n", 
               (int)wcslen(settings->secret), settings->algorithm, settings->digits);
    OutputDebugStringW(debug_buf);

    /* Convert Base32 secret to binary */
    if (!base32_decode(settings->secret, secret_bin, &secret_bin_len)) {
        OutputDebugStringW(L"OTP: Base32 decoding failed\n");
        goto cleanup;
    }
    swprintf_s(debug_buf, _countof(debug_buf), L"OTP: Base32 decoded successfully, length: %d\n", (int)secret_bin_len);
    OutputDebugStringW(debug_buf);

    /* Generate counter/time value */
    DWORD counter;
    if (settings->algorithm == OTP_ALGO_TOTP)
    {
        time_t now = time(NULL);
        counter = (DWORD)(now / 30);  // 30-second intervals
        swprintf_s(debug_buf, _countof(debug_buf), 
                  L"OTP: Using TOTP with counter: %lu (time: %I64d)\n", 
                  counter, (INT64)now);
        OutputDebugStringW(debug_buf);
    }
    else
    {
        // For HOTP, we should maintain a counter in the registry
        connection_t *c = GetConnByName(o.chead->config_name);
        if (!c) {
            OutputDebugStringW(L"OTP: Failed to get connection\n");
            goto cleanup;
        }
            
        counter = GetConfigRegistryValueDWORD(c->config_name, L"hotp_counter", 0);
        counter++;
        if (!SetConfigRegistryValueDWORD(c->config_name, L"hotp_counter", counter)) {
            OutputDebugStringW(L"OTP: Failed to update HOTP counter\n");
            goto cleanup;
        }
        swprintf_s(debug_buf, _countof(debug_buf), L"OTP: Using HOTP with counter: %lu\n", counter);
        OutputDebugStringW(debug_buf);
    }

    /* Convert counter to big-endian bytes */
    BYTE counter_bytes[8] = {0};
    for (int i = 7; i >= 0; i--)
    {
        counter_bytes[i] = counter & 0xFF;
        counter >>= 8;
    }

    /* Calculate HMAC-SHA1 */
    hmac_sha1(secret_bin, secret_bin_len, counter_bytes, sizeof(counter_bytes), hmac);
    OutputDebugStringW(L"OTP: HMAC-SHA1 calculation completed\n");

    /* Dynamic Truncation */
    int offset = hmac[19] & 0xf;
    int bin_code = ((hmac[offset] & 0x7f) << 24) |
                   ((hmac[offset+1] & 0xff) << 16) |
                   ((hmac[offset+2] & 0xff) << 8) |
                   (hmac[offset+3] & 0xff);

    /* Convert to string with modulus */
    int mod = settings->digits == 8 ? 100000000 : 1000000;
    bin_code %= mod;
    swprintf_s(otp, otp_size, settings->digits == 8 ? L"%08d" : L"%06d", bin_code);
    swprintf_s(debug_buf, _countof(debug_buf), L"OTP: Generated code: %s\n", otp);
    OutputDebugStringW(debug_buf);

    result = TRUE;

cleanup:
    swprintf_s(debug_buf, _countof(debug_buf), L"OTP: Generation %s\n", result ? L"succeeded" : L"failed");
    OutputDebugStringW(debug_buf);
    return result;
} 