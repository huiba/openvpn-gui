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
#endif

static void
LoadOTPDlgParams(HWND hwndDlg)
{
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
    connection_t *c = GetConnByName(o.chead->config_name);
    if (c && LoadOTPSettings(c->config_name, &settings))
    {
        SetDlgItemTextW(hwndDlg, ID_EDT_OTP_SECRET, settings.secret);
        ComboBox_SetCurSel(hwndAlgo, settings.algorithm);
        ComboBox_SetCurSel(hwndDigits, settings.digits == 8 ? 1 : 0);
        Button_SetCheck(GetDlgItem(hwndDlg, ID_CHK_OTP_AUTOFILL), 
                       settings.autofill ? BST_CHECKED : BST_UNCHECKED);
    }
}

INT_PTR CALLBACK
OTPSettingsDlgProc(HWND hwndDlg, UINT msg, WPARAM wParam, LPARAM lParam)
{
    LPPSHNOTIFY psn;
    otp_settings_t settings;
    connection_t *c;

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
            }
            break;

        case WM_NOTIFY:
            psn = (LPPSHNOTIFY)lParam;
            if (psn->hdr.code == PSN_APPLY)
            {
                /* Save settings */
                GetDlgItemTextW(hwndDlg, ID_EDT_OTP_SECRET, settings.secret, _countof(settings.secret));
                settings.algorithm = ComboBox_GetCurSel(GetDlgItem(hwndDlg, ID_CMB_OTP_ALGO));
                settings.digits = ComboBox_GetCurSel(GetDlgItem(hwndDlg, ID_CMB_OTP_DIGITS)) == 1 ? 8 : 6;
                settings.autofill = Button_GetCheck(GetDlgItem(hwndDlg, ID_CHK_OTP_AUTOFILL)) == BST_CHECKED;

                c = GetConnByName(o.chead->config_name);
                if (c)
                {
                    SaveOTPSettings(c->config_name, &settings);
                }
                return TRUE;
            }
            break;
    }
    return FALSE;
}

BOOL
SaveOTPSettings(const WCHAR *config_name, const otp_settings_t *settings)
{
    /* Save encrypted secret */
    DWORD len = (wcslen(settings->secret) + 1) * sizeof(WCHAR);
    if (!SetConfigRegistryValueBinary(config_name, OTP_SECRET_DATA, (BYTE *)settings->secret, len))
        return FALSE;

    /* Save other settings */
    if (!SetConfigRegistryValueDWORD(config_name, OTP_ALGO_DATA, settings->algorithm))
        return FALSE;
    if (!SetConfigRegistryValueDWORD(config_name, OTP_DIGITS_DATA, settings->digits))
        return FALSE;
    if (!SetConfigRegistryValueDWORD(config_name, OTP_AUTOFILL_DATA, settings->autofill))
        return FALSE;

    return TRUE;
}

BOOL
LoadOTPSettings(const WCHAR *config_name, otp_settings_t *settings)
{
    DWORD len = sizeof(settings->secret);
    
    /* Load secret */
    if (!GetConfigRegistryValue(config_name, OTP_SECRET_DATA, (BYTE *)settings->secret, len))
        return FALSE;

    /* Load other settings with defaults */
    settings->algorithm = GetConfigRegistryValueDWORD(config_name, OTP_ALGO_DATA, OTP_ALGO_TOTP);
    settings->digits = GetConfigRegistryValueDWORD(config_name, OTP_DIGITS_DATA, 6);
    settings->autofill = GetConfigRegistryValueDWORD(config_name, OTP_AUTOFILL_DATA, FALSE);

    return TRUE;
}

/* Helper function to convert hex string to bytes */
static BOOL hex2bin(const WCHAR *hex, BYTE *bin, size_t *bin_len);

/* Helper function to convert hex string to bytes */
static BOOL
hex2bin(const WCHAR *hex, BYTE *bin, size_t *bin_len)
{
    size_t hex_len = wcslen(hex);
    if (hex_len % 2 != 0 || hex_len/2 > *bin_len)
        return FALSE;

    *bin_len = hex_len/2;
    for (size_t i = 0; i < hex_len; i += 2)
    {
        WCHAR hex_byte[3] = {hex[i], hex[i+1], 0};
        bin[i/2] = (BYTE)wcstoul(hex_byte, NULL, 16);
    }
    return TRUE;
}

BOOL
GenerateOTP(WCHAR *otp, size_t otp_size)
{
    otp_settings_t settings;
    connection_t *c = GetConnByName(o.chead->config_name);
    if (!c || !LoadOTPSettings(c->config_name, &settings))
    {
        return FALSE;
    }

    BYTE secret_bin[64];
    size_t secret_bin_len = sizeof(secret_bin);
    BYTE hmac[20];
    DWORD hmac_len = sizeof(hmac);
    HCRYPTPROV hProv = 0;
    HCRYPTHASH hHash = 0;
    HCRYPTKEY hKey = 0;
    BOOL result = FALSE;

    /* Convert hex secret to binary */
    if (!hex2bin(settings.secret, secret_bin, &secret_bin_len))
        goto cleanup;

    /* Get crypto provider */
    if (!CryptAcquireContext(&hProv, NULL, MS_ENHANCED_PROV, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT))
        goto cleanup;

    /* Create hash object */
    if (!CryptCreateHash(hProv, CALG_HMAC, 0, 0, &hHash))
        goto cleanup;

    /* Set hash parameters */
    HMAC_INFO hmacInfo;
    ZeroMemory(&hmacInfo, sizeof(hmacInfo));
    hmacInfo.HashAlgid = CALG_SHA1;
    if (!CryptSetHashParam(hHash, HP_HMAC_INFO, (BYTE*)&hmacInfo, 0))
        goto cleanup;

    /* Set the key */
    if (!CryptSetHashParam(hHash, HP_HASHVAL, secret_bin, 0))
        goto cleanup;

    /* Generate counter/time value */
    DWORD counter;
    if (settings.algorithm == OTP_ALGO_TOTP)
    {
        time_t now = time(NULL);
        counter = (DWORD)(now / 30);  // 30-second intervals
    }
    else
    {
        // For HOTP, we should maintain a counter in the registry
        counter = GetConfigRegistryValueDWORD(c->config_name, L"hotp_counter", 0);
        counter++;
        SetConfigRegistryValueDWORD(c->config_name, L"hotp_counter", counter);
    }

    /* Convert counter to big-endian bytes */
    BYTE counter_bytes[8];
    for (int i = 7; i >= 0; i--)
    {
        counter_bytes[i] = counter & 0xFF;
        counter >>= 8;
    }

    /* Calculate HMAC */
    if (!CryptHashData(hHash, counter_bytes, sizeof(counter_bytes), 0))
        goto cleanup;

    if (!CryptGetHashParam(hHash, HP_HASHVAL, hmac, &hmac_len, 0))
        goto cleanup;

    /* Get offset */
    int offset = hmac[19] & 0xf;

    /* Generate OTP */
    int bin_code = ((hmac[offset] & 0x7f) << 24) |
                   ((hmac[offset+1] & 0xff) << 16) |
                   ((hmac[offset+2] & 0xff) << 8) |
                   (hmac[offset+3] & 0xff);

    /* Convert to string */
    int mod = settings.digits == 8 ? 100000000 : 1000000;
    bin_code %= mod;
    swprintf_s(otp, otp_size, settings.digits == 8 ? L"%08d" : L"%06d", bin_code);

    result = TRUE;

cleanup:
    if (hHash)
        CryptDestroyHash(hHash);
    if (hKey)
        CryptDestroyKey(hKey);
    if (hProv)
        CryptReleaseContext(hProv, 0);

    return result;
} 