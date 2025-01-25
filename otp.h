#ifndef OTP_H
#define OTP_H

#include <windows.h>
#include <tchar.h>

/* OTP algorithms */
#define OTP_ALGO_TOTP 0
#define OTP_ALGO_HOTP 1

/* OTP settings */
typedef struct {
    WCHAR secret[128];
    int algorithm;
    int digits;
    BOOL autofill;
} otp_settings_t;

/* Function declarations */
INT_PTR CALLBACK OTPSettingsDlgProc(HWND hwndDlg, UINT msg, WPARAM wParam, LPARAM lParam);
BOOL SaveOTPSettings(const WCHAR *config_name, const otp_settings_t *settings);
BOOL LoadOTPSettings(const WCHAR *config_name, otp_settings_t *settings);
BOOL GenerateOTP(otp_settings_t *settings, WCHAR *otp, size_t otp_size);

#endif /* OTP_H */ 