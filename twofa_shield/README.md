# 2FA Shield - Force Two-Factor Authentication for Odoo

Odoo 17 / 18 / 19. License OPL-1.

## Install
1. Uninstall any previous forced-2FA module (e.g. `kw_2fa`).
2. Copy `mfa_guard` (and `twofa_shield_hr` for department policies) into your addons path, restart Odoo.
3. Apps > Update Apps List > install **2FA Shield** (`twofa_shield_hr` installs itself when HR is present).
4. Settings > 2FA Shield > set **2FA enforcement** to *Enabled*.

Requires the Python package `qrcode` (already required by Odoo's `auth_totp`).

## Emergency switch (admin locked out)
```sql
UPDATE ir_config_parameter SET value = 'off' WHERE key = 'twofa_shield.mode';
```
then restart Odoo (or clear the cache). A single user can be released with:
```sql
UPDATE res_users SET mfa_guard_override = 'exempt' WHERE login = 'someone';
```

## How it works
* Hooks into Odoo's native `_mfa_url()` step, so it works after password AND after OAuth/SSO sign-in.
* Not enrolled + required -> `/twofa_shield/setup` (QR code). Enrolled -> standard Odoo code page.
* An enrolled account can never be re-enrolled from the setup page; only an administrator can reset it.
* The secret is saved before the redirect and nothing raises after the write (no rollback).
