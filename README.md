# Odoo 2FA Shield

**Professional Two-Factor Authentication and Account Security for Odoo**

Odoo 2FA Shield strengthens Odoo account security through configurable multi-factor authentication (MFA) enforcement, authenticator applications, administrative recovery, user enrollment management, and security auditing.

## Features

- Configurable MFA enforcement
- User, group, department, and account-type policies
- TOTP authenticator support
- Administrative MFA resets and recovery workflows
- Recovery codes
- Email invitations and reminders
- Security audit logging
- User self-service enrollment
- Optional HR integration

## Compatibility

- Odoo 17.0
- Odoo 18.0
- Odoo 19.0

Each version is maintained on its own Git branch.

## Pricing

Target Odoo Apps Store price: **$42 USD**

## Repository Structure

- `main`: Odoo 18.0 source code, project documentation, and release ZIP packages.
- `17.0`: Odoo 17.0 module source code.
- `18.0`: Odoo 18.0 module source code.
- `19.0`: Odoo 19.0 module source code and release archives.

The root directory contains the `twofa_shield` module and the optional `twofa_shield_hr` integration.

## Publisher

- **Company:** Misterinfo Maroc
- **Developer:** Abdechakour Hrouchan
- **Website:** https://misterinfo.ma/
- **Support:** contact@misterinfo.ma

## Installation

Download the ZIP package matching your Odoo version, extract it into your custom addons directory, update the Apps List, and install the module.

**Important:** Test on a staging database before production deployment. Validate compatibility and security on each supported Odoo version.

## License

Odoo Proprietary License (OPL-1). Refer to the module's license terms before redistribution or commercial use.