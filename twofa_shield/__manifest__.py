{
    'name': '2FA Shield - Force Two-Factor Authentication for All Users',
    'version': '18.0.1.0.0',
    'category': 'Tools',
    'summary': 'Make 2FA mandatory in Odoo: choose who, reset lost devices, work with Microsoft Azure / SSO, '
               'recovery codes, e-mail invitations and audit log.',
    'description': """
2FA Shield
=========
Professional two-factor authentication enforcement for Odoo.

* Enable / disable enforcement from Settings, no uninstall needed
* Policies: everybody, internal, portal, access groups, companies, specific users
  (and departments with the bundled twofa_shield_hr bridge)
* Per-user override: force or exempt
* Works with password login AND SSO (Microsoft Azure, Google, any OAuth)
* Admin reset / emergency bypass / local-account recovery wizard
* One-time recovery codes (hashed), grace period, automatic reminders
* Invitation e-mails to one, many or all users
* Full audit log
""",
    'author': 'Your Company',
    'website': 'https://www.example.com',
    'support': 'support@example.com',
    'license': 'OPL-1',
    'price': 42.00,
    'currency': 'USD',
    'depends': ['base', 'web', 'mail', 'auth_signup', 'auth_totp'],
    'external_dependencies': {'python': ['qrcode']},
    'data': [
        'security/ir.model.access.csv',
        'data/policy_data.xml',
        'data/mail_templates.xml',
        'data/ir_cron.xml',
        'views/policy_views.xml',
        'views/user_views.xml',
        'wizard/wizard_views.xml',
        'views/log_views.xml',
        'views/settings_views.xml',
        'views/menus.xml',
        'views/templates.xml',
    ],
    'images': ['static/description/banner.png'],
    'post_init_hook': 'post_init_hook',
    'application': True,
    'installable': True,
    'auto_install': False,
}
