{
    'name': '2FA Shield - HR Departments',
    'version': '18.0.1.0.0',
    'category': 'Tools',
    'summary': 'Bridge: enforce 2FA by HR department (auto-installed with 2FA Shield + HR).',
    'author': 'Your Company',
    'website': 'https://www.example.com',
    'license': 'OPL-1',
    'depends': ['twofa_shield', 'hr'],
    'data': ['views/policy_views.xml'],
    'auto_install': True,
    'installable': True,
    'application': False,
}
