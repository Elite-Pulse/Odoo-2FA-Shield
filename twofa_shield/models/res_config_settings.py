from odoo import _, fields, models


class ResConfigSettings(models.TransientModel):
    _inherit = 'res.config.settings'

    mfa_guard_mode = fields.Selection([
        ('off', 'Disabled - behave like standard Odoo'),
        ('enforce', 'Enabled - enforce the policies below'),
    ], string='2FA Enforcement', config_parameter='twofa_shield.mode', default='off')
    mfa_guard_grace_days = fields.Integer(
        string='Grace Period (days)', config_parameter='twofa_shield.grace_days', default=0,
        help='Days a user may postpone enrolment ("Remind me later"). 0 = enrol immediately.')
    mfa_guard_trust_sso = fields.Boolean(
        string='Trust SSO (OAuth / Azure)', config_parameter='twofa_shield.trust_sso',
        help='Users who signed in through an OAuth provider (Microsoft Azure, Google...) are not '
             'asked for an Odoo 2FA code: the provider is trusted to do MFA itself.')
    mfa_guard_allow_remember = fields.Boolean(
        string='Allow "Remember this device"', config_parameter='twofa_shield.allow_remember',
        help='Let users skip the code for 30 days on a trusted browser (standard Odoo option).')
    mfa_guard_no_recovery = fields.Boolean(
        string='Disable recovery codes', config_parameter='twofa_shield.no_recovery')
    mfa_guard_no_notice = fields.Boolean(
        string='No security e-mails to users', config_parameter='twofa_shield.no_notice',
        help='Do not e-mail users when their 2FA is enabled or reset.')
    mfa_guard_no_reminders = fields.Boolean(
        string='Disable automatic reminders', config_parameter='twofa_shield.no_reminders')
    mfa_guard_reminder_days = fields.Integer(
        string='Reminder Every (days)', config_parameter='twofa_shield.reminder_days', default=3)
    mfa_guard_log_retention = fields.Integer(
        string='Keep Audit Log (days)', config_parameter='twofa_shield.log_retention', default=365)
    mfa_guard_issuer = fields.Char(
        string='Name Shown in Authenticator App', config_parameter='twofa_shield.issuer',
        help='Defaults to the user company name.')

    def set_values(self):
        old = self.env['res.users']._mfa_guard_param('mode', 'off')
        res = super().set_values()
        new = self.mfa_guard_mode or 'off'
        if old != new:
            self.env['mfa.guard.log']._log(
                self.env['res.users'], 'mode',
                _('Enforcement switched from %(old)s to %(new)s', old=old, new=new))
        return res
