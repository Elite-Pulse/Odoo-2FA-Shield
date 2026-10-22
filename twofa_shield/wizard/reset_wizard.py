from datetime import timedelta

from odoo import _, fields, models
from odoo.exceptions import UserError


class MfaGuardResetWizard(models.TransientModel):
    _name = 'mfa.guard.reset.wizard'
    _description = 'Reset 2FA / Recovery access'

    user_ids = fields.Many2many(
        'res.users', 'mfa_guard_reset_wiz_user_rel', 'wizard_id', 'user_id',
        string='Users', required=True)
    reset_totp = fields.Boolean(
        string='Reset 2FA (delete secret, trusted devices and recovery codes)', default=True,
        help='The user will have to enrol a new authenticator at next login '
             'if 2FA is mandatory for him.')
    bypass_hours = fields.Integer(
        string='Allow sign-in without 2FA for (hours)', default=0,
        help='Emergency window: the user can sign in with password/SSO only. 0 = no bypass.')
    exempt = fields.Boolean(
        string='Exempt permanently from 2FA',
        help='Use for emergency / local accounts. Can be reverted from the user form.')
    send_password_reset = fields.Boolean(
        string='Send password reset e-mail',
        help='Lets a user who lost his SSO (e.g. Azure) account create a local password.')
    notify_user = fields.Boolean(string='Notify the user by e-mail', default=True)

    def action_apply(self):
        self.ensure_one()
        Users = self.env['res.users']
        Users._mfa_guard_check_admin()
        users = self.user_ids.sudo()
        if not users:
            raise UserError(_('Select at least one user.'))
        Log = self.env['mfa.guard.log']
        notes = []
        if self.reset_totp:
            users._mfa_guard_do_reset(_('Reset from the recovery wizard'))
            notes.append(_('2FA reset'))
        if self.bypass_hours > 0:
            until = fields.Datetime.now() + timedelta(hours=self.bypass_hours)
            users.write({'mfa_guard_bypass_until': until})
            Log._log(users, 'bypass', _('Until %s UTC', until))
            notes.append(_('bypass for %s h', self.bypass_hours))
        if self.exempt:
            users.write({'mfa_guard_override': 'exempt'})
            Log._log(users, 'exempt')
            notes.append(_('exempted'))
        failed = []
        if self.send_password_reset:
            for user in users:
                try:
                    user.action_reset_password()
                except UserError:
                    failed.append(user.login)
            notes.append(_('password reset e-mail'))
        if self.notify_user and not Users._mfa_guard_param('no_notice'):
            users._mfa_guard_send_mail(
                'twofa_shield.mail_template_notice',
                mfa_title=_('Your two-factor authentication was updated'),
                mfa_text=_('An administrator has updated the two-factor authentication settings '
                           'of your account (%s). You may be asked to set up 2FA again at your '
                           'next sign-in.', ', '.join(notes) or '-'))
        message = _('Done: %s.', ', '.join(notes) or '-')
        if failed:
            message += ' ' + _('No e-mail address for: %s.', ', '.join(failed))
        return {
            'type': 'ir.actions.client',
            'tag': 'display_notification',
            'params': {
                'title': _('2FA recovery'),
                'message': message,
                'type': 'warning' if failed else 'success',
                'sticky': False,
                'next': {'type': 'ir.actions.act_window_close'},
            },
        }
