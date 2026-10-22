from datetime import timedelta

from odoo import SUPERUSER_ID, _, api, fields, models
from odoo.exceptions import UserError


class MfaGuardInviteWizard(models.TransientModel):
    _name = 'mfa.guard.invite.wizard'
    _description = 'Send 2FA invitation'

    target = fields.Selection([
        ('selected', 'Selected users'),
        ('pending', 'Everybody who must enable 2FA but has not yet'),
        ('internal', 'All internal users'),
        ('all', 'All users (internal + portal)'),
    ], string='Send to', required=True, default='selected')
    user_ids = fields.Many2many(
        'res.users', 'mfa_guard_invite_wiz_user_rel', 'wizard_id', 'user_id', string='Users')
    only_pending = fields.Boolean(
        string='Skip users who already enabled 2FA', default=True)
    force = fields.Boolean(
        string='Force 2FA for these users', default=True,
        help='Sets the user override to "Force 2FA", whatever the policies say.')
    deadline_days = fields.Integer(
        string='Days to comply', default=7,
        help='During this period users may postpone enrolment. 0 = must enrol at next login.')
    send_email = fields.Boolean(string='Send e-mail', default=True)
    message = fields.Text(string='Personal message')
    mode_off = fields.Boolean(compute='_compute_mode_off')
    user_count = fields.Integer(string='Users concerned', compute='_compute_user_count')

    @api.model
    def default_get(self, fields_list):
        res = super().default_get(fields_list)
        ctx = self.env.context
        if ctx.get('active_model') == 'res.users' and ctx.get('active_ids'):
            res['user_ids'] = [(6, 0, ctx['active_ids'])]
            res['target'] = 'selected'
        elif 'target' in fields_list and not ctx.get('default_target'):
            res['target'] = 'pending'
        return res

    def _compute_mode_off(self):
        off = not self.env['res.users']._mfa_guard_enabled()
        for wiz in self:
            wiz.mode_off = off

    @api.depends('target', 'user_ids', 'only_pending')
    def _compute_user_count(self):
        for wiz in self:
            wiz.user_count = len(wiz._get_users())

    def _get_users(self):
        self.ensure_one()
        Users = self.env['res.users'].sudo()
        if self.target == 'selected':
            users = self.user_ids.sudo()
        elif self.target == 'pending':
            policies = self.env['mfa.guard.policy'].sudo().search([])
            users = Users.search([]).filtered(
                lambda u: u._mfa_guard_status_value(policies) == 'pending')
        elif self.target == 'internal':
            users = Users.search([('share', '=', False)])
        else:
            users = Users.search([])
        users = users.filtered(lambda u: u.id != SUPERUSER_ID and u.active)
        if self.only_pending:
            users = users.filtered(lambda u: not u.totp_enabled)
        return users

    def action_send(self):
        self.ensure_one()
        self.env['res.users']._mfa_guard_check_admin()
        users = self._get_users()
        if not users:
            raise UserError(_('No user matches your selection.'))
        now = fields.Datetime.now()
        vals = {'mfa_guard_deadline': now + timedelta(days=max(self.deadline_days, 0)),
                'mfa_guard_last_reminder': now}
        if self.force:
            vals['mfa_guard_override'] = 'force'
        users.write(vals)
        Log = self.env['mfa.guard.log']
        if self.force:
            Log._log(users, 'forced', _('Forced from the invitation wizard'))
        sent = 0
        if self.send_email:
            ctx = {'mfa_message': self.message or ''}
            if self.deadline_days > 0:
                ctx['mfa_deadline'] = fields.Date.to_string(vals['mfa_guard_deadline'])
            sent = users._mfa_guard_send_mail('twofa_shield.mail_template_invite', **ctx)
        Log._log(users, 'invite', _('E-mail sent: %s', bool(self.send_email)))
        missing = len(users.filtered(lambda u: not u.email))
        message = _('%(users)s user(s) updated, %(sent)s e-mail(s) queued.', users=len(users), sent=sent)
        if self.send_email and missing:
            message += ' ' + _('%s user(s) have no e-mail address.', missing)
        return {
            'type': 'ir.actions.client',
            'tag': 'display_notification',
            'params': {
                'title': _('2FA invitation'),
                'message': message,
                'type': 'success' if not missing else 'warning',
                'sticky': False,
                'next': {'type': 'ir.actions.act_window_close'},
            },
        }
