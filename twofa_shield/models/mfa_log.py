from datetime import timedelta

from odoo import api, fields, models
from odoo.http import request


class MfaGuardLog(models.Model):
    _name = 'mfa.guard.log'
    _description = '2FA Shield Audit Log'
    _order = 'create_date desc, id desc'

    user_id = fields.Many2one('res.users', string='User', ondelete='set null', index=True)
    login = fields.Char(string='Login', index=True)
    event = fields.Selection([
        ('enrolled', '2FA enabled'),
        ('enroll_failed', 'Enrolment failed'),
        ('reset', '2FA reset'),
        ('disabled', '2FA disabled'),
        ('bypass', 'Temporary bypass'),
        ('exempt', 'Exempted'),
        ('forced', 'Forced'),
        ('override_cleared', 'Override cleared'),
        ('skipped', 'Enrolment postponed'),
        ('invite', 'Invitation sent'),
        ('reminder', 'Reminder sent'),
        ('codes', 'Recovery codes generated'),
        ('recovery_used', 'Recovery code used'),
        ('mode', 'Setting changed'),
    ], string='Event', required=True, index=True)
    detail = fields.Char(string='Details')
    ip = fields.Char(string='IP address')
    actor_id = fields.Many2one('res.users', string='Done by', ondelete='set null')

    @api.model
    def _log(self, users, event, detail=False, actor=None):
        ip = False
        try:
            if request:
                ip = request.httprequest.remote_addr
        except Exception:  # noqa: BLE001 - never break a security flow for logging
            ip = False
        actor = actor or self.env.user
        vals = [{
            'user_id': user.id,
            'login': user.login,
            'event': event,
            'detail': detail,
            'ip': ip,
            'actor_id': actor.id,
        } for user in users]
        if not vals:
            vals = [{'event': event, 'detail': detail, 'ip': ip, 'actor_id': actor.id,
                     'login': actor.login}]
        return self.sudo().create(vals)

    @api.model
    def _purge(self):
        days = int(self.env['res.users']._mfa_guard_param('log_retention', 365) or 365)
        limit = fields.Datetime.now() - timedelta(days=days)
        self.sudo().search([('create_date', '<', limit)]).unlink()
