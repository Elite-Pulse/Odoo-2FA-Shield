from odoo import _, fields, models


class MfaGuardPolicy(models.Model):
    _name = 'mfa.guard.policy'
    _description = 'MFA Enforcement Policy'
    _order = 'sequence, id'

    name = fields.Char(required=True)
    active = fields.Boolean(default=True)
    sequence = fields.Integer(default=10)
    scope = fields.Selection([
        ('all', 'Everybody (internal + portal)'),
        ('internal', 'Internal users'),
        ('portal', 'Portal users'),
        ('groups', 'Users in selected access groups'),
        ('users', 'Specific users'),
        ('companies', 'Users allowed in selected companies'),
    ], string='Applies to', required=True, default='internal')
    group_ids = fields.Many2many(
        'res.groups', 'mfa_guard_policy_group_rel', 'policy_id', 'group_id',
        string='Access groups')
    user_ids = fields.Many2many(
        'res.users', 'mfa_guard_policy_user_rel', 'policy_id', 'user_id',
        string='Users')
    company_ids = fields.Many2many(
        'res.company', 'mfa_guard_policy_company_rel', 'policy_id', 'company_id',
        string='Companies')
    exempt_user_ids = fields.Many2many(
        'res.users', 'mfa_guard_policy_exempt_rel', 'policy_id', 'user_id',
        string='Exceptions', help='These users are never targeted by this policy.')
    note = fields.Text(string='Internal note')

    def _matches(self, user):
        """Return True if this policy requires 2FA for ``user`` (a sudo record)."""
        self.ensure_one()
        if user in self.exempt_user_ids:
            return False
        scope = self.scope
        if scope == 'all':
            return True
        if scope == 'internal':
            return not user.share
        if scope == 'portal':
            return bool(user.share)
        if scope == 'groups':
            return bool(user._mfa_guard_groups() & self.group_ids)
        if scope == 'users':
            return user in self.user_ids
        if scope == 'companies':
            return bool(user.company_ids & self.company_ids)
        return False

    def _matching_users(self):
        self.ensure_one()
        users = self.env['res.users'].sudo().search([])
        return users.filtered(lambda u: u.id != 1 and self._matches(u))

    def action_view_users(self):
        self.ensure_one()
        users = self._matching_users()
        return {
            'type': 'ir.actions.act_window',
            'name': _('Users targeted by "%s"', self.name),
            'res_model': 'res.users',
            'view_mode': 'tree,form',
            'domain': [('id', 'in', users.ids)],
            'views': [
                (self.env.ref('twofa_shield.view_users_mfa_list').id, 'tree'),
                (False, 'form'),
            ],
        }
