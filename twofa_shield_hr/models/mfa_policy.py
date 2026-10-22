from odoo import fields, models


class MfaGuardPolicy(models.Model):
    _inherit = 'mfa.guard.policy'

    scope = fields.Selection(
        selection_add=[('departments', 'Employees of selected departments')],
        ondelete={'departments': 'set default'})
    department_ids = fields.Many2many(
        'hr.department', 'mfa_guard_policy_department_rel', 'policy_id', 'department_id',
        string='Departments')
    include_subdepartments = fields.Boolean(string='Include sub-departments', default=True)

    def _matches(self, user):
        if self.scope == 'departments':
            self.ensure_one()
            if user in self.exempt_user_ids:
                return False
            departments = user.sudo().employee_ids.department_id
            if not departments:
                return False
            targets = self.department_ids
            if self.include_subdepartments and targets:
                targets = self.env['hr.department'].sudo().search([('id', 'child_of', targets.ids)])
            return bool(departments & targets)
        return super()._matches(user)
