from odoo import fields, models


class MfaGuardRecoveryCode(models.Model):
    """One-time recovery codes. Only a salted hash is stored."""
    _name = 'mfa.guard.recovery.code'
    _description = 'MFA Recovery Code'

    user_id = fields.Many2one('res.users', required=True, ondelete='cascade', index=True)
    code_hash = fields.Char(required=True)
    used_on = fields.Datetime()
