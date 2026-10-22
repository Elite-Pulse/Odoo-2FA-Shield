import hashlib
import logging
import secrets
from datetime import timedelta

from odoo import SUPERUSER_ID, _, api, fields, models
from odoo.exceptions import AccessDenied, AccessError, UserError
from odoo.http import request

_logger = logging.getLogger(__name__)

RECOVERY_CODE_COUNT = 10
SYSTEM_GROUP = 'base.group_system'


class ResUsers(models.Model):
    _inherit = 'res.users'

    # ------------------------------------------------------------------ fields
    mfa_guard_override = fields.Selection([
        ('default', 'Follow policies'),
        ('force', 'Force 2FA'),
        ('exempt', 'Exempt from 2FA'),
    ], string='2FA Override', default='default', copy=False, groups=SYSTEM_GROUP,
        help="Force: this user must use 2FA whatever the policies say.\n"
             "Exempt: this user is never asked for 2FA (e.g. emergency local account).")
    mfa_guard_bypass_until = fields.Datetime(
        string='2FA Bypass Until', copy=False, groups=SYSTEM_GROUP,
        help='Until this date the user can sign in without a 2FA code '
             '(lost phone). Reset the 2FA afterwards.')
    mfa_guard_deadline = fields.Datetime(
        string='Enrolment Deadline', copy=False, groups=SYSTEM_GROUP,
        help='Until this date the user may postpone 2FA enrolment.')
    mfa_guard_enrolled_on = fields.Datetime(string='2FA Enabled On', copy=False, groups=SYSTEM_GROUP)
    mfa_guard_last_reminder = fields.Datetime(copy=False, groups=SYSTEM_GROUP)
    mfa_guard_status = fields.Selection([
        ('enabled', '2FA active'),
        ('pending', 'Required - not enrolled'),
        ('optional', 'Not required - not enrolled'),
        ('exempt', 'Exempt / bypass'),
    ], string='2FA Status', compute='_compute_mfa_guard_status',
        search='_search_mfa_guard_status', groups=SYSTEM_GROUP)
    mfa_guard_recovery_count = fields.Integer(
        string='Recovery Codes Left', compute='_compute_mfa_guard_recovery_count',
        groups=SYSTEM_GROUP)

    # ----------------------------------------------------------------- helpers
    @api.model
    def _mfa_guard_param(self, key, default=None):
        value = self.env['ir.config_parameter'].sudo().get_param('twofa_shield.%s' % key)
        return default if value in (None, False, '') else value

    @api.model
    def _mfa_guard_enabled(self):
        return self._mfa_guard_param('mode', 'off') == 'enforce'

    @api.model
    def _mfa_guard_check_admin(self):
        if not (self.env.su or self.env.user._is_system()):
            raise AccessError(_('Only administrators can manage two-factor authentication.'))

    def _mfa_guard_groups(self):
        self.ensure_one()
        fname = 'all_group_ids' if 'all_group_ids' in self._fields else 'groups_id'
        return self[fname]

    def _mfa_guard_bypass_active(self):
        user = self.sudo()
        return bool(user.mfa_guard_bypass_until and user.mfa_guard_bypass_until > fields.Datetime.now())

    def _mfa_guard_required(self, policies=None):
        """True when this user must have 2FA according to override + policies."""
        self.ensure_one()
        user = self.sudo()
        if user.id == SUPERUSER_ID or not self._mfa_guard_enabled():
            return False
        if user.mfa_guard_override == 'exempt' or user._mfa_guard_bypass_active():
            return False
        if user.mfa_guard_override == 'force':
            return True
        if policies is None:
            policies = self.env['mfa.guard.policy'].sudo().search([])
        return any(policy._matches(user) for policy in policies)

    def _mfa_guard_status_value(self, policies=None):
        self.ensure_one()
        user = self.sudo()
        enrolled = bool(user.totp_enabled)
        if user.id == SUPERUSER_ID:
            return 'exempt'
        if self._mfa_guard_enabled() and (
                user.mfa_guard_override == 'exempt' or user._mfa_guard_bypass_active()):
            return 'exempt'
        if enrolled:
            return 'enabled'
        return 'pending' if user._mfa_guard_required(policies) else 'optional'

    @api.depends('totp_enabled', 'mfa_guard_override', 'mfa_guard_bypass_until')
    def _compute_mfa_guard_status(self):
        policies = self.env['mfa.guard.policy'].sudo().search([])
        for user in self:
            user.mfa_guard_status = user._mfa_guard_status_value(policies)

    def _search_mfa_guard_status(self, operator, value):
        if operator not in ('=', '!=', 'in', 'not in'):
            raise UserError(_('Unsupported search operator for the 2FA status.'))
        values = value if isinstance(value, (list, tuple)) else [value]
        policies = self.env['mfa.guard.policy'].sudo().search([])
        users = self.env['res.users'].sudo().search([])
        ids = [u.id for u in users if u._mfa_guard_status_value(policies) in values]
        negative = operator in ('!=', 'not in')
        return [('id', 'not in' if negative else 'in', ids)]

    def _compute_mfa_guard_recovery_count(self):
        Code = self.env['mfa.guard.recovery.code'].sudo()
        for user in self:
            user.mfa_guard_recovery_count = Code.search_count(
                [('user_id', '=', user.id), ('used_on', '=', False)])

    # ------------------------------------------------------- login flow hooks
    def _check_credentials(self, credential, env):
        """Remember in the (partial) session that the user came through SSO."""
        auth_info = super()._check_credentials(credential, env)
        try:
            if request and isinstance(credential, dict):
                if credential.get('type') == 'oauth_token':
                    request.session['mfa_guard_sso'] = self.id
                elif credential.get('type') == 'password':
                    request.session.pop('mfa_guard_sso', None)
        except Exception:  # noqa: BLE001
            _logger.debug('2FA Shield: could not flag SSO session', exc_info=True)
        return auth_info

    def _mfa_guard_sso_trusted(self):
        if not self._mfa_guard_param('trust_sso'):
            return False
        try:
            return bool(request) and request.session.get('mfa_guard_sso') == self.id
        except Exception:  # noqa: BLE001
            return False

    def _mfa_url(self):
        """Second step URL after the first factor (password or SSO).

        MUST stay read-only: Odoo calls it on a dedicated cursor during login.
        """
        self.ensure_one()
        enforce = self._mfa_guard_enabled()
        if enforce:
            user = self.sudo()
            if user.id != SUPERUSER_ID and (
                    user.mfa_guard_override == 'exempt'
                    or user._mfa_guard_bypass_active()
                    or user._mfa_guard_sso_trusted()):
                return None
        url = super()._mfa_url()
        if url or not enforce:
            return url
        if not self.sudo().totp_enabled and self._mfa_guard_required():
            return '/twofa_shield/setup'
        return url

    def _totp_check(self, code):
        """Accept a one-time recovery code in place of the TOTP code."""
        try:
            return super()._totp_check(code)
        except AccessDenied:
            if self._mfa_guard_consume_recovery_code(code):
                return None
            raise

    def action_totp_disable(self):
        """Users cannot switch off a mandatory 2FA themselves."""
        if not (self.env.su or self.env.user._is_system()):
            for user in self:
                if user._mfa_guard_required():
                    raise UserError(_(
                        'Two-factor authentication is mandatory for your account and '
                        'cannot be disabled. Please contact your administrator.'))
        res = super().action_totp_disable()
        self.env['mfa.guard.log']._log(self, 'disabled', _('Disabled from user preferences'))
        return res

    # ------------------------------------------------------------- enrolment
    def _mfa_guard_grace_open(self):
        """True while the user may still postpone enrolment."""
        user = self.sudo()
        now = fields.Datetime.now()
        deadline = user.mfa_guard_deadline
        if not deadline:
            days = int(self._mfa_guard_param('grace_days', 0) or 0)
            if days <= 0:
                return False
            deadline = now + timedelta(days=days)
            user.mfa_guard_deadline = deadline
        return deadline > now

    def _mfa_guard_complete_enrollment(self, secret):
        """Persist the secret. Never raises after the write (no rollback)."""
        self.ensure_one()
        user = self.sudo()
        user.totp_secret = secret
        user.write({'mfa_guard_enrolled_on': fields.Datetime.now(), 'mfa_guard_deadline': False})
        codes = []
        if not self._mfa_guard_param('no_recovery'):
            codes = user._mfa_guard_generate_recovery_codes()
        self.env['mfa.guard.log']._log(user, 'enrolled', actor=user)
        if not self._mfa_guard_param('no_notice'):
            user._mfa_guard_send_mail(
                'twofa_shield.mail_template_notice',
                mfa_title=_('Two-factor authentication was enabled'),
                mfa_text=_('Two-factor authentication has just been enabled on your account. '
                           'If this was not you, contact your administrator immediately.'))
        return codes

    @api.model
    def _mfa_guard_refresh_current_session(self):
        """Keep the current browser session valid after totp_secret changed."""
        if request and request.session.uid:
            self.env.flush_all()
            user = self.env['res.users'].sudo().browse(request.session.uid)
            request.session.session_token = user._compute_session_token(request.session.sid)

    # -------------------------------------------------------- recovery codes
    def _mfa_guard_hash_code(self, code):
        salt = self.env['ir.config_parameter'].sudo().get_param('database.secret') or ''
        return hashlib.sha256(('%s:%s:%s' % (salt, self.id, code)).encode()).hexdigest()

    def _mfa_guard_generate_recovery_codes(self, count=RECOVERY_CODE_COUNT):
        self.ensure_one()
        Code = self.env['mfa.guard.recovery.code'].sudo()
        Code.search([('user_id', '=', self.id)]).unlink()
        codes = []
        for _i in range(count):
            code = str(secrets.randbelow(9 * 10 ** 9) + 10 ** 9)  # 10 digits, no leading 0
            codes.append(code)
            Code.create({'user_id': self.id, 'code_hash': self._mfa_guard_hash_code(code)})
        self.env['mfa.guard.log']._log(self, 'codes', actor=self)
        return codes

    def _mfa_guard_consume_recovery_code(self, code):
        self.ensure_one()
        if self._mfa_guard_param('no_recovery'):
            return False
        if not isinstance(code, int) or not 10 ** 9 <= code < 10 ** 10:
            return False
        record = self.env['mfa.guard.recovery.code'].sudo().search([
            ('user_id', '=', self.id),
            ('code_hash', '=', self._mfa_guard_hash_code(code)),
            ('used_on', '=', False),
        ], limit=1)
        if not record:
            return False
        record.used_on = fields.Datetime.now()
        left = self.sudo().mfa_guard_recovery_count
        self.env['mfa.guard.log']._log(
            self, 'recovery_used', _('%s recovery code(s) left', left), actor=self)
        return True

    # ----------------------------------------------------------- admin tools
    def _mfa_guard_do_reset(self, detail=None):
        """Wipe secret, trusted devices and recovery codes."""
        self._mfa_guard_check_admin()
        for user in self.sudo():
            if 'totp_trusted_device_ids' in user._fields:
                user.totp_trusted_device_ids.unlink()
            user.totp_secret = False
            self.env['mfa.guard.recovery.code'].sudo().search([('user_id', '=', user.id)]).unlink()
            user.write({'mfa_guard_enrolled_on': False})
        self.env['mfa.guard.log']._log(self, 'reset', detail)
        self._mfa_guard_refresh_current_session()

    def _mfa_guard_send_mail(self, xmlid, **ctx):
        template = self.env.ref(xmlid, raise_if_not_found=False)
        if not template:
            return 0
        base_url = self.env['ir.config_parameter'].sudo().get_param('web.base.url') or ''
        sent = 0
        for user in self.sudo():
            if not user.email or not user.active:
                continue
            template.sudo().with_context(
                mfa_base_url=base_url, lang=user.lang, **ctx
            ).send_mail(user.id, force_send=False, raise_exception=False)
            sent += 1
        return sent

    def action_mfa_guard_open_reset(self):
        self.ensure_one()
        self._mfa_guard_check_admin()
        return {
            'type': 'ir.actions.act_window',
            'name': _('Reset / Recovery'),
            'res_model': 'mfa.guard.reset.wizard',
            'view_mode': 'form',
            'target': 'new',
            'context': {'default_user_ids': [(6, 0, self.ids)]},
        }

    def action_mfa_guard_open_invite(self):
        self.ensure_one()
        self._mfa_guard_check_admin()
        return {
            'type': 'ir.actions.act_window',
            'name': _('Send 2FA invitation'),
            'res_model': 'mfa.guard.invite.wizard',
            'view_mode': 'form',
            'target': 'new',
            'context': {'default_user_ids': [(6, 0, self.ids)], 'default_target': 'selected'},
        }

    # ------------------------------------------------------------------ cron
    @api.model
    def _mfa_guard_send_reminders(self):
        if not self._mfa_guard_enabled() or self._mfa_guard_param('no_reminders'):
            return
        days = int(self._mfa_guard_param('reminder_days', 3) or 3)
        limit = fields.Datetime.now() - timedelta(days=days)
        policies = self.env['mfa.guard.policy'].sudo().search([])
        candidates = self.sudo().search([
            '|', ('mfa_guard_last_reminder', '=', False), ('mfa_guard_last_reminder', '<', limit),
        ], order='id')
        sent_total = 0
        for user in candidates:
            if sent_total >= 200:
                break
            if (user.id == SUPERUSER_ID or not user.email or user.totp_enabled
                    or not user.login_date or not user._mfa_guard_required(policies)):
                continue
            ctx = {}
            if user.mfa_guard_deadline:
                ctx['mfa_deadline'] = fields.Date.to_string(user.mfa_guard_deadline)
            if user._mfa_guard_send_mail('twofa_shield.mail_template_reminder', **ctx):
                user.mfa_guard_last_reminder = fields.Datetime.now()
                self.env['mfa.guard.log']._log(user, 'reminder', actor=user)
                sent_total += 1

    @api.model
    def _cron_mfa_guard_maintenance(self):
        self.env['mfa.guard.log']._purge()
        self._mfa_guard_send_reminders()
