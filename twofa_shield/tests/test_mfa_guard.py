from odoo.tests import TransactionCase, tagged

SECRET = 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ'  # nosec - test value


@tagged('post_install', '-at_install')
class TestMfaGuard(TransactionCase):

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.env['ir.config_parameter'].sudo().set_param('twofa_shield.mode', 'enforce')
        cls.env['mfa.guard.policy'].search([]).write({'active': False})
        cls.user = cls.env['res.users'].create({
            'name': 'MFA Test', 'login': 'mfa_test', 'email': 'mfa_test@example.com'})
        cls.other = cls.env['res.users'].create({
            'name': 'MFA Other', 'login': 'mfa_other', 'email': 'mfa_other@example.com'})
        cls.policy = cls.env['mfa.guard.policy'].create({
            'name': 'Only test user', 'scope': 'users', 'user_ids': [(6, 0, cls.user.ids)]})

    def test_policy_targets_only_selected_user(self):
        self.assertTrue(self.user._mfa_guard_required())
        self.assertFalse(self.other._mfa_guard_required())

    def test_mode_off_disables_everything(self):
        self.env['ir.config_parameter'].sudo().set_param('twofa_shield.mode', 'off')
        self.assertFalse(self.user._mfa_guard_required())
        self.assertNotEqual(self.user._mfa_url(), '/twofa_shield/setup')

    def test_setup_url_when_required_and_not_enrolled(self):
        self.assertEqual(self.user._mfa_url(), '/twofa_shield/setup')

    def test_exempt_override(self):
        self.user.sudo().mfa_guard_override = 'exempt'
        self.assertFalse(self.user._mfa_guard_required())
        self.assertFalse(self.user._mfa_url())

    def test_force_override(self):
        self.other.sudo().mfa_guard_override = 'force'
        self.assertTrue(self.other._mfa_guard_required())

    def test_policy_exception(self):
        self.policy.exempt_user_ids = [(6, 0, self.user.ids)]
        self.assertFalse(self.user._mfa_guard_required())

    def test_enrolled_user_is_sent_to_totp_page(self):
        self.user._mfa_guard_complete_enrollment(SECRET)
        self.assertTrue(self.user.totp_enabled)
        self.assertEqual(self.user._mfa_url(), '/web/login/totp')

    def test_recovery_code_is_single_use(self):
        codes = self.user._mfa_guard_complete_enrollment(SECRET)
        self.assertEqual(len(codes), 10)
        self.assertTrue(self.user._mfa_guard_consume_recovery_code(int(codes[0])))
        self.assertFalse(self.user._mfa_guard_consume_recovery_code(int(codes[0])))
        self.assertFalse(self.user._mfa_guard_consume_recovery_code(1234567890))

    def test_reset_wipes_secret_and_codes(self):
        self.user._mfa_guard_complete_enrollment(SECRET)
        self.user._mfa_guard_do_reset()
        self.assertFalse(self.user.totp_enabled)
        self.assertEqual(self.user.sudo().mfa_guard_recovery_count, 0)
        self.assertEqual(self.user._mfa_url(), '/twofa_shield/setup')

    def test_bypass_window(self):
        from datetime import timedelta
        from odoo import fields
        self.user.sudo().mfa_guard_bypass_until = fields.Datetime.now() + timedelta(hours=1)
        self.assertFalse(self.user._mfa_url())

    def test_status_search(self):
        found = self.env['res.users'].search([('mfa_guard_status', '=', 'pending')])
        self.assertIn(self.user, found)
        self.assertNotIn(self.other, found)
