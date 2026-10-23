import base64
import contextlib
import io
import logging
import re
import secrets
from urllib.parse import quote, urlencode

import qrcode

from odoo import _, fields, http
from odoo.addons.auth_totp.models.totp import TOTP
from odoo.addons.web.controllers.home import Home
from odoo.exceptions import AccessDenied
from odoo.http import request

_logger = logging.getLogger(__name__)


class MfaGuardController(Home):

    # ---------------------------------------------------------------- helpers
    @staticmethod
    def _mfa_guard_safe_redirect(redirect):
        """Only local paths: never redirect to another site."""
        if (not redirect or not redirect.startswith('/') or redirect.startswith('//')
                or '\\' in redirect or '\n' in redirect or '\r' in redirect):
            return '/web'
        return redirect

    def _mfa_guard_context(self):
        """Return (user, is_partial_session)."""
        session = request.session
        if session.get('uid'):
            return request.env['res.users'].sudo().browse(session['uid']), False
        pre_uid = session.get('pre_uid')
        if pre_uid:
            return request.env['res.users'].sudo().browse(pre_uid), True
        return None, False

    def _mfa_guard_finalize(self):
        """Turn the partial (password/SSO only) session into a full session."""
        request.env.flush_all()
        request.session.finalize(request.env)
        request.update_env(user=request.session.uid)
        request.update_context(**request.session.context)
        with contextlib.suppress(Exception):
            request.session.touch()

    @staticmethod
    def _mfa_guard_auth_guard(user):
        """Odoo's brute-force protection (login cooldown) around code checks."""
        guard = getattr(user, '_assert_can_auth', None)
        if guard is None:
            return contextlib.nullcontext()
        try:
            return guard(user=user.id)
        except TypeError:
            return guard()

    def _mfa_guard_check_totp(self, user, raw_code, secret=None):
        """Return None if valid, else an error message. Never raises."""
        try:
            code = int(re.sub(r'\s', '', raw_code or ''))
        except ValueError:
            return _('The code must only contain digits.')
        try:
            with self._mfa_guard_auth_guard(user):
                if secret is not None:
                    if TOTP(base64.b32decode(secret)).match(code) is None:
                        raise AccessDenied(_('Invalid code. Check the 6 digits and that the '
                                             'clock of your phone is automatic.'))
                else:
                    user._totp_check(code)
        except AccessDenied as exc:
            return str(exc)
        return None

    def _mfa_guard_qr(self, user, secret):
        issuer = (user._mfa_guard_param('issuer') or user.company_id.name
                  or request.httprequest.host.split(':', 1)[0])
        query = urlencode({'secret': secret, 'issuer': issuer, 'algorithm': 'SHA1',
                           'digits': 6, 'period': 30}, quote_via=quote)
        uri = 'otpauth://totp/%s:%s?%s' % (quote(issuer, safe=''), quote(user.login, safe='@'), query)
        buf = io.BytesIO()
        qrcode.make(uri, box_size=6, border=2).save(buf, format='PNG')
        return {
            'qr': base64.b64encode(buf.getvalue()).decode(),
            'formatted_secret': ' '.join(secret[i:i + 4] for i in range(0, len(secret), 4)),
            'issuer': issuer,
        }

    def _mfa_guard_render_codes(self, codes, redirect):
        formatted = ['%s %s' % (c[:5], c[5:]) for c in codes]
        text = _('Recovery codes - keep them safe, each code works once.') + '\n\n' + '\n'.join(formatted)
        return request.render('twofa_shield.codes_page', {
            'codes': formatted,
            'codes_uri': 'data:text/plain;charset=utf-8,' + quote(text),
            'continue_url': self._mfa_guard_safe_redirect(redirect),
            'disable_database_manager': True,
        })

    def _mfa_guard_render_my(self, user, message=None, error=None):
        return request.render('twofa_shield.my_page', {
            'user': user,
            'enrolled': bool(user.totp_enabled),
            'enrolled_on': user.mfa_guard_enrolled_on,
            'required': user._mfa_guard_required(),
            'codes_left': user.mfa_guard_recovery_count,
            'recovery_enabled': not user._mfa_guard_param('no_recovery'),
            'message': message,
            'error': error,
            'disable_database_manager': True,
        })

    # ----------------------------------------------------------------- setup
    @http.route('/twofa_shield/setup', type='http', auth='public', methods=['GET', 'POST'],
                sitemap=False, readonly=False)
    def mfa_guard_setup(self, redirect=None, totp_code=None, **kw):
        user, partial = self._mfa_guard_context()
        if not user:
            return request.redirect('/web/login')
        if partial:
            request.update_context(lang=user.lang)
        # Core protection: an enrolled account can NEVER be re-enrolled from here.
        if user.totp_enabled:
            return request.redirect('/web/login/totp' if partial else '/twofa_shield/my')
        if partial and not user._mfa_guard_required():
            return request.redirect('/web/login')

        session = request.session
        secret = session.get('mfa_guard_secret')
        if not secret or session.get('mfa_guard_secret_uid') != user.id:
            secret = base64.b32encode(secrets.token_bytes(20)).decode()
            session['mfa_guard_secret'] = secret
            session['mfa_guard_secret_uid'] = user.id

        error = None
        if request.httprequest.method == 'POST':
            error = self._mfa_guard_check_totp(user, totp_code, secret=secret)
            if not error:
                codes = user._mfa_guard_complete_enrollment(secret)
                session.pop('mfa_guard_secret', None)
                session.pop('mfa_guard_secret_uid', None)
                if partial:
                    self._mfa_guard_finalize()
                else:
                    user._mfa_guard_refresh_current_session()
                if codes:
                    return self._mfa_guard_render_codes(codes, redirect)
                return request.redirect(self._mfa_guard_safe_redirect(redirect))
            request.env['mfa.guard.log']._log(user, 'enroll_failed', actor=user)

        can_skip = bool(partial and user._mfa_guard_grace_open())
        deadline = user.sudo().mfa_guard_deadline
        values = {
            'login': user.login,
            'error': error,
            'redirect': redirect,
            'can_skip': can_skip,
            'deadline': fields.Datetime.to_string(deadline)[:10] if deadline and can_skip else None,
            'partial': partial,
            'disable_database_manager': True,
        }
        values.update(self._mfa_guard_qr(user, secret))
        return request.render('twofa_shield.setup_page', values)

    @http.route('/twofa_shield/skip', type='http', auth='public', methods=['POST'],
                sitemap=False, readonly=False)
    def mfa_guard_skip(self, redirect=None, **kw):
        user, partial = self._mfa_guard_context()
        if (not partial or user.totp_enabled or not user._mfa_guard_required()
                or not user._mfa_guard_grace_open()):
            return request.redirect('/web/login')
        request.env['mfa.guard.log']._log(user, 'skipped', actor=user)
        self._mfa_guard_finalize()
        return request.redirect(self._mfa_guard_safe_redirect(redirect))

    # --------------------------------------------------------- self-service
    @http.route('/twofa_shield/my', type='http', auth='user', methods=['GET'], sitemap=False)
    def mfa_guard_my(self, **kw):
        return self._mfa_guard_render_my(request.env.user.sudo())

    @http.route('/twofa_shield/recovery', type='http', auth='user', methods=['POST'],
                sitemap=False, readonly=False)
    def mfa_guard_recovery(self, totp_code=None, **kw):
        user = request.env.user.sudo()
        if not user.totp_enabled or user._mfa_guard_param('no_recovery'):
            return request.redirect('/twofa_shield/my')
        error = self._mfa_guard_check_totp(user, totp_code)
        if error:
            return self._mfa_guard_render_my(user, error=error)
        codes = user._mfa_guard_generate_recovery_codes()
        return self._mfa_guard_render_codes(codes, '/twofa_shield/my')

    # ------------------------------------------------- standard TOTP page
    @http.route()
    def web_totp(self, redirect=None, **kwargs):
        users = request.env['res.users']
        hide_remember = users._mfa_guard_enabled() and not users._mfa_guard_param('allow_remember')
        if hide_remember:
            kwargs.pop('switch', None)  # server-side: never set the trusted-device cookie
        response = super().web_totp(redirect=redirect, **kwargs)
        if hide_remember and hasattr(response, 'qcontext'):
            response.qcontext['mfa_guard_hide_remember'] = True
        return response
