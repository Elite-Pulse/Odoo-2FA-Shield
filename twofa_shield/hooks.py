from odoo import SUPERUSER_ID, api


def post_init_hook(*args):
    """Make the maintenance cron recurring on every Odoo series.

    Odoo 17 passes (cr, registry), Odoo 18+ passes (env). On series where
    ``ir.cron.numbercall`` still exists it defaults to 1, which would disable
    the cron after its first run.
    """
    first = args[0]
    env = first if isinstance(first, api.Environment) else api.Environment(first, SUPERUSER_ID, {})
    cron = env.ref('twofa_shield.ir_cron_mfa_guard_maintenance', raise_if_not_found=False)
    if cron and 'numbercall' in cron._fields:
        cron.sudo().numbercall = -1
