# -*- coding: utf-8 -*-

from openerp import models, fields, api, exceptions, _
from openerp.http import request
from openerp.exceptions import ValidationError
from openerp.exceptions import AccessDenied

from Crypto.PublicKey import RSA
import ast
import pdb
import pyotp

import qrcode
import base64
import cStringIO

# class lubon_partners(models.Model):
#     _name = 'lubon_partners.lubon_partners'

#     name = fields.Char()
# -*- coding: utf-8 -*-
#from openerp import fields, models

def encrypt_string(string):
    f= open('/home/odoo/.odoo/public_key.pem','r')
    r = RSA.importKey(f.read())
    f.close()
    p=string.encode('utf-8')
    encrypted=r.encrypt(p,32)
    return encrypted

def decrypt_string(encrypted):
    f= open('/home/odoo/.odoo/private_key.pem','r')
    r = RSA.importKey(f.read())
    f.close()
    encrypted= ast.literal_eval(str(encrypted))
    unencrypted=r.decrypt(encrypted) 
    return unencrypted




class Partner(models.Model):
    _inherit = 'res.partner'
    credential_ids = fields.One2many('lubon_credentials.credentials', 'partner_id', string='credentials')
    masterkey = fields.Char()

    @api.one
    def reveal_credentials(self, pin=None):

        require_pin = True

        def validate_retry():
            retry_count = request.session.get('lubon_pin_retry', 1)
            request.session['lubon_pin_retry'] = retry_count + 1
            if retry_count >= 3:
                request.session.logout()
                return False
            return True

        if require_pin and not pin:
            b=1
            raise ValidationError("PIN required!")

        if require_pin and pin != self.env.user.pin:
            if not validate_retry():
                return -1
            raise ValidationError("Incorrect PIN!")

        request.session['lubon_pin_retry'] = 1

        return [self.masterkey or '', self.env['ir.config_parameter'].get_param('lubon_credentials.reveal_credentials_timeout', '') or 15000]


class Users(models.Model):
    _inherit = 'res.users'
    pin = fields.Char()
    twofactorsharedsecret = fields.Char()

    @api.multi
    def preference_change_2fa(self):
        if self.twofactorsharedsecret:
            raise ValidationError("2fa allready set, contact sysadmin to reset")
        else:
            return {
                 'name': 'Init 2 factor',
                 'view_type': 'form',
                 'view_mode': 'form',
                 'res_model': 'change2fa.wizard',
                 'target': 'new',
                 'type': 'ir.actions.act_window',
                 'context': {'default_user_id':self.id}
                }
    @api.multi
    def clear2fa(self):
        self.twofactorsharedsecret=""                
    @api.multi
    def check2fa(self,code):
        seed=decrypt_string(self.twofactorsharedsecret)
        now=pyotp.TOTP(decrypt_string(self.twofactorsharedsecret)).now()
        return (now == code)

    @api.multi
    def test2fa(self):
        if not self.twofactorsharedsecret:
            raise ValidationError("2fa not set")
        else:
#            pdb.set_trace()
            return {
                 'name': 'Test 2 factor',
                 'view_type': 'form',
                 'view_mode': 'form',
                 'res_model': 'proces2fa.wizard',
                 'target': 'new',
                 'type': 'ir.actions.act_window',
                 'context': {'default_user_id':self.id}
                }
    

class lubon_qlan_credentials(models.Model):
    _name = 'lubon_credentials.credentials'
    _rec_name = 'description'
    active=fields.Boolean(default=True)
    description = fields.Char(string="Description", required=True)
    user = fields.Char(string="User")
    password = fields.Char()
    hint = fields.Char()
    password01 = fields.Char(string="Pass")
    password02 = fields.Char(string="Conf")
    encrypted=fields.Char(string="Encrypted")
    is_saved=fields.Boolean(string="Saved")
    partner_id = fields.Many2one('res.partner',  ondelete='set null', string="Partner", index=True)
    model=fields.Char()
    related_id=fields.Integer()
 #   credentials_type=fields.Selection([('tenant_admin','Tenant admin'),('wifi','Wifi'),('site_admin','Site admin'),('telephony','Telephony'),('general','General')], default='general')
    @api.one
    def show_password(self):
        raise exceptions.ValidationError(self.password)
        return True

    def _get_ipaddress(self, cr, uid, context=None):
        return request.httprequest.environ['REMOTE_ADDR']
    @api.one
    def reveal_credentials(self, pin=None):

        require_pin = True

        def validate_retry():
            retry_count = request.session.get('lubon_pin_retry', 1)
            request.session['lubon_pin_retry'] = retry_count + 1
            if retry_count >= 3:
                request.session.logout()
                return False
            return True

        if require_pin and not pin:
            raise ValidationError("PIN required!")

        if require_pin and pin != self.env.user.pin:
            if not validate_retry():
                return -1
            raise ValidationError("Incorrect PIN!")

        request.session['lubon_pin_retry'] = 1
        password=""
        if self.encrypted:
            f= open('/home/odoo/.odoo/private_key.pem','r')
            r = RSA.importKey(f.read())
            f.close()
            encrypted= ast.literal_eval(str(self.encrypted))
            password=r.decrypt(encrypted)
        return [password or '', self.env['ir.config_parameter'].get_param('lubon_credentials.reveal_credentials_timeout', '') or 15000]
    
    @api.one
    def encrypt(self):
        if not self.is_saved:
            self.password01=self.password
            self.password02=self.password
            self.encrypt_password(True)
            self.password=''
        return True
    @api.one
    def decrypt(self):
        if self.encrypted:
            f= open('/home/odoo/.odoo/private_key.pem','r')
            r = RSA.importKey(f.read())
            f.close()
            encrypted= ast.literal_eval(str(self.encrypted))
            password=r.decrypt(encrypted) 
        return password

    
    @api.one
    @api.onchange('password01','password02')
    def encrypt_password(self, force=False):
        if (self.password01 and self.password02) or force:
            if self.password01 == self.password02:
                f= open('/home/odoo/.odoo/public_key.pem','r')
                r = RSA.importKey(f.read())
                f.close()
                #pdb.set_trace()
                encrypted=""
                if self.password01:
                    p=self.password01.encode('utf-8')
                    encrypted=r.encrypt(p,32)
                self.encrypted=encrypted
                self.password01=''
                self.password02=''
                self.is_saved=1
            else:
                raise ValidationError("Pls enter the same password twice")



class base_config_settings(models.TransientModel):
    _name = 'lubon_credentials.config.settings'
    _inherit = 'res.config.settings'

    def _get_default_reveal_credentials_timeout(self):
        return self.env['ir.config_parameter'].get_param('lubon_credentials.reveal_credentials_timeout', '') or 15000

    reveal_credentials_timeout = fields.Integer('Reveal Credentials Timeout (ms)', required=True, default=_get_default_reveal_credentials_timeout)

    @api.model
    def set_reveal_credentials_timeout(self, ids):
        config = self.browse(ids[0])
        icp = self.env['ir.config_parameter']
        icp.set_param('lubon_credentials.reveal_credentials_timeout', config.reveal_credentials_timeout)


class change2fa(models.TransientModel):
    _name = "change2fa.wizard"
    user_id=fields.Many2one('res.users')
    init_string=fields.Char()
    result_code=fields.Char()
    qr_image=fields.Binary()
    password=fields.Char()
    attempts=fields.Char()
    def _set_seed(self):
        return pyotp.random_base32()

    seed=fields.Char(default=_set_seed)
    
    @api.onchange('seed')
    def _set_init_string(self):
        #pdb.set_trace()
        self.init_string=pyotp.totp.TOTP(self.seed).provisioning_uri(self.user_id.name, issuer_name="Odoo db %s" % (self.env.cr.dbname))

    @api.onchange('password')    
    def generate_qr(self):
        #only if password is entered correctly 
        try:
            if self.password:
                result=self.env['res.users'].check_credentials(self.password)
                qr = qrcode.QRCode(version=1,error_correction=qrcode.constants.ERROR_CORRECT_L,box_size=20,border=4,)
                qr.add_data(self.init_string)
                qr.make(fit=True)
                img = qr.make_image()
                buffer = cStringIO.StringIO()
                img.save(buffer, "PNG")
                img_str = base64.b64encode(buffer.getvalue())
                self.qr_image=img_str
        except AccessDenied:
            self.attempts +=1
    

    @api.multi
    def save_seed(self):
        if self.qr_image and self.result_code == pyotp.TOTP(self.seed).now():
            self.user_id.twofactorsharedsecret=encrypt_string(self.seed)
        else:
            raise ValidationError ("Operation failed")

class proces2fa(models.TransientModel):
    _name = "proces2fa.wizard"
    user_id=fields.Many2one('res.users')
    result_code=fields.Char()
    test_result=fields.Boolean()

    def _default_user_id(self):
        return self.env['res.users'].browse(self._context.get('active_id'))

    user_id=fields.Many2one('res.users', default=_default_user_id)

    @api.onchange('result_code')
    @api.multi
    def testcode(self):
        if self.result_code:
            self.test_result=self.user_id.check2fa(self.result_code)
       
