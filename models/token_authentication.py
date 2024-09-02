import datetime
import secrets
import string
import time

from werkzeug.exceptions import HTTPException

from odoo import models, fields, api, _, http
from odoo.http import Response


def generate_token_key(length=32):
    characters = string.ascii_letters + string.digits
    return ''.join(secrets.choice(characters) for _ in range(length)) + str(int(time.time()))


class TokenAuthentication(models.Model):
    _name = "token.authentication"
    _description = "Token authentication"

    user_id = fields.Many2one("res.users", required=True)
    key = fields.Char("Token Key", required=True)
    expiration_date = fields.Datetime("Expiration Date", required=True,
                                      default=fields.Datetime.today() + datetime.timedelta(days=30))

    _sql_constraints = [
        ("user_unique", "unique (user_id)", "User is unique"),
        ("key_unique", "unique (key)", "Key is unique")
    ]

    @api.model
    def get_token(self, user):
        """
        Get token by user
        """
        self.search([("expiration_date", "=", False)]).unlink()

        token = self.search([("user_id", "=", user.id)], limit=1)

        # Create a new token if it doesn't exist
        if not token:
            token = self.create({
                "user_id": user.id,
                "key": generate_token_key()
            })
            return token.key, True, False

        # Return the token if it is valid
        if token.expiration_date >= fields.Datetime.now():
            return token.key, False, False

        token.write({
            "key": generate_token_key(),
            "expiration_date": fields.Datetime.today() + datetime.timedelta(days=30)
        })
        return token.key, False, True

    @api.model
    def get_key(self):
        """
        Get key from header
        """
        return http.request.httprequest.headers.get('Authorization')

    @api.model
    def get_user(self):
        """
        Get user by token key
        """
        key = self.get_key()
        if not bool(key):
            return

        token_authorization = self.search([("key", "=", key)], limit=1)
        if not bool(token_authorization):
            raise HTTPException(
                response=Response(status=404, response=_("Token not found"), content_type="application/json"))

        if token_authorization.expiration_date < fields.Datetime.now():
            token_authorization.unlink()
            raise HTTPException(
                response=Response(status=400, response=_("Token expired"), content_type="application/json"))

        return token_authorization.user_id

    @api.model
    def login(self, login, password):
        """
        Authenticate user by login and password
        """
        user = self.env["res.users"].sudo().search([("login", "=", login)], limit=1)
        if not user:
            raise HTTPException(
                description=_("User not found"),
                response=Response(status=404)
            )

        user = user.with_user(user)
        try:
            check_user_password = user._check_credentials(
                password, {"password": user.password, "interactive": False}
            )
        except Exception as e:
            print(e)
            check_user_password = True
        if check_user_password:
            raise HTTPException(response=Response(status=401, response=_("Invalid password")))

        token, created, updated = self.get_token(user=user)
        return {
            "token": token
        }

    @api.model
    def logout(self):
        """
        Logout user by token key
        """
        key = self.get_key()
        if not key:
            raise HTTPException(
                response=Response(status=400, response=_("Token not provided"), content_type="application/json"))

        token = self.search([("key", "=", key)], limit=1)
        if not token:
            raise HTTPException(
                response=Response(status=404, response=_("Token not found"), content_type="application/json"))

        token.unlink()

        return {"message": "User logout successfully"}
