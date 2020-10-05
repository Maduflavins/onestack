from django.db import models
import jwt
import uuid
from datetime import datetime, timedelta
from django.conf import settings
from django.contrib.auth.models import (
    AbstractBaseUser, BaseUserManager, PermissionsMixin)

from django.db import models
from rest_framework_simplejwt.tokens import RefreshToken
from django.core.validators import RegexValidator


class UserManager(BaseUserManager):

    def create_user(self, company_name, company_address, company_phone, contact_person,  email, password=None):
        if company_name is None:
            raise TypeError('Users should have a company_name')
        if company_address is None:
            raise TypeError('Users should have a company_address')
        if company_address is None:
            raise TypeError('Users should have a company_address')
        if company_phone is None:
            raise TypeError('Users should have a company_phone')
        if contact_person is None:
            raise TypeError('Users should have a contact_person')
        if email is None:
            raise TypeError('Users should have a email')

        user = self.model(company_name=company_name, company_address=company_address,
                          company_phone=company_phone, contact_person=contact_person,
                          email=self.normalize_email(email))
        user.set_password(password)
        user.save()
        return user

    def create_superuser(self, username, email, password=None):
        if password is None:
            raise TypeError('Password should not be none')

        user = self.create_user(username, email, password)
        user.is_superuser = True
        user.is_staff = True
        user.save()
        return user
EMAIL_REGEX = RegexValidator(r'^/^(([^<>()[\]\\.,;:\s@"]+(\.[^<>()[\]\\.,;:\s@"]+)*)|(".+"))@((\[[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\])|(([a-zA-Z\-0-9]+\.)+[a-zA-Z]{2,}))$/',
                             'valid email is required')
phone_regex = RegexValidator(regex=r'^[0]\d{10}$', message="must be a valid phone number")
class User(AbstractBaseUser, PermissionsMixin):
    company_name = models.CharField(max_length=255, unique=True, db_index=True)
    company_address = models.CharField(max_length=255)
    company_phone = models.CharField(validators=[phone_regex], max_length=15, blank=True)
    email = models.EmailField(max_length=255, unique=True, db_index=True)
    contact_person = models.CharField(max_length=255,)
    is_verified = models.BooleanField(default=False)
    is_active = models.BooleanField(default=True)
    is_staff = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = ['company_name']

    objects = UserManager()

    def __str__(self):
        return self.company_name

    # def tokens(self):
    #     refresh = RefreshToken.for_user(self)
    #     return {
    #         'refresh': str(refresh),
    #         'access': str(refresh.access_token)
    #     }

    def token(self):
        dt = datetime.now() + timedelta(days=60)

        token = jwt.encode({
            'id': self.pk,
            'company': self.company_name,
            'username': self.contact_person,
            'is_staff': self.is_staff,
            # 'exp': int(dt.strftime('%s'))
            'exp': dt.utcfromtimestamp(dt.timestamp())
        }, settings.SECRET_KEY, algorithm='HS256')

        return token.decode('utf-8')
