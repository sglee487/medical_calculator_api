import datetime
from django.db import models

from django.contrib.auth.models import User


User._meta.get_field('email').blank = False


class Action(models.TextChoices):
    GET = 'view'
    POST = 'create'
    PATCH = 'update'
    DELETE = 'delete'


class UserInfo(models.Model):
    user = models.OneToOneField(
        User, related_name='user_info', on_delete=models.CASCADE)

    uuid = models.CharField(max_length=100)
    social_account_id = models.CharField(max_length=250)

    name = models.CharField(max_length=30, null=True)
    memo = models.CharField(max_length=1000, null=True)


class EpinephrineRate(models.Model):
    email = models.ForeignKey(User, related_name='user_email', on_delete=models.CASCADE)
    created_at = models.DateTimeField(
        default=datetime.datetime.now()
    )

    result_rate = models.FloatField(max_length=250)
    dose = models.FloatField(max_length=250)
    weight = models.FloatField(max_length=250)
    drug = models.FloatField(max_length=250)
    afterSuffleIV = models.FloatField(max_length=250)

    def __str__(self) -> str:
        return f"{self.email}_{self.created_at}"


class AuditLog(models.Model):
    user_email = models.CharField(null=True, max_length=200)
    action_type = models.CharField(choices=Action.choices, max_length=16)
    action_detail = models.TextField(default='')
    created_at = models.DateTimeField(default=datetime.datetime.now)
