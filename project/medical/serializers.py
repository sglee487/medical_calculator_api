from dataclasses import field, fields
from django.contrib.auth.models import User
from rest_framework import serializers

from project.medical.models import UserInfo, EpinephrineRate


class UserInfoSerializer(serializers.HyperlinkedModelSerializer):
    class Meta:
        model = UserInfo
        fields = ['uuid', 'name', 'memo']

class UserSerializer(serializers.ModelSerializer):
    user_info = UserInfoSerializer(read_only=True)

    class Meta:
        model = User
        fields = ['id', 'email', 'username', 'password',
                  'user_info', 'is_active', 'last_login', 'date_joined']
        extra_kwargs = {
            'id': {'read_only': True},
            'password': {'write_only': True},
            'is_active': {'read_only': True},
            'last_login': {'read_only': True},
            'date_joined': {'read_only': True}
        }


class EpinephrineRateSwerializer(serializers.HyperlinkedModelSerializer):
    class Meta:
        model = EpinephrineRate
        fields = ['email', 'created_at', 'result_rate',
                  'dose', 'weight', 'drug', 'afterSuffleIV']
