import random
import string
import uuid
import datetime
import json
import base64
from urllib.parse import urlencode

import jwt
import requests
from datetime import timedelta
from django.conf import settings
from django.utils import timezone
from social_core.backends.oauth import BaseOAuth2
from social_core.utils import handle_http_errors

from django import views
from django.db.models import QuerySet
from django.contrib.auth.models import User
from django.contrib.auth.hashers import make_password, check_password
from django.core.mail import send_mail
from django.http import HttpRequest, HttpResponse, HttpResponseRedirect, JsonResponse
from django.views.decorators.csrf import csrf_exempt
from django.shortcuts import redirect

from rest_framework import viewsets, status
from rest_framework.response import Response
from rest_framework.authentication import TokenAuthentication
from rest_framework.authtoken.views import ObtainAuthToken
from rest_framework.authtoken.models import Token
from rest_framework.permissions import IsAuthenticated
from rest_framework import viewsets
from project import settings

from project.medical.models import Action, AuditLog, UserInfo
from project.medical.serializers import UserSerializer, EpinephrineRateSwerializer

HttpResponseRedirect.allowed_schemes.append('intent')

class UserViewSet(viewsets.ModelViewSet):
    authentication_classes = [TokenAuthentication]
    permission_classes = [IsAuthenticated]
    serializer_class = UserSerializer
    queryset = User.objects.all()

    def create(self, request):
        try:
            # Check if user already exists
            if User.objects.filter(email=request.data['email']).count() > 0:
                return Response({'error': 'message.emailAlreadyExists'}, status=status.HTTP_400_BAD_REQUEST)
        except:
            return Response(status=status.HTTP_400_BAD_REQUEST)

        user_data = request.data.copy()

        # Generate password
        user_data['password'] = make_password(
            password=request.data['password'])

        serializer = self.get_serializer(data=user_data)

        if not serializer.is_valid():
            return Response(serializer.errors,
                            status=status.HTTP_400_BAD_REQUEST)

        log = AuditLog()
        log.user_email = request.data['name']
        log.action_type = Action.POST
        log.action_detail = 'register as a user (email)'
        log.save()

        serializer.save()

        # for user info
        user = User.objects.get(email=request.data['email'])
        user_info = UserInfo()
        user_info.user = user
        user_info.uuid = str(uuid.uuid4()).upper()

        if 'name' in request.data:
            user_info.name = request.data['name']
            user.is_active = False
            user.save()

        if 'memo' in request.data:
            user_info.memo = request.data['memo']

        user_info.save()

        return Response(serializer.data, status=status.HTTP_201_CREATED)

    def update(self, request, *args, **kwargs):
        if 'new_password' in request.data:

            user = self.get_object()

            if not check_password(password=request.data['password'], encoded=user.password):
                return Response({'error': 'message.wrongPassword'}, status=status.HTTP_400_BAD_REQUEST)

            new_password = make_password(password=request.data['new_password'])

            partial = kwargs.pop('partial', False)
            serializer = self.get_serializer(
                user, data={'password': new_password}, partial=partial)

            if not serializer.is_valid():
                return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

            log = AuditLog()
            log.user_email = user.username
            log.action_type = Action.PATCH
            log.action_detail = 'change password'
            log.save()

            serializer.save()

        elif 'is_activate' in request.data:
            if not request.user.is_staff:
                return Response(status=status.HTTP_401_UNAUTHORIZED)

            user = self.get_object()
            is_active = request.data['is_activate']

            partial = kwargs.pop('partial', False)
            serializer = self.get_serializer(user,
                                             data={'is_active': is_active}, partial=partial)

            if not serializer.is_valid():
                return Response(serializer.errors,
                                status=status.HTTP_400_BAD_REQUEST)

            log = AuditLog()
            log.user_email = user.username
            log.action_type = Action.PATCH
            log.action_detail = f'change is_active to {is_active}'
            log.save()

            serializer.save()

            # # Send mail
            # if is_active:
            #     email = {
            #         'subject': '[ECG Buddy] Account Activated',
            #         'message': f'Your account is now activated!',
            #         'from': settings.EMAIL_FROM,
            #         'to': user.email
            #     }

            #     mail = EmailMessage(
            #         email['subject'], email['message'], email['from'], [email['to']])
            #     mail.send()

        return Response(serializer.data, status=status.HTTP_200_OK)

    def destroy(self, request, *args, **kwargs):
        user = self.get_object()
        print(user)
        print(user.is_active)

        user.is_active = False
        print(user.is_active)
        user.save()

        log = AuditLog()
        log.user_email = user.username
        log.action_type = Action.DELETE
        log.action_detail = 'delete account'
        log.save()

        return Response(status=status.HTTP_200_OK)


class CustomAuthToken(ObtainAuthToken):
    permission_classes = [IsAuthenticated]

    @csrf_exempt
    def post(self, request):
        print(request.data)
        try:
            if 'social_account_id' in request.data:
                user = UserInfo.objects.get(
                    social_account_id=request.data['social_account_id']).user
                print(user)
            else:
                user = User.objects.get(username=request.data['username'])
        except:
            if request.data['type'] == 'email':
                return Response({'error': 'message.wrongEmailOrPassword'}, status=status.HTTP_404_NOT_FOUND)

            # no social account. create.
            user = User()
            user.email = request.data['email']
            user.username = request.data['username']
            user.password = make_password(password=request.data['password'])
            user.save()

            user_info = UserInfo()
            user_info.user = user
            user_info.uuid = str(uuid.uuid4()).upper()
            if 'social_account_id' in request.data:
                user_info.social_account_id = request.data['social_account_id']
                
            user_info.save()
            
            log = AuditLog()
            log.user_email = request.data['name']
            log.action_type = Action.POST
            log.action_detail = f'register as a user ({request.data["type"]})'
            log.save()

        if not user.is_active:
            return Response({'error': 'message.wrongEmailOrPassword'}, status=status.HTTP_404_NOT_FOUND)

        password = request.data['password']
        if request.data['type'] != 'email':
            password = f'{request.data["type"]}:{user.email}'

        if not check_password(password=password, encoded=user.password):
            return Response({'error': 'message.wrongEmailOrPassword'}, status=status.HTTP_401_UNAUTHORIZED)

        token, _ = Token.objects.get_or_create(user=user)

        user.last_login = datetime.datetime.now()
        user.save()

        log = AuditLog()
        log.user_email = user.username
        log.action_type = Action.POST
        log.action_detail = 'login'
        log.save()

        return Response({
            'user_id': user.id,
            'user_email': user.email,
            'is_staff': user.is_staff,
            'token': token.key
        }, status=status.HTTP_200_OK)

@csrf_exempt
def auth_callback(request: HttpRequest, auth_type:str) -> HttpResponse:
    if auth_type == 'google':
        return HttpResponse(status=status.HTTP_200_OK)

    if 'apple' in auth_type:
        if request.method != 'POST':
            return HttpResponse(status=status.HTTP_405_METHOD_NOT_ALLOWED)

        if 'id_token' not in request.POST:
            return HttpResponse(status=status.HTTP_400_BAD_REQUEST)

        # Get user info from Apple
        payload = request.POST['id_token'].split('.')[1]
        payload = base64.b64decode(payload + '==')
        payload = json.loads(payload)

        if auth_type == 'appleandroid':
            data = request.POST.copy()
            data['user'] = json.dumps({
                'email': payload['email']
            })

            to = f'intent://callback?{urlencode(data)}#Intent;package={"com.sglee487.medical_calculator"};scheme=signinwithapple;end'
            return redirect(to)

        return JsonResponse({
            'id': payload['sub'],
            'email': payload['email']
        })

    return HttpResponse(status=status.HTTP_400_BAD_REQUEST)



def createEpinephrineRateViewSet(request):
    request.data['created_at'] = datetime.datetime.now()
    return


def get_queryset_by_email(self) -> QuerySet:

    return


@csrf_exempt
def reset_password(request: HttpRequest) -> HttpResponse:
    print('resetpassword')
    print(request)
    print(request.POST)
    if request.method != 'POST':
        return HttpResponse(status=status.HTTP_405_METHOD_NOT_ALLOWED)

    if 'email' not in request.POST:
        return HttpResponse(status=status.HTTP_400_BAD_REQUEST)

    try:
        user = User.objects.get(username=request.POST['email'])
    except User.DoesNotExist:
        return HttpResponse(status=status.HTTP_404_NOT_FOUND)

    # Generate a random password
    characters = string.ascii_letters + string.digits
    password = ''.join(random.choice(characters) for _ in range(8))

    user.password = make_password(password)
    user.save()
    
    send_mail(
        '[Medical calculator] Password reset',
        f'Your new password is {password}',
        'sglee4872@naver.com',
        [user.email],
        fail_silently=False,
    )
    
    log = AuditLog()
    log.user_email = user.username
    log.action_type = Action.POST
    log.action_detail = 'reset password sent'
    log.save()

    return HttpResponse(status=status.HTTP_200_OK)


class EpinephrineRateViewSet(viewsets.ModelViewSet):
    authentication_classes = [TokenAuthentication]
    permission_classes = [IsAuthenticated]
    serializer_class = EpinephrineRateSwerializer
    queryset = User.objects.all()

    def create(self, request):
        return createEpinephrineRateViewSet(request, self.serializer_class)

    def get_queryset(self):
        return get_queryset_by_email(self)
