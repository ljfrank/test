from django import forms
from django.core import validators
from django.contrib.auth import authenticate, login
from django.contrib.auth.models import User
from game.models import *

class TweetForm(forms.Form):
    tweet = forms.CharField(max_length=200, required=True, widget=forms.Textarea(attrs={'rows':'3', 'cols':'67'}))

class SignUpForm(forms.Form):
    username = forms.CharField(label='username', required=True, min_length=1, max_length=20)
    password = forms.CharField(label='password', widget=forms.PasswordInput, required=True, min_length=6, max_length=20)

    def clean_username(self):
        username = self.cleaned_data.get('username')
        try :
            User.objects.get(username=username)
        except User.DoesNotExist :
            return username
        raise validators.ValidationError('Username already existed. Plz modify.')

    def save(self, request):
        user = User.objects.create_user(self.cleaned_data['username'], None, self.cleaned_data['password']);
        user_profile = UserProfile(user=user)
        user.save()
        user_profile.save()
        user = authenticate(username=self.cleaned_data['username'], password=self.cleaned_data['password'])
        login(request, user)
        return user

class ChangePWForm(forms.Form):
    password = forms.CharField(label='password', widget=forms.PasswordInput, required=True, min_length=6, max_length=20)

class LogInForm(forms.Form):
    username = forms.CharField(label='username', required=True, max_length=20)
    password = forms.CharField(label='password', widget=forms.PasswordInput, required=True, max_length=20)

    def clean_username(self):
        username = self.cleaned_data.get('username')
        try:
            User.objects.get(username=username)
            return username
        except User.DoesNotExist:
            raise validators.ValidationError('Not valid username. You may want to signup first.')

    def clean(self):
        username = self.cleaned_data.get('username')
        password = self.cleaned_data.get('password')
        if authenticate(username=username, password=password) is None : raise validators.ValidationError('Password is not correct. Maybe check Caps Lock?')
        return self.cleaned_data

    def save(self, request):
        username = self.cleaned_data.get('username')
        password = self.cleaned_data.get('password')
        user = authenticate(username=username, password=password)
        login(request, user)
        return user
