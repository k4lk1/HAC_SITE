from django import forms
from django.contrib.auth.models import User
from django.contrib.auth.forms import UserCreationForm
from .models import Profile

# Form for User Registration
class UserRegisterForm(UserCreationForm):
    # email = forms.EmailField()
    password1 = forms.CharField(widget=forms.PasswordInput(attrs={'pattern':"(?=.*\d)(?=.*[a-z])(?=.*[A-Z]).{8,}", 'title':"Must contain at least one number and one uppercase and lowercase letter, and at least 8 or more characters"}),label="Password")
    password2 = forms.CharField(widget=forms.PasswordInput(attrs={'pattern':"(?=.*\d)(?=.*[a-z])(?=.*[A-Z]).{8,}", 'title':"Must contain at least one number and one uppercase and lowercase letter, and at least 8 or more characters"}),label="Confirm Password")

    class Meta:
        model=User
        fields = ['username','email','password1','password2']

    # adding CSS Classes 
    def __init__(self, *args, **kwargs):
        super(UserRegisterForm, self).__init__(*args, **kwargs)
        for visible in self.visible_fields():
            visible.field.widget.attrs['class'] = 'form-control'
            visible.field.widget.attrs['placeholder'] = visible.field.label          

        for field in self.Meta.fields:
            self.fields[field].required = True    


class UserUpdateForm(forms.ModelForm):
    # email = forms.EmailField()

    class Meta:
        model = User    
        fields = ['username','email']

    # adding CSS Classes 
    def __init__(self, *args, **kwargs):
        super(UserUpdateForm, self).__init__(*args, **kwargs)
        for visible in self.visible_fields():
            visible.field.widget.attrs['class'] = 'form-control'
            visible.field.widget.attrs['placeholder'] = visible.field.label          

        for field in self.Meta.fields:
            self.fields[field].required = True    

class ProfileUpdateForm(forms.ModelForm):
    class Meta:
        model = Profile
        fields = ['image']

    # adding CSS Classes 
    def __init__(self, *args, **kwargs):
        super(ProfileUpdateForm, self).__init__(*args, **kwargs)
        for visible in self.visible_fields():
            visible.field.widget.attrs['class'] = 'form-control'
            visible.field.widget.attrs['placeholder'] = visible.field.label
        

class LoginForm(forms.ModelForm):
    password = forms.CharField(widget=forms.PasswordInput(),label="Password")

    class Meta():
        model = User
        fields = ('username', 'password')
    
    def __init__(self, *args, **kwargs):
        super(LoginForm, self).__init__(*args, **kwargs)
        for visible in self.visible_fields():
            visible.field.widget.attrs['class'] = 'form-control'
            visible.field.widget.attrs['placeholder'] = visible.field.label