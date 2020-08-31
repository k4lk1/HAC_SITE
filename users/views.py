from django.shortcuts import render,redirect
from django.contrib import messages

from django.contrib.auth.forms import UserCreationForm
from django.contrib.auth.decorators import login_required
from django.contrib.auth.models import User
from django.contrib.auth import authenticate, login, logout


from .forms import UserRegisterForm, UserUpdateForm, ProfileUpdateForm, LoginForm

#def index(request):
#    return render(request,'users/login.html')

# login view
def user_login(request):
    if request.user.is_authenticated:
        return redirect('/')

    if request.method == "POST":
        username = request.POST.get('username')
        password = request.POST.get('password')

        user = authenticate(username=username, password=password)

        if user:
            if user.is_active:
                login(request, user)                
                return redirect('/')
            else:
                login_form = LoginForm()

                return render(request,'users/login.html', {"errors":"Account is not active! Please activate your account!","login_form":login_form})
        else:
            login_form = LoginForm()

            return render(request,'users/login.html', {"errors":"Invalid username or password!","login_form":login_form})
            
    else:
        login_form = LoginForm()
        return render(request, 'users/login.html',{"login_form":login_form})

# logout view
@login_required(login_url="/login/")
def user_logout(request):
    logout(request)
    return redirect('login')

#registration view
def register(request):
    if request.user.is_authenticated:
        return redirect('/')

    form = UserRegisterForm()

    if request.method == 'POST':
        form = UserRegisterForm(request.POST)
        if form.is_valid():
            form.save() 
            username = form.cleaned_data.get('username')
            messages.success(request, f'Account created for {username}!')
            return redirect('login')
        else:
            return render(request, 'users/register.html', {'form':form})
    else:        
        return render(request, 'users/register.html', {'form':form})

# profile view
@login_required(login_url="/login/")
def profile(request):
    if request.method == "POST":
        u_form=UserUpdateForm(request.POST,instance=request.user)
        p_form=ProfileUpdateForm(request.POST, request.FILES ,instance=request.user.profile)

        if u_form.is_valid() and p_form.is_valid():
            u_form.save()
            p_form.save()
            messages.success(request, f'Account updated!')
            return redirect('profile')
    else:
        u_form=UserUpdateForm(instance=request.user)
        p_form=ProfileUpdateForm(instance=request.user.profile)
         

    context = {
        'u_form':u_form,
        'p_form':p_form
    }
    return render(request,'users/profile.html',context)



