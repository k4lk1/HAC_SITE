from django.contrib import admin
from django.urls import path, include
from django.contrib.auth import views as auth_views
from django.conf import settings
from django.conf.urls.static import static
import vuln_scanner.urls
from vuln_scanner.urls import url
from users import views as user_views


admin.site.site_title = "Admin Panel"
admin.site.site_header = "HAC-SEC-Administration"
admin.site.index_title = "HAC-SEC"


urlpatterns = [
    # vuln_scanner app's urls
    path('',include('vuln_scanner.urls')),

    # admin pane;
    path('admin/', admin.site.urls),

    # profile page
    path('profile/',user_views.profile,name='profile'),

    # register page
    path('register/',user_views.register, name='register'),    

    #login page
    path('login/',user_views.user_login, name='login'),    

    # logout user
    path('logout/',user_views.user_logout, name='logout'),
]


if settings.DEBUG:
    urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)