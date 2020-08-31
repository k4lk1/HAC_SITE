from django.urls import path

from . import views
from .views import SiteListView, SiteInput, SiteDetailView, SiteDeleteView, SiteReview, GeneratePDF, ReadStatusLFI, ReadStatusSQLI, ReadStatusIDOR, ReadStatusXSS

from users import views as user_views
from . import read_status
from django.conf.urls import url

urlpatterns= [
    # path('',user_views.index,name='index'),
    # path('home/',views.home,name='hac_sec-home'),

    # scan page
    path('',SiteInput.as_view() ,name='index'),
    
    #pdf report
    path('pdf/<int:pk>',GeneratePDF.as_view(), name='report'),

    # dashboard page
    path('dashboard/', SiteListView.as_view(), name='dashboard'),

    #detailed report page
    path('details/<int:pk>',SiteDetailView.as_view(),name='details'),

    #user scan report logs for lfi
    path('details/<int:pk>/lfi', ReadStatusLFI.as_view() , name='lfi'),

    #user scan report logs for sqli
    path('details/<int:pk>/sqli', ReadStatusSQLI.as_view(), name='sqli'),

    #user scan report logs for click
    #path('details/<int:pk>/click', views.read_click, name='click'),

    #user scan report logs for xss
    path('details/<int:pk>/xss', ReadStatusXSS.as_view(), name='xss'),

    #user scan report logs for idor
    path('details/<int:pk>/idor', ReadStatusIDOR.as_view(), name='idor'),
    #user_reviews
    path('reviews/', SiteReview.as_view(),name='reviews'),

    #delete scan report
    path('details/<int:pk>/delete/',SiteDeleteView.as_view(),name='delete'),


    # dashboard page
    path('dashboard/', SiteListView.as_view(), name='dashboard'),

    #detailed report page
    path('details/<int:pk>/',SiteDetailView.as_view(), name='details'),

    #user_reviews
    path('reviews/', SiteReview.as_view(), name='reviews'),

    #delete scan report
    path('details/<int:pk>/delete/',SiteDeleteView.as_view(), name='delete'),

    
]

