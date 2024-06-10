from django.urls import path, include

from main import views

urlpatterns = [
    path('', views.index, name='index'),
    path('log_events/', views.log_events_view, name='log_events'),
    path('login/', views.login_view, name='login_view'),
    path('logout/', views.logout_view, name='logout_view'),
]