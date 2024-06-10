import json

from django import forms
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.decorators import login_required
from django.db.models import Count
from django.db.models.functions import TruncDate
from django.shortcuts import render, redirect

from main.models import *
from main.parser import parse_log_file, save_logs_to_bd
from main.tg_notifications import send_telegram_message


class DateInput(forms.DateInput):
    input_type = 'date'


@login_required
def index(request):
    if request.method == 'POST':
        file = request.FILES['file']
        logs = parse_log_file(file)
        print(logs)
        save_logs_to_bd(logs)
        return redirect('log_events')

    log_events = LogEvent.objects.all()
    total_events = log_events.count()
    unique_event_types = LogEvent.objects.values_list('event_type', flat=True).distinct()
    event_counts_by_date = LogEvent.objects.annotate(date=TruncDate('datetime')).values('date').annotate(
        count=Count('id')).order_by('date')
    event_counts_by_date_json = json.dumps(list(event_counts_by_date), default=str)
    event_type_counts = log_events.exclude(event_type__isnull=True).values('event_type').annotate(count=Count('event_type'))
    event_type_counts_json = json.dumps(list(event_type_counts))

    context = {
        'total_events': total_events,
        'event_type_counts_json': event_type_counts_json,
        'unique_event_types': unique_event_types,
        'event_counts_by_date_json': event_counts_by_date_json,
    }

    return render(request, 'index.html', context)


def login_view(request):
    if request.method == 'POST':
        username = request.POST['login']
        password = request.POST['password']
        user = authenticate(request, username=username, password=password)
        if user is not None:
            login(request, user)
            next_url = request.GET.get('next', 'index')
            send_telegram_message(f'User {username} logged in')
            return redirect(next_url)
    else:
        return render(request, 'login.html')


def logout_view(request):
    send_telegram_message(f'User {request.user.username} logged out')
    logout(request)
    return redirect('index')



@login_required
def log_events_view(request):
    event_types = request.GET.getlist('event_type')
    start_date = request.GET.get('start_date')
    end_date = request.GET.get('end_date')
    sort_by = request.GET.get('sort_by', 'datetime')
    sort_order = request.GET.get('sort_order', 'asc')
    start_time = request.GET.get('start_time')
    end_time = request.GET.get('end_time')

    log_events = LogEvent.objects.all().order_by(f'{"-" if sort_order == "desc" else ""}{sort_by}')

    if event_types:
        log_events = log_events.filter(event_type__in=event_types)

    if start_date:
        log_events = log_events.filter(datetime__date__gte=start_date)

    if end_date:
        log_events = log_events.filter(datetime__date__lte=end_date)

    if start_date and start_time:
        log_events = log_events.filter(datetime__gte=f'{start_date}T{start_time}')

    if end_date and end_time:
        log_events = log_events.filter(datetime__lte=f'{end_date}T{end_time}')

    unique_event_types = LogEvent.objects.values_list('event_type', flat=True).distinct()

    context = {
        'log_events': log_events,
        'unique_event_types': unique_event_types,
        'selected_event_types': event_types,
        'start_date': start_date,
        'end_date': end_date,
        'date_input': DateInput(),
        'sort_by': sort_by,
        'sort_order': sort_order,
    }
    return render(request, 'log_events.html', context)
