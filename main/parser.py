import re
from collections import defaultdict
from datetime import datetime

from django.db import IntegrityError

from main.models import LogEvent
from main.tg_notifications import send_telegram_message

# Регулярные выражения для извлечения данных
date_pattern = r'(\w+\s+\d+)'
time_pattern = r'(\d+:\d+:\d+)'
event_pattern = r'(\w+)\[\d+\]'
auth_pattern = r'Accepted (\w+) for (\w+) from (\d+.\d+.\d+.\d+) port (\d+)'
session_open_pattern = r'session opened for user (\w+)\(uid=(\d+)\) by \(uid=(\d+)\)'
session_close_pattern = r'session closed for user (\w+)'
new_session_pattern = r'New session (\d+) of user (\w+)'
sudo_fail_pattern = r'sudo: pam_unix\(sudo:auth\): (.*)'
connection_closed_pattern = r'Connection closed by authenticating user (\w+) (\d+\.\d+\.\d+\.\d+) port (\d+)'
received_disconnect_pattern = r'Received disconnect from (\d+\.\d+\.\d+\.\d+) port (\d+):'
disconnected_user_pattern = r'Disconnected from user (\w+) (\d+\.\d+\.\d+\.\d+) port (\d+)'
auth_failure_pattern = r'pam_unix\(sshd:auth\): authentication failure.*?user=(\w+)'
failed_password_pattern = r'Failed password for (\w+) from (\d+\.\d+\.\d+\.\d+) port (\d+)'
sshd_server_listening_pattern = r'Server listening on (.*) port (\d+)'
new_session_logind_pattern = r'systemd-logind\[\d+\]: New session (\d+) of user (\w+).'
session_logged_out_pattern = r'systemd-logind\[\d+\]: Session (\d+) logged out. Waiting for processes to exit.'
session_removed_pattern = r'systemd-logind\[\d+\]: Removed session (\d+).'


def parse_log_line(line):
    date_match = re.search(date_pattern, line)
    time_match = re.search(time_pattern, line)
    event_match = re.search(event_pattern, line)
    auth_match = re.search(auth_pattern, line)
    session_open_match = re.search(session_open_pattern, line)
    session_close_match = re.search(session_close_pattern, line)
    new_session_match = re.search(new_session_pattern, line)
    sudo_fail_match = re.search(sudo_fail_pattern, line)
    connection_closed_match = re.search(connection_closed_pattern, line)
    received_disconnect_match = re.search(received_disconnect_pattern, line)
    disconnected_user_match = re.search(disconnected_user_pattern, line)
    auth_failure_match = re.search(auth_failure_pattern, line)
    failed_password_match = re.search(failed_password_pattern, line)
    sshd_server_listening_match = re.search(sshd_server_listening_pattern, line)
    new_session_logind_match = re.search(new_session_logind_pattern, line)
    session_logged_out_match = re.search(session_logged_out_pattern, line)
    session_removed_match = re.search(session_removed_pattern, line)

    date_str, time_str, event, auth_type, user, ip, port, session_event, session_user, session_uid, session_by_uid, \
        session_id, sudo_fail_message = None, None, None, None, None, None, None, None, None, None, None, None, None
    connection_closed_user, connection_closed_ip, connection_closed_port = None, None, None
    received_disconnect_ip, received_disconnect_port = None, None
    disconnected_user, disconnected_ip, disconnected_port = None, None, None
    auth_failure_user = None
    failed_password_user, failed_password_ip, failed_password_port = None, None, None
    sshd_server_listening_address, sshd_server_listening_port = None, None
    new_session_logind_id, new_session_logind_user = None, None
    session_logged_out_id = None
    session_removed_id = None

    if date_match and time_match:
        date_str = date_match.group(1)
        time_str = time_match.group(1)

    if event_match:
        event = event_match.group(1)

    if auth_match:
        auth_type = auth_match.group(1)
        user = auth_match.group(2)
        ip = auth_match.group(3)
        port = auth_match.group(4)

    if session_open_match:
        session_event = 'session_open'
        session_user = session_open_match.group(1)
        session_uid = session_open_match.group(2)
        session_by_uid = session_open_match.group(3)

    if session_close_match:
        session_event = 'session_close'
        session_user = session_close_match.group(1)

    if new_session_match:
        session_event = 'new_session'
        session_id = new_session_match.group(1)
        session_user = new_session_match.group(2)

    if sudo_fail_match:
        session_event = 'sudo_fail'
        sudo_fail_message = sudo_fail_match.group(1)

    if connection_closed_match:
        session_event = 'connection_closed'
        connection_closed_user = connection_closed_match.group(1)
        connection_closed_ip = connection_closed_match.group(2)
        connection_closed_port = connection_closed_match.group(3)

    if received_disconnect_match:
        session_event = 'received_disconnect'
        received_disconnect_ip = received_disconnect_match.group(1)
        received_disconnect_port = received_disconnect_match.group(2)

    if disconnected_user_match:
        session_event = 'disconnected_user'
        disconnected_user = disconnected_user_match.group(1)
        disconnected_ip = disconnected_user_match.group(2)
        disconnected_port = disconnected_user_match.group(3)

    if auth_failure_match:
        session_event = 'auth_failure'
        auth_failure_user = auth_failure_match.group(1)

    if failed_password_match:
        session_event = 'failed_password'
        failed_password_user = failed_password_match.group(1)
        failed_password_ip = failed_password_match.group(2)
        failed_password_port = failed_password_match.group(3)

    if sshd_server_listening_match:
        session_event = 'sshd_server_listening'
        sshd_server_listening_address = sshd_server_listening_match.group(1)
        sshd_server_listening_port = sshd_server_listening_match.group(2)

    if new_session_logind_match:
        session_event = 'new_session_logind'
        new_session_logind_id = new_session_logind_match.group(1)
        new_session_logind_user = new_session_logind_match.group(2)

    if session_logged_out_match:
        session_event = 'session_logged_out'
        session_logged_out_id = session_logged_out_match.group(1)

    if session_removed_match:
        session_event = 'session_removed'
        session_removed_id = session_removed_match.group(1)

    return (date_str, time_str, event, auth_type, user, ip, port, session_event, session_user, session_uid,
            session_by_uid, session_id, sudo_fail_message, connection_closed_user, connection_closed_ip,
            connection_closed_port, received_disconnect_ip, received_disconnect_port, disconnected_user,
            disconnected_ip, disconnected_port, auth_failure_user, failed_password_user, failed_password_ip,
            failed_password_port, sshd_server_listening_address, sshd_server_listening_port, new_session_logind_id,
            new_session_logind_user, session_logged_out_id, session_removed_id)


def parse_log_file(log_file):
    log_data = defaultdict(list)

    for line in log_file:
        parsed_data = parse_log_line(line.strip().decode('utf-8'))
        date_str, time_str, event, auth_type, user, ip, port, session_event, session_user, session_uid, \
            session_by_uid, session_id, sudo_fail_message, connection_closed_user, connection_closed_ip, \
            connection_closed_port, received_disconnect_ip, received_disconnect_port, disconnected_user, \
            disconnected_ip, disconnected_port, auth_failure_user, failed_password_user, failed_password_ip, \
            failed_password_port, sshd_server_listening_address, sshd_server_listening_port, \
            new_session_logind_id, new_session_logind_user, session_logged_out_id, session_removed_id = parsed_data

        log_data[(date_str, time_str)].append((event, auth_type, user, ip, port, session_event, session_user,
                                               session_uid, session_by_uid, session_id, sudo_fail_message,
                                               connection_closed_user, connection_closed_ip, connection_closed_port,
                                               received_disconnect_ip, received_disconnect_port, disconnected_user,
                                               disconnected_ip, disconnected_port, auth_failure_user,
                                               failed_password_user, failed_password_ip, failed_password_port,
                                               sshd_server_listening_address, sshd_server_listening_port,
                                               new_session_logind_id, new_session_logind_user,
                                               session_logged_out_id,
                                               session_removed_id))

    return log_data


def save_logs_to_bd(log_data):
    send_telegram_message(f'New log file has been uploaded. Total events: {sum(len(v) for v in log_data.values())}')
    for key, value in log_data.items():
        date_time = key
        if date_time[0] is None or date_time[1] is None:
            continue  # Skip this entry if date_time contains None

        for item in value:
            event, auth_type, user, ip, port, session_event, session_user, session_uid, session_by_uid, session_id, \
                sudo_fail_message, connection_closed_user, connection_closed_ip, connection_closed_port, \
                received_disconnect_ip, received_disconnect_port, disconnected_user, disconnected_ip, \
                disconnected_port, auth_failure_user, failed_password_user, failed_password_ip, failed_password_port, \
                sshd_server_listening_address, sshd_server_listening_port, new_session_logind_id, \
                new_session_logind_user, session_logged_out_id, session_removed_id = item

            datetime_str = datetime.strptime(f"{date_time[0]} {date_time[1]}", "%b %d %H:%M:%S").strftime(
                "%Y-%m-%d %H:%M:%S")
            datetime_str = datetime.strptime(datetime_str, "%Y-%m-%d %H:%M:%S").replace(
                year=datetime.now().year).strftime("%Y-%m-%d %H:%M:%S")

            try:
                LogEvent.objects.get_or_create(
                    datetime=datetime_str,
                    event_type=event,
                    auth_type=auth_type,
                    username=user,
                    ip_address=ip,
                    port=port,
                    session_event=session_event,
                    session_username=session_user,
                    session_uid=session_uid,
                    session_by_uid=session_by_uid,
                    session_id=session_id,
                    sudo_fail_message=sudo_fail_message,
                    connection_closed_username=connection_closed_user,
                    connection_closed_ip=connection_closed_ip,
                    connection_closed_port=connection_closed_port,
                    received_disconnect_ip=received_disconnect_ip,
                    received_disconnect_port=received_disconnect_port,
                    disconnected_username=disconnected_user,
                    disconnected_ip=disconnected_ip,
                    disconnected_port=disconnected_port,
                    auth_failure_username=auth_failure_user,
                    failed_password_username=failed_password_user,
                    failed_password_ip=failed_password_ip,
                    failed_password_port=failed_password_port,
                    sshd_listening_address=sshd_server_listening_address,
                    sshd_listening_port=sshd_server_listening_port,
                    new_session_logind_id=new_session_logind_id,
                    new_session_logind_user=new_session_logind_user,
                    session_logged_out_id=session_logged_out_id,
                    session_removed_id=session_removed_id
                )
                temp_date_time = datetime.strptime(datetime_str, "%Y-%m-%d %H:%M:%S")
                send_telegram_message(f'Added new log event: {event} at {temp_date_time.strftime("%Y-%m-%d %H:%M:%S")}')
            except IntegrityError:
                continue
