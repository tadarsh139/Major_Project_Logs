import win32evtlog
from datetime import datetime, timedelta
from django.shortcuts import render
from django.http import JsonResponse

def index(request):
    return render(request, 'logs/index.html')


def check_security_logs(request):
    server = 'localhost'  # Name of the target computer
    log_type = 'Security'

    # Set time frame to check (last 5 minutes)
    time_frame = datetime.now() - timedelta(minutes=5)

    # Read the log
    hand = win32evtlog.OpenEventLog(server, log_type)
    total_events = win32evtlog.GetNumberOfEventLogRecords(hand)
    
    failed_attempts = 0
    
    for i in range(total_events):
        event = win32evtlog.ReadEventLog(hand, win32evtlog.EVENTLOG_FORWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ, 0)
        
        # Check for failed logon event (event ID 4625)
        if event:
            for e in event:
                event_time = e.TimeGenerated
                if event_time >= time_frame:
                    if e.EventID == 4625:  # Failed logon
                        failed_attempts += 1

    if failed_attempts > 4:
        return JsonResponse({'status': 'Potential brute force attack detected!'})
    
    return JsonResponse({'status': 'No attack detected.'})
