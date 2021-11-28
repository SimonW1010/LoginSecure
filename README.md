# LoginSecure
Windows event collector service which monitors all forwarded events for any elevated logins/log offs or any universal changes in admin elevation, deletion or successful access/attempt 

## Imports
Imports needed:
```
import win32evtlog
import xml.etree.ElementTree
import ctypes
import sys
import yagmail
import datetime
import traceback
import smtplib
import datetime
import time 
import traceback
import pathlib
```

## Creating google app password
Follow simple instructions here under "Create and use App Passwords"
> [Google instructions link](https://support.google.com/mail/answer/185833?hl=en)
> 
Place developers gmail and created app password in line 283 and 299 of main file

## add email to send/receive alerts
Add emails server IP in line 42 of main and add email address in line 44 and 46
>NOTE: this is only for using non gmail emails. To easily use a gmail simply replace lines 41 - 56 with
```
yag = yagmail.SMTP('gmail example: test@gmail.com', 'app password')
yag.send(to=' example: 8183467643@mms.att.net',
         subject='alert_print',
         contents=str(event_data))
print(event_data)
```
# Adding events to Windows forwarded events
Open Windows event viewer (Windows + R and type: eventvwr)
>![Subscription Location](https://user-images.githubusercontent.com/93505099/143784391-a4fbffc4-cb24-4df2-a18f-a296988988bb.png)

>Click "create subscription" on the right side of the event viewer
>![Screenshot 2021-11-28 121937](https://user-images.githubusercontent.com/93505099/143784526-06f372f5-6acc-4eb3-8a0a-67c38e932c4f.png)

>Configure Event Id's and computer from which to forward events from and too
>
>For more help on how to forward events visit [Forwarding Events](https://adamtheautomator.com/windows-event-collector/)
>NOTE: Be sure to add Forwarded Events as Destination Log!

# Run it as a Windows Service
Open Windows command terminal (Windows + R Type: cmd)
>type 
>```cd C:\Users\ Location of LoginSecure file```
>
>When you are in the correct directory type
>```python main.pyw install```
>Go to Windows services (Windows + R Type: services.msc)
>Find Login Secure Service and make sure it is running 
>Right click > properties and make sure "Startup Type" is set to "Automatic"
