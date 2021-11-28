import win32evtlog
import xml.etree.ElementTree as ET
import ctypes
import sys
import yagmail
from datetime import timedelta
from datetime import datetime, timezone
import traceback
import smtplib
import datetime
from datetime import datetime
import time, traceback
from pathlib import Path
from SMWinservice import SMWinservice


def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False


def every(delay, task):
    next_time = time.time() + delay
    while True:
        time.sleep(max(0, next_time - time.time()))
        try:
            task()
        except Exception:
            traceback.print_exc()
            # in production code you might want to have this instead of course:
            # logger.exception("Problem while executing repetitive task.")
        # skip tasks if we are behind schedule:
        next_time += (time.time() - next_time) // delay * delay + delay


def run():

    def ALERT(key_data, alert_print):
        #send and receive alerts from a non google email (smtp server)
        smtpServer = 'smtp Server IP'

        fromAddr = 'info@example.com'

        toAddr = 'info@example.com'

        text = """Subject:""" + alert_print + """\n\n""" + key_data

        server = smtplib.SMTP(smtpServer, 25)

        server.ehlo()

        server.sendmail(fromAddr, toAddr, text)

        server.quit()

    # open event file
    query_handle = win32evtlog.EvtQuery(
        'C:\Windows\System32\winevt\Logs\ForwardedEvents.evtx',
        win32evtlog.EvtQueryFilePath)

    ## Original datetime
    datetime_original = datetime.now(timezone.utc)
    datetime_utc = str(datetime_original)[5:10]
    today = datetime.today()
    date_today = str(today)[5:10]

    ## Subtracting Minute(s)
    minutes_to_add = 2
    datetime_new = datetime_original - timedelta(minutes=minutes_to_add)

    snip_time = str(datetime_new)
    new_snip = snip_time[11:17]
    end_snip = new_snip[2:5]
    minus_snip = new_snip[:2]

    if int(minus_snip) >= 7:
        minus_snip = int(minus_snip) - 7
    else:
        minus_snip = int(minus_snip) + 24
        minus_snip = int(minus_snip) - 7

    if int(minus_snip) < 10:
        minus_snip = "0" + str(minus_snip)

    fixed_time = str(minus_snip) + end_snip

    print("After subtracting minutes: ", fixed_time)
    print(date_today, "\n")

    alert_ids = "1102, 7045, 4732, 4733, 4720, 4726, 4756, 4757, 4728, 4729, 4723, 4724"
    login_off = "4625, 4624"

    read_count = 0
    while True:
        try:

            events = win32evtlog.EvtNext(query_handle, 100)

            read_count += len(events)
            # if there is no record break the loop
            if len(events) == 0:
                break
            for event in events:

                xml_content = win32evtlog.EvtRender(event, win32evtlog.EvtRenderEventXml)
                # parse xml content

                xml = ET.fromstring(xml_content)

                for data in xml.findall("EventData"):
                    name = data.get('Data Name')
                    print(name)

                # xml namespace, root element has a xmlns definition, so we have to use the namespace
                ns = '{http://schemas.microsoft.com/win/2004/08/events/event}'

                try:
                    time_created = xml[0][7].get('SystemTime')
                    date_created = str(time_created)[5:10]
                except:
                    time_created = snip_time[11:17]
                    date_created = date_today

                if snip_time[11:17] in time_created:

                    try:
                        substatus = "Sub Status: " + xml.find('.//*[@Name="SubStatus"]').text
                    except:
                        substatus = "None"

                    try:
                        workstationname = "Workstation Name: " + xml.find('.//*[@Name="WorkstationName"]').text
                    except:
                        workstationname = "None"

                    try:
                        ipaddress = "Ip Address: " + xml.find('.//*[@Name="IpAddress"]').text
                    except:
                        ipaddress = "None"

                    try:
                        targetusername = "Target User Name: " + xml.find('.//*[@Name="TargetUserName"]').text
                    except:
                        targetusername = "None"

                    if targetusername is None:
                        targetusername = "None"

                    if targetusername[-1] != "-":
                        targetusername += " (Who it was done to)"

                    try:
                        raw_targetusername = xml.find('.//*[@Name="TargetUserName"]').text
                    except:
                        raw_targetusername = "None"

                    if raw_targetusername is None:
                        raw_targetusername = "None"


                    try:
                        subjectusername = "Subject User Name: " + xml.find('.//*[@Name="SubjectUserName"]').text
                    except:
                        subjectusername = "None"

                    if subjectusername[-1] != "-":
                        subjectusername += " (Who did it)"

                    try:
                        imagepath = "Image Path: " + xml.find('.//*[@Name="ImagePath"]').text
                    except:
                        imagepath = "None"

                    try:
                        targetusersid = "Target User Sid: " + xml.find('.//*[@Name="TargetUserSid"]').text
                    except:
                        targetusersid = "None"

                    try:
                        processname = "Process Name: " + xml.find('.//*[@Name="ProcessName"]').text
                    except:
                        processname = "None"

                    try:
                        logonprocessname = "Logon Process Name: " + xml.find('.//*[@Name="LogonProcessName"]').text
                    except:
                        logonprocessname = "None"

                    try:
                        processid = "Process Id: " + xml.find('.//*[@Name="ProcessId"]').text
                    except:
                        processid = "None"

                    try:
                        raw_processid = xml.find('.//*[@Name="ProcessId"]').text
                    except:
                        raw_processid = "None"

                    try:
                        eventrecordID = "Event Record ID: " + xml[0][8].text
                    except:
                        eventrecordID = "Unknown"

                    try:
                        computer = "Computer: " + xml[0][12].text
                    except:
                        computer = "Unknown"

                    event_id = xml[0][1].text
                    str(event_id)

                    alert_print = ""

                    if event_id == "1102":
                        alert_print = "Security log was cleared"
                    elif event_id == "7045":
                        alert_print = "A new service was installed"
                    elif event_id == "4732":
                        alert_print = "A member was added to local security enabled group"
                    elif event_id == "4733":
                        alert_print = "A member was removed from security enabled group"
                    elif event_id == "4720":
                        alert_print = "A user account was created"
                    elif event_id == "4726":
                        alert_print = "A user account was deleted"
                    elif event_id == "4756":
                        alert_print = "A member was added to universal security group"
                    elif event_id == "4757":
                        alert_print = "A member was removed from universal security group"
                    elif event_id == "4728":
                        alert_print = "A member was added to security enabled global group"
                    elif event_id == "4729":
                        alert_print = "A member was removed from security enabled global group"
                    elif event_id == "4723":
                        alert_print = "An attempt was made to change an account's password"
                    elif event_id == "4724":
                        alert_print = "An attempt was made to reset an accounts password"
                    elif event_id == "4625":
                        alert_print = "There was an unsuccessful login attempt"
                    elif event_id == "4624":
                        alert_print = "There was a successful logon"
                    elif event_id == "111":
                        alert_print = "Change made to subscriptions program continuing scan"

                    if event_id == "111" and snip_time[11:17] in time_created and datetime_utc in date_created:
                        continue


                    variable_data = substatus, workstationname, ipaddress, targetusername, targetusersid, subjectusername, imagepath, \
                                    processname, logonprocessname, processid, eventrecordID, computer

                    event_data = f"{alert_print}\nTime: {time_created[:19]}\nEvent Id: {event_id}\n"

                    for data_loop in variable_data:
                        if data_loop != "None":
                            if data_loop[-1] != "-":
                                event_data += data_loop + "\r\n"
                                
                                
                    if snip_time[11:17] in time_created and datetime_utc in date_created and str(
                            event_id) in login_off and str(raw_targetusername).lower() == "administrator":
                        if "4624" in str(event_id):
                            ALERT(event_data, alert_print)
                            print(event_data)
                        if "4625" in str(event_id):
                            ALERT(event_data, alert_print)
                            print(event_data)

                    if snip_time[11:17] in time_created and datetime_utc in date_created and str(
                            event_id) in login_off and str(raw_targetusername).lower() == "another example of target username.exe":
                        if "4624" in str(event_id):
                            ALERT(event_data, alert_print)
                            print(event_data)
                        if "4625" in str(event_id):
                            ALERT(event_data, alert_print)
                            print(event_data)


                    if snip_time[11:17] in time_created and datetime_utc in date_created \
                            and str(event_id) in login_off and str(raw_targetusername).lower() == "sc":
                        yag = yagmail.SMTP('gmail example: test@gmail.com', 'app password')
                        yag.send(to=' example: 8183467643@mms.att.net',
                                 subject='ALERT',
                                 contents=str(event_data))
                        print(event_data)



                    if snip_time[11:17] in time_created and datetime_utc in date_created and str(event_id) in alert_ids:
                        ALERT(event_data, alert_print)
                        print(event_data)


        except Exception:
            err = traceback.format_exc()
            print(err)
            yag = yagmail.SMTP('gmail example: test@gmail.com', 'app password')
            yag.send(to='example: 8187865473@mms.att.net',
                     subject='ERROR',
                     contents=str(err))
            input()

def main():
    if is_admin():
        every(60, run)
    else:
        ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, " ".join(sys.argv), None, 1)

class PythonCornerExample(SMWinservice):
    _svc_name_ = "Login Secure"
    _svc_display_name_ = "Login Secure"
    _svc_description_ = "Scanning through win event log"

    def start(self):
        self.isrunning = True

    def stop(self):
        self.isrunning = False

    def main(self):
        main()
        

if __name__ == '__main__':
    PythonCornerExample.parse_command_line()