
# Introduction

Hello World! This is marks my first ever writeup for a TryHackMe room so please let me know how I can improve my formatting or writing. 'Benign' essentially tests your ability to search through Windows event logs using Splunk Query Language to find indicators of compromise. Although the room is fairly simple, its good to grasp the fundamentals of Splunk through this challenge.

Room Link: https://tryhackme.com/room/benign

### Context

Before we dive in, it's important to take note of some information given to us in this scenario.
- tools related to *network information gathering* and *scheduled tasks were* executed
- the **"win_eventlogs"** index will only provide us Event ID: 4688
	- Windows Security Log event indicating new process creation
- There are three departments containing three users each.

Go ahead and boot up that machine and launch up your AttackBox (or connect to THM VPN)!
You can navigate to the Target IP Address as a url in your AttackBox's web browser to access Splunk.
<img width="954" height="519" alt="Pasted image 20250729183515" src="https://github.com/user-attachments/assets/0496223e-7717-446f-992c-ae3940394239" />


## Challenge

### Question 1: "How many logs are ingested from the month of March, 2022?"

Find the time filter to the right of the search bar. Set the time range between 03/01/2022 to 03/31/2022.
<img width="661" height="434" alt="Pasted image 20250729183833" src="https://github.com/user-attachments/assets/514f4175-f450-424a-a546-d4d7270b8303" />

Hit Apply then search the **"win_eventlogs"** index. You should be able to see the total number of logs in that month right under the search bar.
<img width="944" height="375" alt="Pasted image 20250729184154" src="https://github.com/user-attachments/assets/7b13211f-12de-4d2c-8707-a6df737ae16a" />

Answer: 13959


### Question 2: "Imposter Alert: There seems to be an imposter account observed in the logs, what is the name of that user?"

There are many ways to check for all values in a field. You can run the query: `index=win_eventlogs | stats count by UserName` which provides a count for each event with a unique UserName and list it in a table.
<img width="950" height="394" alt="Pasted image 20250729184433" src="https://github.com/user-attachments/assets/cb9cbde7-9766-4c0c-85cf-8bd7a363444c" />
Looks like someone is trying to impersonate Amelia by replacing the "i" with a "1" :o

Answer: Amel1a


### Question 3: "Which user from the HR department was observed to be running scheduled tasks?"

`schtasks` is a Windows command for creating, deleting, and editing scheduled tasks.
Since all logs are Process Creations, it's easy to figure out the format of each event. Just by looking at any event, we see that the ProcessName field contains which process was started and it's full path.
Using the following query, we can filter events only with `schtasks` as the process being created:
`index=win_eventlogs ProcessName="*schtasks.exe"`
<img width="952" height="625" alt="brave_Z31hErJSYa" src="https://github.com/user-attachments/assets/0e39cc4c-e27b-43d4-b24c-ed2aa82c16e7" />

Alright, we're getting closer. Let's filter the `schtasks` commands being ran and see which event runs a scheduled task.
The `schtasks` command has a flag that runs a given task : `/tr`
Looking through some of the logs, we see a field named CommandLine which specifies options, flags, and arguments the ProcessName ran with.
Using the following filter, we'll filter out only events running  `schtasks` with the `/tr` flag.
`index=win_eventlogs ProcessName="*schtasks.exe" CommandLine="*/tr*"`
<img width="925" height="647" alt="Pasted image 20250729190050" src="https://github.com/user-attachments/assets/e63fbbe7-422e-4383-b431-72be7df4bf87" />

Exactly one event was found with the running the follow command:
`schtasks.exe /create /tn OfficUpdater /tr "C:\Users\Chris.fort\AppData\Local\Temp\update.exe" /sc onstart` 
This command creates a task named OfficUpdater and runs an exe named update.exe. It's been scheduled to run on computer startup.
In a real SOC environment, we'd obviously have to look into this and ask questions such as "Is this normal or expected activity for this user?". Some things stand out to me as suspicious: Task name misspelled, an exe file from Temp folder, runs on startup indicating persistence. Lots of questions to be asked here but we must move on. 

Answer: Chris.fort


### Question 4: "Which user from the HR department executed a system process (LOLBIN) to download a payload from a file-sharing host."

For this specific question, we'll have to research into LOLBINs and LOLBAS (https://lolbas-project.github.io/). Here's a TLDR:
**LOLBIN** *(Living Off the Land Binary)* are legitimate, signed binaries (executables) that comes pre-installed in Windows and can be abused by attackers to perform malicious actions without triggering antivirus or EDR.
**LOLBAS** *(Living Off the Land Binaries and Scripts)* is a community-driven project that catalogs legitimate Windows binaries and scripts that can be abused by attackers for malicious purposes

There are several LOLBINs that can be used by threat actors to download payloads onto a compromised host: *certutil.exe, bitsadmin.exe, powershell.exe, msiexec.exe, rundll32.exe, curl.exe, wget.exe, mshta.exe, installutil.exe*
To be completely honest, I picked one of these binaries (certutil.exe) and queried it as a first guess and managed to find the alert indicating payload download. 😂
The query I used followed the same logic as the last question. For the CommandLine field, I had filtered for anything matching "http" as certutil is known for installing or verifying WEB certificates:
`index=win_eventlogs ProcessName="*certutil.exe*" CommandLine="*http*"`

Exactly one event returns and and the information here will provide us answers for the next few questions.
<img width="669" height="525" alt="Pasted image 20250729191633" src="https://github.com/user-attachments/assets/c56af0d5-7e48-4136-85dc-8d9a6c9aa973" />

Answer: haroon


### Question 5: "To bypass the security controls, which system process (lolbin) was used to download a payload from the internet?"

Answer: certutil.exe


### Question 6: "What was the date that this binary was executed by the infected host? format (YYYY-MM-DD)"

Answer: 2022-03-04


### Question 7: "Which third-party site was accessed to download the malicious payload?"

Answer: controlc.com


### Question 8: "What is the name of the file that was saved on the host machine from the C2 server during the post-exploitation phase?"

Answer: benign.exe


### Question 9: "The suspicious file downloaded from the C2 server contained malicious content with the pattern THM{..........}; what is that pattern?"

To figure out the contents of the exe, we'll have to navigate to the malicious domain to try and download whatever is on the other end. Without other event logs besides process creation in our Splunk index to identify the exe, this is our only way.
When visiting a malicious domain for any investigations, it's best practice to stay protected and utilize a sandbox. Here I used AnyRun to navigate to `"https://controlc.com/e4d11035"`.
<img width="1911" height="915" alt="image" src="https://github.com/user-attachments/assets/e6142260-ebc9-4cab-864f-c33934e2a811" />

Answer: THM{KJ&*H^B0}


### Question 10: "What is the URL that the infected host connected to?"

Answer: `"https://controlc.com/e4d11035"`

# Conclusion

Benign is a fairly easy room in terms of digging through logs for IOCs and suspicious activities. Being restricted to only one type of Windows event log does force some out-of-the-box thinking as well as the needed research into LOLBAS. Overall a very good beginner room for those learning Splunk and diving first time into SOC investigations. Thanks for reading, happy hacking!
