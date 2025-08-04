# Introduction

Hello World! I'm back with another TryHackMe writeup and diving further into investigation with Splunk! This room dives a lot deeper into investigating different event IDs with Splunk and really getting you to think outside the box. This room had me in a few rabbit holes but taught me how to be better at looking in between the lines. Let's hop into it!

Room Link: https://tryhackme.com/room/investigatingwithsplunk

### Context

Not much context is given besides the fact that an adversary had created several backdoors that we'll dig up. Not as relevant but we are assisting SOC Analyst Johny in this investigation!

Go ahead and boot up that machine and launch up your AttackBox (or connect to THM VPN)!
You can navigate to the Target IP Address as a url in your AttackBox's web browser to access Splunk.
<img width="952" height="509" alt="Pasted image 20250804150829" src="https://github.com/user-attachments/assets/8611fc9c-ae94-4268-9f9f-d39603d73f73" />

## Challenge

### Question 1: "How many events were collected and Ingested in the index **main**?"

Make sure to set the time filter to "All time" the search the "main" index. 
<img width="950" height="593" alt="Pasted image 20250804151358" src="https://github.com/user-attachments/assets/9bf7f68e-b1c3-4652-bb72-8437a3a9e4db" />

Answer: 12256


### Question 2: "On one of the infected hosts, the adversary was successful in creating a backdoor user. What is the new username?"

Windows Event Logs have an Event ID for almost anything done on a Windows system. A quick Google search for "windows event id new user account created" gives us the following:
<img width="1173" height="433" alt="Pasted image 20250804151847" src="https://github.com/user-attachments/assets/d9d25884-b182-4919-9355-d4894cabad24" />

We can search for events with EventID field having the value of "4720": `index=main  EventID=4720`. Exactly one event will show up and we can parse through the "Message" field to find the answer.
<img width="953" height="466" alt="Pasted image 20250804153213" src="https://github.com/user-attachments/assets/47965316-3e62-409c-b950-c6b1f911145e" />
<img width="625" height="588" alt="Pasted image 20250804153150" src="https://github.com/user-attachments/assets/e9baf57d-b217-4d68-9b4e-7ea37922eedb" />

Looks like our adversary is attempting to impersonate Alberto by replace the "i" with a "1".

Answer: A1berto


### Question 3: "On the same host, a registry key was also updated regarding the new backdoor user. What is the full path of that registry key?"

Back to Googling because I won't ever remember these event IDs :)
Searching up "event id registry key updated" will provide us the following:
<img width="1157" height="482" alt="Pasted image 20250804153856" src="https://github.com/user-attachments/assets/a34285e5-b2c8-4c22-943e-d99ecb46b6f0" />

When querying for Event ID 4657 and the keywork "A1berto", no events are returned. To save you the hassle, this is where I fell down a rabbit hole and was looking through a lot of logs to make sense of all fields available.
<img width="452" height="221" alt="Pasted image 20250804154656" src="https://github.com/user-attachments/assets/37525cdc-6687-4f5a-a74b-f2fbfae45fdd" />

So after an hour of looking through those countless logs, I had found out that the logs were also ingesting Sysmon data so decided to look up the Sysmon ID instead of registry key updates.
<img width="1180" height="513" alt="Pasted image 20250804154347" src="https://github.com/user-attachments/assets/5d6febeb-731d-48b8-81e3-690139bab405" />

Using my query: `index=main EventID=13 | search A1berto`
One event returned with the registry key we were looking for!
<img width="635" height="547" alt="Pasted image 20250804154927" src="https://github.com/user-attachments/assets/061a1793-0699-45f9-ac41-f8c6b130f894" />

This just goes to show why it's important to understand the index you're investigating and know what you're looking for.

Answer: HKLM\SAM\SAM\Domains\Account\Users\Names\A1berto
*(Strip off the "(Default)" as that is not the part of the registry key path)*



### Question 4: "Examine the logs and identify the user that the adversary was trying to impersonate."

This question is pretty easy to guess but I'll show a quick query that displays all values in the field "SubjectUserName" so you can be 100% sure!
`index=main | stats count by SubjectUserName`
<img width="951" height="511" alt="Pasted image 20250804155610" src="https://github.com/user-attachments/assets/17baf672-fca7-4cc7-b97b-202a0829fd81" />


Answer: Alberto



### Question 5: "What is the command used to add a backdoor user from a remote computer?"

I had several approaches to this question but had accidently stumbled onto the answer by listing out the values of the "CommandLine" field.
<img width="942" height="368" alt="Pasted image 20250804155939" src="https://github.com/user-attachments/assets/5b50657f-05e4-411b-91e4-67902cd817db" />

Several approaches to consider:
1. Event ID 4688 logs process creation
2. Looking for commands that had "A1berto" string
3. Checking for suspicious public IPs

Answer: `C:\windows\System32\Wbem\WMIC.exe" /node:WORKSTATION6 process call create "net user /add A1berto paw0rd1`


### Question 6: "How many times was the login attempt from the backdoor user observed during the investigation?"

This question also had me in a bit of confusion but turns out, there actually was no log in attempts from the backdoor user at all.
My query searched for events with field "EventID" having any of the following values: 3, 4625.
These are both Windows log and Sysmon IDs for login attempts.}
I had also included "| search A1lberto" to filter by event with that string.
![[Pasted image 20250804161220.png]]

After taking off the search command in my query, I checked the "User" field in the left hand fields column, these were the only login attempts observed in the "main" index.
<img width="874" height="466" alt="Pasted image 20250804161253" src="https://github.com/user-attachments/assets/38774db9-11ef-42ed-9704-0ea6fac9b9e7" />

Answer: 0


### Question 7: "What is the name of the infected host on which suspicious Powershell commands were executed?"

Going back to the event we found in question 5, I used the following query to pull it up again:
`index=main CommandLine="\"C:\\windows\\System32\\Wbem\\WMIC.exe\" /node:WORKSTATION6 process call create \"net user /add A1berto paw0rd1\""`
*(extra slashes added to escape certain characters)*

Instead of using the "stats count by" command to extract values in a field, we can head to the let field column and press on "All Fields",,,
<img width="488" height="493" alt="Pasted image 20250804161903" src="https://github.com/user-attachments/assets/f190e436-1637-4b13-8ed1-367f4d7557e1" />

Then searching for a field named "Hostname" and expanding the drop down list for that field.
<img width="891" height="436" alt="Pasted image 20250804162004" src="https://github.com/user-attachments/assets/f518367a-923b-489a-a348-9b52f2cc98ba" />

Answer: James.browne


### Question 8: "What is the name of the infected host on which suspicious Powershell commands were executed?"

I think the hardest thing about investigating Windows logs are the event IDs. Unless you've worked with it for a very long time and know many of the IDs to get what you're looking for, you'll have to go digging for event IDs to actually search for what you need.

It took me straight up 30 minutes to figure out that there were 2-4 different event IDs for Powershell logs: 4103, 4104, 4105, 4106.
<img width="1268" height="636" alt="Pasted image 20250804163054" src="https://github.com/user-attachments/assets/2065fe21-8aa5-4448-9ee0-f0e4a38c7a24" />

The correct EventID was 4103
<img width="399" height="273" alt="Pasted image 20250804163323" src="https://github.com/user-attachments/assets/c710bc67-c929-4ee3-acea-721c27e29581" />

Answer: 79


### Question 9: "An encoded Powershell script from the infected host initiated a web request. What is the full URL?"

Out of the 79 logs, only one appears to be interesting (and the first one to be shown when query EventID 4103). This event had an insanely long command within the "ContextInfo" field.
<img width="947" height="605" alt="Pasted image 20250804163718" src="https://github.com/user-attachments/assets/15308441-c190-4907-ab3f-d55df8152a69" />

We can view the event as raw text to easily copy it over to a text editor to analyze.
<img width="432" height="176" alt="Pasted image 20250804163825" src="https://github.com/user-attachments/assets/91fe1070-4b80-4b21-a18a-5b368d182040" />
<img width="1759" height="867" alt="Pasted image 20250804163911" src="https://github.com/user-attachments/assets/c65a3693-496a-4fff-8543-f653a02e1055" />

This area I've highlighted is the encrypted part of this powershell command. I copied this over to CyberChef to see if we can decode it. The two equal sign at the end of this long string indicates that this might be Base64.
<img width="1694" height="662" alt="Pasted image 20250804164156" src="https://github.com/user-attachments/assets/f5ec34e3-08fa-48a9-b289-8975c1aa92b0" />

My guess on Base64 was correct but you'll have to decode the text into UTF-16LE (1200) as the "From Base64" block will default to UTF 8.
<img width="1532" height="878" alt="Pasted image 20250804164428" src="https://github.com/user-attachments/assets/fc2ed25b-e151-4c1c-acc2-ad34d1cd752f" />

Within the decoded text, we have yet another Base 64 string to decode.![[Pasted image 20250804164557.png]]
<img width="963" height="209" alt="Pasted image 20250804164557" src="https://github.com/user-attachments/assets/bb348a3f-292c-4dd6-9731-48a02c489de8" />

This is just the domain part of the URL, looks like the question wants us to find the full URL. Going back to the full decoded Base64 string, there was a URI sitting in that line of code.
<img width="275" height="106" alt="Pasted image 20250804164853" src="https://github.com/user-attachments/assets/50cc80b0-0094-479a-b6a8-84153ede0d10" />

Putting it together, we have:
`http://10.10.10.5/news.php`

TryHackMe actually wants you to defang the URL as well before submitting the answer so we can do that with CyberChef as well.
<img width="1067" height="571" alt="Pasted image 20250804165050" src="https://github.com/user-attachments/assets/5351d656-d4d7-4cd7-8e9c-c297716f94f4" />

Answer: `hxxp[://]10[.]10[.]10[.]5/news[.]php`


# Conclusion

This room was pretty fun overall. Although I did have some struggle and confusion, the room had put me in a challenging position and really emulated what investigating alerts in a SOC environment looks like. The final parts of this room involving decoding a malicious PowerShell command felt like a fun little CTF! Thanks for reading, happy hacking!
