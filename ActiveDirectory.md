
# Active Directory Events


![](/images/ad1.png)


## New Users

```
dataset = xdr_data // Using the xdr dataset
 | filter event_type = ENUM.EVENT_LOG and action_evtlog_event_id = 4720 
| alter  Account_Creator = arrayindex(regextract(action_evtlog_message, "\s+(?:[^:]+:){3}([^\n]+)"),0), User_Name = arrayindex(regextract(action_evtlog_message, "\s+(?:[^:]+:){8}([^\n]+)"),0), Domain = arrayindex(regextract(action_evtlog_message, "\s+(?:[^:]+:){9}([^\n]+)"),0)
| fields  User_Name as NEW_USER , Domain, Account_Creator as Who
| filter NEW_USER not contains "Administrator"
| sort desc _TIME 

```

###  New Users Graph 

```
dataset = xdr_data // Using the xdr dataset
 | filter event_type = ENUM.EVENT_LOG and action_evtlog_event_id = 4720 // Filtering by windows event log and id 4625

 // | fields action_evtlog_message
| alter  Account_Creator = arrayindex(regextract(action_evtlog_message, "\s+(?:[^:]+:){3}([^\n]+)"),0), User_Name = arrayindex(regextract(action_evtlog_message, "\s+(?:[^:]+:){8}([^\n]+)"),0), Domain = arrayindex(regextract(action_evtlog_message, "\s+(?:[^:]+:){9}([^\n]+)"),0)


| fields  User_Name as NEW_USER , Domain, Account_Creator as Who
| filter NEW_USER not contains "Administrator"

| comp count(NEW_USER )
| view graph type = gauge subtype = radial yaxis = count_1 maxscalerange = 20 scale_threshold("#5dad1a","#e40000","10") seriestitle("count_1","New Users") 

```




##  Users Enabled

```
dataset = xdr_data // Using the xdr dataset
 | filter event_type = ENUM.EVENT_LOG and action_evtlog_event_id = 4722 

 // | fields action_evtlog_message
| alter  Account_Creator = arrayindex(regextract(action_evtlog_message, "\s+(?:[^:]+:){3}([^\n]+)"),0), User_Name = arrayindex(regextract(action_evtlog_message, "\s+(?:[^:]+:){8}([^\n]+)"),0), Domain = arrayindex(regextract(action_evtlog_message, "\s+(?:[^:]+:){9}([^\n]+)"),0)
| fields  User_Name as Enabled_Account , Domain, Account_Creator as Who
| sort desc _TIME 

```

##  Users Disabled

```
dataset = xdr_data // Using the xdr dataset
| filter event_type = ENUM.EVENT_LOG and action_evtlog_event_id = 4725 
| alter  Account_Creator = arrayindex(regextract(action_evtlog_message, "\s+(?:[^:]+:){3}([^\n]+)"),0), User_Name = arrayindex(regextract(action_evtlog_message, "\s+(?:[^:]+:){8}([^\n]+)"),0), Domain = arrayindex(regextract(action_evtlog_message, "\s+(?:[^:]+:){9}([^\n]+)"),0)
| fields  User_Name as Disabled_Account , Domain, Account_Creator as Who
| sort desc _TIME 
```


## Locked User Accounts

```
dataset = xdr_data // Using the xdr dataset
| filter event_type = ENUM.EVENT_LOG and action_evtlog_event_id = 4740 
| alter  Locked_Account = arrayindex(regextract(action_evtlog_message, "\s+(?:[^:]+:){8}([^\n]+)"),0), Domain = arrayindex(regextract(action_evtlog_message, "\s+(?:[^:]+:){4}([^\n]+)"),0)
| fields  Locked_Account, Domain , agent_hostname as HOST
| sort desc _TIME 

```

## Local Admin Elevation using Consent

```
filter actor_process_image_name = "consent.exe"
| filter causality_actor_process_image_name not in ("consent.exe")
| fields _TIME as Time, agent_hostname, causality_actor_primary_username , actor_process_image_name, actor_process_image_path, causality_actor_process_image_name
| comp values(causality_actor_primary_username) as User by Time , causality_actor_primary_username, actor_process_image_name, actor_process_image_path
| fields  Time, User, actor_process_image_name, actor_process_image_path

```

## User Logons with Forensics

//Title: Security_4624_LogonEvents
//Description: Dataset Query - this will return Windows Security 4624 Logon Events
//Author: Clint Patterson
//Technical QC: Dominique Kilman
//Date: April 4, 2023
//Dataset: forensics_event_log
//Requirements: Security Event 4624 can be populated automatically by enabling search collections, or manually by performing an event log search for the channel and EventID or triaging targeted endpoints.
//Filter: Security, Event ID 4624. Filter for Logon_Type 3/10 from a non-local source and only returns relevant fields by default.
//Tags: noAPI,Windows,LowFi,PANWOpen, CA_event_logs

//Disable case sensitivity, last 30 days
config case_sensitive = false timeframe=30d

// Use the forensics_event_log dataset
| dataset = forensics_event_log

// Filter for Security, Event ID 4624
| filter source = "Security" AND event_id = 4624

// Filter here for Host_Name

| alter Subject_User_SID = if (search_uuid != null, arrayindex(regextract(message,"Security ID:\t+(.*)\r\n\t"),0), arrayindex(regextract(message,"SubjectUserSid=(.*)\n"),0)),
    Subject_User_Name = if (search_uuid != null, arrayindex(regextract(message,"Account Name:\t+(.*)\r\n\t"),0), arrayindex(regextract(message,"SubjectUserName=(.*)\n"),0)),
    Subject_Domain_Name = if (search_uuid != null, arrayindex(regextract(message,"Account Domain:\t+(.*)\r\n\t"),0), arrayindex(regextract(message,"SubjectDomainName=(.*)\n"),0)),
    Subject_Logon_Id = if (search_uuid != null, arrayindex(regextract(message,"Logon ID:\t+(.*)\r\n"),0), arrayindex(regextract(message,"SubjectLogonId=(.*)\n"),0)),
    Logon_Type = if (search_uuid != null, arrayindex(regextract(message,"Logon Type:\t+(.*)\r\n"),0), arrayindex(regextract(message,"LogonType=(.*)\n"),0)),
    Target_User_SID = if (search_uuid != null, arrayindex(regextract(message,"Security ID:\t+(.*)\r\n\t"),1), arrayindex(regextract(message,"TargetUserSid=(.*)\n"),0)),
    Target_User_Name = if (search_uuid != null, arrayindex(regextract(message,"Account Name:\t+(.*)\r\n\t"),1), arrayindex(regextract(message,"TargetUserName=(.*)\n"),0)),
    Target_Domain_Name = if (search_uuid != null, arrayindex(regextract(message,"Account Domain:\t+(.*)\r\n\t"),1), arrayindex(regextract(message,"TargetDomainName=(.*)\n"),0)),
    Target_Logon_Id = if (search_uuid != null, arrayindex(regextract(message,"Logon ID:\t+(.*)\r\n\t"),0), arrayindex(regextract(message,"TargetLogonId=(.*)\n"),0)),
    Process_Name = if (search_uuid != null, arrayindex(regextract(message,"Process Name:\t+(.*)\r\n"),0), arrayindex(regextract(message,"ProcessName=(.*)\n"),0)),
    Process_Id = if (search_uuid != null, arrayindex(regextract(message,"Process ID:\t+(.*)\r\n\t"),0), arrayindex(regextract(message,"ProcessId=(.*)\n"),0)),
    Workstation_Name = if (search_uuid != null, arrayindex(regextract(message,"Workstation Name:\t+(.*)\r\n\t"),0), arrayindex(regextract(message,"WorkstationName=(.*)\n"),0)),
    Source_Address = if (search_uuid != null, arrayindex(regextract(message,"Source Network Address:\t+(.*)\r\n\t"),0), arrayindex(regextract(message,"IpAddress=(.*)\n"),0)),
    Source_Port = if (search_uuid != null, arrayindex(regextract(message,"Source Port:\t+(.*)\r\n"),0), arrayindex(regextract(message,"IpPort=(.*)\n"),0)),
    Logon_Process = if (search_uuid != null, arrayindex(regextract(message,"Logon Process:\t+(.*)\r\n\t"),0), arrayindex(regextract(message,"LogonProcessName=(.*)\n"),0)),
    Authentication_Package = if (search_uuid != null, arrayindex(regextract(message,"Authentication Package:\t+(.*)\r\n\t"),0), arrayindex(regextract(message,"AuthenticationPackageName=(.*)\n"),0)),
    Transmitted_Services = if (search_uuid != null, arrayindex(regextract(message,"Transited Services:\t+(.*)\r\n\t"),0), arrayindex(regextract(message,"TransmittedServices=(.*)\n"),0)),
    Lm_Package_Name = if (search_uuid != null, arrayindex(regextract(message,"Package Name \(NTLM only\):\t+(.*)\r\n\t"),0), arrayindex(regextract(message,"LmPackageName=(.*)\n"),0)),
    Key_Length = if (search_uuid != null, arrayindex(regextract(message,"Key Length:\t+(.*)\r\n"),0), arrayindex(regextract(message,"KeyLength=(.*)\n"),0))

// Filter here for Subject/Target User, Workstation_Name, Source Address, Logon_Type, etc..

// Recommended filter to remove least-important logon events


// Recommended filter below for noninteractive/interactive remote logon events
| filter Logon_Type in ( "10") and Source_Address not in("","-","LOCAL", "127.0.0.1", "::1")

// Convert Timestamp to timestamp field, add Event_Description
| alter Timestamp  = to_timestamp(event_generated, "millis"),
    Event_Description = "An account was successfully logged on"

// Create Logon_Type_Description Field for each Logon_Type
| alter Logon_Type_Description = if (Logon_Type = "0", "System",
    if (Logon_Type = "2", "Interactive",
    if (Logon_Type = "3", "Network", 
    if (Logon_Type = "4", "Batch", 
    if (Logon_Type = "5", "Service",
    if (Logon_Type = "7", "Unlock", 
    if (Logon_Type = "8", "NetworkCleartext",
    if (Logon_Type = "9", "NewCredentials", 
    if (Logon_Type = "10", "RemoteInteractive",
    if (Logon_Type = "11", "CachedInteractive",
    if (Logon_Type = "12", "NewCredentials",
    if (Logon_Type = "13", "CachedUnlock", "Invalid"))))))))))))

// Create Source_Address_Private to determine is the source address is a private IP address
| alter Source_Address_Private = if (incidr(Source_Address, "10.0.0.0/8") = true, "TRUE",
    if (incidr(Source_Address, "127.0.0.0/8") = true, "TRUE",
    if (incidr(Source_Address, "169.254.0.0/16") = true, "TRUE",
    if (incidr(Source_Address, "172.16.0.0/12") = true, "TRUE",
    if (incidr(Source_Address, "192.168.0.0/16") = true, "TRUE", "FALSE")))))

//Join on event_logs to get logoff Timestamp (Security 4634) - Will be null if no related 4634 event logged.
| join type=left ( dataset = forensics_event_log 
| filter source = "Security" and event_id = 4634 and search_uuid = null

// Extract relevant fields to match with 4624 Event
| alter Logoff_User_SID = if (search_uuid != null, arrayindex(regextract(message,"Security ID:\t+(.*)\r\n\t"),0), arrayindex(regextract(message,"TargetUserSid=(.*)\n"),0)),
    Logoff_User_Name = if (search_uuid != null, arrayindex(regextract(message,"Account Name:\t+(.*)\r\n\t"),0), arrayindex(regextract(message,"TargetUserName=(.*)\n"),0)),
    Logoff_Logon_Id = if (search_uuid != null, arrayindex(regextract(message,"Logon ID:\t+(.*)\r\n"),0), arrayindex(regextract(message,"TargetLogonId=(.*)\n"),0)),
    Logoff_Time = to_timestamp(event_generated, "millis")

// Return Relevant fields, match on hostname, user_SID, and Logon_ID
| fields host_name as Logoff_HostName, Logoff_User_Name, Logoff_User_SID, Logoff_Logon_Id, Logoff_Time
) as logoff logoff.Logoff_HostName = host_name and logoff.Logoff_Logon_Id = Target_Logon_Id and logoff.Logoff_User_SID = Target_User_SID 
// End Join on Event Logs

//Join on endpoints dataset to see if source address is in XDR 
| join type = left (dataset = endpoints 
| arrayexpand ip_address
| fields endpoint_name as XDR_Endpoint_Name, ip_address, endpoint_id
) as endpoints endpoints.ip_address = source_address
// End join on endpoints inventory

// Create Source_XDR_Installed, set to "TRUE" if source in XDR, "FALSE" otherwise
| alter Source_XDR_Installed = if (endpoint_id != null, "TRUE", "FALSE")

// Create Session Minutes field with Loggoff Timestamp - Logon Timestamp
| alter Session_Minutes = timestamp_diff(Logoff_Time, Timestamp, "MINUTE")

// Recommended line to return most relevant fields ****TURN OFF for CA**** 

//| fields Timestamp, host_name,source, provider, event_id, Event_Description, Subject_User_SID, Subject_User_Name, Subject_Domain_Name, Subject_Logon_Id, Logon_Type, Logon_Type_Description, Target_User_SID, Target_User_Name, Target_Domain_Name, Target_Logon_Id, Process_Name, Process_Id, Workstation_Name, Source_Address, Source_Address_Private, Source_Port, Logon_Process, Authentication_Package, Transmitted_Services, Lm_Package_Name, Key_Length, Source_XDR_Installed, XDR_Endpoint_Name, Logoff_Time, Session_Minutes, message

// Recommended line to return most relevant fields
| fields Timestamp, host_name,source, event_id, Event_Description, Logon_Type, Logon_Type_Description, Target_User_SID, Target_User_Name, Target_Domain_Name, Workstation_Name, Source_Address, Source_Address_Private, Source_Port, Logon_Process, Source_XDR_Installed, XDR_Endpoint_Name, Logoff_Time, Session_Minutes, message

// Sort by Timestamp, descending
// Sort Struggles with a high number of events. If the query is failing, try disabling sort.
| sort desc Timestamp

// COMPROMISE ASSESMENT COMPONANTS ****Turn off fields line above****

//comp #1 to get idea of what types of logons are in use - type 8 cleartext, 3 and 10 are network
/*| comp count() by Event_Description , Logon_Type_Description ,Logon_Type, Logon_Process, Source_Address_Private   

//| filter (Source_Address_Private != "TRUE") and Logon_Type in ("3", "10") and Source_Address not in ("::1", "-", "0.0.0.0") and Source_Address != "fe80:*"
// comp #2 to see what kind of locations
//| comp count() as eventCount by Source_Address, Target_User_Name , Target_Domain_Name , Logon_Process , Logon_Type_Description , host_name   
//| iploc Source_Address loc_city as city, loc_country as country

//Comp line for CA reporting
//| comp count() as eventCount, max(Timestamp) as lastTime, min(Timestamp) as firstTime, values(source) as source, values(provider) as provider, values(event_id) as event_id, values(user) as user, max(message) as message by host_name , Source_Address, Event_Description, country, Target_User_Name , Target_Domain_Name , Logon_Process , Logon_Type_Description

//| alter discSource = "Forensics - Event Logs", note = concat(to_string(eventCount), " ", Event_Description, " events. logon type: ", Logon_Type_Description, " from source IP ", Source_Address), xtra = ""
//| fields host_name, event_id, source, Provider, lastTime, user, message, xtra, discSource , note */



