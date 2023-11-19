
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

## Domain Group Changes
````
dataset = xdr_data // Using the xdr dataset
 | filter event_type = ENUM.EVENT_LOG and action_evtlog_event_id in (4756)  

 // | fields action_evtlog_message
| alter  DA = arrayindex(regextract(action_evtlog_message, "\s+(?:[^:]+:){3}([^\n]+)"),0), User_Name = arrayindex(regextract(action_evtlog_message, "\s+(?:[^:]+:){8}([^\n]+)"),0), Domain = arrayindex(regextract(action_evtlog_message, "\s+(?:[^:]+:){4}([^\n]+)"),0), NewGroup = arrayindex(regextract(action_evtlog_message, "\s+(?:[^:]+:){11}([^\n]+)"),0)

| fields DA as Domain_Administrator, User_Name as Affected_User, NewGroup ,Domain as User_Domain  
| sort desc _time 
```
