# Fortinet 



## Threats by destination
```
dataset = fortinet_fortigate_raw 
| filter (cat contains "utm:ips") or (cat contains "webfilter" and act = "blocked")
| iploc dst loc_country
| comp count(_id) as counter by loc_country 
| view graph type = map xaxis = loc_country yaxis = counter 
```

## Threats by origin country
```
dataset = fortinet_fortigate_raw 
| iploc src loc_country
| filter (cat contains "utm:waf") or (cat contains "utm:ips")
| filter (loc_country not in (null, "")) 
| comp count(_id) as counter by loc_country 
|  view graph type = map xaxis = loc_country yaxis = counter 
```

## Fortinet - Number of IPS Events

```
dataset = fortinet_fortigate_raw 
| filter cat contains "utm:ips"
| comp count(_id) as IPS_Events by cat
| view graph type = gauge subtype = radial yaxis = IPS_Events maxscalerange = 872 
```

## Fortinet - Number of IPS Events

```
dataset = fortinet_fortigate_raw 
| filter cat contains "utm:ips"
| comp count(_id) as IPS_Events by cat
| view graph type = gauge subtype = radial yaxis = IPS_Events maxscalerange = 872 
```

## Fortinet - Number of WAF Events

```
dataset = fortinet_fortigate_raw 
| filter cat contains "utm:waf"
| comp count(_id) as WAF_Events by cat
| view graph type = gauge subtype = radial yaxis = WAF_Events maxscalerange = 872  
```

## Fortinet - WAF Categories

```
dataset = fortinet_fortigate_raw 
| filter cat contains "utm:waf" and msg != null
| comp count(_id) as WAF_Events by msg
| sort desc WAF_Events 
| limit 15
| view graph type = column subtype = grouped layout = horizontal xaxis = msg yaxis = WAF_Events  
```

## Fortinet - WAF Risk

```
dataset = fortinet_fortigate_raw 
| filter cat contains "utm:waf"
| comp count(_id) as risk by FTNTFGTseverity
| view graph type = pie subtype = full xaxis = FTNTFGTseverity yaxis = risk 
```

## Fortinet - Top IPS Events

```
dataset = fortinet_fortigate_raw 
| filter cat contains "utm:ips"
| comp count(_id) as Counter by msg
| sort desc Counter
| limit 10
| view graph type = pie subtype = semi_donut xaxis = msg yaxis = Counter  
```

## Fortinet - Blocked Domains

```
dataset = fortinet_fortigate_raw 
| filter cat contains "webfilter" and act = "blocked"
| comp count(_id) as Counter by dhost 
| sort desc Counter 
| limit 15
| view graph type = column subtype = grouped layout = horizontal xaxis = dhost yaxis = Counter 
```

## Fortinet - Blocked Categories

```
dataset = fortinet_fortigate_raw 
| filter cat contains "webfilter" and act = "blocked"
| comp count(_id) as Counter by RequestContext  
| sort desc Counter 
| limit 10
| view graph type = pie subtype = full xaxis = RequestContext yaxis = Counter 
```


