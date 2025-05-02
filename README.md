# DLP-in-Wazuh

## Windows 
  - Enable Windows Security Policies (GPO) — This is done on the Windows Agent (If you're using windows home edition then you can skip this step)
  - You can enable ```secpol.msc``` in windows home edition by typing the following command in the cmd running as administrator:
    ```
    DISM /Online /Add-Capability /CapabilityName:Rsat.GroupPolicy.Management.Tools~~~~0.0.1.0
    ```
  - For ```gpedit.msc```
    ```
    for %F in (%SystemRoot%\servicing\Packages\Microsoft-Windows-GroupPolicy-ClientExtensions-Package~*.mum %SystemRoot%\servicing\Packages\Microsoft-Windows-GroupPolicy-ClientTools-Package~*.mum) do ( 
    DISM /Online /NoRestart /Add-Package:"%F"
    )
    ```
    ```
    Tools → Local Security policy → Local Policies → Audit Policies 
    ```
    - From here we can set the Audit Object Access policy to log successes and failures
      
  - Setting up the directory we want to monitor
    - In order for us to test this, we will want to create a test directory and set the permissions. As an example you can create a directory in ```C:\Users\<Username>\Downloads\tmp```. From here we will 
      set the windows security policy to audit this folder. Note- Selecting “Everyone” as the principal ensures the policy is active for every user that attempts to access the file.

    - Right click:
      ```
      Properties → Security → Advanced → Auditing → Click Add → Select Principal → Everyone
      ```
  - Add the directory to be monitored in ```C:\Program Files (x86)\ossec-agent\ossec.conf``` under ```syscheck```
    ```
    <directories check_all="yes" whodata="yes">C:Users\<Username>\Downloads\tmp</directories>
    ```

 ## Wazuh-Server 
  - Add the following rules in ```/var/ossec/etc/rules/local_rules.conf```
    ```
    <group name="integrity, dlp,">
      <rule id="100102" level="5">
        <if_sid>60103</if_sid>
        <field name="win.system.eventID">4663</field>
        <description>Mitre ATT&CK T1119, Windows User attempted to access an object</description>
        <options>no_full_log</options>
      </rule>

      <rule id="100103" level="5">
        <if_sid>100102</if_sid>
        <field name="win.eventdata.accessList">%%4416</field>
        <description>Mitre ATT&CK T1119, Windows User attempted to access an object - Read Data</description>
     </rule>

     <rule id="100104" level="5">
        <if_sid>100102</if_sid>
        <field name="win.eventdata.accessList">%%4417</field>
        <description>Mitre ATT&CK T1119, Windows User attempted to access an object - Write Data</description>
     </rule>

    <rule id="100105" level="5">
       <if_sid>100102</if_sid>
       <field name="win.eventdata.accessList">%%4418</field>
       <description>Mitre ATT&CK T1119, Windows User attempted to access an object - Append Data</description>
    </rule>
 </group>
 ```

## Visualization

 - Create a file or modify anything under the previously monitored file and everything will be visible on dashboard

  ![image](https://github.com/user-attachments/assets/8616125a-3747-432c-b4c9-2ffbff57dd6d)

# USB Detection
## Wazuh-Agent
### Enable Plug and Play Events Logging
```
AuditPol /get /subcategory:"Plug and Play Events"
```
```
AuditPol /set /subcategory:"Plug and Play Events" /success:enable
```
```
auditpol /set /subcategory:"Removable Storage" /success:enable /failure:enable
auditpol /set /subcategory:"Plug and Play Events" /success:enable /failure:enable
auditpol /set /subcategory:"File System" /success:enable /failure:enable
```
```
wevtutil set-log "Microsoft-Windows-DriverFrameworks-UserMode/Operational" /enabled:true
```

In ```C:\Program Files (x86)\ossec-agent\ossec.conf``` file add the following:
```
<localfile>
  <log_format>eventchannel</log_format>
  <location>Microsoft-Windows-Sysmon/Operational</location>
</localfile>

<localfile>
  <log_format>eventchannel</log_format>
  <location>Microsoft-Windows-DriverFrameworks-UserMode/Operational</location>
</localfile>
```

## Wazuh-Server
### Add the following rule in /var/ossec/etc/rules/local_rules.xml
```
<group name="windows-usb-detect,">
  <rule id="111000" level="7">
    <if_sid>60227</if_sid>
    <field name="win.system.eventID">^6416$</field>
    <match>USBSTOR\\Disk</match>
    <options>no_full_log</options>
    <description>Windows: A PNP device $(win.eventdata.deviceDescription) was connected to $(win.system.computer)</description>
  </rule>
</group>
```

### Visualization
![image](https://github.com/user-attachments/assets/6c76a45d-cf48-4be6-b3d4-253ed59a062a)
