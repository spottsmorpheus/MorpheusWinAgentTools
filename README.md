# MorpheusWinAgentTools

## Powershell tool for viewing and configuring Morpheus Windows agent

This Powershell script contains a number of functions to view and edit the Morpheus Windows Agent configuration file and also view the current connected status of the Agent service

To load the script Dot Source the MorpheusAgentFunctions.ps1 file into a powershell session

```
PS> . .\MorpheusAgentFunctions.ps1
```

## Windows Event Logs 

These scripts access the Windows Event logs

- Morpheus Windows Agent (Read-AgentLog)
- Windows Powershell (Read-PSLog)

These logs are rolled over quite frequently so to aid debugging you may need to increase the log size to capture more of the raw logs. Using Event Viewer locate the event log named above and select Properties. Increase the Maximum Log Size to a value that suits your needs.

**NOTE** to run these Powershell Scripts the account must be and Administrator and the session elevated. The script will warn if there are insuccifient access rights.

Functions have some help available which can be access via the Powershell Get-Help \<Function-Name\> command

## Loading Directly from GitHub URL

It is possible to load these Functions directly from GitHub if your Endpoint has an Internet connection. Use the following  Powershell to download and Install a Dynamic Module directly from a GitHub Url

```
[System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls11 -bor [System.Net.SecurityProtocolType]::Tls12
$Uri = "https://raw.githubusercontent.com/spottsmorpheus/MorpheusWinAgentTools/main/src/MorpheusAgentFunctions.ps1"
$ProgressPreference = "SilentlyContinue"
# Load Powershell code from GitHub Uri and invoke as a temporary Module
$Response = Invoke-WebRequest -Uri $Uri -UseBasicParsing
if ($Response.StatusCode -eq 200) {
    $Module = New-Module -Name "MorpheusAgentFunctions" -ScriptBlock ([ScriptBlock]::Create($Response.Content))
}
```

## About the Functions

To list the Functions in this module use the commands above to load the Module and then run the Powershell command

```
Get-Command -Module "MorpheusAgentFunctions"

CommandType Name
----------- ----
   Function Base64Decode
   Function Delay-AgentRestart
   Function Get-MorpheusAgentApiKey
   Function Get-MorpheusAgentConfig
   Function Get-MorpheusAgentSocketStatus
   Function Get-ScheduledTaskEvents
   Function Get-StompActionAck
   Function IsElevated
   Function Make-HTMLTable
   Function Out-HtmlPage
   Function Parse-PSLog
   Function Parse-StompMessage
   Function Read-AgentLog
   Function Read-PSLog
   Function Set-LogOnAsServiceRight
   Function Set-MorpheusAgentConfig
   Function Set-MorpheusAgentCredential
   Function Test-Credential
   Function test-pipe
   Function XmlPrettyPrint
```

It is possible to run these Powershell script from a Morpheus Task. You can use a Remote task (winRm) or even the Morpheus Agent itself. When changes are made to the agent config using the Morpheus Agent, a delayed restart is used to ensure the task completes and returns an acknowledgement to Morpheus, preventing possible issues with the task being re-queued by RabbitMq

### Get-MorpheusAgentSocketStatus

```
NAME
    Get-MorpheusAgentSocketStatus

SYNOPSIS
    Returns the Morpheus Windows Agent Service Status and associated TCP Socket details


SYNTAX
    Get-MorpheusAgentSocketStatus [-AsJson] [<CommonParameters>]
```

Example Output using the -AsJson parameter

```
{
    "adminAccess":  true,
    "machineName":  "SP60-W-0002",
    "agentStatus":  "OK",
    "agentState":  "Running",
    "agentPid":  3224,
    "agentSockets":  {
                         "state":  "Established",
                         "apiKey":  "b58a0dee-a4b9-441f-ba35-eb56ca5f124e",
                         "creationTime":  "2023-09-06T09:55:30",
                         "localAddress":  "10.99.20.73",
                         "localPort":  63682,
                         "remoteAddress":  "10.99.23.192",
                         "remotePort":  443
                     }
}
```

### Get-MorpheusAgentConfig

```
NAME
    Get-MorpheusAgentConfig

SYNOPSIS
    Returns the current contents of the Morpheus Windows Agent config file


SYNTAX
    Get-MorpheusAgentConfig [<CommonParameters>]
```


### Get-MorpheusAgentApiKey

```
NAME
    Get-MorpheusAgentApiKey

SYNOPSIS
    Returns the Morpheus Agent Api Key


SYNTAX
    Get-MorpheusAgentApiKey [<CommonParameters>]
```

### Set-MorpheusAgentConfig

```

NAME
    Set-MorpheusAgentConfig

SYNOPSIS
    Used to perform safe updates to the Morpheus Agent Configuration file


SYNTAX
    Set-MorpheusAgentConfig [[-LogLevel] <Int32>] [[-ApplianceUrl] <String>] [[-ApiKey] <String>] [-RestartAgent]
    [[-ProxyXml] <String>] [<CommonParameters>]

```

### Set-MorpheusAgentCredential

Modifies the Morpheus Windows Agent service to run under the Credential Provided.
**NOTE** User must be a Member of the Local Administrators Group and must have Logon As Service rights granted in the Local Security Policy

Use the -Default parameter to reset the service to run as LocalSystem

You can use Helper function **Set-LogOnAsServiceRight** to grant Logon As Service rights to a credential.

```
NAME
    Set-MorpheusAgentCredential

SYNOPSIS
    Helper Tool used to modify the Agent Service Logon Account


SYNTAX
    Set-MorpheusAgentCredential [[-Credential] <PSCredential>] [-Default] [<CommonParameters>]


DESCRIPTION


RELATED LINKS
```

### Set-LogOnAsServiceRight

Helper function used to Grant Logon As Service rights to the User in the Credential Object

```

NAME
    Set-LogOnAsServiceRight

SYNOPSIS
    Uses the Local Security Editor to Add LogonAsService rights to the user defined in Credential


SYNTAX
    Set-LogOnAsServiceRight [[-Credential] <PSCredential>] [<CommonParameters>]
```

### Test-Credential

Helper Function used to test if a credential is valid (can it be authenticated)

```

NAME
    Test-Credential

SYNTAX
    Test-Credential [-Credential] <pscredential> [[-Context] {Domain | Machine | ApplicationDirectory}]  [<CommonParameters>]


PARAMETERS
    -Context <string>

    -Credential <pscredential>


```

### Read-AgentLog
```
NAME
    Read-AgentLog

SYNOPSIS
    Reads the Morpheus Agentlogs and returns the Event Message


SYNTAX
    Read-AgentLog [[-StartDate] <DateTime>] [-AsJson] [<CommonParameters>]

```

### Parse-StompMessage

Requires Agent in Debug or Info mode

Takes the events and attemps to categorise the Stomp frames. You can pipe the output to ConvertTo-Json -Depth 5 to see the frames in json format

```
NAME
    Parse-StompMessage

SYNOPSIS
    Takes the output from Read-AgentLog and attents to process the Stomp frames


SYNTAX
    Parse-StompMessage [-AgentEvent] <Object[]> [<CommonParameters>]


```

### Get-StompActionAck

**NOTE**  Requires the Morpheus Windows Agent in Debug or Info mode to log the raw messages in the windows Event Log

Use this function with Parse-StompMessage to attempt to match up the Action requests and responses contained within the stomp frames.  The Microsoft Event log has a character limit so often the log message has an incomplete frame. In this case the output will say the frame is too long.

```
NAME
    Get-StompActionAck

SYNOPSIS
    Takes the output from Parse-StompMessage and extracts the actionAcknowledged messages


SYNTAX
    Get-StompActionAck [-Message] <Object[]> [-AsJson] [<CommonParameters>]
```

Here is an example, show the Agent command actions starting at the DateTime in variable $Start for a duration of 10 minutes, The output shows the recordId of the request and that of the matching response (request property will match). Record id 49709 shows the decoded command in the property cmd and recordId 49714 shows the output. Note the request property matches showing the relationship between command request and response

```
Read-Agentlog -StartDate $Start -Minutes 10 | Parse-StompMessage | Get-StompActionAck

recordId  : 49709
timeStamp : 2025-05-20T17:37:31.929
request   : c8ba5345-eccb-46dc-960e-31c3b8801f5d
cmd       : $ProgressPreference = 'SilentlyContinue'
            $Uri = "https://raw.githubusercontent.com/spottsmorpheus/WindowsSecEvents/main/src/WindowsSecEvents.ps1"
            $ProgressPreference = "SilentlyContinue"
            # Load Powershell code from GitHub Uri and invoke as a temporary Module
            $Response = Invoke-WebRequest -Uri $Uri -UseBasicParsing
            if ($Response.StatusCode -eq 200) {
                $Module = New-Module -Name "WindowsSecEvents" -ScriptBlock ([ScriptBlock]::Create($Response.Content))
            }

            Get-RpcSessionInfo -AsJson

exitValue :
output    :
error     :

recordId  : 49714
timeStamp : 2025-05-20T17:37:32.867
request   : c8ba5345-eccb-46dc-960e-31c3b8801f5d
cmd       :
exitValue : 0
output    : {
                "status":  0,
                "cmdOut":  {
                               "userId":  "NT AUTHORITY\\SYSTEM",
                               "computerName":  "MYINSTANCE",
                               "manufacturer":  "VMware, Inc.",
                               "model":  "VMware Virtual Platform",
                               "domainName":  "myad.com",
                               "domainJoined":  true,
                               "authenticationType":  "Negotiate",
                               "impersonation":  "None",
                               "isAdmin":  true,
                               "localProfile":  "C:\\Windows\\system32\\config\\systemprofile\\AppData\\Local",
                               "tokenGroups":  [
                                                   "BUILTIN\\Administrators",
                                                   "Everyone",
                                                   "NT AUTHORITY\\Authenticated Users"
                                               ],
                               "isSystem":  true,
                               "isService":  false,
                               "isNetwork":  false,
                               "isBatch":  false,
                               "isInteractive":  false,
                               "isNtlmToken":  false,
                               "osVersion":  "Microsoft Windows NT 10.0.17763.0",
                               "systemDrive":  "C:",
                               "psVersion":  "5.1.17763.592",
                               "psEdition":  "Desktop",
                               "psExePath":  "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"
                           },
                "errOut":  null
            }

error     :

```


## Some more Examples

Set the Morpheus Agent log level to Informational level (1) restarting the agent after a 60 second delay

```
Set-MorpheusAgentConfig -LogLevel 1 -RestartAgent
```

Set the Morpheus Agent log level to Debug level (0) and set the ApiKey. The config file will be updated but changes will not take effect until the agent is restarted.

```
Set-MorpheusAgentConfig -LogLevel 0 -ApiKey "0538e2b0-d85f-4377-9f56-07df0ab04ea2"
```

To simply restart the agent after a 60 second delay

```
Set-MorpheusAgentConfig  -RestartAgent
```

If the Debug level is Info or Debug you can use the following function to extract the last 30 minutes of Agent events

```
Read-AgentLog
```

and to parse the message frames use

```
Read-AgentLog | Parse-StompMessage
```


Set the agent to use a proxy. Set bypass proxy on the local network to false. 
Also set a proxy bypass list of addresses with a regex. To do this construct an XML fragment as shown below

```
# Create an XML String with containing the proxy details
$proxyXml = @'
<configuration>
  <system.net>
    <defaultProxy>
      <proxy usesystemdefault="False" proxyaddress="http://10.99.23.194:3128" bypassonlocal="False"/>
      <bypasslist>
         <add address="10\.99\..*" />
      </bypasslist>
    </defaultProxy>
  </system.net>
</configuration>
'@

# Then use the Set-MorpheusAgentConfig funtion to update the config and restart the agent
Set-MorpheusAgentConfig -ProxyXml $proxyXml -RestartAgent

Paramater specifies following XML for <defaultProxy> element
<?xml version="1.0" encoding="utf-16"?>
<configuration>
  <system.net>
    <defaultProxy>
      <proxy usesystemdefault="False" proxyaddress="http://10.99.23.194:3128" bypassonlocal="False" />
      <bypasslist>
        <add address="10\.99\..*" />
      </bypasslist>
    </defaultProxy>
  </system.net>
</configuration>
WARNING: <defaultProxy> Node exists in current config - replacing <defaultProxy> element
Saving new config
WARNING: Agent Service must be restarted to use new configuration
Returning Updated Agent Config ...
<?xml version="1.0" encoding="utf-8"?>
<configuration>
  <appSettings>
    <add key="ServiceName" value="Morpheus Windows Agent" />
    <add key="ApiKey" value="0538e2b0-d85f-4377-9f56-xxxxxxxx" />
    <add key="Host" value="https://myappliance.example.com/" />
    <add key="VmMode" value="true" />
    <add key="LogLevel" value="1" />
    <!-- 0 = debug; 1 = info; 2 = warn; 3 = error; 4 = off;-->
    <add key="ClientSettingsProvider.ServiceUri" value="" />
  </appSettings>
  <startup>
    <supportedRuntime version="v4.0" sku=".NETFramework,Version=v4.5.2" />
  </startup>
  <system.web>
    <membership defaultProvider="ClientAuthenticationMembershipProvider">
      <providers>
        <add name="ClientAuthenticationMembershipProvider" type="System.Web.ClientServices.Providers.ClientFormsAuthenticationMembershipProvider, System.Web.Extensions, Version=4.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35" serviceUri="" />
      </providers>
    </membership>
    <roleManager defaultProvider="ClientRoleProvider" enabled="true">
      <providers>
        <add name="ClientRoleProvider" type="System.Web.ClientServices.Providers.ClientRoleProvider, System.Web.Extensions, Version=4.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35" serviceUri="" cacheTimeout="86400" />
      </providers>
    </roleManager>
  </system.web>
  <system.net>
    <defaultProxy>
      <proxy usesystemdefault="False" proxyaddress="http://10.32.23.194:3128" bypassonlocal="False" />
      <bypasslist>
        <add address="10\.32\..*" />
      </bypasslist>
    </defaultProxy>
  </system.net>
</configuration>
```

See the Microsoft pages for details https://learn.microsoft.com/en-us/previous-versions/dotnet/netframework-1.1/aa903360(v=vs.71)

## Rerading the Powershell Log

There are 2 functions included in this module to read the Windows Powershell log. This can be useful alongside the Morpheus Agent Log as it logs every Powershell command executed on the instance.  The Powershell log can be accessed even of a Morpheus Agent is not installed

### Read-PSlog

Read events from the Windows Powershell event log

```
NAME
    Read-PSLog

SYNOPSIS
    Reads the Windows Powershell logs and returns script executions. If the script is Base64 encoded then
    this script decodes and returns the actual powershell. Useful for reading any Morpheus WinRm RPC commands


SYNTAX
    Read-PSLog [[-EventId] <Object>] [[-Computer] <String>] [[-StartDate] <DateTime>] [[-Minutes] <Int32>] [[-ClockAdjust] <Int32>] [-AsJson] [<CommonParameters>]


DESCRIPTION


PARAMETERS
    -EventId <Object>
        Event ID to read. Default is Event 400

    -Computer <String>
        Computername. Default is local Computer

    -StartDate <DateTime>
        Date / Time to start reading the log

    -Minutes <Int32>
        Number of Minutes to read from StartDate - Default 60

    -ClockAdjust <Int32>

    -AsJson [<SwitchParameter>]
        Output results in json
```

Example

```
Read-PSlog

computer       : myinstance.mydomain.com
index          : 962
Time           : 2025-05-20T20:32:47.716
host           : ConsoleHost
command        : powershell.exe -NoProfile -encodedcommand JABQAHIAbwBnAHIAZQBzAHMAUAByAGUAZgBlAHIAZQBuAGMAZQAgAD0AIAAn
                 AFMAaQBsAGUAbgB0AGwAeQBDAG8AbgB0AGkAbgB1AGUAJwAKACQAVQByAGkAIAA9ACAAIgBoAHQAdABwAHMAOgAvAC8AcgBhAHcALg
                 BnAGkAdABoAHUAYgB1AHMAZQByAGMAbwBuAHQAZQBuAHQALgBjAG8AbQAvAHMAcABvAHQAdABzAG0AbwByAHAAaABlAHUAcwAvAFcA
                 aQBuAGQAbwB3AHMAUwBlAGMARQB2AGUAbgB0AHMALwBtAGEAaQBuAC8AcwByAGMALwBXAGkAbgBkAG8AdwBzAFMAZQBjAEUAdgBlAG
                 4AdABzAC4AcABzADEAIgAKACQAUAByAG8AZwByAGUAcwBzAFAAcgBlAGYAZQByAGUAbgBjAGUAIAA9ACAAIgBTAGkAbABlAG4AdABs
                 AHkAQwBvAG4AdABpAG4AdQBlACIACgAjACAATABvAGEAZAAgAFAAbwB3AGUAcgBzAGgAZQBsAGwAIABjAG8AZABlACAAZgByAG8AbQ
                 AgAEcAaQB0AEgAdQBiACAAVQByAGkAIABhAG4AZAAgAGkAbgB2AG8AawBlACAAYQBzACAAYQAgAHQAZQBtAHAAbwByAGEAcgB5ACAA
                 TQBvAGQAdQBsAGUACgAkAFIAZQBzAHAAbwBuAHMAZQAgAD0AIABJAG4AdgBvAGsAZQAtAFcAZQBiAFIAZQBxAHUAZQBzAHQAIAAtAF
                 UAcgBpACAAJABVAHIAaQAgAC0AVQBzAGUAQgBhAHMAaQBjAFAAYQByAHMAaQBuAGcACgBpAGYAIAAoACQAUgBlAHMAcABvAG4AcwBl
                 AC4AUwB0AGEAdAB1AHMAQwBvAGQAZQAgAC0AZQBxACAAMgAwADAAKQAgAHsACgAgACAAIAAgACQATQBvAGQAdQBsAGUAIAA9ACAATg
                 BlAHcALQBNAG8AZAB1AGwAZQAgAC0ATgBhAG0AZQAgACIAVwBpAG4AZABvAHcAcwBTAGUAYwBFAHYAZQBuAHQAcwAiACAALQBTAGMA
                 cgBpAHAAdABCAGwAbwBjAGsAIAAoAFsAUwBjAHIAaQBwAHQAQgBsAG8AYwBrAF0AOgA6AEMAcgBlAGEAdABlACgAJABSAGUAcwBwAG
                 8AbgBzAGUALgBDAG8AbgB0AGUAbgB0ACkAKQAKAH0ACgAKAEcAZQB0AC0AUgBwAGMAUwBlAHMAcwBpAG8AbgBJAG4AZgBvACAALQBB
                 AHMASgBzAG8AbgAKAA==
encodedcommand : $ProgressPreference = 'SilentlyContinue'
                 $Uri =
                 "https://raw.githubusercontent.com/spottsmorpheus/WindowsSecEvents/main/src/WindowsSecEvents.ps1"
                 $ProgressPreference = "SilentlyContinue"
                 # Load Powershell code from GitHub Uri and invoke as a temporary Module
                 $Response = Invoke-WebRequest -Uri $Uri -UseBasicParsing
                 if ($Response.StatusCode -eq 200) {
                     $Module = New-Module -Name "WindowsSecEvents" -ScriptBlock
                 ([ScriptBlock]::Create($Response.Content))
                 }

                 Get-RpcSessionInfo -AsJson
```

The output shows the raw command (command property) and the base64 decoded string (encodedCommand property)

**Note** The results of the command execution are NOT recorded in the event log

### Parse-PSLog

When Powershell Scripts execeed a certain size, Morpheus will split the powershell info fragments and transfer the fragment over to the instance before re-assembling them into a temporary script and executing. 


The Parse-PSLog function takes the output from Read-PSLog and is able to reassemble the fragments allowing the full script to be inspected.

```
$cmd = Read-PSLog | Parse-PSLog

id         : rpc-962
eventIndex : 962
length     : 488
executed   : 2025-05-20T20:32:47.716
content    : $ProgressPreference = 'SilentlyContinue'
             $Uri = "https://raw.githubusercontent.com/spottsmorpheus/WindowsSecEvents/main/src/WindowsSecEvents.ps1"
             $ProgressPreference = "SilentlyContinue"
             # Load Powershell code from GitHub Uri and invoke as a temporary Module
             $Response = Invoke-WebRequest -Uri $Uri -UseBasicParsing
             if ($Response.StatusCode -eq 200) {
                 $Module = New-Module -Name "WindowsSecEvents" -ScriptBlock ([ScriptBlock]::Create($Response.Content))
             }

             Get-RpcSessionInfo -AsJson


```

