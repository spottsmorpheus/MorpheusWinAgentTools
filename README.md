# MorpheusWinAgentTools

## Powershell tool for viewing and configuring Morpheus Windows agent

This Powershell script contains a number of functions to view and edit the Morpheus Windows Agent configuratiion file and also view the current connected status of the Agent service

To load the script Dot Source the MorpheusAgentFunctions.ps1 file into a powershell session

```
PS> . .\MorpheusAgentFunctions.ps1
```

**NOTE** to run these Powershell Scripts the account must be and Administrator and the session elevated. The scriopt will warn if there are insuccifient access rights.

Functions have some help available which can be access via the Powershell Get-Help \<Function-Name\> command

## Loading Directly from GitHub URL

It is possible to load these Functions directly from GitHub if your Endpoint has an Internet connection. Use the following  Powershell to download and Install a Dynamic Module directly from a GitHub Url

```
$Uri = "https://raw.githubusercontent.com/spottsmorpheus/MorpheusWinAgentTools/main/src/MorpheusAgentFunctions.ps1"
$ProgressPreference = "SilentlyContinue"
# Load Powershell code from GitHub Uri and invoke as a temporary Module
$Response = Invoke-WebRequest -Uri $Uri -UseBasicParsing
if ($Response.StatusCode -eq 200) {
    $Module = New-Module -Name "MorpheusAgentFunctions" -ScriptBlock ([ScriptBlock]::Create($Response.Content))
}
```

## About the Functions

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

### Examples

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

Set the agent to use a proxy. Set bypass proxy on the local network to false. 
Also set a proxy bypass list of addresses with a regex

```
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

Set-MorpheusAgentConfig -ProxyXml $proxyXml

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