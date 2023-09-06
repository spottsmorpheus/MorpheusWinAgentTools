# MorpheusWinAgentTools

## Powershell tool for viewing and configuring Morpheus Windows agent

This Powershell script contains a number of functions to view and edit the Morpheus Windows Agent configuratiion file and also view the current connected status of the Agent service

To load the script Dot Source the MorpheusAgentFunctions.ps1 file into a powershell session

```
PS> . .\MorpheusAgentFunctions.ps1
```

**NOTE** to run these Powershell Scripts the account must be and Administrator and the session elevated. The scriopt will warn if there are 
insuccifient access rights.

Functions have some help available which can be access via the Powershell Get-Help \<Function-Name\> command

## Loading Directly from GitHub URL

It is possible to load these Functions directly from GitHub if your Endpoint has an Internet connection. Use the following  Powershell to download and Install a Dynamic Module directly from a GitHub Url

```
$Uri = "https://raw.githubusercontent.com/spottsmorpheus/MorpheusWinAgentTools/main/src/MorpheusAgentFunctions.ps1"
$PrgressPreference = "SilentlyContinue"
# Load Powershell code from GitHub Uri and invoke as a temporary Module
$Response = Invoke-WebRequest -Uri $Uri -UseBasicParsing
if ($Response.StatusCode -eq 200) {
    $Module = New-Module -Name "MorpheusAgentFunctions" -ScriptBlock ([ScriptBlock]::Create($Response.Content))
}
```

## About the Functions

It is possible to run these Powershell script from a Morpheus Task. You can use a Remote task (winRm) or even the Morpheus Agent itself. When changes are made to the agent config using the Morpheus Agent, a delayed restart is used to ensure the task completes and returns an acknowledgement to Morpheus, preventing possible issues with the task being re-queued by RabbitMq

### Get-MorpheusAgentConfig

Returns the current XML Documument containing the Agent configuration

### Set-MorpheusAgentConfig

Used to update the Agent XML Config. 

### Get-MorpheusAgentSocketStatus

```
NAME
    Get-MorpheusAgentSocketStatus

SYNOPSIS
    Returns the Morpheus Windows Agent Service Status and associated TCP Socket details


SYNTAX
    Get-MorpheusAgentSocketStatus [-AsJson] [<CommonParameters>]
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

### Set-MorpheusAgentConfig

```

NAME
    Set-MorpheusAgentConfig

SYNOPSIS
    Used to perform safe updates to the Morpheus Agent Configuration file


SYNTAX
    Set-MorpheusAgentConfig [[-LogLevel] <Int32>] [[-ApplianceUrl] <String>] [[-ApiKey] <String>] [-RestartAgent]
    [[-SystemNetProxyXml] <String>] [<CommonParameters>]

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