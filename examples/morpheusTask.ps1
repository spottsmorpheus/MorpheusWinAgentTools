# This script can be used in a Morpheus Powershell Task. 
# The task can be run against and instance over the Agent to set the logging level to 1 (Informational)



# Load the Module directly from GitHub in this example. NOTE This is not a Requirement. 
# The contents of the module can also be included directly in the task

$Uri = "https://raw.githubusercontent.com/spottsmorpheus/MorpheusWinAgentTools/main/src/MorpheusAgentFunctions.ps1"
# Load Powershell code from GitHub Uri and invoke as a temporary Module
$ProgressPreference = "SilentlyContinue"
$Response = Invoke-WebRequest -Uri $Uri -UseBasicParsing
if ($Response.StatusCode -eq 200) {
    $mod=New-Module -Name "MorpheusAgentFunctions" -ScriptBlock ([ScriptBlock]::Create($Response.Content))
}

# Module functions are now loaded

# Get the current agent status - return as json
Get-MorpheusAgentSocketStatus -AsJson

# Set the Agent logging level to 1 and delay a restart of the agent
Set-MorpheusAgentConfig -LogLevel 1 -RestartAgent