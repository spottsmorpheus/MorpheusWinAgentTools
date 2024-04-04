
Function Set-MorpheusAgentConfig {
    <#
    .SYNOPSIS
        Used to perform safe updates to the Morpheus Agent Configuration file
        
    .PARAMETER LogLevel
        Sets the LogLevel 0 = debug; 1 = info; 2 = warn; 3 = error; 4 = off
        Default value is 1

    .PARAMETER ApplianceUrl
        Optionally sets the appliance Host. There is no Default value.
        Only specify if you need to change the Host name

        Format is "https://ApplianceNameOrIp/"

    .PARAMETER ApiKey
        Optionally sets the Instance ApiKey. There is no Default value.
        Only specify if you need to change the ApiKey

        The ApiKey MUST match exactly the ApiKey on the Compute Server details page
    
    .PARAMETER ProxyXml
        Use this parameter to safely insert a well formed XML fragment for the agent Proxy configuration
        
        For example the Xml should be formed as so
        <configuration>
            <system.net>
                <defaultProxy>
                    <proxy usesystemdefault="False" proxyaddress="http://10.32.23.194:3128" bypassonlocal="False" />
                </defaultProxy>
            </system.net>
        </configuration>

        See Microsoft documentation for full details

    .PARAMETER RestartAgent
        Specify this parameter to schedule a delayed restart (60 seconds) of the Morpheus Windows Agent Service

    .OUTPUTS
        if successful the updated contents of the MorpheusAgent.exe.config file are returned and an XML String

    #> 
    [CmdletBinding()]
    param (
        [ValidateRange(0,4)]
        [Int32]$LogLevel=1,
        [String]$ApplianceUrl=$null,
        [String]$ApiKey=$null,
        [Switch]$RestartAgent,
        [String]$ProxyXml=""
    )
    
    if (IsElevated) {
        $Agent = Get-CIMInstance -Class win32_Service -Filter "Name like 'Morpheus Windows Agent'"
        if ($Agent) {
            $AgentFolder = Split-Path -Path ($Agent.PathName -replace '"','') -Parent
            $ConfigFile = Join-Path -Path $AgentFolder -ChildPath "MorpheusAgent.exe.config"
            if (Test-Path -Path $ConfigFile) {
                # Config file exists - load the file as XML - Fail and exit if not valid
                try {
                    [Xml]$Config = Get-Content -Path $ConfigFile -Raw
                }
                Catch {
                    Write-Warning "Failed to Parse XML Agent Config file"
                    $Config = $null
                }
                if ($Config) {
                    #Navigate the XML - run through the app settings modifying the attributes as required
                    foreach ($node in $Config.SelectNodes("/configuration/appSettings/add")) {
                        if (($LogLevel -ge 0 -AND $LogLevel -lt 5) -AND $node.GetAttribute("key") -eq "LogLevel") {$node.SetAttribute("value",$LogLevel.toString())}
                        if ($ApplianceUrl -AND $node.GetAttribute("key") -eq "Host") {$node.SetAttribute("value",$ApplianceUrl)}
                        if ($ApiKey -AND $node.GetAttribute("key") -eq "ApiKey") {$node.SetAttribute("value",$ApiKey)}
                    }
                    # Optionally Configure <system.Net> by adding XML $SystemNetXML

                    if ($ProxyXml) {
                        try {
                            [Xml]$systemNet= $ProxyXml
                            Write-Host "Paramater specifies following XML for <defaultProxy> element" -ForegroundColor Green
                            Write-Host $(XmlPrettyPrint -Xml $ProxyXml) -ForegroundColor Cyan
                            # Import the new node ready to use in the Config XML document
                            # <system.net> Node for import
                            $newSystemNetNode = $Config.ImportNode($systemNet.SelectSingleNode("/configuration/system.net"),$True)
                            # <defaultProxy> Node for import
                            $newProxyNode = $newSystemNetNode.SelectSingleNode("/defaultProxy")

                        }
                        catch {
                            Write-Error "Parameter ProxyXml is badly formed - check your XML"
                            return
                        }
                        $systemNetNode = $Config.SelectSingleNode("/configuration/system.net")
                        if ($systemNetNode) {
                            #<system.net> element exists replace defaultProxy element with ours
                            $oldProxyNode = $Config.SelectSingleNode("/configuration/system.net/defaultProxy")                            
                            if ($oldProxyNode) {
                                #replace XML
                                Write-Warning "<defaultProxy> Node exists in current config - replacing <defaultProxy> element"
                                $ret=$Config.SelectNodes("/configuration/system.net").ReplaceChild($newProxyNode,$oldProxyNode)
                            } else {
                                #Add
                                Write-Host "Inserting <defaultProxy> Node into current config" -ForegroundColor Green
                                $ret=$Config.SelectNodes("/configuration/system.net").AppendChild($newProxyNode)
                            }
                        } else {
                            Write-Host "<system.net> Node does not exist in current config. Inserting XML" -foregroundcolor green
                            # Insert new system.net element
                            $ret=$Config.SelectSingleNode("/configuration").AppendChild($newSystemNetNode)
                        }
                    }

                    Write-Host "Saving new config "
                    $Config.Save($ConfigFile)
                    # Restart Service - use Delay-AgentRestart to detach a process to do the restart otherwise it kills this job
                    if ($RestartAgent) {
                        $RestartPid = Delay-AgentRestart -Delay 60
                        Write-Host "Delaying Agent Service Restart - detaching process $($RestartPid)"
                    }
                    else {
                        Write-Warning "Agent Service must be restarted to use new configuration"
                    }
                    Write-Host "Returning Updated Agent Config ..."
                    # Return the updated Config File (as a String)
                    return (Get-MorpheusAgentConfig)
                }
            }
            else {
                Write-Warning "Agent Config file $($ConfigFile) Not Found"
            }
        }
        else {
            Write-Warning "Morpheus Windows Agent Not Found"
        }
    }
    else {
        Write-Warning "This function must have Administrator privilege"
    }
} 

Function Get-MorpheusAgentConfig {
    <#
    .SYNOPSIS
        Returns the current contents of the Morpheus Windows Agent config file

    .OUTPUTS
        if successful the contents of the MorpheusAgent.exe.config file are returned as XML String

    #>     
    if (IsElevated) {
        $Agent = Get-CIMInstance -Class win32_Service -Filter "Name like 'Morpheus Windows Agent'"
        if ($Agent) {
            $AgentFolder = Split-Path -Path ($Agent.PathName -replace '"','') -Parent
            $ConfigFile = Join-Path -Path $AgentFolder -ChildPath "MorpheusAgent.exe.config"
            if (Test-Path -Path $ConfigFile) {
                # Config file exists
                $CF = Get-Content -Path $ConfigFile -Raw
                return $CF
            }
            else {
                Write-Warning "Agent Config file $($ConfigFile) Not Found"
            }
        }
        else {
            Write-Warning "Morpheus Windows Agent Not Found"
        }
    }
    else {
        Write-Warning "This function must have Administrator privilege"
    }
}


Function Get-MorpheusAgentApiKey {
    <#
    .SYNOPSIS
        Returns the Morpheus Agent Api Key

    .OUTPUTS
        String containing the Api Key

    #>

    if (IsElevated) {     
        [XML]$Config = Get-MorpheusAgentConfig
        if ($Config) {
            $ApiKey = $Config.SelectNodes("/configuration/appSettings/add") | Where-Object {$_.Key -eq "ApiKey"}
            return $ApiKey.Value
        } else {
            Write-Warning "Failed to get ApiKey from Agent Config"
            return ""
        }
    } else {
        Write-Warning "This function must have Administrator privilege"
        return ""
    }
}


Function IsElevated {
    <#
    .SYNOPSIS
        Helper function.
        Determines if the current user has Administrator Privilege

    .OUTPUTS
        $true - Current user has Administrator role
        $false = Curent User does not have Administrator Role

    #>     
    $userIdentity =  [System.Security.Principal.WindowsIdentity]::GetCurrent()
    $userPrincipal = [System.Security.Principal.WindowsPrincipal]$UserIdentity
    $adminElevated=$UserPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    return $adminElevated
}

Function Get-MorpheusAgentSocketStatus {
    <#
    .SYNOPSIS
        Returns the Morpheus Windows Agent Service Status and associated TCP Socket details 

    .PARAMETER AsJson
        Specify this parameter to return output as a json string

    .OUTPUTS
        PSCustomObject, or optionally json string containing the Agent and Socket status 

    #> 
    [CmdletBinding()]
    param (
        [Switch]$AsJson
    )

    $Status = [PSCustomObject]@{
        adminAccess=IsElevated;
        machineName=[Environment]::MachineName;
        agentStatus="";
        agentState="";
        apiKey="";
        agentPid=$null;
        agentSockets=$null
    }

    if (IsElevated) {
        $Agent = Get-CIMInstance -Class win32_Service -Filter "Name like 'Morpheus Windows Agent'"
        if ($Agent) {
            $Status.agentStatus = $Agent.Status
            $Status.agentState = $Agent.State
            $Status.apiKey = Get-MorpheusAgentApiKey
            # We have an agent - Does it have a Pid
            if ($Agent.ProcessId -Ne 0) {
                $Status.agentPid = $Agent.ProcessId
                try {
                    $Sockets = @(Get-NetTCPConnection -RemotePort 443 -OwningProcess $Agent.ProcessId)
                }
                catch {
                    $Sockets = @()
                    Write-Warning "Agent ProcessId Owns no Sockets on port 443"
                }
                $Status.agentSockets = foreach ($Socket in $Sockets) {
                    [PSCustomObject]@{
                        state = $Socket.State.ToString();
                        creationTime = $Socket.CreationTime.ToString("s");
                        localAddress = $Socket.LocalAddress;
                        localPort = $Socket.LocalPort;
                        remoteAddress = $Socket.RemoteAddress;
                        remotePort = $Socket.RemotePort
                    } 
                }
            }
            else {
                Write-Warning "Morpheus Windows Agent Installed but Not Running on  $($Status.machineName)"
                $Status.agentStatus="NotRunning"                
            }
        }
        else {
            Write-Warning "Morpheus Windows Agent Not Installed on  $($Status.machineName)"
            $Status.agentStatus="NoAgent"
        }         
    }
    else {
        Write-Warning "You need to be an Administrator to run this Function"
    }
    if ($AsJson) {
        return $Status | ConvertTo-Json -Depth 5
    }
    else {
        return $Status
    }
}

Function Delay-AgentRestart {
    <#
    .SYNOPSIS
        Helper Tool used to detach a process to delay a restart of the Morpheus Windows Agent service.
        This way you can restart the Agent from a command bus session without affecting the running job 

    .PARAMETER Delay
        Number of seconds to Wait before the Agent is restarted. Default is 30

    .OUTPUTS
        Returns the Process Id of the detached process responsible for restarting the Morpheus Windows Agent service.
        Returns 0 if the Detached process failed to start successfully

    #>     
    [CmdletBinding()]
    param (
        [Int32]$Delay=30
    )

        $ArgString = " -noprofile -command ""& {start-sleep -seconds $($Delay); Restart-Service 'Morpheus Windows Agent' }"" "
        $RestartProcess = Start-Process -FilePath "powershell.exe" -ArgumentList $ArgString -Verb "RunAs" -WindowStyle "Hidden" -Passthru
        if ($RestartProcess) {
            return $RestartProcess.Id
        }
        else {
            return 0
        }
}

Function Base64Decode {
    param (
        [String]$B64
    )
    return [System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String($B64))
}

Function XmlPrettyPrint {
    <#
    .SYNOPSIS
        Helper Tool used to Pretty format an XML String

    .PARAMETER Xml
        Number of seconds to Wait before the Agent is restarted. Default is 30

    .OUTPUTS
        Returns a Pretty formated XML String

    #>     
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true, Position = 0)]
        [string]$Xml
    )

    if ($Xml) {
        $stringReader = New-Object System.IO.StringReader($Xml)
        $settings = New-Object System.Xml.XmlReaderSettings
        $settings.CloseInput = $true
        $settings.IgnoreWhitespace = $true
        $reader = [System.Xml.XmlReader]::Create($stringReader, $settings)
        $stringWriter = New-Object System.IO.StringWriter
        $settings = New-Object System.Xml.XmlWriterSettings
        $settings.CloseOutput = $true
        $settings.Indent = $true
        $writer = [System.Xml.XmlWriter]::Create($stringWriter, $settings)
       
        while (!$reader.EOF) {
            $writer.WriteNode($reader, $false)
        }
        $writer.Flush()
       
        $result = $stringWriter.ToString()
        $reader.Close()
        $writer.Close()
        $result
    } else {
        Write-Warning "XML String is Empty"
        return ""
    }

}


Function Read-AgentLog {
    <#
    .SYNOPSIS
        Reads the Morpheus Agentlogs and returns the Event Message

    .PARAMETER StartDate
        Enter a [DateTime] to start reading events from. Default is previous 30 minutes
    
    .PARAMETER AsJson
        Return output as Json

    .OUTPUTS
        Morpheus Agent events from StartDate

    #>
    [CmdletBinding()]    
    param (
        [DateTime]$StartDate=[DateTime]::Now.AddMinutes(-30),
        [Switch]$AsJson
    )

    #Default to Setup Date if no StartDate
    if (-Not $StartDate) {
        $StartDate = (Get-WindowsSetupDate).installDate.Date
    }
    $Filter = @{LogName="Morpheus Windows Agent";StartTime=$StartDate}

    $Events = Get-WinEvent -FilterHashtable $Filter | Sort-Object -Property RecordId

    $eventData = foreach ($e in $Events) {
        $output = [PSCustomObject]@{
            computer=$e.MachineName;
            recordId=$e.RecordId;
            timeStamp=$e.TimeCreated.ToString("yyyy-MM-ddTHH:mm:ss.fff");
            message=$e.Message
        }
        $output
    }
    if ($AsJson) {
        return $eventData | ConvertTo-Json -Depth 3 
    } else {
        return $eventData
    }    
}

Function Parse-StompMessage {
    <#
    .SYNOPSIS
        Takes the output from Read-AgentLog and attents to process the Stomp frames

    .PARAMETER AgentEvent
        Array of agent events returned form Read-AgentLogs.  Will accept input from pipeline

    .OUTPUTS
        Morpheus Agent Stomnp Messages

    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true, Position = 0,ValueFromPipeline=$true)]
        [Object[]]$AgentEvent
    )

    Begin {
        #Match and caputre the json body in a Stomp Frame
        $jsonPattern = "^([\[\{]*.*[\}\]]*)\u0000$"
        $pscmdPattern = "^.*-encodedcommand ([A-Za-z0-9=]*)$"
        $Rtn = [System.Collections.Generic.List[Object]]::new()
    }
    Process {
        foreach ($Event in $AgentEvent) {
            $m = $Event.Message
            $stomp = [PSCustomObject]@{
                recordId = $Event.RecordId;
                timeStamp = $Event.timeStamp;
                frameType="";
                header=[PSCustomObject]@{};
                body=[PSCustomObject]@{}
            }
            #Match and capture the json body in a Stomp Frame
            $data = $null
            if ($m -Match "^INFO:Received Stomp Frame: ([A-Z]*)\\n(.*)$") {
                $stomp.frameType = $Matches[1]
                $data = $Matches[2]
                Write-Verbose "Found Received MESSAGE Frame" 
            } elseif ($m -Match '^INFO:Sending Message: \["(.*)"\]$' ) {
                $stomp.frameType = "" # don't know frame type just yet
                $data = $Matches[1]
                Write-Verbose "Found a SEND Frame" 
            }
            if ($data) {
                $frame = [Regex]::Unescape($data) -Split "\n"
                if ($stomp.frameType -eq "") {$stomp.frameType = $frame[0]}
                foreach ($f in $frame) {
                    if ($f -match $jsonPattern) {
                        #json Body
                        Write-Verbose "Found json Body $($Matches[1])" 
                        $body = ConvertFrom-Json -InputObject $Matches[1]
                        if ($body) {$stomp.body = $body}
                        if ($body.command) {
                            $decodedCmd = [Text.encoding]::utf8.getstring([convert]::FromBase64String($body.command))
                            Add-Member -InputObject $stomp.body -MemberType NoteProperty -Name "decodedCommand" -Value $decodedCmd
                            if ($decodedCmd -match $pscmdPattern) {
                                $script = Base64Decode $Matches[1]
                                Add-Member -InputObject $stomp.body -MemberType NoteProperty -Name "decodedScript" -Value $script
                            }
                        }             
                    } else {
                        Write-Verbose "Line $($f)"
                        $keyVal = $f -split ":"
                        if ($keyVal.count -eq 2) {
                            #Write-Host "Found $($keyVal[0]) value $($keyVal[1])" -ForegroundColor Green
                            Add-Member -InputObject $stomp.header -MemberType NoteProperty -Name $keyVal[0] -Value $keyVal[1]
                        } elseif ($keyVal.count -eq 0) {
        
                        }
                    }
                }
                $Rtn.Add($stomp)
            }
        }
    }
    End {
        Return $Rtn
    }

}