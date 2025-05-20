# Script wide Variable
$XmlQueryTemplate = @'
<QueryList>
  <Query Id="0" Path="{1}">
    <Select Path="{1}">
       {0}
    </Select>
  </Query>
</QueryList>
'@

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
        logonAs="";
        apiKey="";
        agentPid=$null;
        agentSockets=$null
    }

    if (IsElevated) {
        $Agent = Get-CIMInstance -Class win32_Service -Filter "Name like 'Morpheus Windows Agent'"
        if ($Agent) {
            $Status.agentStatus = $Agent.Status
            $Status.agentState = $Agent.State
            $Status.logonAs = $Agent.StartName
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

Function Set-MorpheusAgentCredential {
    <#
    .SYNOPSIS
        Helper Tool used to modify the Agent Service Logon Account

    .PARAMETER Credential
        Credential Object. The Morpheus Agent will be set to use these credentials

    .PARAMETER Default
        Switch Parameter which if present resets credentials to LocalSystem. Overrides Credential if this is also present

    .OUTPUTS
        Returns the Process Id of the detached process responsible for restarting the Morpheus Windows Agent service.
        Returns 0 if the Detached process failed to start successfully

    #>     
    [CmdletBinding()]
    param (
        [PSCredential]$Credential,
        [Switch]$Default
    )
    
    # Note that Credential should be a member of Local administrators group and will need to have Logon as Service rights assigned
    # TODO Only pick up an error when trying to start the service
    if (IsElevated) {
        $restart = $false
        $agent = Get-WmiObject -Class win32_Service -Filter "Name like 'Morpheus Windows Agent'"
        if ($agent) {
            if ($Default) {
                $status = $agent.Change($null,$null,$null,$null,$null,$null,".\LocalSystem","",$null,$null,$null)
                if ($status.ReturnValue -gt 0) {
                    Write-Warning "Agent Service retuned a status code $($status.ReturnValue)"
                } else {
                    $restart = $true
                }           
            } else {
                if ($Credential) {
                    $status = $agent.Change($null,$null,$null,$null,$null,$null,$Credential.UserName,$Credential.GetNetworkCredential().Password,$null,$null,$null)
                    if ($status.ReturnValue -gt 0) {
                        Write-Warning "Agent Service retuned a status code $($status.ReturnValue)"
                    } else {
                        $restart = $true
                    }
                }
            }
            if ($restart) {
                $process = Delay-AgentRestart -Delay 10
            }
        } 
    } else {
        Write-Warning "You need to be an Administrator to run this Function"
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
    [CmdletBinding()]
    param (
        [String]$B64,
        [ValidateSet("Unicode","UTF8")]
        [String]$Encoding="Unicode"
    )
    if ($Encoding) {
        return [System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String($B64))
    } else {
        return [System.Text.Encoding]::UFT8.GetString([System.Convert]::FromBase64String($B64))
    } 
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
    
    .PARAMETER Minutes

        Number of Minutes to read from StartDate - Default 60        
    
    .PARAMETER AsJson
        Return output as Json

    .OUTPUTS
        Morpheus Agent events from StartDate

    #>
    [CmdletBinding()]    
    param (
        [DateTime]$StartDate=[DateTime]::Now.AddMinutes(-30),
        [Int32]$Minutes=60,
        [Int32]$ClockAdjust,
        [Switch]$AsJson
    )

    #Default to Setup Date if no StartDate
    if (-Not $StartDate) {
        $StartDate = (Get-WindowsSetupDate).installDate.Date
    }
    $EndDate = $StartDate.AddMinutes($Minutes)
    $Filter = @{LogName="Morpheus Windows Agent";StartTime=$StartDate;EndTime=$EndDate}

    try {
        $Events = Get-WinEvent -FilterHashtable $Filter -ErrorAction "Stop" | Sort-Object -Property RecordId
    }
    catch {
        Write-Warning "No Events found in this timnespan"
        return
    }
    
    $eventData = foreach ($e in $Events) {
        if ($ClockAdjust) {$timeStamp = $e.TimeCreated.AddSeconds($clockAdjust)} else {$timeStamp = $e.TimeCreated}
        $output = [PSCustomObject]@{
            computer=$e.MachineName;
            recordId=$e.RecordId;
            timeStamp=$timeStamp.ToString("yyyy-MM-ddTHH:mm:ss.fff");
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
            if ($Event.GetType().Name -eq "EventLogRecord") {
                #This is a raw Event log record
                $stomp = [PSCustomObject]@{
                    recordId = $Event.RecordId;
                    timeStamp = $Event.TimeCreated;
                    frameType="";
                    header=[PSCustomObject]@{};
                    body=[PSCustomObject]@{}
                }
            } else {
                # this record was filtered by Read-Agentlog
                $stomp = [PSCustomObject]@{
                    recordId = $Event.RecordId;
                    timeStamp = $Event.timeStamp;
                    frameType="";
                    header=[PSCustomObject]@{};
                    body=[PSCustomObject]@{}
                }
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
                                $entry = Base64Decode $Matches[1]
                                Add-Member -InputObject $stomp.body -MemberType NoteProperty -Name "decodedScript" -Value $entry
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

Function Get-StompActionAck {
    <#
    .SYNOPSIS
        Takes the output from Parse-StompMessage and extracts the actionAcknowledged messages

    .PARAMETER Message
        Output from Parse-StompMessage

    .OUTPUTS
        DateTime when the Windows Installation completed

    #>
    [CmdletBinding()]    
    param (
        [Parameter(Mandatory = $true, Position = 0,ValueFromPipeline=$true)]
        [Object[]]$Message,
        [Switch]$AsJson
    )

    begin {
        $Out = [System.Collections.Generic.List[PSCustomObject]]::new()
    }
    process {
        foreach ($frame in $Message) {
            if (($frame.frameType -eq "SEND") -and ($frame.header.destination -eq "/app/actionAcknowledged")) {
                # Ack frame
                $ack = [PSCustomObject]@{
                    recordId = $frame.recordId;
                    timeStamp = $frame.timeStamp;
                    request = $frame.body.id;
                    cmd = "";
                    exitValue = $frame.body.data.exitValue;
                    output = $frame.body.data.output;
                    error = $frame.body.data.error
                }
                $out.Add($ack)
            } elseif (($frame.frameType -eq "MESSAGE") -and ($frame.header.destination -eq "/user/queue/morpheusAgentActions")) {
                # Action frame
                $request =  if ($frame.body.id) {$frame.body.id} else {"frame too long for log"}
                $cmd =  if ($frame.body.id) {$frame.body.decodedScript} else {"frame too long for log"}
                $ack = [PSCustomObject]@{
                    recordId = $frame.recordId;
                    timeStamp = $frame.timeStamp;
                    request = $request;
                    cmd = $cmd;
                    exitValue = "";
                    output = "";
                    error = ""
                }
                $out.Add($ack)
            }
        }
    }
    end {
        return $out
    }

}

Function Get-ScheduledTaskEvents {
    [CmdletBinding()]
    param (
        [String]$TaskName,
        [String]$TaskPath="\",
        [Int32]$RecentMinutes=30
    )    

    $TimeSpan = (New-TimeSpan -Minutes $RecentMinutes).TotalMilliseconds
    $Task = Join-Path -Path $TaskPath -ChildPath $TaskName
    #Filter the Event\System Node for EventId's and TimeCreated 
    $xSysFilter = "TimeCreated[timediff(@SystemTime)&lt;={0}]" -f $TimeSpan
    $xEventDataFilter = "[EventData[Data[@Name='TaskName']='{0}']]" -f $Task
    # Construct the xPath filter
    $xPath = "Event[System[{0}]]{1}" -f $xSysFilter, $xEventDataFilter
    Write-Verbose "Using xPath Filter $($xPath)"
    $XmlQuery = $entry:XmlQueryTemplate -f $xPath, "Microsoft-Windows-TaskScheduler/Operational"
    Write-Host $XmlQuery
    $Events = Get-WinEvent -FilterXml $XmlQuery  -ErrorAction "SilentlyContinue"
    $Events
}

Function Read-PSLog {
    <#
    .SYNOPSIS
        Reads the Windows Powershell logs and returns script executions. If the script is Base64 encoded then
        this script decodes and returns the actual powershell. Useful for reading any Morpheus WinRm RPC commands

    .PARAMETER EventId
        Event ID to read. Default is Event 400

    .PARAMETER Computer
        Computername. Default is local Computer

    .PARAMETER StartDate
        Date / Time to start reading the log
    
    .PARAMETER Minutes

        Number of Minutes to read from StartDate - Default 60
    
    .PARAMETER AsJson

        Output results in json

    .OUTPUTS
        DateTime when the Windows Installation completed

    #>
    [CmdletBinding()]    
    param (
        $EventId=400,
        [String]$Computer=$null,
        [DateTime]$StartDate,
        [Int32]$Minutes=60,
        [Int32]$ClockAdjust,
        [Switch]$AsJson
    )

    #Default last 30 minutes if no start date
    if (-Not $StartDate) {
        $StartDate = (Get-Date).AddMinutes(-30)
    }
    $EndDate = $StartDate.AddMinutes($Minutes)
    $Filter = @{LogName="Windows Powershell";Id=$EventId;StartTime=$StartDate;EndTime=$EndDate}

    try {
        $Events = Get-WinEvent -FilterHashtable $Filter -ErrorAction "Stop" | Sort-Object -Property RecordId
    }
    catch {
        Write-Warning "No Events found in this timnespan"
        return
    }

    $eventData = foreach ($e in $Events) {
        if ($ClockAdjust) {$timeStamp = $e.TimeCreated.AddSeconds($clockAdjust)} else {$timeStamp = $e.TimeCreated}
        $output = [PSCustomObject]@{
            computer=$e.MachineName;
            index=$e.RecordId;
            Time=$timeStamp.ToString("yyyy-MM-ddTHH:mm:ss.fff");
            host="";
            command="";
            encodedcommand=""
        }
        
        if ($e.message -match "HostName=(.*)\r") {
            $output.host=$matches[1]
        }
        if ($e.message -match "HostApplication=(.*)\r") {
            $output.command=$matches[1]
            if ($output.command -match "-encodedcommand (\S*)") {
                #Base64 encoded command
                $output.encodedcommand=[System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String($matches[1]))
            }
        }
        $output
    }
    if ($AsJson) {
        return $eventData | ConvertTo-Json -Depth 3 
    } else {
        return $eventData
    }    
}


Function Parse-PSLog {
    <#
    .SYNOPSIS
        Takes the output from Read-PSLog and attemts to extract the Powershell scripts executes of RPC/Agent.

    .PARAMETER Path
        Where to dump the script files

    .OUTPUTS
        DateTime when the Windows Installation completed

    #>
    [CmdletBinding()]    
    param (
        [Parameter(Mandatory = $true, Position = 0,ValueFromPipeline=$true)]
        [Object[]]$PSEvent,
        [String]$Path=$Env:UserProfile,
        [Switch]$AsJson,
        [Switch]$Cleanup
    )
    
    Begin {
        #Match and caputre the json body in a Stomp Frame
        $psFragment = '^powershell.*(\[System\.IO\.File\]::AppendAllText\(([^,]*).*)'
        $psFile = "^powershell.*-File\s+(.*)$"
        $psEncoded = "^powershell.*-encodedcommand\s+(.*)$"
        $p2 = "^powershell.*AppendAllText\(([^,]*),([^,]*).*$"
        $Index = @{}
        $Out = [System.Collections.Generic.List[PSCustomObject]]::new()
    }
    Process {
        foreach ($event in $PSEvent) {
            $entry = [PSCustomObject]@{
                id="";
                eventIndex=$event.index;
                length=0;
                executed=$event.Time;
                content=""
            }
            if ($event.command -Match $psFile) {
                write-Host ("Found Execute file {0} - Add to list " -f $Matches[1]) -ForegroundColor Yellow
                $id = Split-Path -Path $filepath.Trim("'") -Leaf
                $tmpPath = Join-Path -Path $Path -ChildPath $id
                $entry.id = $id
                $entry.content = [System.IO.File]::ReadAllText($tmpPath)
                $entry.length = $entry.content.length
                $Out.Add($entry)
                if ($CleanUp) {Remove-Item -Path $tmpPath -Force}
            } elseif ($event.command -Match $psFragment) {
                # Matches[1] - command
                # Matches[2] - filename
                $filepath = $Matches[2]
                $id = Split-Path -Path $filepath.Trim("'") -Leaf
                write-Host ("Event {0} - Time {1}" -f $event.Index, $event.Time) -ForegroundColor Green
                write-Host ("File Id {0}" -f $id) -ForegroundColor Green
                #write-Host ("Found cmd {0}" -f $cmd) -ForegroundColor Green
                $Name = Join-Path -Path $Path -ChildPath $id
                $cmd = $Matches[1].Replace($filepath,"`$Name")
                if ($Index.ContainsKey($id)) {
                    #Append
                    $Index.Item($id)++
                    write-Host ("Found Next fragment for {0} - fragment {1}" -f $Name, $Index.Item($Id)) -ForegroundColor Green			
                } else {
                    #New File
                    $Index.Add($id,1)
                    if (Test-Path -Path $Name) {Remove-Item -Path $Name -Force}
                    write-Host ("Found New fragment for {0}" -f $Name) -ForegroundColor Blue
                }
                # Execute the fragment
                Invoke-Expression $cmd
            } elseif ($event.command -Match $psEncoded) {
                Write-Host "Found Encoded Command"
                $cmd = Base64Decode -B64 $Matches[1]
                $entry.id = "rpc-{0}" -F $event.index
                $entry.content = $cmd
                $entry.length = $cmd.length
                $Out.Add($entry)
            }
        }
    }
    End {
        if ($AsJson) {
            return $Out | ConvertTo-Json
        } else {
            return $Out
        }
    }
}

Function Test-Credential
<#
.SYNOPSIS
	Takes a PSCredential object and validates it against the domain (or local machine, or ADAM instance).

.PARAMETER cred
	A PScredential object with the username/password you wish to test. Typically this is generated using the Get-Credential cmdlet. Accepts pipeline input.

.PARAMETER context
	An optional parameter specifying what type of credential this is. Possible values are 'Domain','Machine',and 'ApplicationDirectory.' The default is 'Domain.'

.OUTPUTS
	A boolean, indicating whether the credentials were successfully validated.

#>
{
	[CmdletBinding()]
	Param
	(
		[parameter(Mandatory=$true,ValueFromPipeline=$true)]
        [System.Management.Automation.PSCredential]$Credential,
		[parameter()][validateset('Domain','Machine','ApplicationDirectory')]
        [String]$Context = 'Domain'
	)
	
	Begin
	{
		Add-Type -assemblyname system.DirectoryServices.accountmanagement
		if ($context -Match 'Domain')
		{
			$DomainName = $Credential.GetNetworkCredential().Domain
			$DS = New-Object System.DirectoryServices.AccountManagement.PrincipalContext([System.DirectoryServices.AccountManagement.ContextType]::$Context,$DomainName) 
		}
		else
		{
			$DS = New-Object System.DirectoryServices.AccountManagement.PrincipalContext([System.DirectoryServices.AccountManagement.ContextType]::$Context) 
		}
	}
	process 
	{
		$Valid = $DS.ValidateCredentials($Credential.GetNetworkCredential().UserName, $Credential.GetNetworkCredential().password)
		Write-Verbose "Authenticating Credential $($Credential.UserName) against $Context Context : Validated $Valid"
		$Valid
	}
} #End of Test-Credential

Function Set-LogOnAsServiceRight {
    <#
    .SYNOPSIS
        Uses the Local Security Editor to Add LogonAsService rights to the user defined in Credential

    .PARAMETER Credential
        Where to dump the script files

    .OUTPUTS
        Returns $true if successful

    #>
    [CmdletBinding()] 
    param(
        [PSCredential]$Credential
    )
        
    if ($Credential) {
        try {
            $user =  New-Object System.Security.Principal.NTAccount($Credential.UserName)
            $userSid = ($user.Translate([System.Security.Principal.SecurityIdentifier])).Value
        }
        catch {
            Write-Warning "Unable to Obtain SID for user $(Credential.UserName)"
            return $false
        }
    } else {
        Write-Warning "You must supply a valid Credential Object"
        return $false 
    }

    
    $currentCfgFile = Join-Path -Path $Env:LocalAppData -ChildPath "exportCfg.inf"
    $newCfgFile = Join-Path -Path $Env:LocalAppData -ChildPath "importCfg.inf"
    $secDb = Join-Path -Path $Env:LocalAppData -ChildPath "secedit.sdb"
    $status = $false
    #Get the current Policy config
    $export = Invoke-Command -ScriptBlock  {secedit /export /cfg $($currentCfgFile)}
    if (Test-Path $currentCfgFile) {
        $Unicode = Select-String -Path $currentCfgFile -Pattern 'Unicode=yes'
        # Find the SeServiceLogonRight Rights line
        $currentSetting = Select-String -Path $currentCfgFile -Pattern '^SeServiceLogonRight = .*$'
        if ($currentSetting) {
            $currentSids = $currentSetting.line
            if ($currentSids -match $userSid) {
                #User Already has right
                Write-Host "User $($Credential.UserName) already has LogonAsService rights on this computer"
                $status = $true
            } else {
                #Need to add $UserSid to the list of current SIDs
                $newSids = "{0},*{1}" -f $currentSids, $userSid
                Write-Host "Updating Policy with $($newSids)"
                $policy = Get-Content -Path $currentCfgFile -Raw
                if ($unicode) {
                    $policy.Replace($currentSids,$newSids) | Set-Content -Path $newCfgFile -Encoding Unicode
                } else {
                    $policy.Replace($currentSids,$newSids) | Set-Content -Path $newCfgFile
                }
                #Update Policy
                $update = {
                    secedit /import /db $secDb /cfg $newCfgFile 
                    secedit /configure /db $secDb
                    gpupdate /force 
                }
                try {
                    $out = Invoke-Command -ScriptBlock $update -ErrorAction Stop
                    $status = $true
                }
                catch {
                    Write-Warning "Exception raised Updating policy $($_.Message.Exception)"
                    $status = $false
                }
            }
        }
    }
    # Clean-Up
    if (Test-Path -Path $currentCfgFile) {Remove-Item -Path $currentCfgFile -Force}
    if (Test-Path -Path $newCfgFile) {Remove-Item -Path $newCfgFile -Force}
    if (Test-Path -Path $secDb) {Remove-Item -Path $secDb -Force}
    $status
}

