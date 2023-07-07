function Connect-SynoServer
{
    [cmdletbinding()]
    param([String]$Server,[System.Management.Automation.PSCredential]$Credential = (Get-Credential),[int]$Port=5001,[Switch]$Force)
    
    $SynoBaseUri = "https://${Server}:$Port/webapi"
    try {
        if ($Force.IsPresent)
        {
            if (-not("dummy" -as [type])) {
                add-type -TypeDefinition @"
using System;
using System.Net;
using System.Net.Security;
using System.Security.Cryptography.X509Certificates;

public static class Dummy {
    public static bool ReturnTrue(object sender,
        X509Certificate certificate,
        X509Chain chain,
        SslPolicyErrors sslPolicyErrors) { return true; }

    public static RemoteCertificateValidationCallback GetDelegate() {
        return new RemoteCertificateValidationCallback(Dummy.ReturnTrue);
    }
}
"@
            }

            [System.Net.ServicePointManager]::ServerCertificateValidationCallback = [dummy]::GetDelegate()
            [Net.ServicePointManager]::SecurityProtocol = 'TLS11','TLS12','ssl3'
        }
    }
    catch
    {
        Write-Error $_.Exception
    }    
    $response = Invoke-RestMethod -Uri "$SynoBaseUri/entry.cgi" -Method GET -Body @{api='SYNO.API.Info';method='query';version=1}
    if ($response.success)
    {
        $apiInfo = $response.data
    } else {
        throw "Error $([SynoError]$response.error.code)"
    }
    $api = 'SYNO.API.Auth'
    $authApiInfo = $apiInfo.$api
    $response = Invoke-RestMethod -Uri "$SynoBaseUri/$($authApiInfo.path)" -Method POST -Body @{api=$api;method='login';version=6;account=$Credential.UserName;passwd=$Credential.getNetworkCredential().password} -SessionVariable websession -ContentType 'application/json; charset=UTF-8'
    if (!$response.success)
    {
        throw "Error $([SynoError]$response.error.code)"
    }
    $global:SynologySession = [PSCustomObject]@{websession = $WebSession;uri = $SynoBaseUri;apiInfo = $ApiInfo}
}

Set-Alias -Name Connect-ABServer -Value Connect-SynoServer

function Invoke-SynoApiMethod
{
    [CmdletBinding()]
    param([Parameter(Mandatory=$true)][ArgumentCompleter(
            {
                param($Command, $Parameter, $WordToComplete, $CommandAst, $FakeBoundParams)
                $global:SynologySession.apiInfo.psobject.Properties | Where-Object {$_.Name -Like "$WordToComplete*"} | ForEach-Object Name

            }
           )][ValidateScript(
            {
                ($global:SynologySession.apiInfo.psobject.Properties | ForEach-Object {$_.Name}) -contains $_
            })][String]$Api,
            [Parameter(Mandatory=$true)][String]$Method,
            [int]$Limit,
            [int]$Offset,
            [Hashtable]$Parameters = @{},
            [int]$Version = ($global:SynologySession.ApiInfo.$api.MinVersion)
           )

    Write-Verbose $global:SynologySession.ApiInfo.$api
    $ProgressPreference = 'SilentlyContinue'

    if ($limit)
    {
        $Parameters['limit'] = $limit
    }
    if ($offset)
    {
        $Parameters['offset'] = $offset
    }
    $Body = @{api=$api;method=$Method;version=$Version}
    
    foreach ($key in $Parameters.Keys)
    {
       $Body[$key] = ConvertTo-Json -InputObject $Parameters[$key] -Compress
    }
    #TODO: Override duplicates
    Write-Verbose ($Body | Convertto-json | Out-String)
    #$response = Invoke-RestMethod -Uri "$($global:SynologySession.Uri)/$($global:SynologySession.ApiInfo.$api.path)" -Headers @{'Accept-Charset'='UTF-8'} -Method POST -Body $Body -WebSession $global:SynologySession.websession -ContentType 'application/json; charset=UTF-8' -ErrorAction SilentlyContinue
    #Invoke-RestMethod refuses to interpret the response as utf-8 so some conversion has to be done.
    $response = Invoke-WebRequest -Uri "$($global:SynologySession.Uri)/$($global:SynologySession.ApiInfo.$api.path)" -Headers @{'Accept-Charset'='UTF-8'} -Method POST -Body $Body -WebSession $global:SynologySession.websession -ContentType 'application/json; charset=UTF-8'
    $response = [system.text.encoding]::UTF8.GetString(([system.text.encoding]::GetEncoding('iso-8859-1').GetBytes($response.content))) | ConvertFrom-Json
    if (!$response.success)
    {
        Write-Error "Error $([SynoError]$response.error.code)"
    }
    $response.data    
}

function Disconnect-SynoServer
{
    [CmdletBinding()]
    param()
    Invoke-SynoApiMethod -Api SYNO.API.Auth -Method logout
    Remove-Variable -Scope global -Name SynologySession
}

Set-Alias -Name Disconnect-ABServer -Value Disconnect-SynoServer

function Get-SynoVolume
{
    [cmdletbinding()]
    param([Parameter(ValueFromPipelineByPropertyName=$true)][String[]]$volume_path)
    PROCESS
    {
        foreach($path in $volume_path)
        {
            Write-Verbose "volume_path: $path"
            Invoke-SynoApiMethod -Api SYNO.Core.Storage.Volume -Method get -Parameters @{volume_path=$path} | ForEach-Object {$_.volume}
        }
    }
    END
    {
        if (!$PSBoundParameters.ContainsKey('volume_path'))
        {
            Invoke-SynoApiMethod -Api SYNO.Core.Storage.Volume -Method list -Parameters @{limit=-1;offset=0;location='internal';option='include_cold_storage'} | ForEach-Object {$_.volumes}
        }
    }
    
}

function Get-SynoPool
{
    [cmdletbinding()]
    param()
    Invoke-SynoApiMethod -Api SYNO.Core.Storage.Pool -Method list -Parameters @{limit=-1;offset=0;location='internal'} | ForEach-Object {$_.pools}
}


function Get-SynoUtilization
{
    [cmdletbinding()]
    param()
    Invoke-SynoApiMethod -Api SYNO.Core.System.Utilization -Method get
}


function Get-SynoShare
{
    [cmdletbinding()]
    param([String]$Name = '*')
    Invoke-SynoApiMethod -Api SYNO.Core.Share -Method list -Parameters @{additional = @("share_quota")}| ForEach-Object {$_.shares} | Where-Object {$_.name -like $Name}
}

function Get-SynoChildItem
{
    [cmdletbinding()]
    param([String]$Path,[switch]$Size)
    if ($PSBoundParameters.ContainsKey('Path'))
    {
        Write-Verbose $Path
        $additional = @('real_path','size','owner','time','perm','type','mount_point_type','description','indexed')
        $result = Invoke-SynoApiMethod -Api SYNO.FileStation.List -method list -Parameters @{folder_path=$Path;filetype='all';action='list';checkdir=$true;sort_by='name';additional=$additional} -Version 2 | ForEach-Object {$_.files}
    } else {
        $result = Invoke-SynoApiMethod -Api SYNO.FileStation.List -method list_share | ForEach-Object {$_.shares}
    }
    if ($Size.IsPresent)
    {
        $sum = 0
        foreach ($childitem in $result)
        {
            if ($childitem.isdir)
            {
                $sum += Get-SynoChildItem -Path $childitem.path -Size
            } else {
                $sum += $childitem.additional.size
            }
        }
        $sum
    } else {
        $result
    }
}

enum DRRole
{
    ANY = 0
    MAINSITE
    DRSITE
}

function Get-SynoSyncStatus
{
    [cmdletbinding()]
    param([DRRole]$role = 0)
    $result = Invoke-SynoApiMethod -Api SYNO.DR.Plan -Method list -Parameters @{additional=@("sync_report","main_site_info","dr_site_info","op_info","last_op_info")}
    foreach ($plan in $result.plans)
    {
        if ($role -and $plan.role -ne $role)
        {
            continue
        }
        [PSCustomObject]@{
            target        = $plan.additional.main_site_info.target_name
            main_site     = $plan.additional.main_site_info.hostname
            dr_site       = $plan.additional.dr_site_info.hostname
            elapsed_time  = [nullable[int]]$plan.additional.op_info.op_progress.syncing_record.elapsed_time
            speed_mbps    = [math]::round($plan.additional.op_info.op_progress.syncing_record.current_speed / 1MB,1)
            total_size_gb = [math]::round($plan.additional.op_info.op_progress.syncing_record.total_size_byte / 1GB,1)
            sync_size_gb  = [math]::round($plan.additional.op_info.op_progress.syncing_record.sync_size_byte / 1GB,1)
            progress      = $plan.additional.op_info.op_progress.percentage
            sync_type     = $plan.additional.op_info.op_progress.sync_type
        }
    }
}

function Get-SynoSystemHealth
{
    [cmdletbinding()]
    param()
    Invoke-SynoApiMethod -Api SYNO.Core.System.SystemHealth -method get
}

function Get-ABChildEntity
{
    [cmdletbinding(DefaultParameterSetName='Type')]
    param([Alias('id')][string[]]$EntityId = '',
          [switch]$Recurse,
          [int]$InventoryId = @(Invoke-SynoApiMethod -Api SYNO.ActiveBackup.Inventory -method list -Parameters @{filter=@{type=@(2)}})[0].inventory_id,
          [Parameter(ParameterSetName='Type')][String]$Type = '*',
          [String[]]$Exclude,
          [Parameter(ParameterSetName='AsDevice')][Switch]$AsDevice)
    $result = @()
    
    foreach ($id in $EntityId)
    {
        Write-Verbose "Get-ABChildEntity $id"
        if ($id -like 'vm-*')
        {
            $result += Get-ABEntity -id $id | Where-Object {$_.id -notin $Exclude}
        } else {
            $result += Invoke-SynoApiMethod -Api SYNO.ActiveBackup.Inventory -method list_node -Parameters @{inventory_id=$InventoryId;view_type='vim.VirtualMachine-Folder';parent_id=$id} | Where-Object {$_.id -notin $Exclude}
        }
    }
    $Inventory = @(Invoke-SynoApiMethod -Api SYNO.ActiveBackup.Inventory -method list -Parameters @{filter=@{type=@(2);inventory_id=@($InventoryId)}})
    if ($Recurse.IsPresent)
    {
        foreach ($folder in $result | Where-Object {$_.type -eq 'vim.Folder'})
        {
            $parameters = @{} + $PSBoundParameters
            $parameters['EntityId'] = $folder.id
            Get-ABChildEntity @parameters
        }
    }
    foreach ($item in $result | Sort-Object -Property id -Unique)
    {
        if ($item.type -notlike "vim.$Type" -or ($AsDevice.IsPresent -and ($item.type -notlike 'vim.VirtualMachine' -or $item.is_template)))
        {
            continue
        }

        if ($AsDevice.IsPresent)
        {
            [ABDevice][PSCustomObject]@{
                host_name = $item.name
                os_name = $item.os_name
                device_uuid = $item.instance_uuid
                vm_moid_path = $item.vm_id
                inventory_id = $Inventory.inventory_id
                inventory_name = $Inventory.host_name
            }
        }
        else
        {
            [ABEntity]$item
        }
    }
}
function Update-ABInventory
{
    [cmdletbinding()]
    param([int]$InventoryId = @(Invoke-SynoApiMethod -Api SYNO.ActiveBackup.Inventory -method list -Parameters @{filter=@{type=@(2)}})[0].inventory_id,
          [Switch]$Wait)
    $result = Invoke-SynoApiMethod -Api SYNO.ActiveBackup.Inventory -method get_server_cache -Parameters @{inventory_id=$InventoryId;polling_api=$true}
    if (!$result.Updating)
    {
        try {
            Invoke-SynoApiMethod -Api SYNO.ActiveBackup.Inventory -Method update_cache -Parameters @{inventory_id=$InventoryId} -Version 1
        } catch {
        }
    }
    if ($Wait.IsPresent)
    {
        Wait-ABInventory -InventoryId $InventoryId
    }
}

function Wait-ABInventory
{
    [cmdletbinding()]
    param($InventoryId = @(Invoke-SynoApiMethod -Api SYNO.ActiveBackup.Inventory -method list -Parameters @{filter=@{type=@(2)}})[0].inventory_id)
    do {
        $result = Invoke-SynoApiMethod -Api SYNO.ActiveBackup.Inventory -method get_server_cache -Parameters @{inventory_id=$InventoryId;polling_api=$true}
    } while ($result.Updating -and !(Start-Sleep -Seconds 5))
}

function Get-ABEntity
{
    [cmdletbinding(DefaultParameterSetName='Id')]
    param([Parameter(ParameterSetName='Id')][string]$id,
          $InventoryId = @(Invoke-SynoApiMethod -Api SYNO.ActiveBackup.Inventory -method list -Parameters @{filter=@{type=@(2)}})[0].inventory_id,
          [Switch]$AsDevice)
    $Path = Invoke-SynoApiMethod -Api SYNO.ActiveBackup.Inventory -Method get_node_path -Parameters @{inventory_id=$InventoryId;view_type='vim.VirtualMachine-Folder';parent_id='';entity_id=$id}
    if ($Path.found)
    {
        $ParentPath = @('') + $Path.Path -split '/'
        $Parent = $ParentPath[-2]
        Get-ABChildEntity -EntityId $Parent -InventoryId $InventoryId -AsDevice:$AsDevice.IsPresent| Where-Object {(!$AsDevice.IsPresent -and $_.id -eq $id) -or ($AsDevice.IsPresent -and $_.vm_moid_path -eq $id)}
    }
}
function Set-ABTask
{
    [cmdletbinding(SupportsShouldProcess=$true,ConfirmImpact='Medium',DefaultParameterSetName='Devices')]
    param([String]$TaskName, 
          [Parameter(ValueFromPipelineByPropertyName=$true)][int []]$task_id,
          [Parameter(ParameterSetName='EntityId')][String[]]$EntityId,
          [Parameter(ParameterSetName='EntityId')][String[]]$Exclude,
          [Parameter(ParameterSetName='Devices')][ABDevice[]]$Devices,
          [int]$max_concurrent_devices,
          [ABVMFolder[]]$CheckFolder,
          [ABSchedule]$Schedule,
          [int]$InventoryId = @(Invoke-SynoApiMethod -Api SYNO.ActiveBackup.Inventory -method list -Parameters @{filter=@{type=@(2)}})[0].inventory_id,
          [String]$ShareName,
          [ABRetentionPolicy]$RetentionPolicy,
          [ValidateSet('vim.VirtualMachine-Host','vim.VirtualMachine-Folder')][String]$ViewType
    )
    BEGIN
    {
        $parameters = @{task_ids=@()}
        if ($PSBoundParameters.ContainsKey('EntityId'))
        {
            $parameters['devices'] = @(Get-ABChildEntity -EntityId $EntityId -Recurse -Exclude $Exclude -AsDevice -InventoryId $InventoryId)
        }
        if ($PSBoundParameters.ContainsKey('Devices'))
        {
            $parameters['devices'] = $Devices
        }
        if ($PSBoundParameters.ContainsKey('TaskName'))
        {
            $parameters['task_name'] = $TaskName
        }
        if ($PSBoundParameters.ContainsKey('ShareName'))
        {
            $parameters['share_name'] = $ShareName
        }
        if ($PSBoundParameters.ContainsKey('RetentionPolicy'))
        {
            $parameters['retention_policy'] = $RetentionPolicy.psobject.properties | Where-Object {$_.value -ne $null} | ForEach-Object {$h=@{}}{$h[$_.Name]=$_.value}{$h}
        }
        if ($PSBoundParameters.ContainsKey('Schedule'))
        {
            $parameters['sched_content'] = $Schedule
        }
        if ($PSBoundParameters.ContainsKey('ViewType'))
        {
            $parameters['view_type'] = $view_type
        }
        if ($PSBoundParameters.ContainsKey('CheckFolder'))
        {
            $parameters['check_folders'] = $CheckFolder
        }
        if ($PSBoundParameters.ContainsKey('max_concurrent_devices'))
        {
            $parameters['max_concurrent_devices'] = $max_concurrent_devices
        }
    }
    PROCESS
    {
        $parameters['task_ids'] += $task_id
    }
    END
    {
        if ($PSCmdlet.ShouldProcess("task $id","$([PSCustomObject]$parameters | Format-List | Out-String)"))
        {
            Invoke-SynoApiMethod -Api SYNO.ActiveBackup.Task -Method set -Parameters $parameters
        }
    }
}

function New-ABSchedule
{
    [cmdletbinding()]
    param([int]$Hour = 3,[int]$Minute = 0)
    [ABSchedule]::New($Hour,$Minute)
}

function New-ABRetentionPolicy
{
    [cmdletbinding(DefaultParameterSetName='Days')]
    param([Parameter(ParameterSetName='Disabled')][switch]$DisablePolicy,
          [Parameter(Mandatory=$true,ParameterSetName='Days')][Parameter(ParameterSetName='GFS')][int]$KeepDays,
          [Parameter(Mandatory=$true,ParameterSetName='GFS')][int]$KeepVersions,
          [Parameter(ParameterSetName='GFS')][int]$GFSDays,
          [Parameter(ParameterSetName='GFS')][int]$GFSWeeks,
          [Parameter(ParameterSetName='GFS')][int]$GFSMonths,
          [Parameter(ParameterSetName='GFS')][int]$GFSYears
    )
    Write-Verbose $PSCmdlet.ParameterSetName
    $result = @{ keep_all = $DisablePolicy.IsPresent }

    foreach ($key in $PSBoundParameters.Keys)
    {
        switch ($key) {
            KeepDays      {$result['keep_days']     = $KeepDays      }
            KeepVersions  {$result['keep_versions'] = $KeepVersions  }
            GFSDays       {$result['gfs_days']      = $GFSDays       }
            GFSWeeks      {$result['gfs_weeks']     = $GFSWeeks      }
            GFSMonths     {$result['gfs_months']    = $GFSMonths     }
            GFSYears      {$result['gfs_years']     = $GFSYears      }
        }
    }
    [ABRetentionPolicy]$result
}

function New-ABTask
{
    [cmdletbinding(SupportsShouldProcess=$true,ConfirmImpact='Medium',DefaultParameterSetName='Devices')]
    param([String]$TaskName = (Invoke-SynoMethod -Api SYNO.ActiveBackup.Task -method get_default_task_name -Parameters @{default_prefix='vSphere-Task'}), 
          [Parameter(ParameterSetName='EntityId')][Alias('id')][String[]]$EntityId,
          [Parameter(ParameterSetName='EntityId')][String[]]$Exclude,
          [int]$max_concurrent_devices = 4,
          [Parameter(ValueFromPipeline=$true,ParameterSetName='Devices')][ABDevice[]]$Devices,
          [int]$InventoryId = @(Invoke-SynoApiMethod -Api SYNO.ActiveBackup.Inventory -method list -Parameters @{filter=@{type=@(2)}})[0].inventory_id,
          [String]$ShareName = (Invoke-SynoApiMethod -Api SYNO.ActiveBackup.Share -Method list).default_share,
          [ABRetentionpolicy]$RetentionPolicy = (New-ABRetentionPolicy -KeepDays 30 -KeepVersions 30 -GFSWeeks 12 -GFSMonths 12),
          [ABSchedule]$Schedule = (New-ABSchedule -Hour 2 -Minute 0),
          [Switch]$CompressTransfer,
          [ValidateSet('vim.VirtualMachine-Host','vim.VirtualMachine-Folder')][String]$ViewType = 'vim.VirtualMachine-Folder' )
    BEGIN
    {
        [ABDevice[]]$devicelist = @()
        if ($PSCmdlet.ParameterSetName -eq 'EntityId')
        {
            foreach ($Id in $EntityId)
            {
                $devicelist += Get-ABChildEntity -EntityId $Id -Recurse -AsDevice -Exclude $Exclude
            }
        }
    }
    PROCESS
    {
        
        if ($PSCmdlet.ParameterSetName -eq 'Devices')
        {
            $devicelist += $devices
        }
    }
    END
    {
        Write-Verbose ($devicelist | ForEach-Object {$_.Name} | Out-String)

        $admins = Invoke-SynoApiMethod -Api SYNO.ActiveBackup.UserGroup -Method list_admin -Parameters @{type='local'}
        if ((Invoke-SynoApiMethod -Api SYNO.ActiveBackup.Wrapper.Domain -Method get).domain_name -and (Invoke-SynoApiMethod -Api SYNO.ActiveBackup.Wrapper.Domain -Method test_dc).test_join_success)
        {
            $domainadmins = Invoke-SynoApiMethod -Api SYNO.ActiveBackup.UserGroup -Method list_admin -Parameters @{type='domain_ldap'}
            $admins.groups += $domainadmins.groups
            $admins.users += $domainadmins.users
        }
        
        $groups = @($admins.groups | ForEach-Object {$_.uid})
        $users = @($admins.users | ForEach-Object {$_.uid})
        
        $Parameters = @{
            cbt_enable_mode	= $true
            datastore_reserved_percentage = 5
            devices	= @($devicelist)
            enable_app_aware_bkp = $true #quiesce
            enable_compress_transfer = $CompressTransfer.IsPresent #for slow networks
            enable_datastore_aware = $true
            enable_encrypt_transfer = $false
            enable_verification = $false
            groups = $groups
            max_concurrent_devices = $max_concurrent_devices
            retention_policy = $RetentionPolicy.psobject.properties | Where-Object {$_.value -ne $null} | ForEach-Object {$h=@{}}{$h[$_.Name]=$_.value}{$h} #properties with null value will be changed to default (which is really dumb).
            sched_content = $Schedule
            scripts = @{}
            share_name = $ShareName
            task_name = $TaskName
            users = $users
            verification_policy = 120 #Why 120? 120 seconds recording?
            view_type = $ViewType
        }
        Write-Verbose "Devices: $($devicelist | ForEach-Object {$_.host_name})"
        #todo: test
        #Invoke-SynoApiMethod -Api SYNO.ActiveBackup.Task -Method create_vm_check -Parameters $Parameters
        #Invoke-SynoApiMethod -Api SYNO.ActiveBackup.Task -Method list_vm_check
        if ($PSCmdlet.ShouldProcess("$([PSCustomObject]$parameters | Format-List | Out-String)","create task"))
        {
            Invoke-SynoApiMethod -Api SYNO.ActiveBackup.Task -Method create_vm -Parameters $Parameters
        }
    }
}

function Get-ABTask
{
    [cmdletbinding(DefaultParameterSetName='Name')]
    param([Parameter(ParameterSetName='Name',Position=1)][String[]]$Name = '*',
          [Parameter(ParameterSetName='task_id',ValueFromPipelineByPropertyName=$true)][int[]]$task_id,
          [Parameter(ParameterSetName='device_id',ValueFromPipelineByPropertyName=$true)][int]$device_id,
          [Parameter(ParameterSetName='Name')][ABBackupType]$backup_type,
          [Switch]$Quick)
    BEGIN
    {
        $Parameters = @{
            load_versions = !$Quick.IsPresent
            load_status   = !$Quick.IsPresent
            load_result   = !$Quick.IsPresent
            load_devices  = !$Quick.IsPresent
            filter = @{}
        }
        
    }
    PROCESS
    {
        if ($PSBoundParameters.ContainsKey('task_id'))
        {
            $Parameters['filter'] = @{task_id=$task_id}
        }
        if ($PSBoundParameters.ContainsKey('device_id'))
        {
            $Parameters['filter'] = @{device_id=$device_id}
        }
        if ($PSBoundParameters.ContainsKey('backup_type'))
        {
            $Parameters['filter'] = @{backup_type=$backup_type}
        }

        ((Invoke-SynoApiMethod -Api SYNO.ActiveBackup.Task -method list -Parameters $Parameters).tasks | Where-Object { $t = $_.task_name; $Name | Where-Object {$t -like $_} }) | ForEach-Object {[ABTask]$_}
    }
}

function Remove-ABTask
{
    [cmdletbinding(SupportsShouldProcess=$true,ConfirmImpact="High")]
    param([Parameter(ValueFromPipelineByPropertyName=$true)][int[]]$task_id)
    BEGIN
    {
        $id = @()
    }
    PROCESS
    {
        $id += $task_id
    }
    END
    {
        if($PSCmdlet.ShouldProcess((Get-ABTask -id $task_id | Select-Object -ExpandProperty task_name | Out-String),'Remove'))
        {
            Invoke-SynoApiMethod -Api SYNO.ActiveBackup.Task -Method remove -Parameters @{task_ids=$id}
        }
    }
}

function Get-ABLog
{
    [cmdletbinding(DefaultParameterSetName='limit')]
    param([Parameter(ValueFromPipelineByPropertyName=$true)][int]$task_id,
          [int]$device_id,
          [ABLogLevel]$log_level,
          [Parameter(ParameterSetName='start')][datetime]$Start,
          [Parameter(ParameterSetName='start')][datetime]$Finish = [datetime]::Now,
          [Parameter(ParameterSetName='limit')][int]$Limit=200,
          [Parameter(ParameterSetName='limit')][int]$Offset=0,
          [hashtable]$filter=@{})
    BEGIN
    {
        $Parameters = @{}
        if($PSCmdlet.ParameterSetName -eq 'start')
        {
            $filter['from_timestamp'] = [int]($start.ToUniversalTime() -  [datetime]"1970-01-01").TotalSeconds
            $filter['to_timestamp']   = [int]($finish.ToUniversalTime() - [datetime]"1970-01-01").TotalSeconds
        } else {
            $Parameters['limit'] = $Limit
            $Parameters['offset'] = $Offset
            
        }
        if ($PSBoundParameters.ContainsKey('device_id'))
        {
                $filter['device_id'] = $device_id
        }
        if ($PSBoundParameters.ContainsKey('log_level'))
        {
                $filter['log_level'] = $log_level
        }
        $Parameters['filter'] = $filter
    }
    PROCESS
    {
        if ($PSBoundParameters.ContainsKey('task_id'))
        {
                $Parameters['task_id'] = $task_id
        }
        (Invoke-SynoApiMethod -Api SYNO.ActiveBackup.Log -Method list_log -Parameters $Parameters).logs | ForEach-Object {[ABLog]$_}
    }
}

function Get-ABResult
{
    [cmdletbinding(DefaultParameterSetName='all')]
    param([Parameter(Position=1,ParameterSetName='result_id')][int]$result_id,
          [Parameter(ParameterSetName='all',ValueFromPipelineByPropertyName=$true)][int]$task_id,
          [Parameter(ParameterSetName='all')][ABBackupType]$backup_type, #ALL returns none
          [ABJobAction[]]$job_action, #ALL returns none
          [Parameter(ParameterSetName='all')][datetime]$Start,
          [Parameter(ParameterSetName='all')][datetime]$Finish = [datetime]::Now,
          [Parameter(ParameterSetName='all')][int]$Limit=200,
          [Parameter(ParameterSetName='all')][int]$Offset=0,
          [hashtable]$filter=@{})
    BEGIN
    {
        $Parameters = @{filter=$filter}
    }
    PROCESS
    {
        
        if ($PSBoundParameters.ContainsKey('task_id'))
        {
            $Parameters['task_id']   = $task_id
        }
        if ($PSBoundParameters.ContainsKey('backup_type'))
        {
            $Parameters['filter']['backup_type'] = $backup_type
        }
        if ($PSBoundParameters.ContainsKey('result_id'))
        {
            $Parameters['result_id'] = $result_id
        }
        if ($PSBoundParameters.ContainsKey('start'))
        {
            $Parameters['filter']['from_timestamp'] = [int]($start.ToUniversalTime() -  [datetime]"1970-01-01").TotalSeconds
            $Parameters['filter']['to_timestamp']   = [int]($finish.ToUniversalTime() - [datetime]"1970-01-01").TotalSeconds
        } else {
            $Parameters['limit']  = $Limit
            $Parameters['offset'] = $Offset
        }
        if ($PSBoundParameters.ContainsKey('job_action'))
        {
            $Parameters['filter']['job_action']  = $job_action
                
        }
        (Invoke-SynoApiMethod -Api SYNO.ActiveBackup.Log -Method list_result -Parameters $Parameters).results | ForEach-Object {[ABResult]$_}
    }
}

function Get-ABResultDetail
{
    [cmdletbinding()]
    param([Parameter(Position=1,ParameterSetName='result_id',ValueFromPipelineByPropertyName=$true)][int]$result_id,[int]$Limit=200,[int]$Offset=0,[hashtable]$filter=@{})
    BEGIN
    {
        $Parameters = @{filter=$filter}
    }
    PROCESS
    {
        if ($PSBoundParameters.ContainsKey('result_id'))
        {
                $Parameters['result_id'] = $result_id
        }
        (Invoke-SynoApiMethod -Api SYNO.ActiveBackup.Log -Method list_result_detail -Parameters $Parameters -Limit $Limit -Offset $Offset).result_detail_list | ForEach-Object {[ABResultDetail]$_}
    }
}

function Get-ABDevice
{
    [cmdletbinding()]
    param([Parameter(Position=1,ParameterSetName='host_name',ValueFromPipelineByPropertyName=$true)][String]$host_name,[int]$Limit=200,[int]$Offset=0,[hashtable]$filter=@{})
    BEGIN
    {
        $Parameters = @{load_result=$true;filter=$filter}
    }
    PROCESS
    {
        if ($PSBoundParameters.ContainsKey('host_name'))
        {
                $Parameters['filter']['host_name'] = $host_name
        }
        (Invoke-SynoApiMethod -Api SYNO.ActiveBackup.Device -Method list -Parameters $Parameters -Limit $Limit -Offset $Offset).devices | ForEach-Object {[ABDevice]$_}
    }
}

function Get-ABVersion
{
    [cmdletbinding(DefaultParameterSetName='task_id')]
    param([Parameter(Position=1,Mandatory=$true,ParameterSetName='task_id',ValueFromPipelineByPropertyName=$true)][int]$task_id,
          [Parameter(Mandatory=$true,ParameterSetName='device_id',ValueFromPipelineByPropertyName=$true)][int]$device_id,
          [Parameter(ParameterSetName='device_id')][Switch]$Latest)

    BEGIN
    {
    }
    PROCESS
    {
        if ($PSCmdlet.ParameterSetName -eq 'task_id')
        {
            $Parameters = @{task_id=$task_id}
            (Invoke-SynoApiMethod -Api SYNO.ActiveBackup.Version -Method list -Parameters $Parameters).versions | ForEach-Object {[abversion]$_}
        } else {
            if ($Latest.IsPresent)
            {
                $Parameters = @{device_id=$device_id;single_mode=$true}
                [abversion](Invoke-SynoApiMethod -Api SYNO.ActiveBackup.RestoreVM -Method list_latest_version -Parameters $Parameters).device_list.version | Where-Object {$_.version_id}
            } else {
                $Parameters = @{device_id=$device_id; load_available=$true}
                (Invoke-SynoApiMethod -Api SYNO.ActiveBackup.Device -Method list_version -Parameters $Parameters).versions | ForEach-Object {[abversion]$_}
            }
        }
        
    }
}

function Get-ABActivity
{
    [CmdletBinding()]
    param()
    (Invoke-SynoApiMethod -Api SYNO.ActiveBackup.Overview -method list_activity).activity_list

}

function Get-ABLogMessage
{
    [cmdletbinding()]
    param([ABLogMessageId]$log_type, [PSCustomObject]$params)
    $text = @{
        add_server_completed    =    "The user {user} has added the VMware vSphere server {server}."
        add_server_completed_general    =    "The user {user} added the hypervisor server {server}."
        add_vsphere    =    "Add {vsphere_name} to the virtual machine list."
        agent_continuous_cbt_speed_info    =    "The average backup speed is {speed}. Utilization rates of different components are shown as below: snapshot operation [{ratio_snapshot}], source disk read [{ratio_read_disk}], source data transfer [{ratio_transfer}], and write to file [{ratio_write}]."
        agent_speed_info    =    "The average backup speed is {speed}. Utilization rates of different components are shown as below: snapshot operation [{ratio_snapshot}], source disk read [{ratio_read_disk}], source data transfer [{ratio_transfer}], data deduplication [{ratio_dedup}], and write to file [{ratio_write}]."
        automount_device_not_mount    =    "Failed to automatically mount volume {storage} because the external device is not mounted. Please reconnect the external device."
        automount_enabled    =    "{storage} had been automatically mounted, and the encryption key was stored on {automount_location}."
        automount_fail    =    "Failed to mount volume {storage} automatically."
        automount_key_not_exist    =    "Failed to automatically mount volume {storage} because the private key is not found."
        automount_success    =    "Successfully mounted volume {storage}."
        check_app_aware_failed    =    "{device_name}The virtual machine cannot perform application-aware processing."
        check_broken_snapshot_failed    =    "{device_name}Some snapshots on the virtual machine were taken before CBT was enabled."
        check_disk_4k_aligned_failed    =    "Failed to back up the virtual disk of {device_name}."
        check_enable_cbt_failed    =    "{device_name}CBT is not enabled on the virtual machine."
        check_hypervisor_ssh_service_failed    =    "{device_name}Unable to check the hypervisor's license."
        check_pci_passthrough_failed    =    "{device_name}Unable to take snapshots."
        check_vm_script_failed    =    "{device_name}Pre-thaw/post-thaw script cannot be processed."
        continuous_need_cbt    =    "To perform a continuous backup, the `"Changed Block Tracking`" function must be activated."
        dedup_speed_info    =    "The average speed of removing duplicated data is {speed}. Utilization rates of different components are shown as below: data deduplication [{ratio_dedup}], and write to file [{ratio_write}]."
        delegation_create    =    "DSM administrator {user_name} granted user {user_list} with permissions to [{delegation_rules}]."
        delegation_delete    =    "DSM administrator {user_name} removed user {user_list}'s manager privileges."
        delegation_update    =    "DSM administrator {user_name} changed user {user_list}'s permissions."
        delete_delegation_rule_failed    =    "Unable to delete the delegation. Please try again."
        device_apply_task_template    =    "The task template {task_template} was applied to the device {device}."
        device_connect    =    "The user {user} connected the device {device} to the server."
        device_connect_no_license_pc    =    "Failed to connect device {device} with the server due to insufficient valid PC license."
        device_connect_no_license_server    =    "Failed to connect device {device} with the server due to insufficient valid physical server license."
        device_dedup_cancel    =    "Cancel removing duplicated data in the device {device}."
        device_dedup_error    =    "Failed to remove duplicated data in the device {device}."
        device_dedup_start    =    "Starting to remove duplicated data in the device {device}."
        device_dedup_success    =    "Success to remove duplicated data in the device {device}."
        device_export_vm    =    "The user {user} exported the device {device} to a VM."
        device_logout    =    "The user {user} has disconnected the device {device} from the server."
        device_merge_cancel    =    "Cancel merging expired temporary data into the device {device}."
        device_merge_error    =    "Failed to merge expired temporary data into the device {device}."
        device_merge_start    =    "Starting to merge expired temporary data into the device {device}."
        device_merge_success    =    "Success to merge expired temporary data into the device {device}."
        device_not_found    =    "Unable to find the device. Please make sure the device is still connected to your Synology NAS."
        device_offline    =    "The device {device} is offline."
        device_open_vmm    =    "The user {user} opened the device {device} in Synology Virtual Machine Manager."
        device_pc_offline    =    "The device {device} is offline."
        device_remove    =    "The user {user} disconnected the device {device} from the server."
        device_restore_destination    =    "Target device {dest_device_name} successfully restored."
        device_shadow_check_sparse    =    "The backup version of device {host_name} may be corrupted. Please try to back up again. The next backup will be a full backup."
        dsm_backup_precheck_fail    =    "Failed to back up. (Reason: {error_reason})"
        dsm_clear_logs    =    "Logs were cleared."
        dsm_restore_share_fail    =    "Unable to restore shared folder {path}."
        free_license_esxi_need_ssh    =    "SSH service is not enabled for the free ESXi {host_name}."
        free_license_esxi_need_ssh_connect    =    "When using the free ESXi version, please enable ESXi shell and SSH service and make sure the connection is available."
        fs_another_backup_task    =    "Task {task} is currently being backed up."
        fs_another_restore_task    =    "Task {task} is currently being restored."
        fs_auth    =    "Authentication failed. Please make sure the username and password are correct and the corresponding file protocol has been enabled on the source server."
        fs_auth_ssh_key    =    "Authentication failed. Please make sure the username and SSH key are both correct and the corresponding file protocol has been enabled on the source server."
        fs_connection_abort    =    "The connection is terminated by the source server. Please check the network settings between the source server and the Synology NAS."
        fs_connection_refused    =    "The connection is refused by the source server. Please check the network settings between the source server and the Synology NAS."
        fs_couldnot_resolve_host    =    "Unable to connect to the source server. The system cannot resolve the IP address of the source server. Please check the DNS settings."
        fs_dir_not_found    =    "{path} will not be backed up. (Reason: The directory doesn't exist.)"
        fs_error_quota_not_enough    =    "Your personal data has exceeded the quota."
        fs_error_read_file    =    "Unable to read the file. Please make sure the disk is functioning properly and you have the permission to read the file."
        fs_error_set_acl    =    "Failed to set ACL."
        fs_error_write_file    =    "Unable to write the file. Please make sure the disk is functioning properly and you have the permission to write the file."
        fs_failed_verification_update_discard    =    "Make sure you have access permissions to the file. Check if the file is locked or a virtual file, and if no driver defects occurred."
        fs_file_name_too_long    =    "Filename is too long."
        fs_file_not_support    =    "File is not supported."
        fs_folder_invalid    =    "The name of the chosen folder contains invalid characters. Please choose another folder."
        fs_folder_no_permission    =    "You do not have the permission to access the selected folder. Please make sure you have read/write permissions for the selected folder."
        fs_folder_used    =    "The folder is selected as the backup destination of another file server task. Please select a different folder."
        fs_illegal_ssh_key    =    "Invalid SSH key or passphrase error"
        fs_illegal_ssh_key_no_passphrase    =    "The SSH key is invalid or you are using a SSH key with passphrase."
        fs_initializing    =    "Initializing..."
        fs_inout    =    "Network I/O error. Please check the network settings and try again later."
        fs_internet    =    "No Internet connection. Please check the network settings between the source server and the Synology NAS."
        fs_interrupt    =    "The task is canceled."
        fs_invalid    =    "Invalid parameters. Please restart your Synology NAS and Active Backup for Business and try again later."
        fs_local_bkpfolder_not_found    =    "Unable to find the backup destination folder. Please go to File Station to check if the folder still exists."
        fs_local_exists    =    "Local file already exists."
        fs_local_is_dir    =    "Local target is a folder. Please select file instead."
        fs_local_no_permission    =    "You do not have permission to access files on the backup destination folder. Please make sure you have read/write permissions for the backup destination folder and try again."
        fs_local_no_space    =    "There is not enough space in the backup destination folder. Please free up space and back up again."
        fs_local_not_dir    =    "Local target is a file. Please select a folder instead."
        fs_local_not_found    =    "Unable to find the backed up data in the backup destination folder. Please make sure the data are still in the folder."
        fs_network_dropped_connection    =    "Connection error. Check the SMB/rsync permissions on the source server and the network settings between the source server and your Synology NAS."
        fs_no_matching_cipher    =    "Unable to connect to the source server. Check the SSH Cipher settings between the source server and Synology NAS."
        fs_no_route_to_host    =    "Unable to connect to the source server. Please check the network settings between the source server and the Synology NAS."
        fs_not_select_ssh_key    =    "No SSH key selected yet"
        fs_not_support_acls    =    "ACL not supported."
        fs_not_support_xattrs    =    "Extended attributes are not supported."
        fs_not_supported_destination_filesystem_type    =    "Cannot select a volume in ext3 file system"
        fs_old_task_created    =    "Task {task} created to back up from {address}."
        fs_old_task_edit_backup_folder    =    "The backup folder for the task {task} has been changed."
        fs_old_task_edit_bandwidth    =    "Set task {task} bandwidth to {bandwidth} KB/s."
        fs_old_task_edit_rename    =    "Task {old_name} renamed to {task}."
        fs_old_task_edit_schedule_off    =    "Task {task} schedule disabled."
        fs_old_task_edit_schedule_on    =    "Task {task} schedule enabled."
        fs_old_task_removed    =    "Task {task} deleted."
        fs_only_transmitted_part_files    =    "Files are partially transmitted."
        fs_operation_not_support    =    "Client API request is not supported."
        fs_package_expired    =    "Package has expired. Please upgrade to the latest version in Package Center."
        fs_path_set_acl    =    "Unable to set ACL on path {path}. Please make sure you have read/write permissions for the source server and the backup destination folder."
        fs_path_set_attr    =    "Unable to set attribute on path {path}. Please make sure the length of attribute is valid and you have read/write permissions for the source server and the backup destination folder."
        fs_path_set_attr_xattr_data_limit    =    "Unable to back up the ACL entries in file {path} because the size of the ACL entries exceed the limit. Please remove some of the ACL entries from the file on the server."
        fs_path_set_attr_xattr_enospc    =    "Unable to back up the ACL entries in file {path} due to insufficient storage space of Synology NAS."
        fs_repo_move    =    "Moving database. Please wait..."
        fs_rsync_command_not_found    =    "The rsync service is not installed on the source server. Please install and try again."
        fs_rsync_conf_invalid_gid    =    "The rsync configuration file (rsyncd.conf) on the source server is invalid. Please check if the account of the gid value exists and can be signed in."
        fs_rsync_conf_invalid_uid    =    "The rsync configuration file (rsyncd.conf) on the source server is invalid. Please check if the account of the uid value exists and can be signed in."
        fs_rsync_file_delete_skipped    =    "I/O errors occurred on the source server, causing files which has been deleted on the source server to be remained on the backup destination."
        fs_rsync_protocol_incompatible    =    "Incompatible communication protocol. Please make sure the rsync version is 3.0 or above."
        fs_run_backup_conflict    =    "Failed to run backup because the task is currently being restored."
        fs_run_restore_conflict    =    "Failed to restore because the task is currently being backed up."
        fs_samba_acl_not_support    =    "The SMB shared folder settings of the source data is not supported for backup. Please disable `"store dos attributes`" and `"vss objects`" first."
        fs_server    =    "The source server reports error. Please check the status of the source server."
        fs_server_bkpfolder_not_found    =    "Server backup folder does not exist."
        fs_server_deny_ip    =    "Access to this IP address is denied. Please check the network settings."
        fs_server_device_resource_busy    =    "The file cannot be backed up because it has been opened on the remote server."
        fs_server_disable    =    "Server can be reached but the given port is not opened."
        fs_server_exists    =    "Server file already exists."
        fs_server_invalid_option    =    "The source server does not support this option. To enable this option, please make sure the rsync version of the source server is 3.0 or above."
        fs_server_io_error    =    "An error occurred when accessing the path. Make sure the disk is working and you have access permissions to the path."
        fs_server_is_dir    =    "Server target is a folder. Please select a file instead."
        fs_server_no_permission    =    "You do not have the permission to access the file on the source server. To learn the required permission, please refer to <a class=`"link-font`" target=`"_blank`" href=`"https://www.Synology.com/knowledgebase/DSM/help/ActiveBackup/activebackup_business_requireandlimit?version=7`">this article</a>."
        fs_server_no_space    =    "There is not enough space on the server."
        fs_server_not_dir    =    "Server target is a file. Please select a folder instead."
        fs_server_not_found    =    "Server file cannot be found."
        fs_server_offline    =    "Server is offline."
        fs_server_operation_not_permmited    =    "Connection error. Check the network settings between the source server and your Synology NAS, or make sure you have access permissions to the file on the source server."
        fs_server_used    =    "The server address is being used."
        fs_set_attr    =    "Failed to set file attribute."
        fs_share_folder_type    =    "You cannot select mounted shared folders."
        fs_share_unmount    =    "Shared folder is not mounted."
        fs_space    =    "There is not enough space."
        fs_ssh_key_upload_failed    =    "Failed to upload the SSH key. Please make sure the key exists and you have the permission to upload it to the rsync server."
        fs_ssl_connection_refused    =    "SSL connection refused. Please check the network settings of the source server."
        fs_ssl_verify    =    "Unable to verify SSL. Please make sure the certificate is valid and the network is connected."
        fs_system    =    "System error."
        fs_task_execution_failed    =    "Task failed"
        fs_task_name_used    =    "A task with the same name already exists."
        fs_test_connection_failed    =    "Connection failed. Check the network settings between the source server and your Synology NAS, or make sure you have access permissions to the file on the source server."
        fs_time_out    =    "The operation timed out. Please try again later."
        fs_too_many_errors    =    "Too many errors occurred."
        fs_unable_connect_to_daemon    =    "Unable to connect to the rsync service. Please check the network settings and make sure the rsync service is enabled. If the source server is a Synology NAS, please make sure User Home service is enabled."
        fs_unknow    =    "An unknown error occurred. Please try again later."
        fs_unknown_module    =    "No rsync module found. If your backup source is a Synology NAS, please check for any changes to the source shared folder. If using other servers, please confirm that the path setting in rsyncd.conf is correct."
        fs_upgrading    =    "Upgrading database..."
        fs_vss_another_vss_already_running    =    "Failed to run Volume Shadow Copy Service (VSS) since another VSS instance is already running. Please try again later."
        fs_vss_bad_state    =    "Please make sure you have allocated enough shadow copy storage on the backup source server to create shadow copies."
        fs_vss_create_storage_full    =    "The remote server doesn't have enough space to execute Windows VSS (Volume Shadow Copy Service)."
        fs_vss_not_found    =    "Data stored on Windows Volume Shadow Copy Service (VSS) cannot be found. "
        fs_vss_not_supported_operation    =    "Windows Volume Shadow Copy Service (VSS) is not supported. Please refer to this <a href=`"https://www.Synology.com/knowledgebase/DSM/help/ActiveBackup/activebackup_business_fileserver?version=7`"target=`"blank`">article</a> to check the VSS agent is installed on the server."
        fs_vss_operation_failed    =    "The volume shadow copy operation failed. Error message from the source server: {message}"
        fs_vss_operation_timed_out    =    "The operation of Volume Shadow Copy Service (VSS) timed out. Please check the network settings and try again later."
        fs_vss_volume_is_not_supported    =    "The following folders are not supported by Windows Volume Shadow Copy Service (VSS). If you wish to enable VSS for this backup task, please deselect the folders for backup."
        help_article    =    "article"
        hyperv_account_no_domain    =    "Please make sure you enter a domain account (use DOMAIN NAME\USER NAME format) with administrator privileges on the hypervisor {host_name}."
        hyperv_cluster_ip_mismatch    =    "For the failover cluster, please enter the IP address of the cluster server."
        hyperv_failover_cluster_service_not_enabled    =    "Failover Cluster services are not installed or activated on the Hyper-V server. Please installed or activated properly and try again."
        hyperv_incompatible_version    =    "The version of this Hyper-V server is not supported. Please add Hyper-V installed on Windows Server 2016 or later."
        hyperv_powershell_not_enabled    =    "The task failed because the Hyper-V PowerShell module is not installed or activated on the Hyper-V server."
        hyperv_samba_mount_fail    =    "Failed to mount system drive in \\{host_name}{samba_mount_failed_path} via SMBv{samba_version}. If the signed in account is a domain account, please use DOMAIN\USERNAME format. Please also check if the signed in account has the permission to mount the system drive. For more information, please refer to <a href=`"http://sy.to/abbhyperv`"target=`"blank`">this article</a>."
        hyperv_samba_not_enable    =    "SMBv{samba_version} file sharing is not enabled on {host_name}. For more details, please refer to this <a href=`"http://sy.to/abbhyperv`"target=`"blank`">article</a>."
        hyperv_script_not_enable    =    "Failed to execute PowerShell script on {host_name}. Please make sure the PowerShell's execution policy of local machine is RemoteSigned. For more details, please refer to this <a href=`"http://sy.to/abbhyperv`"target=`"blank`">article</a>."
        hyperv_scvmm_service_not_enabled    =    "SCVMM services are not installed or activated on the Hyper-V server. Please installed or activated properly and try again."
        hyperv_service_not_enabled    =    "Hyper-V services are not installed or activated on the Hyper-V server. Please install or activate it properly and try again."
        hyperv_service_not_enabled_v2    =    "The Hyper-V service is not installed or activated on the Hyper-V server. Or the operating system of the Hyper-V server is Windows 10."
        hyperv_share_not_enable    =    "Please enable administrative share for {invalid_shares} on {host_name} whose drive contains configuration files of a virtual machine. For more details, please refer to this <a href=`"http://sy.to/abbhyperv`"target=`"blank`">article</a>."
        hyperv_use_cluster_as_standalone    =    "This is a failover cluster. Please select a compatible hypervisor type."
        hyperv_virtual_disk_not_found    =    "Error message from hypervisor [{host_name}]: [{error_message}]. Delete the checkpoint on the hypervisor."
        hypervisor_account_access_denial    =    "Cannot execute operations on the host [{hostname}], please verify the provided account is authorized to access the hypervisor."
        incompatible_vm_version    =    "Failed to restore due to VMware compatibility issue. Please check the ESXi version of restored VM(s) and the destination ESXi."
        incompatible_vm_version_general    =    "Failed to restore virtual machines owing to compatibility issues. Please check the compatibility between versions of the restored virtual machines and the destination hypervisor."
        instant_restore_device_cancel    =    "The instant restoration of virtual machine {device} in task {task} was canceled."
        instant_restore_device_error    =    "Unable to instantly restore virtual machine {device} in task {task}."
        instant_restore_device_finish    =    "Successfully instantly restored virtual machine {device} in task {task}."
        instant_restore_device_start    =    "Starting to instantly restore virtual machine {device} in task {task}."
        internal_error    =    "An unknown internal error occurred. Please contact Synology Technical Support."
        invalid_cluster_shared_volume    =    "{path} is not a valid cluster shared volume."
        iscsi_nat_reverse_connection_fail    =    "Failed to connect to the DSM iSCSI target from hypervisor [{host_name}]. Please check the server address, port, and network settings. Instant Restore is not supported on NAT environment. [{error_message}]"
        iscsi_reverse_connection_fail    =    "Failed to connect to the DSM iSCSI target from hypervisor [{host_name}]. Please check the server address, port, and network settings. [{error_message}]"
        iscsi_service_not_running    =    "The iSCSI Initiator Service is required to restore virtual machines instantly. Please start the iSCSI Initiator Service on the host [{host_name}]."
        job_forbidden    =    "Cannot perform the task because the selected storage {share} may have been relinked by another device. Please try and relink the space to obtain its ownership."
        job_reason_encrypted_storage_mount    =    "Failed to restore task {task} because the encrypted destination is not mounted. Please mount the destination first."
        job_reason_storage_broken    =    "The task {task} failed owing to the corrupted storage. Please contact Synology Technical Support for assistance."
        job_reason_storage_encryption    =    "The task {task} failed owing to the encrypted storage. Please contact Synology Technical Support for assistance."
        job_reason_storage_readonly    =    "The task {task} failed owing to the read-only storage. Please contact Synology Technical Support for assistance."
        job_reason_vmm_conflict_delete_target    =    "Cannot delete task {task_name}. The device is instantly restored to and then managed by Synology Virtual Machine Manager."
        job_reason_vmm_conflict_delete_version    =    "Cannot delete version [{timestamp_list}] of task {task_name}. The device is instantly restored to and then managed by Synology Virtual Machine Manager."
        jobqueue_down    =    "Service not ready."
        license_can_extend    =    "You can renew your license key {license_key} now."
        license_connect_error    =    "Cannot connect to the license server. Backup task(s) of device(s) has been terminated."
        license_connect_warning    =    "Cannot connect to the license server. Backup task(s) of device(s) will be terminated on {expired_time}."
        license_create    =    "Add {backup_type_str} {license_type} license for {add_quantity} device(s). License key: {license_key}."
        license_expired    =    "The grace period of license key {license_key} has ended."
        license_extend    =    "{backup_type_str} subscription license {license_key_old} for {add_quantity} device(s) has been renewed for one year. New license key: {license_key}."
        license_graced    =    "The grace period for license key {license_key} has started."
        log_delete_all    =    "User {user} deleted all the logs."
        log_disable_retention    =    "User {user} disabled log retention rules."
        log_retention_counts    =    "number of logs greater than {0}"
        log_retention_days    =    "log created earlier than {0}"
        log_set_retention    =    "User {user} changed log retention rules. ({log_retention_setting})"
        merge_speed_info    =    "The average speed of merging temporary version is {speed}."
        migrate_device_cancel    =    "The migration of virtual machine {device} in task {task} was canceled."
        migrate_device_error    =    "Failed to migrate virtual machine {device} in task {task}."
        migrate_device_finish    =    "Successfully migrated virtual machine {device} in task {task}."
        migrate_device_start    =    "Starting to migrate virtual machine {device} in task {task}."
        mount_dir_exist    =    "Failed to perform the actions since the folder {mount_path} already contains data. Please remove or rename the folder."
        os_not_support    =    "Failed to back up the device because the agent version is newer than the package. Update the package to the latest version and try again."
        partial_success    =    "Partially complete."
        path_backup    =    "Backup path {path} ready."
        path_backup_attr_error    =    "Failed to back up file attributes."
        path_backup_error    =    "Backup path {path} failed."
        path_download    =    "Download path {path} created."
        path_restore    =    "Restore path {path} restored."
        path_restore_attr_error    =    "Failed to restore file attributes."
        path_restore_cancel    =    "Restore path {path} canceled."
        path_restore_error    =    "Failed to create the restore path {path}."
        path_restore_meta_capability    =    "Restore file attributes [{attrList}]."
        path_restore_meta_error    =    "Fail to restore file attributes [{attrList}] of {path}."
        path_restore_metadata_error    =    "Failed to restore the metadata of {path}."
        path_restore_no_permission    =    "No permission to restore path {path} because it might be protected by operating system settings, anti-virus software, or others."
        path_restore_no_space    =    "No space on destination disk to restore path {path}."
        path_restore_not_support    =    "Unsupported file type: {path}"
        path_restore_overwrite    =    "The path {path} was overwritten (path already exists)."
        path_restore_parent_not_exist    =    "Failed to create the restoration path {path} because folder {parent_path} does not exist."
        path_restore_parent_type_conflict    =    "Failed to create the restoration path {path} because it conflicts with the file in {parent_path}."
        path_restore_skip    =    "The path {path} was skipped (path already exists)."
        path_restore_source_error    =    "Failed to restore path {path}. Error code: {error_code}"
        path_too_long    =    "The path is too long [{path}]."
        pc_asr_failed    =    "Error code {error_code}: Failed to run asr (Apple Software Restore) on {volume_name}."
        pc_backup_access_denied    =    "Failed to back up {volume_name}. (Reason: access denied, Error Code: {error_code}) Please check snapshot permissions."
        pc_backup_device_busy    =    "Failed to back up {volume_name}. (Reason: device is busy, Error Code: {error_code}) Please try again later."
        pc_backup_invalid_function    =    "Failed to back up {volume_name}. (Reason: invalid function, Error Code: {error_code}) Please contact Synology Technical Support for assistance."
        pc_backup_path_not_found    =    "Failed to back up {volume_name}. (Reason: path not found, Error Code: {error_code}) Please contact Synology Technical Support for assistance."
        pc_backup_sector_not_found    =    "Failed to back up {volume_name}. (Reason: sector not found, Error Code: {error_code}) Please contact Synology Technical Support for assistance."
        pc_bad_information_volume    =    "Cannot back up {volume_name}. (Reason: volume information not available)"
        pc_cache_base_snapshot_not_found    =    "Task {task_name} can not perform backup cache to make incremental backup. Please make a full backup first."
        pc_cache_cbt_initialize_fail    =    "Task {task_name} can not retrieve change block tracking bitmap between snapshots, so create backup cache failure."
        pc_cache_create_file_error    =    "Failed to access the disk. (Error code: {error_code})"
        pc_cache_location_data_volume_not_found    =    "Cannot find data volume as backup cache storage, it may be only system volume in PC. Therefore, disable backup cache for task {task}."
        pc_cache_not_found    =    "Cannot find {image_name} data on ActiveBackupforBusiness data volume. Performing full backup instead."
        pc_cache_read_file_error    =    "Failed to read data to the disk. (Error code: {error_code})"
        pc_cache_storage_quota_full    =    "Task {task_name}'s free space of storage is under {lower_bound_value} {lower_bound_unit} for cached location."
        pc_cache_write_file_error    =    "Failed to write data to the disk. (Error code: {error_code})"
        pc_cbt_version_has_new_volume    =    "Because {volume_name} do not have base snapshot, it can not do change block tracking. it will be uploaded at the next fixed version."
        pc_cbt_version_volume_layout_change    =    "The layout of {volume_name} is changed, it will be uploaded at the next fixed version."
        pc_collect_device_spec    =    "Retrieving device information."
        pc_create_cache_volume    =    "Starts creating ActiveBackupforBusiness data volume."
        pc_create_task_error_data_corrupt    =    "User {user} failed to create the task owing to data corruption of the storage. Please contact <a class=`"link-font`" target=`"_blank`" href=`"https://www.Synology.com/company/contact_us`">Synology Technical Support</a>"
        pc_create_task_error_internal    =    "User {user} failed to create an agent task due to a system error. Please contact <a class=`"link-font`" target=`"_blank`" href=`"https://www.Synology.com/company/contact_us`">Synology Technical Support</a>"
        pc_create_task_error_no_quota    =    "User {user} cannot create a task because the quota of the backup destination has reached its maximum limit."
        pc_create_task_error_no_space    =    "User {user} cannot create a task because of insufficient storage space on the Synology NAS. To allow the user to create a task, please free up space."
        pc_create_task_error_share_name    =    "User {user} failed to create a task. Please make sure the backup destination folder is still on your Synology NAS. The backup destination folder cannot be an encrypted shared folder nor on an ext4 volume."
        pc_create_task_error_storage_existed    =    "User {user} cannot create a task because the shared folder already contains backup data. Please relink the folder first."
        pc_create_task_error_storage_existed_old_version    =    "User {user} cannot create a task since the shared folder already contains backup data. Please select another folder."
        pc_database_error    =    "An error occurred on the agent."
        pc_device_upgrade    =    "Device {device} has been upgraded to be backed as a physical server sucessfully."
        pc_exclude_volume_external    =    "{volume_name} will not be backed up. (Reason: External hard drive is excluded in the task.)"
        pc_exclude_volume_info_error    =    "{volume_name} will not be backed up. (Reason: Unable to obtain volume information.)"
        pc_exclude_volume_removable    =    "{volume_name} will not be backed up. (Reason: Unsupported removable media.)"
        pc_exclude_volume_unknown_fs    =    "{volume_name} will not be backed up. (Reason: Unidentified file system.)"
        pc_exclude_volume_unrecognize    =    "{volume_name} will not be backed up. (Reason: Unrecognized volume)"
        pc_exclude_volume_unsupported    =    "{volume_name} will not be backed up. (Reason: unsupported disk bus type)"
        pc_exclude_volume_unsupported_bus    =    "{volume_name} will not be backed up. (Reason: Unsupported disk bus type.)"
        pc_exclude_volume_unsupported_device    =    "{volume_name} will not be backed up. (Reason: Unsupported disk type.)"
        pc_exclude_volume_unsupported_fs    =    "{volume_name} will not be backed up. (Reason: Unsupported file system.)"
        pc_exec_post_script    =    "Post-thaw script successfully executed."
        pc_exec_post_script_error    =    "Failed to execute post-thaw script {script_result_path} with exit status {exit_code}."
        pc_exec_post_script_ignore_failure    =    "Ignored the failed execution of post-thaw script {script_result_path} with exit status {exit_code}."
        pc_exec_post_script_timeout    =    "Post-thaw script {script_result_path} has been terminated due to timeout."
        pc_exec_pre_script    =    "Pre-freeze script successfully executed."
        pc_exec_pre_script_error    =    "Failed to execute pre-freeze script {script_result_path} with exit status {exit_code}."
        pc_exec_pre_script_ignore_failure    =    "Ignored the failed execution of pre-freeze script {script_result_path} with exit status {exit_code}."
        pc_exec_pre_script_timeout    =    "Pre-freeze script {script_result_path} is terminated due to timeout."
        pc_exec_script_client_can_not_access    =    "Failed to access pre-freeze/post-thaw script files on the client device."
        pc_exec_script_server_can_not_access    =    "Failed to access pre-freeze/post-thaw script file on the _DISKSTATION_."
        pc_exec_script_size_too_large    =    "The size of pre-freeze/post-thaw script files has exceeded the 32 KB limit."
        pc_failed_login_hidden_user    =    "Failed to login hidden user,  please remove it and reinstall."
        pc_failed_read_pw_file    =    "Failed to load encrypted password file, please reset it."
        pc_mac_snapshot_not_found    =    "Cannot find snapshot of {volume_name}. Performing full backup instead."
        pc_query_update_server_failed    =    "Failed to update the device since it could not connect to Synology's download center and retrieve the latest version. If your Synology NAS does not have internet connection, please refer to this {help_link} to learn how to update the device."
        pc_read_snapshot_error    =    "Failed to read the snapshot. Please check the disks of the device to rule out track error. (Error Code: {error_code})"
        pc_restore_create_file_error    =    "Failed to access the disk. (Error code: {error_code})"
        pc_restore_missing_offset    =    "Cannot restore data because data offset is out of range."
        pc_restore_retry    =    "Retrying the restore task."
        pc_restore_write_file_error    =    "Failed to write data to the disk. (Error code: {error_code})"
        pc_resume_volume_cbt_fail    =    "The change block tracking bitmap of {volume_name} can not be retrieved between snapshots after being resumed."
        pc_shadow_not_found    =    "<a class=`"link-font`" href=`"http://sy.to/xzk9k`"target=`"blank`">Previous snapshots of {volume_name} not found.</a> Start to perform full backup of the device."
        pc_snapshot_driver_error    =    "Failed to read the snapshot. Check the snapshot status on the device and try backing up again. (Error code: {error_code})"
        pc_snapshot_need_full_access    =    "Unable to take a snapshot for {volume_name}. (Reason: Full Disk Access isn't enabled)"
        pc_snapshot_no_available_volume    =    "No available volume to take snapshot for."
        pc_snapshot_not_found    =    "Unable to find the snapshot of {volume_name}. The snapshot might be deleted by the operating system, third-party applications, or other reasons. Please try to back up again."
        pc_snapshot_open_error    =    "Failed to open {volume_name}. (Error Code: {error_code}) Please contact Synology Technical Support for assistance."
        pc_snapshot_skip_bad_cluster    =    "{volume_name} has a bad cluster in {interval_start} - {interval_end}. The interval is skipped."
        pc_take_snapshot_finish    =    "Snapshot for {volume_name} successfully taken."
        pc_take_snapshot_finish_error    =    "Failed to take a snapshot for {volume_name}. (Error Code: {error_code})"
        pc_take_snapshot_set_finish    =    "Snapshot set for {volume_name} successfully taken."
        pc_take_snapshot_set_finish_error    =    "Failed to take snapshot set for {volume_name}. Retrying."
        pc_take_snapshot_set_start    =    "Starting to take a snapshot set for {volume_name}."
        pc_take_snapshot_start    =    "Starting to take a snapshot for {volume_name}."
        pc_trigger_event    =    "Triggered by {trigger_event}"
        pc_unsupported_dynamic_volume    =    "{volume_name} will not be backed up. (Reason: unsupported dynamic volume type)"
        pc_unsupported_file_system    =    "{volume_name} will not be backed up. (Reason: unsupported file system type)"
        pc_upload_device_spec_finish    =    "Device information successfully uploaded."
        pc_upload_device_spec_finish_error    =    "Unable to upload the device information. Please check the network settings and try again later."
        pc_upload_device_spec_start    =    "Starting to upload device information."
        pc_upload_need_kext_allow    =    "Backup failed. (Reason: Kernel extensions aren't enabled)"
        pc_upload_script_output_file_error    =    "Failed to upload the script output."
        pc_upload_volume_backup_cache_read_finish    =    "Backup cached content of {volume_name} successfully read and uploaded."
        pc_upload_volume_backup_cache_read_finish_error    =    "Failed to read and upload the backup cached content of {volume_name}."
        pc_upload_volume_backup_cache_read_start    =    "Starting to read and upload the backup cached content of {volume_name}."
        pc_upload_volume_backup_cache_write_finish    =    "Backup cached content of {volume_name} successfully read and write to disk."
        pc_upload_volume_backup_cache_write_finish_error    =    "Failed to read the backup cached content of {volume_name} and write to disk."
        pc_upload_volume_backup_cache_write_start    =    "Starting to read the backup cached content of {volume_name} and write to disk."
        pc_upload_volume_finish    =    "Volume content of {volume_name} successfully read and uploaded."
        pc_upload_volume_finish_error    =    "Failed to read and upload the volume content of {volume_name}."
        pc_upload_volume_start    =    "Starting to read and upload the volume content of {volume_name}."
        pc_volume_cbt_fail    =    "The change block tracking bitmap of {volume_name} can not be retrieved between snapshots."
        pci_passthrough    =    "The virtual machine contains the PCI network device with DirectPath I/O passthrough mode. Due to VMware limitations, you cannot perform any snapshot operations. Please power off the virtual machine or remove the PCI network device."
        reason_backup_image_open_failure    =    "System cannot find the backup image. Error code is {error_code}."
        reason_data_corrupt    =    "The data in the backup destination are corrupted, please manually remove the tasks from the destination."
        reason_data_corrupt_single    =    "The data in the backup destination are corrupted, please manually remove the task from the destination."
        reason_guest_os    =    "An error occurred in the guest OS {address}: [{error_message}]."
        reason_hypervisor_connect_fail    =    "Fail to connect to the Hypervisor, please check the server address, port, and account settings. [{hypervisor_error_string}]"
        reason_hypervisor_general_error    =    "An error occurred in the hypervisor library [{hypervisor_error_string}]."
        reason_hypervisor_retry_warning    =    "Hypervisor library is retrying [{hypervisor_error_string}]."
        reason_hypervisor_vcenter_connect_fail    =    "Failed to connect to the hypervisor. Please check the server address, port, and account settings of vCenter and the ESXi managed by vCenter. [{hypervisor_error_string}]"
        reason_io_err    =    "Unexpected error occurred when accessing files on the backup destination."
        reason_no_perm    =    "Insufficient permission to access certain subfolders or files under the destination shared folder."
        reason_no_quota    =    "Quota reached on the backup destination."
        reason_no_quota_system    =    "Quota reached on the system volume."
        reason_no_space    =    "The free space of the backup destination is less than 8 GB."
        reason_no_space_system    =    "There was not enough space available in the volume where Active Backup for Business was installed."
        reason_no_target_database    =    "The version is corrupted due to missing backup database of the selected task."
        reason_no_target_folder    =    "Cannot find the target folder. Please check if the target folder has been removed or renamed."
        reason_no_target_folder_log    =    "Unable to back up task {task} due to missing backup destination folder. Please make sure the folder still exists."
        reason_no_target_version_folder    =    "Unable to find the backup destination folder of the selected version."
        reason_not_support_compress_share    =    "DSM compressed shared folders cannot be used as the destination for compressed or encrypted backup tasks."
        reason_powershell    =    "Backup failed because of an error on {host_name}: [{error_message}]"
        reason_readonly_fs    =    "The backup destination is in a read-only file system."
        reason_target_missing    =    "The backup destination is damaged due to the loss of target folder [{path}]. Please manually delete the corresponding backup task first."
        reason_vddk_general_error    =    "VMware VDDK library error message [{vddk_error_string}]."
        reason_vddk_retry_warning    =    "VMware VDDK library is reoperating [{vddk_error_string}]."
        relink_data_corrupt    =    "The data in relinked target folder {share} are corrupted. Please contact Synology Technical Support for assistance."
        relink_no_enough_space    =    "Insufficient storage space in the relinked target folder {share}."
        relink_permission_denied    =    "No permission to access the relinked target folder {share}."
        relink_target_error    =    "Failed to relink the target folder {share}."
        relink_target_finish    =    "Successfully relinked the target folder {share}."
        relink_target_finish_v2    =    "Successfully relinked the target folder {share} and created the relevant tasks."
        relink_target_folder_not_found    =    "The relinked folder {folder} does not exist. Retrieve the folder, re-install Active Backup for Business, and try relinking again."
        remove_server_completed    =    "The user {user} has removed the VMware vSphere server {server}."
        remove_server_completed_general    =    "The user {user} removed the hypervisor {server}."
        remove_server_failed    =    "Failed to remove the VMware vSphere server {server}."
        remove_server_failed_general    =    "Failed to remove the hypervisor {server}."
        remove_server_start    =    "Start to remove the VMware vSphere server {server}."
        remove_server_start_general    =    "Starting to remove the hypervisor {server}."
        remove_storage_busy    =    "ActiveBackup does not have permission to delete the selected storage. Please go to Control Panel > Shared Folder to adjust the permission and try again."
        remove_vm_in_task_failed    =    "Failed to remove the backed up data of the virtual machine on {server} from the task {task}."
        remove_vm_in_task_finish    =    "The backed up data of the virtual machine on {server} has been removed from the task {task}."
        remove_vm_in_task_start    =    "Start to remove the backed up data of the virtual machine on {server} from the task {task}."
        remove_vm_name_in_task    =    "Remove the backed up data of the virtual machine {device} from the task {task}."
        restore_another_exist    =    "The restore task {task} cannot be run now because another restore task is being processed."
        restore_cancel    =    "The restore task {task} was canceled."
        restore_cancel_device_offline    =    "The restoration of task {task} was canceled due to device {device} connection timeout."
        restore_conflict    =    "The restore task {task} cannot be run now because a backup task is being processed."
        restore_device_cancel    =    "The restoration of virtual machine {device} in task {task} was canceled."
        restore_device_error    =    "Failed to restore virtual machine {device} in task {task}."
        restore_device_finish    =    "Successfully restored virtual machine {device} in task {task}."
        restore_device_start    =    "Starting to restore virtual machine {device} in task {task}."
        restore_error    =    "The restore task {task} failed."
        restore_finish    =    "The restore task {task} was completed."
        restore_partial_success    =    "The restore task {task} was partially completed."
        restore_physical_disk_as_empty    =    "[{virtual_disk}] is restored as an empty thin provisioned disk since the disk is not supported to be backed up."
        restore_physical_disk_as_empty_v2    =    "The virtual machine {device} in task {task}: [{virtual_disk}] is restored as an empty thin provisioned disk since the disk is not supported to be backed up."
        restore_start    =    "The restore task {task} has started."
        restore_task_get_used_block_fail    =    "The version is corrupted due to missing backup database of the selected task."
        restore_task_not_found    =    "Unable to find the restoration task. Please make sure the restoration task still exists on the Synology NAS."
        restore_task_version_not_found    =    "The selected version of the restoration task does not exist."
        restore_warning    =    "The restore task {task} was partially completed."
        retention_delete_failed_being_deleted    =    "The version [{version_ids}] of the task {task} failed to be deleted by the retention policy since the task is being deleted."
        retention_delete_failed_being_deleted_v2    =    "Version [{timestamp_list}] of backup task {task} failed to be deleted by the retention policy since the backup task is being deleted."
        retention_delete_failed_being_restored    =    "The version [{version_ids}] of the task {task} failed to be deleted by the retention policy since the task is being restored."
        retention_delete_failed_being_restored_v2    =    "Version [{timestamp_list}] of backup task {task} failed to be deleted by the retention policy since the backup task is being restored."
        retention_delete_failed_forbidden    =    "Failed to rotate version [{version_ids}] of task {task} since shared folder {share} cannot be accessed. Please relink the shared folder."
        retention_delete_failed_forbidden_v2    =    "Failed to delete version [{timestamp_list}] of backup task {task} by the retention policy since shared folder {share} cannot be accessed. Please relink the shared folder."
        retention_delete_failed_unknown_error    =    "The version [{version_ids}] of the task {task} failed to be deleted by the retention policy due to unknown error."
        retention_delete_failed_unknown_error_v2    =    "Version [{timestamp_list}] of backup task {task} failed to be deleted by the retention policy due to the system error."
        samba_mount_fail    =    "Failed to mount the Samba drive [{error_message}]. Please make sure that the Samba service on the hypervisor works properly."
        samba_mount_fail_dsm_6_1    =    "Failed to perform the action owing to SMB compatibility issues between the Hyper-V and your DSM version. Please update your DSM to 6.2 or above to support SMB2."
        scvmm_incompatible_version    =    "The version of this SCVMM server is not supported. Please add the server with SCVMM 2016 RTM or later version."
        set_delegation_rule_failed    =    "Unable to assign the privileges. Please try again."
        share_deleted    =    "The shared folder {folder} for the task {task} was removed."
        share_path_changed    =    "The path of the shared folder {share} for the task {task} was changed."
        share_rename    =    "The shared folder {old_name} for the task {task} was renamed {share}."
        short_reason_data_corrupt    =    "Data corrupted."
        snapshot_no_cbt    =    "There are snapshots without Changed Block Tracking in virtual machine {device}. Please delete all snapshots of this virtual machine manually, and then power on the virtual machine."
        snapshot_no_cbt_off    =    "There are snapshots without Changed Block Tracking in powered off virtual machine {device}. Please keep the virtual machine powered on or delete all snapshots in this virtual machine manually, power on the virtual machine, and power it off again."
        snapshot_num_reach_limit    =    "The number of virtual machine {device}'s snapshots reached the limit ({snapshot_limit}). Please delete unneeded snapshots on the virtual machine manually."
        storage_busy    =    "The storage {storage} is busy."
        storage_compact_failed    =    "Failed to free up space in storage {storage}."
        storage_compact_start    =    "Started to free up space in storage {storage}."
        storage_compact_success    =    "The space in storage {storage} was successfully freed up."
        storage_create_success    =    "The storage {storage} was successfully created."
        storage_not_support_newer_version    =    "Incompatible version. Please update Active Backup for Business to the latest version."
        storage_not_support_older_version    =    "Version incompatibility found. Data version on the backup target is too old to support."
        storage_not_verified    =    "Storage {share_name} has not been mounted yet"
        storage_remove_success    =    "The storage {storage} was successfully removed."
        storage_remove_success_v2    =    "The storage {storage} (Number of tasks: PC: {pc_num}, physical server: {ps_num}, file server: {fs_num}, and virtual machine: {vm_num}) was successfully removed."
        task_another_backup_exist    =    "The backup task {task} cannot be run now because another backup task is being processed."
        task_backup_conflict    =    "The backup task {task} cannot be run now because a restore task is being processed."
        task_backup_no_license    =    "Failed to back up task {task} due to insufficient valid {backup_type_str} license."
        task_backup_window_start_allow    =    "Backup window starting to launch backup of the task {task}."
        task_backup_window_start_deny    =    "Backup window starting to stop backup of the task {task}."
        task_cancel    =    "The backup task {task} was canceled."
        task_cancel_cache_upload    =    "The backup task {task} was canceled and backup cached data is paused to upload."
        task_cancel_dedup_fail    =    "The backup task {task} was canceled because dedup failed."
        task_cancel_device_offline    =    "Backup task {task} was canceled due to device {device} connection timeout."
        task_cancel_need_cbt_need_dedup_version    =    "The backup task {task} was canceled because cbt version have new volume, disklayout changed or cbt failed ."
        task_cancelled_by_backup_window    =    "Task {task} was canceled by the configured backup window."
        task_conflict_inventory_delete    =    "Cannot run backup task {task} since the system is deleting the hypervisor."
        task_created    =    "The user {user} has created the task {task} to back up {device}."
        task_dedup_cancel    =    "Canceling to remove duplicated data in the version [{version_id}] of the task {task}."
        task_dedup_error    =    "Failed to remove duplicated data in the version [{version_id}] of the task {task}."
        task_dedup_finish    =    "Success to remove duplicated data in the version [{version_id}] of the task {task}."
        task_dedup_noversion_error    =    "Failed to remove the duplicate data in task {task}."
        task_dedup_noversion_start    =    "Starting to remove the duplicate data in task {task}."
        task_dedup_partial_success    =    "Remove duplicated data in the version [{version_id}] of the task {task} was partially completed."
        task_dedup_start    =    "Starting to remove duplicated data in the version [{version_id}] of the task {task}."
        task_delete_exist    =    "Failed to backup task {task} because the task is processing version deletion."
        task_delete_target_error    =    "Failed to remove the target folder of the task {task}."
        task_edit_bandwidth    =    "The user {user} has set the bandwidth limit of the task {task} to {bandwidth} KB/s."
        task_edit_rename    =    "The user {user} has changed the task name {old_name} to {task}."
        task_edit_schedule_off    =    "The user {user} has disabled the schedule for the task {task}."
        task_edit_schedule_on    =    "The user {user} has enabled the schedule for the task {task}."
        task_error    =    "The backup task {task} failed."
        task_export_config_fail    =    "Cannot export task configurations. This error may cause the relinking of the shared folder's task settings to fail."
        task_finish    =    "The backup task {task} was completed."
        task_forbidden    =    "Backup task {task} failed to be executed since shared folder {share} cannot be accessed. Please try and relink the shared folder to obtain its ownership."
        task_forbidden_copy    =    "Failed to copy the versions of backup task {task} as shared folder {share} could not be accessed. Please relink the shared folder to regain ownership."
        task_fullbackup_merge    =    "Merge pending task into full backup task {task}."
        task_ignored_by_backup_window    =    "Backup task {task} is not allowed to be run during this period of time due to the configured backup window."
        task_merge_cancel    =    "Canceling to merge temporary data into the version [{version_id}] of the task {task}."
        task_merge_error    =    "Failed to merge expired temporary data into the version [{version_id}] of the task {task}."
        task_merge_finish    =    "Success to merge expired temporary data into the version [{version_id}] of the task {task}."
        task_merge_noversion_start    =    "Starting to merge temporary version in the task {task}."
        task_merge_partial_success    =    "Merge expired temporary data into the version [{version_id}] of the task {task} was partially completed."
        task_merge_start    =    "Starting to merge expired temporary data into the version [{version_id}] of the task {task}."
        task_miss_scheduled    =    "Device {device} missed scheduled backups of task {task}."
        task_partial_success    =    "The backup task {task} was partially completed."
        task_paused    =    "The task {task} was paused by the user {user}."
        task_paused_by_backup_window    =    "Task {task} was paused by the configured backup window."
        task_period_cancel    =    "The continuous backup task {task} period was canceled."
        task_period_error    =    "The continuous backup task {task} period failed."
        task_period_finish    =    "The continuous backup task {task} period was completed."
        task_period_partial_success    =    "The continuous backup task {task} period was partially completed."
        task_period_start    =    "The continuous backup task {task} period has started."
        task_removed    =    "The user {user} has removed the task {task} from {device}."
        task_resume    =    "The task {task} was resumed by the user {user}."
        task_resumed_by_backup_window    =    "Task {task} was resumed due to the configured backup window."
        task_same_backup_exist    =    "The backup task {task} can not be run now because the task is already being processed."
        task_start    =    "The backup task {task} has started."
        task_start_by_event    =    "Backup task {task} has been triggered by event {trigger_event}."
        task_target_delete_error    =    "Failed to remove the target of the task {task}."
        task_target_delete_finish    =    "The target folder of the task {task} was successfully removed."
        task_target_delete_start    =    "Starting to remove the target folder of the task {task}."
        task_unexpected_stop    =    "Task {task} failed due to an unexpected stop. Please try again later."
        task_verify_exist    =    "Failed to backup task {task} as the backup is being verified currently."
        task_version_delete_datacorrupt_v2    =    "The data in the backup destination are corrupted. Please {0}contact us{1} for technical support."
        task_version_delete_error    =    "The version [{version_ids}] of the task {task} failed to be deleted."
        task_version_delete_error_v2    =    "Failed to delete version [{timestamp_list}] of task {task}."
        task_version_delete_finish    =    "The version [{version_ids}] of the task {task} was successfully deleted."
        task_version_delete_finish_v2    =    "Successfully deleted version [{timestamp_list}] of backup task {task}."
        task_version_delete_ioerror_v2    =    "Unable to read/write data to the disk."
        task_version_delete_missing    =    "Version [{version_ids}] of task {task} has already been deleted."
        task_version_delete_noperm_v2    =    "No permission to access the backup destination shared folder. Please make sure the system internal user, ActiveBackup, has read/write permission of this folder."
        task_version_delete_nospace_v2    =    "Spaces on the disk are temporarily insufficient. Please try again later."
        task_version_delete_result_error    =    "Version deletion of task {task} failed."
        task_version_delete_result_finish    =    "Version deletion of task {task} succeeded."
        task_version_delete_result_partial_success    =    "Version deletion of task {task} partially succeeded."
        task_version_delete_start    =    "Starting to delete the version [{version_ids}] of the task {task}."
        task_version_delete_start_v2    =    "Starting to delete version [{timestamp_list}] of backup task {task}."
        task_version_rollback    =    "The task {task} failed due to an unexpected stop."
        task_version_rotate    =    "Rotation triggered for the version {version} of the task {task}."
        task_warning    =    "The backup task {task} was partially completed."
        template_create    =    "The user {user} created the task template {task_template}."
        template_edit    =    "The user {user} edited the task template {task_template}."
        template_edit_rename    =    "The user {user} changed the task template name from {old_name} to {task}."
        template_remove    =    "The user {user} removed the task template {task_template}."
        unknown_internal_error    =    "An unknown internal error occurred. Please contact Synology Technical Support for assistance."
        vddk_not_support_compression    =    "Data transfer compression is not supported."
        vddk_not_support_compression_v2    =    "The VM {device} in task {task}: Data transfer compression is not supported."
        vddk_not_support_encryption    =    "Data transfer encryption is not supported."
        verification_activate_codec_error    =    "Unable to activate codec for the verification task {task}. Please make sure your DNS server can resolve codecstatistic.Synology.com."
        verification_cancel    =    "The backup verification for task {task} was canceled."
        verification_create_images_error    =    "Failed to take screenshots for device {device_name}."
        verification_create_video_error    =    "Failed to take live video for task {task}."
        verification_dsm_not_supported    =    "Please upgrade to DSM 6.2."
        verification_error    =    "Backup verification for the task {task} failed."
        verification_img_mount_test_failed    =    "The backup version may be corrupted. Back up again. The next backup will be a full backup."
        verification_mount_test_error    =    "Failed to test the availability of backup files for device {device_name}."
        verification_need_mount_storage    =    "Cannot perform Backup Verification because storage {storage} is unmounted. Go to the Storage page and mount the storage, then try again."
        verification_not_support_bios    =    "Virtual Machine Manager does not support guest operating system {os_name} with the BIOS firmware."
        verification_not_support_os    =    "Virtual Machine Manager does not support the guest operating system ({os_name})."
        verification_partial_success    =    "Backup verification for the task {task} was partially completed."
        verification_report_success    =    "The screenshot for device {device_name} is complete."
        verification_start    =    "Backup verification for the task {task} has started."
        verification_success    =    "Backup verification for the task {task} was completed."
        verification_use_default_video_card    =    "Your virtual machine´s operating system couldn't be detected. Performing Backup Verification might result in a recording of a blank screen. If you're backing up a Hyper-V virtual machine, go to Virtual Machine > Microsoft Hyper-V, click VM information, and update the OS family and OS name to ensure that Backup Verification is successful in the future."
        verification_use_default_video_card_v2    =    "The virtual machine {device} in task {task}: Your virtual machine´s operating system couldn't be detected. Performing Backup Verification might result in a recording of a blank screen. If you're backing up a Hyper-V virtual machine, go to Virtual Machine > Microsoft Hyper-V, click VM information, and update the OS family and OS name to ensure that Backup Verification is successful in the future."
        verification_vmm_no_cluster    =    "No cluster exists in Synology Virtual Machine Manager. Please create a cluster first and try again."
        verification_vmm_no_same_volume    =    "The backup destination and the cluster of Synology Virtual Machine Manager are not in the same volume."
        verification_vmm_no_volume    =    "There is no storage in the cluster of Synology Virtual Machine Manager. Please add a storage to the cluster first and try again."
        verification_vmm_not_installed    =    "Synology Virtual Machine Manager is not installed or run."
        verification_vmm_not_supported    =    "Synology Virtual Machine Manager needs to be upgraded."
        vm_add_vsphere    =    "Add {vsphere_name} to the virtual machine list."
        vm_api_invalid_argument    =    "Error message from the hypervisor [{host_name}]: [{error_message}]"
        vm_authentication_fail    =    "Failed to log in to {host_name} due to wrong username or password."
        vm_backup_cancel    =    "The backup task of the VM {device} was canceled."
        vm_backup_datastore_not_enough_space    =    "Insufficient space on source datastore [{datastore}]. There are only [{free_space} GB] left on datastore, but [{reserve_space} GB] is required."
        vm_backup_disk    =    "The virtual disks (-flat.vmdk) of the VM {device} is being backed up."
        vm_backup_disk_missing    =    "Disk [{virtual_disk}] from the last version is missing. It might be removed or changed to a pass-through, RDM, or an independent disk. The backup task won't back up the disk."
        vm_backup_disk_missing_v2    =    "The virtual machine {device} in task {task}: Disk [{virtual_disk}] from the last version is missing. It might be removed or changed to a pass-through, RDM, or an independent disk. The backup task won't back up the disk."
        vm_backup_encrypt_with_key    =    "Encrypted backup data with key {key_id}."
        vm_backup_error    =    "The VM {device} failed to be backed up."
        vm_backup_finish    =    "The VM {device} was successfully backed up."
        vm_backup_spec    =    "The system configurations (.vmx) of the VM {device} is being backed up."
        vm_backup_start    =    "Starting to back up the VM {device}."
        vm_backup_verification_cancel    =    "Backup verification for the task {task} was canceled."
        vm_backup_verification_error    =    "Backup verification for the task {task} failed."
        vm_backup_verification_finish    =    "Backup verification for the task {task} was completed."
        vm_backup_verification_start    =    "Backup verification for the task {task} has started."
        vm_backup_without_license    =    "There is no valid license to protect this virtual machine."
        vm_backup_zero_disk    =    "There is no disk in virtual machine {device}."
        vm_cancel_dedup_fail    =    "The backup task of the VM {device} was canceled because last deduplication failed."
        vm_cancel_merge_fail    =    "The backup task of the VM {device} was canceled because last merge failed."
        vm_cbt_enable    =    "VMware Changed Block Tracking has been enabled on the VM {device}."
        vm_cbt_enable_error    =    "VMware Changed Block Tracking failed to be enabled on the VM {device}."
        vm_cbt_enable_error_general    =    "Failed to enable Changed Block Tracking on virtual machine {device}."
        vm_cbt_enable_error_general_v2    =    "Failed to enable Changed Block Tracking on virtual machine {device} in task {task}."
        vm_cbt_enable_general    =    "Changed Block Tracking has been enabled on virtual machine {device}."
        vm_cbt_free_license_error    =    "Owing to license issue, Changed Block Tracking is not supported on virtual machine {device}. Please manually enable the function on the hypervisor."
        vm_cbt_free_license_error_v2    =    "Owing to license issue, Changed Block Tracking is not supported on virtual machine {device} in task {task}. Please manually enable the function on the hypervisor."
        vm_cbt_not_support    =    "Changed Block Tracking is not supported on virtual machine {device}. Please check the version of the virtual machine and the hypervisor."
        vm_cbt_not_support_v2    =    "Changed Block Tracking is not supported on virtual machine {device} in task {task}. Please check the version of the virtual machine and the hypervisor."
        vm_cbt_reset_general    =    "Changed Block Tracking is reset on virtual machine {device}."
        vm_connection_fail    =    "Fail to connect to the hypervisor [{host_name}]. Please check the server address, account settings, and your network settings."
        vm_consolidate_error    =    "The virtual machine {device} consolidate disks failed."
        vm_consolidate_start    =    "The virtual machine {device} start to consolidate disks."
        vm_consolidate_success    =    "The virtual machine {device} consolidate disks success."
        vm_create_datastore_error    =    "An error occurred when creating a datastore for virtual machine {device} in the hypervisor."
        vm_create_disk_error    =    "An error occurred when creating a disk of virtual machine {device} in the hypervisor."
        vm_create_folder_error    =    "An error occurred when creating a folder for virtual machine {device} in the hypervisor."
        vm_disk_backup_transfer    =    "Disk [{virtual_disk}]: transfer size [{transfer_size}], transfer speed [{transfer_speed}]."
        vm_disk_full_backup_size_zero    =    "The full backup size of disk [{virtual_disk}] is zero. It could be an unused disk."
        vm_disk_full_backup_size_zero_v2    =    "The virtual machine {device} in task {task}: The full backup size of disk [{virtual_disk}] is zero. It could be an unused disk."
        vm_do_full_backup    =    "Performing full backup of [{virtual_disk}]."
        vm_do_full_backup_free_license    =    "Performing full backup of [{virtual_disk}]. With free ESXi license, please enable Changed Block Tracking manually."
        vm_entity_not_found    =    "Not found [{device}]"
        vm_exec_post_script    =    "Post-thaw script successfully executed."
        vm_exec_post_script_error    =    "Failed to execute the post-thaw script {script_result_path} with exit status {exit_code}."
        vm_exec_post_script_ignore_failure    =    "Ignored failed execution of the post-thaw script {script_result_path} with exit status {exit_code}."
        vm_exec_post_script_ignore_failure_v2    =    "The VM {device} in task {task}: Ignored failed execution of the post-thaw script {script_result_path} with exit status {exit_code}."
        vm_exec_pre_script    =    "Pre-freeze script successfully executed."
        vm_exec_pre_script_error    =    "Failed to execute the pre-freeze script {script_result_path} with exit status {exit_code}."
        vm_exec_pre_script_ignore_failure    =    "Ignored failed execution of the pre-freeze script {script_result_path} with exit status {exit_code}."
        vm_exec_pre_script_ignore_failure_v2    =    "The VM {device} in task {task}: Ignored failed execution of the pre-freeze script {script_result_path} with exit status {exit_code}."
        vm_exec_script_error    =    "Failed to execute the pre-freeze/post-thaw script {script_path}."
        vm_exec_script_no_power_on_error    =    "Failed to execute the script. Please make sure the virtual machine is powered on."
        vm_exec_script_no_return_error    =    "Failed to execute script, with no exit status returned."
        vm_exec_script_no_vmtool_error    =    "Failed to execute script. Please make sure VMware Tools have been installed and powered on."
        vm_exec_script_not_allowed    =    "The pre/post-thaw script cannot be executed on the free-licensed ESXi or vSphere version lower than 5.0."
        vm_exec_script_path_not_found    =    "Failed to access pre/post-thaw script file [{script_path}]."
        vm_exec_script_upload_error    =    "Failed to upload script to VM. Please make sure the credential, path, and operating system type of your script are configured correctly."
        vm_get_cbt_fail    =    "Failed to retrieve the changed blocks (CBT) for virtual machine {device}."
        vm_get_cbt_fail_v2    =    "Failed to retrieve the changed blocks (CBT) for virtual machine {device} in task {task}."
        vm_has_full_backup_capability    =    "Confirmed that virtual machine [{device_name}] is able to perform the enabled options of the task settings."
        vm_hypervisor_reverse_connect_fail    =    "Fail to connect to the DSM from Hypervisor. Please check the server address, port, and your network settings."
        vm_instant_restore_pause    =    "Instant restore task {task} was paused."
        vm_instant_restore_resume    =    "Instant restore task {task} was resumed."
        vm_instant_restore_resume_fail    =    "Unable to resume instant restore task {task}. Please remove the incomplete virtual machine from the hypervisor manually."
        vm_instant_restore_wait_migrate    =    "Virtual machine {device} in task {task} has been instantly restored to the original hypervisor and ready for migration. To ensure the smooth performance of the virtual machine, it is recommended for you to move the virtual machine data back to the datastore on the hypervisor by migration or offline export and import."
        vm_inventory_cert_verify_fail    =    "Failed to verify the certificate of hypervisor {host_name}. Please go to <b>Virtual Machine</b> and click <b>Manage Hypervisor</b>. Select this hypervisor and click <b>Edit</b> to check the certificate."
        vm_inventory_cert_verify_fail_detail    =    "Failed to verify the certificate of hypervisor {host_name} because of {err_reason}. Are you sure you want to trust this certificate? <BR/>Issue to: {issue_to} <BR/>Issued by: {issuer} <BR/>Valid from: {valid_from} <BR/>Valid to: {valid_to}"
        vm_inventory_thumbprint_mismatch    =    "The hypervisor contains incorrect SHA1 thumbprint."
        vm_inventory_timeout    =    "Connection timeout. Please make sure the internet connection and firewall settings are correctly configured and try again."
        vm_inventory_unauthentication    =    "{host_name} is unauthenticated due to wrong username or password. Please enter your hypervisor credentials again."
        vm_migrate_cancel    =    "The VM migration task {task} was canceled."
        vm_migrate_error    =    "VM migration of the task {task} failed."
        vm_migrate_finish    =    "VM migration of the task {task} was completed."
        vm_migrate_partial_success    =    "The VM migration task {task} was partially completed."
        vm_migrate_start    =    "Starting to migrate the selected VM of the task {task}."
        vm_migrate_startplu    =    "Starting to migrate the selected VMs of the task {task}."
        vm_migrate_vm_cancel    =    "The migration task of the VM {device} was canceled."
        vm_migrate_vm_error    =    "The VM {device} failed to be migrated."
        vm_migrate_vm_finish    =    "The VM {device} was successfully migrated."
        vm_migrate_vm_start    =    "Starting to migrate the VM {device}."
        vm_migrate_warning    =    "VM migration of the task {task} was partially completed."
        vm_no_valid_backup_disk    =    "No available virtual disks to be backed up."
        vm_not_found    =    "Unable to find the following virtual machines: {device}. Please remove them from the backup task to prevent backup failures."
        vm_power_on_error    =    "An error occurred when powering on virtual machine {device} in the hypervisor."
        vm_power_on_error_v2    =    "An error occurred when powering on virtual machine {device} in task {task} in the hypervisor."
        vm_register_error    =    "An error occurred when registering virtual machine {device} to the hypervisor."
        vm_remove_vsphere    =    "Remove {vsphere_name} from virtual machine list."
        vm_restore_cancel    =    "The restore task of the VM {device} was canceled."
        vm_restore_create_disk_timeout    =    "Connection expired. Please try again."
        vm_restore_create_nfs_folder    =    "The temporary folder {path} used for instant restore was created in your _DISKSTATION_."
        vm_restore_disk    =    "The virtual disks (-flat.vmdk) of the VM {device} will be restored."
        vm_restore_error    =    "The VM {device} failed to be restored."
        vm_restore_file_transfer    =    "The VM file {path} was processed successfully."
        vm_restore_finish    =    "The VM {device} was successfully restored."
        vm_restore_guest_not_enough_space    =    "There is not enough space to restore the file(s)."
        vm_restore_load_records    =    "Database records associated with the task {task} were loaded."
        vm_restore_nfs_mount_error    =    "No NFS permission for the hypervisor {path} to access the shared folder {share} in your _DISKSTATION_."
        vm_restore_nfs_service_error    =    "Please make sure that 1. the NFS service is activated under the file service, and 2. the hypervisor that runs the to-be-restored VM has NFS permission to the shared folder {share}."
        vm_restore_os_not_support    =    "Failed to restore VM {device} because {os_name} is not supported."
        vm_restore_spec    =    "The system configurations (.vmx) of the VM {device} will be restored."
        vm_restore_start    =    "Starting to restore the VM {device}."
        vm_restore_stop_wait_migration    =    "The Instant Restore to VMware task {task} was stopped."
        vm_restore_stop_wait_migration_general    =    "The instant restore task {task} was terminated."
        vm_restore_vm_create_datastore    =    "The datastore {path} was created in the hypervisor."
        vm_restore_vm_create_folder    =    "The folder {path} was created in the hypervisor for storing VM files."
        vm_restore_vm_power_on    =    "{device} was powered on."
        vm_restore_vm_register    =    "{device} was registered to the hypervisor [{hypervisor}]."
        vm_restore_vm_register_downgrade    =    "By lack of resources on the restored hypervisor, the system cannot assign the backed up CPU ({core_num} core) and memory ({mem_size} GB) configurations. However, to complete the restoration, CPU ({reduce_core_num} core) and ({reduce_mem_size} GB) memory were automatically assigned. You may adjust the CPU and memory on the restored hypervisor manually."
        vm_restore_vm_register_downgrade_os    =    "The restored hypervisor doesn't support the source virtual machine's operating systm ({old_os_name}). To successfully restore the device, the operating system is automatically set as {new_os_name}. You can change it on the hypervisor later."
        vm_restore_vm_remove_conflict    =    "The VM {path} whose name conflicts with the restored VM was removed from the hypervisor."
        vm_send_request_fail    =    "Error message from the hypervisor [{host_name}]: [{error_message}]"
        vm_skip_not_supported_disk    =    "Limitation of the VMware hard disk prevented the RDM disk or independent disk from performing a snapshot."
        vm_skip_not_supported_disk_diskname    =    "Failed to take snapshots of the RDM disk or independent disk because of the limitation of the VMware hard disk."
        vm_skip_not_supported_disk_diskname_hyperv    =    "Failed to take snapshots of the pass-through disk because of the limitation of the Hyper-V hard disk."
        vm_skip_not_supported_disk_first_time    =    "Limitation of the VMware hard disk prevents the RDM disk or independent disk from performing a snapshot. However, the status of the next backup will be displayed as <b>Successful</b>, and this message will no longer be recorded as a warning log."
        vm_skip_not_supported_disk_first_time_diskname    =    "Failed to take snapshots of [{virtual_disk}]. This hard disk will be ignored when being backed up. Snapshots of the RDM disk or independent disk cannot be taken because of the limitation of the VMware hard disk. However, the status of the next backup will display as <b>Successful</b>, and this message will no longer be recorded as a warning log."
        vm_skip_not_supported_disk_first_time_diskname_hyperv    =    "Failed to take snapshots of [{virtual_disk}]. This hard disk will be ignored when being backed up. Snapshots of the pass-through disk cannot be taken because of the limitation of the Hyper-V hard disk. However, the status of the next backup will display as <b>Successful</b>, and this message will no longer be recorded as a warning log."
        vm_skip_not_supported_disk_first_time_diskname_hyperv_v2    =    "The virtual machine {device} in task {task}: Failed to take snapshots of [{virtual_disk}]. This hard disk will be ignored when being backed up. Snapshots of the pass-through disk cannot be taken because of the limitation of the Hyper-V hard disk. However, the status of the next backup will display as <b>Successful</b>, and this message will no longer be recorded as a warning log."
        vm_skip_not_supported_disk_first_time_diskname_v2    =    "The virtual machine {device} in task {task}: Failed to take snapshots of [{virtual_disk}]. This hard disk will be ignored when being backed up. Snapshots of the RDM disk or independent disk cannot be taken because of the limitation of the VMware hard disk. However, the status of the next backup will display as <b>Successful</b>, and this message will no longer be recorded as a warning log."
        vm_skip_not_supported_disk_one    =    "Limitation of the VMware hard disk prevented the RDM disk or independent disk from performing a snapshot."
        vm_skip_not_supported_disk_one_diskname    =    "Failed to take snapshots of [{virtual_disk}]. This hard disk will be ignored when being backed up. Snapshots of the RDM disk or independent disk cannot be taken because of the limitation of the VMware hard disk."
        vm_skip_not_supported_disk_one_diskname_hyperv    =    "Failed to take snapshots of [{virtual_disk}]. This hard disk will be ignored when being backed up. Snapshots of the pass-through disk cannot be taken because of the limitation of the Hyper-V hard disk."
        vm_skip_not_supported_disk_one_first_time    =    "Limitation of the VMware hard disk prevented the RDM disk or independent disk from performing a snapshot. However, the status of the next backup will be displayed as <b>Successful</b>, and this message will no longer be recorded as a warning log."
        vm_skip_not_supported_disk_one_first_time_diskname    =    "Failed to take snapshots of [{virtual_disk}]. This hard disk will be ignored when being backed up. Snapshots of the RDM disk or independent disk could not be taken because of the limitation of the VMware hard disk. However, the status of the next backup will display as <b>Successful</b>, and this message will no longer be recorded as a warning log."
        vm_skip_not_supported_disk_one_first_time_diskname_hyperv    =    "Failed to make checkpoints of [{virtual_disk}]. This hard disk will be ignored when being backed up. Checkpoints of the Passthrough disk could not be made because of the limitation of the HyperV hard disk. However, the status of the next backup will display as <b>Successful</b>, and this message will no longer be recorded as a warning log."
        vm_snapshot_production_checkpoint_fail_error    =    "Failed to take an application aware snapshot of virtual machine `"{device}`" because <a class=`"link-font`" href='https://sy.to/lnitq' target='_blank'>a production checkpoint couldn't be created</a>. The system will disable application aware processing this time and retake the snapshot."
        vm_snapshot_production_checkpoint_fail_error_v2    =    "Failed to take an application aware snapshot of virtual machine `"{device}`" in task {task} because <a class=`"link-font`" href='https://sy.to/lnitq' target='_blank'>a production checkpoint couldn't be created</a>. The system will disable application aware processing this time and retake the snapshot."
        vm_snapshot_remove    =    "The snapshot of the VM {device} was removed."
        vm_snapshot_remove_error    =    "The snapshot of the VM {device} failed to be removed."
        vm_snapshot_remove_error_v2    =    "The snapshot of the VM {device} in task {task} failed to be removed."
        vm_snapshot_remove_time    =    "The snapshot of virtual machine {device} was removed. Elapsed Time: {snapshot_time} seconds."
        vm_snapshot_take    =    "A snapshot will be taken of the VM {device}."
        vm_snapshot_take_error    =    "Failed to take a snapshot of the VM {device}. "
        vm_snapshot_take_quiesce_error    =    "Failed to take a snapshot of the virtual machine {device} because the virtual machine could not be quiesced. Application aware was disabled this time for the task to be backed up."
        vm_snapshot_take_quiesce_fail_error    =    "Failed to take an application aware snapshot of virtual machine `"{device}`" because <a class=`"link-font`" href='https://sy.to/jn6ze' target='_blank'>the virtual machine couldn't be quiesced</a>. The system will disable application aware processing this time and retake the snapshot."
        vm_snapshot_take_quiesce_fail_error_v2    =    "Failed to take an application aware snapshot of virtual machine `"{device}`" in task {task} because <a class=`"link-font`" href='https://sy.to/jn6ze' target='_blank'>the virtual machine couldn't be quiesced</a>. The system will disable application aware processing this time and retake the snapshot."
        vm_speed_info    =    "The average backup speed is {speed}. Utilization rates of different components are shown as below: snapshot operation [{ratio_snapshot}], source data transfer [{ratio_recv_vm}], data deduplication [{ratio_dedup}], and write to file [{ratio_write}]."
        vm_speed_info_v2    =    "The average backup speed is {speed}. Utilization rates of different components are shown as below: snapshot operation [{ratio_snapshot}], source data read[{ratio_read_disk}], source data transfer [{ratio_recv_vm}], data deduplication [{ratio_dedup}], and write to file [{ratio_write}]."
        vm_speed_info_v3    =    "Virtual machine {device} average backup speed: {speed}. Operating module loadings: {vm_read_module_name} source data transfer [{vm_transfer_module_loading}], data deduplication [{vm_dedup_module_loading}] {vm_compress_module_name} {vm_encrypt_module_name}, and write to file [{vm_write_module_loading}]."
        vm_ssh_connection_fail    =    "SSH connection failed."
        vm_task_created    =    "The user {user} has created the task {task}."
        vm_task_partial_success    =    "The backup task {task} was partially completed."
        vm_task_removed    =    "The user {user} has removed the task {task}."
        vm_transfer_finish    =    "Data transfer of the VM {device} was completed."
        vm_transfer_mode_select    =    "The transfer mode {transfer_mode} was selected for the VM {device}."
        vm_transfer_mode_select_error    =    "The transfer mode {transfer_mode} failed to be selected for the VM {device}."
        vm_transfer_start    =    "Data transfer of the VM {device} has started."
        vm_transfer_start_error    =    "Data transfer of the VM {device} failed."
        vm_unstable_full_backup    =    "Cannot reset Changed Block Tracking, so a full backup will be conducted to ensure data integrity. If you want to enable Changed Block Tracking, delete all snapshots on the device before backing up."
        vm_unstable_full_backup_v2    =    "The virtual machine {device} in task {task}: Cannot reset Changed Block Tracking, so a full backup will be conducted to ensure data integrity. If you want to enable Changed Block Tracking, delete all snapshots on the device before backing up."
        vm_upload_file_error    =    "An error occurred when uploading a file from virtual machine {device} to the hypervisor."
        vm_virtual_disk_not_found    =    "Cannot find target virtual disk [{id}]."
        vm_without_disk    =    "No valid disk to backup."
        vmm_internal_error    =    "ABLog Virtual Machine Manager internal error."
        vmm_migrate_create_datastore    =    "The datastore {path} was created in the hypervisor."
        vmm_migrate_create_disk_timeout    =    "Connection expired. Please try again."
        vmm_migrate_create_folder    =    "The folder {path} was created in the hypervisor for storing VM files."
        vmm_migrate_file_transfer    =    "The VM file {path} was processed successfully."
        vmm_migrate_power_on    =    "{device} was powered on."
        vmm_migrate_register    =    "{device} was registered to the hypervisor [{hypervisor}]."
        vmm_migrate_register_downgrade    =    "By lack of resources on the restored hypervisor, the system cannot assign the backed up CPU ({core_num} core) and memory ({mem_size} GB) configurations. However, to complete the restoration, CPU ({reduce_core_num} core) and ({reduce_mem_size} GB) memory were assigned automatically. You may adjust the CPU and memory on the restored hypervisor manually."
        vmm_migrate_register_downgrade_os    =    "The restored hypervisor doesn't support the source virtual machine's operating systm ({old_os_name}). To successfully restore the device, the operating system is automatically set as {new_os_name}. You can change it on the hypervisor later."
        vmm_migrate_remove_conflict    =    "Removed virtual machine {path} from the hypervisor. The virtual machine's name conflicts with the migrated virtual machine."
        vmm_webapi_error    =    "The operation in Synology Virtual Machine Manager failed. Please go to <b>Synology Virtual Machine Manager</b> > <b>Log</b> for detailed information."
        vmm_webapi_error_clone_fail    =    "Synology Virtual Machine Manager failed to clone the disk."
        vmm_webapi_error_clone_power_on    =    "Synology Virtual Machine Manager cannot clone the disk while the virtual machine is powered on."
        vmm_webapi_error_poweroff_guest    =    "Failed to power off the virtual machine in Synology Virtual Machine Manager. Please go to <b>Synology Virtual Machine Manager</b> > <b>Log</b> for detailed information."
        vmm_webapi_error_poweron_guest    =    "Failed to power on the virtual machine in Synology Virtual Machine Manager. Please go to <b>Synology Virtual Machine Manager</b> > <b>Log</b> for detailed information."
        vmm_webapi_error_poweron_guest_sel_host    =    "Failed to power on the virtual machine in Virtual Machine Manager. Please ensure sufficient memory on Virtual Machine Manager. If the memory is sufficient but the problem persists, contact Synology Technical Support for assistance."
        vmm_webapi_error_task_q_reach_max    =    "Too many devices are performing backup verification at the same time. Please try again later."
        vmtool_not_installed    =    "VMware Tools are not installed on the guest OS or the guest OS is not running."
        vmtool_not_installed_when_running_app_aware    =    "Failed to perform application-aware backup since VMware Tools are not installed."
        vmtool_not_installed_when_running_app_aware_v2    =    "The virtual machine {device} in task {task}: Failed to perform application-aware backup since VMware Tools are not installed."
        windows_backup_access_denied    =    "<a class=`"link-font`" href='http://sy.to/abbagenterrorcode' target='_blank'>Error Code: {error_code}</a>. Unable to back up {volume_name}. (Reason: access denied) Please check snapshot permissions."
        windows_backup_invalid_function    =    "<a class=`"link-font`" href='http://sy.to/abbagenterrorcode' target='_blank'>Error Code: {error_code}</a>. Unable to back up {volume_name}."
        windows_backup_path_not_found    =    "<a class=`"link-font`" href='http://sy.to/abbagenterrorcode' target='_blank'>Error Code: {error_code}</a>. Unable to back up {volume_name}. (Reason: path not found)"
        windows_backup_sector_not_found    =    "<a class=`"link-font`" href='http://sy.to/abbagenterrorcode' target='_blank'>Error Code: {error_code}</a>. Unable to back up {volume_name}. (Reason: sector not found)"
        windows_read_snapshot_error    =    "<a class=`"link-font`" href='http://sy.to/abbagenterrorcode' target='_blank'>Error Code: {error_code}</a>. Unable to read the snapshot. Please check the disks of the device."
        windows_restore_create_file_error    =    "<a class=`"link-font`" href='http://sy.to/abbagenterrorcode' target='_blank'>Error Code: {error_code}</a>. Unable to access the disk."
        windows_restore_write_file_error    =    "<a class=`"link-font`" href='http://sy.to/abbagenterrorcode' target='_blank'>Error Code: {error_code}</a>. Unable to write data to the disk."
        windows_snapshot_open_error    =    "<a class=`"link-font`" href='http://sy.to/abbagenterrorcode' target='_blank'>Error Code: {error_code}</a>. Unable to open {volume_name}."
        windows_take_snapshot_finish_error    =    "<a class=`"link-font`" href='http://sy.to/abbagenterrorcode' target='_blank'>Error Code: {error_code}</a>. Unable to take a snapshot for {volume_name}."
        winrm_connection_fail    =    "Failed to connect to host [{host_name}]. Please refer to <a href=http://sy.to/omris target=blank>this article</a> and make sure WinRM is enabled and check the server address and network settings are correct."
        winrm_unknown_protocol    =    "Failed to connect to the host [{host_name}]. Please make sure that WinRM port is correctly configured for the corresponding protocol."
        write_over_image_4k_size    =    "The changed blocks of {device} are larger than the virtual disk capacity. Go to the hypervisor and expand the virtual disk capacity, which must be a multiple of 4 KB."
        write_over_image_size    =    "The size of {device}'s changed data blocks is larger than the virtual disk capacity. Go to the hypervisor and expand the virtual machine's virtual disk capacity to an integer multiple of 4 KB."
    }[[String]$log_type]
    $params.psobject.Properties | ForEach-Object {$text = $text -replace "{$($_.Name -replace '_name','')(_name)?}",$params.$($_.Name)}
    $text
} 

################################# Class definitions ###################################


class ABActivity
{
    [ABDevice[]]$device
    [ABJob]$job
    [ABStorage]$storage
    [ABTask]$task
    [String]ToString () {
        return $this.job.action
    }
}

class ABJob
{
    [ABJobAction]$action
    [ABBAckupType]$backup_type
    [int]$job_id
    [int]$job_type #ABLogLevel?
    [int]$max_parallel
    [PSCustomObject]$params
    [ABJobStage]$stage
    [ABJobStatus]$status
    [int]$storage_id
    [ABSubJob[]]$sub_jobs
    [int]$task_id
    [int]$trigger_uid
    [String]$user_name
    [String]ToString () {
        return $this.action
    }
}

class ABSubJob
{
    [ABJobAction]$action
    [ABBackupType]$backup_type
    [int]$config_device_id
    [int]$job_id
    [int]$job_type #Enum?
    [int]$max_parallel
    [PSCustomObject]$params
    [int]$pid #int64?
    [ABJobStage]$stage
    [ABJobStatus]$status
    [int]$storage_id
    [int]$task_id
    [int]$trigger_uid
    [String]ToString () {
        return $this.action
    }
}

class ABStorage
{
    [String]$automount_iv #datatype?
    [String]$automount_location
    [ABFSType]$fs_type
    [String]$repo_dir
    [String]$share_name
    [int]$storage_id
    [String]$volume_path
    [String]ToString () {
        return $this.share_name
    }
}

class ABResultDetail
{
    [ABErrorCode]$error_code
    [ABLogLevel]$log_level
    [datetime]$log_time
    [ABLogMessageId]$log_type
    [PSCustomObject]$other_params
    [int]$result_detail_id
    [int]$result_id
    [String]$Message
    ABResultDetail ([PSCustomObject]$object) {
        $this.error_code       = $object.error_code              
        $this.log_level        = $object.log_level
        $this.log_type         = $object.log_type
        $this.other_params     = $object.other_params
        $this.result_detail_id = $object.result_detail_id
        $this.result_id        = $object.result_id
        $this.log_time         = ([datetime]"1970-01-01").AddSeconds($object.log_time).ToLocalTime()
        $this.Message = Get-ABLogMessage -log_type $this.log_type -params $this.other_params
    }
    [String]ToString () {
        return $this.log_type
    }
}

class ABTaskConfig
{
    [ABDevice[]]$device_list
    [ABRestoreType]$restore_type
    [String]$target_path  
    [String]ToString () {
        return $this.device_list
    }
}

class ABResult
{
    [ABBackupType]$backup_type
    [String]$detail_path
    [int]$error_count
    [ABJobAction]$job_action
    [int]$none_count
    [int]$result_id
    [ABResultStatus]$status
    [int]$success_count
    [ABTaskConfig]$task_config
    [int]$task_id
    [String]$task_name
    [datetime]$time_end
    [datetime]$time_start
    [int]$warning_count
    ABResult([PSCustomObject]$object) {
        $this.backup_type   = $object.backup_type
        $this.detail_path   = $object.detail_path
        $this.error_count   = $object.error_count
        $this.job_action    = $object.job_action
        $this.none_count    = $object.none_count
        $this.result_id     = $object.result_id
        $this.status        = $object.status
        $this.success_count = $object.success_count
        $this.task_config   = $object.task_config
        $this.task_id       = $object.task_id
        $this.task_name     = $object.task_name
        $this.time_end      = ([datetime]"1970-01-01").AddSeconds($object.time_end).ToLocalTime()
        $this.time_start    = ([datetime]"1970-01-01").AddSeconds($object.time_start).ToLocalTime()
        $this.warning_count = $object.warning_count
    }
    [String]ToString () {
        return $this.status
    }
}

class ABLog
{
    [ABBackupType]$backup_type
    [int]$device_id
    [String]$device_name
    [ABErrorCode]$error_code
    [int]$log_id
    [ABLogLevel]$log_level
    [datetime]$log_time
    [ABLogMessageId]$log_type
    [PSCustomObject]$other_params
    [int]$result_id
    [int]$task_id
    [String]$task_name
    [int]$user_id
    [String]$user_name
    [String]$Message
    ABLog ([PSCustomObject]$object) {
        $this.backup_type  = $object.backup_type 
        $this.device_id    = $object.device_id   
        $this.device_name  = $object.device_name 
        $this.error_code   = $object.error_code  
        $this.log_id       = $object.log_id      
        $this.log_level    = $object.log_level   
        $this.log_type     = $object.log_type    
        $this.other_params = $object.other_params
        $this.result_id    = $object.result_id   
        $this.task_id      = $object.task_id     
        $this.task_name    = $object.task_name   
        $this.user_id      = $object.user_id     
        $this.user_name    = $object.user_name   
        $this.log_time = ([datetime]"1970-01-01").AddSeconds($object.log_time).ToLocalTime()
        $this.Message = Get-ABLogMessage -log_type $this.log_type -params $this.other_params
    }
    [String]ToString () {
        return $this.log_type
    }
}

class ABSchedule
{
    [ABWeekDay[]]$run_weekday = @(0,1,2,3,4,5,6)
    [ABScheduleSettingType]$schedule_setting_type = 'SCHEDULE'
    [String]$repeat_type = 'Weekly' #Can be nothing else it seems
    [int]$repeat_hour = 0
    [int]$run_hour    = 3
    [int]$run_min     = 0
    [bool]$is_modify_schedule_enable = $true
    [bool]$enable_backup_window = $false
    [String]$backup_window         = '111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111'
    [bool]$is_continuous_paused  = $false
    [nullable[int]]$start_day
    [nullable[int]]$start_month
    [nullable[int]]$start_year
    [nullable[datetime]]$date
    ABSchedule ()
    {
    }
    ABSchedule ([int]$Hour, [int]$Minute)
    {
        $this.run_hour = $Hour
        $this.run_min = $Minute
    }
    [String]ToString () {
        if ($this.schedule_setting_type -eq 'SCHEDULE')
        {
            $bitDays = $this.run_weekday | Sort-Object -Unique | ForEach-Object {$sum=0}{$sum+=[math]::pow(2,$_)}{$sum} 
            if ($bitDays -eq 127)
            {
                $days = 'ALL DAYS'
            } elseif ($bitDays -eq 65) {
                $days = 'WEEKENDS'
            } elseif ($bitDays -eq 62) {
                $days = 'WEEKDAYS'
            } else {
                $days = [String]$this.run_weekday
            }

            return '[{0:D2}:{1:D2}][{2}]' -F $this.run_hour,$this.run_min,$days
        }
        return $this.schedule_setting_type
    }
}

class ABRetentionPolicy
{
    [ALias('DisablePolicy')][bool]$keep_all = $false
    [Alias('KeepDays')][nullable[int]]$keep_days
    [Alias('KeepVersions')][nullable[int]]$keep_versions
    [Alias('GFSDays')][nullable[int]]$gfs_days
    [Alias('GFSWeeks')][nullable[int]]$gfs_weeks
    [Alias('GFSMonths')][nullable[int]]$gfs_months
    [Alias('GFSYears')][nullable[int]]$gfs_years
    [String]ToString () {
        if ($this.keep_all)
        {
            return "Disabled"
        }
        $str = ""
        if ($this.keep_days)
        {
            $str += "[$($this.keep_days) Days]"
        }
        if ($this.keep_versions)
        {
            $str += "[$($this.keep_versions) Versions]"
        }
        if ($this.gfs_days -or $this.gfs_weeks -or $this.gfs_months -or $this.gfs_years)
        {
            $str += "[GFS:"
        }
        if ($this.gfs_days)
        {
            $str += "$($this.gfs_days) Days, "
        }
        if ($this.gfs_weeks)
        {
            $str += "$($this.gfs_weeks) Weeks, "
        }
        if ($this.gfs_months)
        {
            $str += "$($this.gfs_months) Months, "
        }
        if ($this.gfs_years)
        {
            $str += "$($this.gfs_years) Years, "
        }
        if ($this.gfs_days -or $this.gfs_weeks -or $this.gfs_months -or $this.gfs_years)
        {
            $str = $str.Substring(0,$str.length - 2) + ']'
        }
        
        return $str
    }
}

class ABEntity
{
    [String]$id
    [String]$name
    [String]$os_name
    [String]$type
    [String]$folder_id
    [nullable[bool]]$consolidation_needed
    [PSCustomobject]$hypervisor
    [guid]$instance_uuid = [guid]::Empty
    [nullable[bool]]$is_template
    [nullable[bool]]$is_vcenter
    [nullable[int]]$num_cpu
    [nullable[bool]]$powered_on
    [nullable[int]]$ram_mb
    [String]$status
    [nullable[bool]]$status_ok
    [String]$vm_id
    [nullable[bool]]$vmtool_running
}

class ABVMFolder
{
    [int]$inventory_id = 1
    [String[]]$exclusive_folder_id
    [String[]]$exclusive_folder_path
    [String[]]$exclusive_vm_id
    [String[]]$exclusive_vm_path
    [String]$folder_id
    [String]$folder_path
    [String]$folder_type
    [String]$viewtype
    [String]ToString () {
        return $this.folder_type
    }

    ABVMFolder ([ABEntity]$entity) {
        switch ($entity.type)
        {
            'vim.Folder' {
                $this.folder_id = $entity.id
                $this.folder_type = $entity.type
                $this.viewtype = 'vim.VirtualMachine-Folder'
            }
        }
    }

    ABVMFolder ([ABEntity]$entity, [int]$inventory_id) {
        switch ($entity.type)
        {
            'vim.Folder' {
                $this.inventory_id = $inventory_id
                $this.folder_id = $entity.id
                $this.folder_type = $entity.type
                $this.viewtype = 'vim.VirtualMachine-Folder'
            }
        }
    }
    ABVMFolder ([Object]$object) {
        $this.inventory_id          = $object.inventory_id
        $this.exclusive_folder_id   = $object.exclusive_folder_id
        $this.exclusive_folder_path = $object.exclusive_folder_path
        $this.exclusive_vm_id       = $object.exclusive_vm_id
        $this.exclusive_vm_path     = $object.exclusive_vm_path
        $this.folder_id             = $object.folder_id
        $this.folder_path           = $object.folder_path
        $this.folder_type           = $object.folder_type
        $this.viewtype              = $object.viewtype
    }
}

class ABTask
{
    [String]$agentless_backup_path
    [ABAgentlessBAckupPolicy]$agentless_backup_policy
    [bool]$agentless_enable_block_transfer
    [bool]$agentless_enable_dedup
    [bool]$agentless_enable_windows_vss
    [bool]$allow_manual_backup
    [String]$backup_cache_content #object?
    [bool]$backup_external
    [ABBackupType]$backup_type
    [int]$bandwidth #double?
    [String]$bandwidth_content #object?
    [ABEnableCBTMode]$cbt_enable_mode
    [int]$connection_timeout
    [String]$custom_volume
    [int]$datastore_reserved_percentage
    [bool]$dedup_api_restore
    [String]$dedup_path
    [int]$device_count
    [ABDevice[]]$devices
    [bool]$enable_app_aware_bkp
    [bool]$enable_compress_transfer
    [bool]$enable_datastore_aware
    [bool]$enable_dedup
    [bool]$enable_encrypt_transfer
    [bool]$enable_notify
    [bool]$enable_shutdown_after_complete
    [bool]$enable_verification
    [bool]$enable_wake_up
    [bool]$enable_windows_working_state
    [nullable[ABHostGroup]]$host_group
    [ABResult]$last_result
    [int]$last_version_id
    [int]$max_concurrent_devices
    [nullable[datetime]]$next_trigger_time
    [ABScript]$pre_post_script_setting
    [String]$repo_dir
    [ABRetentionPolicy]$retention_policy
    [ABSchedule]$sched_content
    [int]$sched_id
    [nullable[datetime]]$sched_modify_time
    [bool]$share_compressed
    [String]$share_name
    [ABSourceType]$source_type
    [nullable[ABStorageCompressAlgorithm]]$storage_compress_algorithm
    [nullable[ABStorageEncryptAlgorithm]]$storage_encrypt_algorithm
    [int]$storage_id
    [String]$target_dir
    [String]$target_status
    [int]$task_id
    [String]$task_name
    [GUID]$unikey = [GUID]::Empty
    [int]$verification_policy
    [int]$version_count
    [ABVersion[]]$versions
    [String]$view_type
    [ABVMFolder[]]$vm_folder
    ABTask ([PSCustomObject]$object)
    {
        $this.agentless_backup_path           = $object.agentless_backup_path
        $this.agentless_backup_policy         = $object.agentless_backup_policy
        $this.agentless_enable_block_transfer = $object.agentless_enable_block_transfer
        $this.agentless_enable_dedup          = $object.agentless_enable_dedup
        $this.agentless_enable_windows_vss    = $object.agentless_enable_windows_vss
        $this.allow_manual_backup             = $object.allow_manual_backup
        $this.backup_cache_content            = $object.backup_cache_content
        $this.backup_external                 = $object.backup_external
        $this.backup_type                     = $object.backup_type
        $this.bandwidth                       = $object.bandwidth
        $this.bandwidth_content               = $object.bandwidth_content
        $this.cbt_enable_mode                 = $object.cbt_enable_mode
        $this.connection_timeout              = $object.connection_timeout
        $this.custom_volume                   = $object.custom_volume
        $this.datastore_reserved_percentage   = $object.datastore_reserved_percentage
        $this.dedup_api_restore               = $object.dedup_api_restore
        $this.dedup_path                      = $object.dedup_path
        $this.device_count                    = $object.device_count
        $this.devices                         = $object.devices
        $this.enable_app_aware_bkp            = $object.enable_app_aware_bkp
        $this.enable_compress_transfer        = $object.enable_compress_transfer
        $this.enable_datastore_aware          = $object.enable_datastore_aware
        $this.enable_dedup                    = $object.enable_dedup
        $this.enable_encrypt_transfer         = $object.enable_encrypt_transfer
        $this.enable_notify                   = $object.enable_notify
        $this.enable_shutdown_after_complete  = $object.enable_shutdown_after_complete
        $this.enable_verification             = $object.enable_verification
        $this.enable_wake_up                  = $object.enable_wake_up
        $this.enable_windows_working_state    = $object.enable_windows_working_state
        $this.host_group                      = $object.host_group
        $this.last_result                     = $object.last_result
        $this.last_version_id                 = $object.last_version_id
        $this.max_concurrent_devices          = $object.max_concurrent_devices
        if ([int]$object.next_trigger_time) {$this.next_trigger_time = ([datetime]"1970-01-01").AddSeconds($object.next_trigger_time).ToLocalTime()}
        $this.pre_post_script_setting         = $object.pre_post_script_setting
        $this.repo_dir                        = $object.repo_dir
        $this.retention_policy                = $object.retention_policy
        $this.sched_content                   = $object.sched_content
        $this.sched_id                        = $object.sched_id
        if ([int]$object.sched_modify_time) {$this.sched_modify_time = ([datetime]"1970-01-01").AddSeconds($object.sched_modify_time).ToLocalTime()}
        $this.share_compressed                = $object.share_compressed
        $this.share_name                      = $object.share_name
        $this.source_type                     = $object.source_type
        $this.storage_compress_algorithm      = $object.storage_compress_algorithm
        $this.storage_encrypt_algorithm       = $object.storage_encrypt_algorithm
        $this.storage_id                      = $object.storage_id
        $this.target_dir                      = $object.target_dir
        $this.target_status                   = $object.target_status
        $this.task_id                         = $object.task_id
        $this.task_name                       = $object.task_name
        if ($object.unikey) { $this.unikey = $object.unikey } else { $this.unikey = [GUID]::Empty }
        $this.verification_policy             = $object.verification_policy
        $this.version_count                   = $object.version_count
        $this.versions                        = $object.versions
        $this.view_type                       = $object.view_type
        $this.vm_folder                       = foreach ($property in $object.vm_folder.psobject.Properties) { $property.value | Add-Member -MemberType NoteProperty -Name inventory_id -Value $property.name -PassThru }
    }
    ABTask () {
    }
    [String]ToString () {
        return $this.task_name
    }
}

class ABDevice
{
    #[bool]$agent_can_backup
    #[String]$agent_driver_status
    #[String]$agent_status
    #[String]$driver_status         
    [String]$agent_token
    [nullable[int]]$agentless_auth_policy
    [nullable[ABBackupType]]$backup_type          
    [nullable[datetime]]$create_time          
    [int]$device_id            
    #[guid]$device_uuid = [guid]::Empty         
    [String]$device_uuid         
    [String]$dsm_model            
    [String]$dsm_unique           
    [String]$host_ip              
    [String]$host_name            
    [nullable[int]]$host_port            
    [nullable[int]]$hypervisor_id        
    [nullable[int]]$inventory_id         
    [String]$login_password       
    [nullable[datetime]]$login_time           
    [String]$login_user           
    [nullable[int]]$login_user_id        
    [String]$os_name              
    [ABScript]$script               
    [String]$vm_moid_path
    [ABResult]$last_result       
    ABDevice ([PSCustomObject]$object)
    {
        #$this.agent_can_backup      = $object.agent_can_backup
        #$this.agent_driver_status   = $object.agent_driver_status
        #$this.agent_status          = $object.agent_status
        #$this.driver_status         = $object.driver_status
        $this.agent_token           = $object.agent_token          
        $this.agentless_auth_policy = $object.agentless_auth_policy
        $this.backup_type           = $object.backup_type          
        if ($object.create_time) { $this.create_time = ([datetime]"1970-01-01").AddSeconds($object.create_time).ToLocalTime()}
        $this.device_id             = $object.device_id            
        #if ($object.device_uuid) { $this.device_uuid = $object.device_uuid } else { $this.device_uuid = [guid]::Empty}         
        $this.device_uuid           = $object.device_uuid
        $this.dsm_model             = $object.dsm_model            
        $this.dsm_unique            = $object.dsm_unique           
        $this.host_ip               = $object.host_ip              
        $this.host_name             = $object.host_name            
        $this.host_port             = $object.host_port            
        $this.hypervisor_id         = $object.hypervisor_id   
        $this.inventory_id          = $object.inventory_id         
        $this.login_password        = $object.login_password       
        if([int]$object.login_time) {$this.login_time = ([datetime]"1970-01-01").AddSeconds($object.login_time).ToLocalTime()} 
        $this.login_user            = $object.login_user           
        $this.login_user_id         = $object.login_user_id        
        $this.os_name               = $object.os_name              
        $this.script                = $object.script               
        $this.vm_moid_path          = $object.vm_moid_path
        $this.last_result           = $object.last_result        
    }
    [String]ToString () {
        return $this.host_name
    }
}

class ABScript
{
    [int]$device_id
    [bool]$enabled
    [int]$id
    [String]$post_script_path
    [String]$pre_script_path
    [ABScriptExecMode]$script_exec_mode
    [ABOSType]$script_os_type
    [int]$task_id
    [String]$vm_moid_path
    [String]ToString () {
        if ($this.enabled)
        {
            return "Enabled"
        }
        return "Disabled"
    }
}

class ABVersion
{
    [int]$crypto_key_id
    [nullable[ABDataFormat]]$data_format
    [String]$folder_name
    [bool]$is_snapshot
    [bool]$locked
    [String]$share_name
    [nullable[ABVersionStatus]]$status
    [nullable[bool]]$storage_compressed
    [nullable[bool]]$storage_encrypted
    [nullable[int]]$task_id
    [String]$task_name
    [datetime]$time_end
    [datetime]$time_start
    [int]$used_size
    [int]$version_id
    ABVersion ([PSCustomObject]$object)
    {
        $this.crypto_key_id      = $object.crypto_key_id
        $this.data_format        = $object.data_format  
        $this.folder_name        = $object.folder_name  
        $this.is_snapshot        = $object.is_snapshot  
        $this.locked             = $object.locked       
        $this.share_name         = $object.share_name
        $this.status             = $object.status
        $this.storage_compressed = $object.storage_compressed
        $this.storage_encrypted  = $object.storage_encrypted
        $this.task_id            = $object.task_id
        $this.task_name          = $object.task_name       
        $this.time_end           = ([datetime]"1970-01-01").AddSeconds($object.time_end).ToLocalTime()    
        $this.time_start         = ([datetime]"1970-01-01").AddSeconds($object.time_start).ToLocalTime()
        $this.used_size          = $object.used_size    
        $this.version_id         = $object.version_id
    }
    [String]ToString () {
        return "$($this.status):$($this.time_end)"
    }
}


###################################### Enums ##################################

enum ABStatus
{
    ALL = -1
    BACKINGUP = 1
    WAITING
    DELETING
    UNSCHEDULED
}

enum ABJobStatus
{
    NONE = 0
    WAITING_TASK
    WAITING_STORAGE
    RUNNING 
    STOPPING
    DELEGATE = 8
 }

 enum ABJobStage
 {
    NONE = 0
    PRE_ACTION
    DO_SUBJOB
    POST_ACTION
}

enum ABJobSubStatus
{
    NONE = 0
    REMOVING_EXPIRED_CBT
    WAITING_LAUNCH_NEXTBACKUP
}

enum ABAgentRunningTaskStatus
{
    WAITING = 0
    RUNNING
    PAUSING
    CANCELING
}

enum ABAgentRunningTaskDetailStatus
{
    NONE = 0
    WAITING_TASK
    WAITING_STORAGE
    WAITING_DEVICE
    WAITING_PREPARING
    PAUSING_MANUAL
    PAUSING_OFFLINE
    PAUSING_BACKUP_WINDOW
}
 
[Flags()]enum ABDataFormat
{
    NONE = 0
    DEDUP = 1
    CBT = 2
    CBT_NEED_DEDUP = 4
}
enum ABHostType
{
    NONE = 0
    ESXi
    vCenter
    HyperV
    SystemCenter
    SCVMM
    FailoverCluster
}

enum ABRetentionType
{
    KEEP_ALL = 1
    APPLY_POLICY
    KEEP_VERSIONS
    KEEP_DAYS
    ADVANCE
}

enum ABVersionStatus
{
    BACKING_UP = 0
    DELETING
    PAUSED
    COMPLETED
    FAILED
    PARTIAL
    CANCELED
    DELETE_FAILED
    CLONING
    WAITING_CONNECTION = 777
}

enum ABLogLevel
{
    ALL = -1
    ERROR = 0
    WARNING
    INFO
    DEBUG
}
enum ABResultStatus
{
    NONE = 0
    INCOMPLETE
    SUCCESS
    PARTIAL_SUCCESS
    FAILURE
    CANCEL
}

enum ABBackupType
{
    ALL = -1
    NONE = 0
    VM
    PC
    SERVER
    AGENTLESS
    DSM
}

enum ABSourceType
{
    NONE = 0
    BARE_METAL
    SYSVOL
    CUSVOL
}

enum ABStorageCompressAlgorithm
{
    NONE = 0
    LZ4
    NOT_SET = 255
}

enum ABStorageEncryptAlgorithm
{
    NONE = 0
    X25519
    NOT_SET = 255
}

enum ABAgentlessBackupPolicy
{
    INCREMENTAL = 0
    MIRROR
    VERSION
}

enum ABEnableCbtMode
{
    DISABLE = 0
    AUTO
}

[Flags()]enum ABScheduleSettingType
{
    NONE = 0
    SCHEDULE = 1
    EVENT = 2
    CONTINUOUS = 4
}

enum ABHostGroup
{
    NONE = 0
    VMWare
    HyperV
    VMM
}

enum ABPlatformType
{
    NONE = 0
    WINDOWS
    LINUX
    MAC
    DSM
}

enum ABProtocolType
{
    ALL = 0
    SMB
    RSYNC
}

enum ABScriptExecMode
{
    NONE = 0
    REQUIRED_SUCCESS
    IGNORE_FAILURE
}

enum ABOSType
{
    NONE = 0
    WINDOWS
    LINUX
}

enum ABRestoreType
{
    INSTANT= 0
    FULL
    FILE
    SYSTEM
    CUSTOM
    VMM
}

[Flags()]enum ABJobAction
{
    ALL = -1
    NONE = 0
    BACKUP = 1
    RESTORE_DEVICE = 128
    MIGRATE_DEVICE = 256
    VERIFY = 512
    RESTORE_FILE = 1024
    RESTORE_PHYSICAL = 2048
    DELETE_TARGET = 65536
    DELETE_VERSION = 131072
    DELETE_INVENTORY = 262144
    DEDUP = 1048576
    RELINK = 2097152
    COMPACT = 4194304
    CREATE_TASK = 268435456
}

enum ABWeekDay
{
    SUN = 0
    MON
    TUE
    WED
    THU
    FRI
    SAT
}

enum ABFSType
{
    BTRFS = 3 #Both peta and normal fs is presented as fstype 3 and none other is supported.
}

enum ABTaskType
{
    NONE = 0
    VM = 256
    VM_HyperV = 272
    VM_VMWare = 288
    PC = 512
    PC_WIN = 513
    PC_LINUX = 514
    PC_MAC = 515
    PS = 768
    PS_WIN = 769
    PS_LINUX = 770
    PS_MAC = 771
    FS = 1024
}

enum SynoError
{
    SUCCESS = 0
    UNKNOWN = 100
    INVALID_PARAMETER #101 No parameter of API, method or version.
    INVALID_API #102 The requested API does not exist.PACKAGE_DISABLED:102
    INVALID_METHOD #103 The requested method does not exist.
    UNSUPPORTED_FUNCTIONALITY #104 The requested version does not support the functionality.
    PERMISSION_DENIED #105 The logged in session does not have permission.
    SESSION_TIMEOUT #106 Session timeout.
    DUPLICATE_LOGIN #107 Session interrupted by duplicated login.
    FILE_UPLOAD_FAILED #108 Failed to upload the file.
    CONNECTION_ERROR_1 #109 The network connection is unstable or the system is busy.
    CONNECTION_ERROR_2 #110 The network connection is unstable or the system is busy.
    CONNECTION_ERROR_3 #111 The network connection is unstable or the system is busy.
    ERROR_112 #112 Preserve for other purpose.
    ERROR_113 #113 Preserve for other purpose.
    MISSING_PARAMETER #114 Lost parameters for this API.
    FILE_UPLOAD_DENIED #115 Not allowed to upload a file.
    DEMO #116 Not allowed to perform for a demo site.
    CONNECTION_ERROR_4 #117 The network connection is unstable or the system is busy.
    CONNECTION_ERROR_5# 118 The network connection is unstable or the system is busy.
    INVALID_SESSION #119 Invalid session.
    ERROR_120 #120-149 Preserve for other purpose.
    ERROR_121 #120-149 Preserve for other purpose.
    ERROR_122 #120-149 Preserve for other purpose.
    ERROR_123 #120-149 Preserve for other purpose.
    ERROR_124 #120-149 Preserve for other purpose.
    ERROR_125 #120-149 Preserve for other purpose.
    ERROR_126 #120-149 Preserve for other purpose.
    ERROR_127 #120-149 Preserve for other purpose.
    ERROR_128 #120-149 Preserve for other purpose.
    ERROR_129 #120-149 Preserve for other purpose.
    ERROR_130 #120-149 Preserve for other purpose.
    ERROR_131 #120-149 Preserve for other purpose.
    ERROR_132 #120-149 Preserve for other purpose.
    ERROR_133 #120-149 Preserve for other purpose.
    ERROR_134 #120-149 Preserve for other purpose.
    ERROR_135 #120-149 Preserve for other purpose.
    ERROR_136 #120-149 Preserve for other purpose.
    ERROR_137 #120-149 Preserve for other purpose.
    ERROR_138 #120-149 Preserve for other purpose.
    ERROR_139 #120-149 Preserve for other purpose.
    ERROR_140 #120-149 Preserve for other purpose.
    ERROR_141 #120-149 Preserve for other purpose.
    ERROR_142 #120-149 Preserve for other purpose.
    ERROR_143 #120-149 Preserve for other purpose.
    ERROR_144 #120-149 Preserve for other purpose.
    ERROR_145 #120-149 Preserve for other purpose.
    ERROR_146 #120-149 Preserve for other purpose.
    ERROR_147 #120-149 Preserve for other purpose.
    ERROR_148 #120-149 Preserve for other purpose.
    ERROR_149 #120-149 Preserve for other purpose.
    IP_MISMATCH = 150 #150 Request source IP does not match the login IP.
    INCORRECT_CREDENTIALS = 400 #400 No such account or incorrect password.
    ACCOUNT_DISABLED #401 Disabled account.
    LOGIN_DENIED #402 Denied permission.
    MF_CODE_REQUIRED #403 2-factor authentication code required.
    MF_FAILED #404 Failed to authenticate 2-factor authentication code.
    MF_UNKNOWN
    MF_ENFORCED #406 Enforce to authenticate with 2-factor authentication code.
    IP_BLOCKED #407 Blocked IP source.
    PASSWORD_EXPIRED_CANNOT_CHANGE #408 Expired password cannot change.
    PASSWORD_EXPIRED #409 Expired password.
    CHANGE_PASSWORD #410 Password must be changed.
    INTERNAL_ERROR = 1001
    ERR_USER_INFO_UNAVAILABLE = 1002
    TEMPLATE_TARGET_NOT_EXIST = 1003
    DOMAIN_CONNECTION_FAILED = 1004
    LDAP_CONNECTION_FAILED = 1005
    UPGRADE_INITIALIZING = 1006
    UPGRADE_RUNNING = 1007
    UPGRADE_FAIL = 1008
    BATCH_ERROR = 1009
    NO_TASK_EXIST = 1010
    NO_TASK_PERMISSION = 1011
    REASON_DATA_CORRUPT = 1012
    REASON_IO_ERR = 1013
    REASON_NO_PERM = 1014
    REASON_NO_QUOTA = 1015
    REASON_NO_SPACE = 1016
    REASON_READONLY_FS = 1017
    DATABASE = 1018
    REASON_NO_SPACE_SYSTEM = 1019
    REASON_NO_QUOTA_SYSTEM = 1020
    NOT_SUPPORT_ACL = 1021
    FOLDER_NOT_EXISTS_BY_VERSION = 1022
    REASON_NO_TARGET_FOLDER = 1023
    ACTIVATION_FAIL = 1024
    UPGRADE_FAIL_REASON_SHARE_UNMOUNT = 1025
    STORAGE_ALREADY_EXISTED = 1026
    OLD_VERSION_STORAGE_ALREADY_EXISTED = 1027
    CONNECT_SERVER_FAIL = 1028
    STORAGE_REMOVE_TASK_RUNNING = 1029
    STORAGE_NOT_SUPPORT_NEWER_VERSION = 1030
    WEBAPI_TIMEOUT = 1031
    STORAGE_UNMOUNT_WHEN_RESTORING = 1032
    TEMPLATE_SHARE_NOT_EXIST = 1033
    ERROR_LONG_PATH = 1034
    SYSLOG_CONFIG_INVALID = 1035
    NO_DELEGATION_PERMISSION = 1036
    TASK_WITH_LOCKED_VERSION_REMOVE_FAIL = 1101
    MODIFY_SOURCE_WHEN_BACKUP_TASK = 1102
    TASK_VERSION_OR_DEVICE_NOT_EXIST = 1103
    TASK_BACKUP_WINDOW_NO_ALLOWED = 1104
    TASK_BACKUP_WINDOW_DENYING = 1105
    JOB_NOT_FOUND = 1201
    JOB_CONFLICT = 1202
    JOB_RESOURCE_LOCKED = 1203
    JOB_RESOURCE_BACKUP_LOCKED = 1204
    JOB_RESOURCE_RESTORE_LOCKED = 1205
    JOB_RESOURCE_DELETE_LOCKED = 1206
    JOB_CONFLICT_VERIFY_EXIST = 1207
    JOB_CONFLICT_DELETE_EXIST = 1208
    JOB_FORBIDDEN = 1209
    JOB_VERSION_RESOURCE_DELETE_LOCKED = 1210
    JOB_REASON_STORAGE_READONLY = 1250
    JOB_REASON_STORAGE_BROKEN = 1251
    JOB_REASON_STORAGE_ENCRYPTION = 1252
    JOB_REASON_VMM_CONFLICT_DELETE_TARGET = 1253
    JOB_REASON_VMM_CONFLICT_DELETE_VERSION = 1254
    JOB_REASON_ENCRYPTED_STORAGE_MOUNT = 1255
    IMAGE_NODE_LIST_ERROR = 1301
    FS_TYPE_NOT_SUPPORTED = 1302
    FILE_TYPE_NOT_SUPPORT = 1303
    FS_TYPE_SFS_NOT_SUPPORTED = 1304
    FS_FEATURE_NOT_SUPPORTED = 1305
    IMAGE_NODE_LIST_TOO_MANY_FILES = 1306
    DEDUP_FILE_NOT_SUPPORT = 1307
    RELINK_DATA_CORRUPT = 1401
    RELINK_NO_ENOUGH_SPACE = 1402
    RELINK_PERMISSION_DENIED = 1403
    MOUNT_DIR_EXIST = 1501
    FS_ILLEGAL_SSH_KEY_NO_PASSPHRASE = 1601
    FS_AUTH_SSH_KEY = 1602
    STORAGE_NOT_VERIFIED = 1701
    STORAGE_VERIFY_FAIL_PASSWORD = 1702
    STORAGE_VERIFY_FAIL_PRIVATE_KEY = 1703
    LICENSE_PUBLIC_BETA = 2e3
    LICENSE_GET_INFO_FAIL = 2002
    VM_CONNECTION_FAIL = 3001
    VM_AUTHENTICATION_FAIL = 3002
    VM_SEND_REQUEST_FAIL = 3003
    HOST_ALREADY_EXIST = 3004
    FREE_LICENSE_ESXI_NEED_SSH_CONNECT = 3005
    VM_UNKNOWN_HOST_TYPE = 3006
    VM_REMOVE_INVENTORY_FAIL = 3007
    FIELD_NOT_EXIST = 3008
    VMTOOL_NOT_INSTALLED = 3009
    VDDK_PORT_UNAVAILABLE = 3010
    VM_INVENTORY_THUMBPRINT_MISMATCH = 3011
    VM_REMOVE_INVENTORY_CONFLICT = 3012
    NAS_ADDR_PORT_UNAVAILABLE = 3013
    ISCSI_SERVICE_NOT_RUNNING = 3014
    WINRM_PORT_NOT_AVAILABLE = 3015
    SAMBA_MOUNT_FAIL_DSM_6_1 = 3016
    WINRM_CONNECTION_FAIL = 3017
    WINRM_UNKNOWN_PROTOCOL = 3018
    UNKNOWN_CERT_ISSUER = 3019
    CERT_EXPIRED = 3020
    CERT_SUBJECT_NAME_NOT_MATCH = 3021
    VM_INVENTORY_CERT_VERIFY_FAIL = 3022
    VM_INVENTORY_CERT_VERIFY_FAIL_DETAIL = 3023
    HYPERV_SAMBA_NOT_ENABLE = 3024
    HYPERV_SHARE_NOT_ENABLE = 3025
    HYPERV_SAMBA_MOUNT_FAIL = 3026
    HYPERV_SCRIPT_NOT_ENABLE = 3027
    HYPERV_ACCOUNT_NO_DOMAIN = 3028
    HYPERV_INCOMPATIBLE_VERSION = 3029
    VM_INVENTORY_UNAUTHENTICATION = 3030
    VM_REMOVE_INVENTORY_FAIL_VMM_CONFLICT = 3031
    HYPERV_SERVICE_NOT_ENABLED = 3032
    HYPERV_FAILOVER_CLUSTER_SERVICE_NOT_ENABLED = 3033
    HYPERV_SCVMM_SERVICE_NOT_ENABLED = 3034
    HYPERV_CLUSTER_IP_MISMATCH = 3035
    HYPERV_USE_CLUSTER_AS_STANDALONE = 3036
    HYPERV_CHILD_NODES_NOT_ENABLED = 3037
    INVALID_CLUSTER_SHARED_VOLUME = 3038
    HYPERV_POWERSHELL_NOT_ENABLED = 3039
    SCVMM_INCOMPATIBLE_VERSION = 3040
    VM_CBT_FREE_LICENSE_ERROR = 3041
    VM_EXEC_SCRIPT_NO_VMTOOL_ERROR = 3042
    PCI_PASSTHROUGH = 3043
    VM_VIRTUAL_DISK_NOT_FOUND = 3044
    SNAPSHOT_NO_CBT_OFF = 3045
    SESSION_JOB_NOT_EXIST = 3046
    REMOVE_STORAGE_BUSY = 3047
    VM_NOT_FOUND = 3048
    HYPERV_SERVICE_NOT_ENABLED_v2 = 3049
    WRITE_OVER_IMAGE_4K_SIZE = 3050
    HYPERVISOR_ACCOUNT_ACCESS_DENIAL = 3051
    HYPERV_VIRTUAL_DISK_NOT_FOUND = 3052
    INVALID_PARAMETERS = 3103 #??
    UNKNOWN_ERROR_3106 = 3106
    REASON_GUEST_OS = 3500
    VERIFICATION_NOT_SUPPORT_OS = 3600
    VERIFICATION_NOT_SUPPORT_BIOS = 3601
    SERVER_USED = 4001
    FS_FOLDER_USED = 4002
    TASK_NAME_USED = 4003
    RESTORE_CONFLICT = 4004
    TASK_BACKUP_CONFLICT = 4005
    RESTORE_ANOTHER_EXIST = 4006
    TASK_ANOTHER_BACKUP_EXIST = 4007
    FS_AUTH = 4008
    SSL_VERIFY = 4009
    SERVER = 4010
    TIME_OUT = 4011
    FS_INTERNET = 4012
    FS_SERVER_OFFLINE = 4013
    FS_SERVER_DISABLE = 4014
    SERVER_INVALID_OPTION = 4015
    SERVER_DENY_IP = 4016
    CONNECTION_ABORT = 4017
    NO_ROUTE_TO_HOST = 4018
    CONNECTION_REFUSED = 4019
    FS_TEST_CONNECTION_FAILED = 4020
    FS_SSL_CONNECTION_REFUSED = 4021
    FS_COULDNOT_RESOLVE_HOST = 4022
    FS_OPERATION_NOT_SUPPORT = 4023
    OPERATION_NOT_SUPPORT = 4024
    FILE_NOT_SUPPORT = 4025
    FOLDER_INVALID = 4026
    FS_LOCAL_BKPFOLDER_NOT_FOUND = 4027
    FS_SHARE_UNMOUNT = 4028
    FS_SHARE_FOLDER_TYPE = 4029
    FS_FOLDER_NO_PERMISSION = 4030
    VSS_NOT_SUPPORTED_OPERATION = 4031
    FS_LOCAL_NO_SPACE = 4032
    FS_LOCAL_NOT_FOUND = 4033
    FS_LOCAL_NO_PERMISSION = 4034
    FS_SERVER_NO_SPACE = 4035
    FS_SERVER_BKPFOLDER_NOT_FOUND = 4036
    FS_SERVER_NOT_FOUND = 4037
    FS_SERVER_NO_PERMISSION = 4038
    FS_VSS_NOT_FOUND = 4039
    FS_VSS_NOT_SUPPORTED_OPERATION = 4040
    FS_VSS_BAD_STATE = 4041
    FS_NOT_SUPPORT_ACLS = 4042
    FS_NOT_SUPPORT_XATTRS = 4043
    FS_RSYNC_COMMAND_NOT_FOUND = 4044
    FS_UNABLE_CONNECT_TO_DAEMON = 4045
    FS_UNKNOWN_MODULE = 4046
    INVALID_DESTINATION_PATH = 4047
    FS_VSS_VOLUME_IS_NOT_SUPPORTED = 4048
    FS_NOT_SUPPORTED_DESTINATION_FILESYSTEM_TYPE = 4049
    FS_RSYNC_PROTOCOL_INCOMPATIBLE = 4050
    PETA_VOLUME_NOT_SUPPORT = 4051
    FS_NO_MATCHING_CIPHER = 4052
    FS_SERVER_OPERATION_NOT_PERMMITED = 4053
    INVALID_DESTINATION_PHOTO_STR = 4054
    FS_NETWORK_DROPPED_CONNECTION = 4055
    DEVICE_OFFLINE = 5001
    DOWNLOAD_INSTALLER_FAILED = 5002
    DEVICE_IS_DELETING = 5003
    GET_URL_FAILED = 5004
    CONNECTION_EXISTED = 6001
    NO_CONNECTION = 6002
    SET_RBD_FAILED = 6003
    ERR_USER_PASSWD = 6004
    ERR_USER_NO_PRIVILEGE = 6005
    ERR_USER_RENAME = 6006
    ERR_QUOTA = 6007
    ERR_DISKFULL = 6008
    ERR_CREATE_TASK = 6009
    ERR_CREATE_TASK_INTERNAL = 6010
    ERR_CREATE_TASK_SHARE = 6011
    ERR_CONNECT_DIFFERENT_SERVER = 6012
    ERR_DEVICE_REMOVED = 6013
    ERR_INVALID_OTP = 6014
    ERR_OTP_ENFORCE = 6015
    ERR_SERVICE_OFFLINE = 6016
    ERR_USER_EXPIRED = 6017
    ERR_IP_NOT_ALLOW = 6018
    ERR_VERSION = 6019
    ERR_VERSION_TOO_LOW = 6020
    ERR_MAX_TRIES = 6021
    ERR_SSL_VERIFY_FAIL = 6022
    ERR_SSL_CHANGE = 6023
    ERR_SSL_HOSTNAME = 6024
    ERR_TARGET_STORAGE_NEWER = 6025
    ERR_TARGET_STORAGE_OLDER = 6026
    ERR_CONNECTION = 6027
    ERR_DISK_NOT_AVAILABLE = 6028
    ERR_DISK_LAYOUT_TYPE = 6029
    ERR_NOT_SUPPORT_PETAVOLUME = 6030
    ERR_FORBID_V8_RESTORE_V9 = 6031
    SET_DELEGATION_RULE_FAILED = 6501
    DELETE_DELEGATION_RULE_FAILED = 6502
    UNKNOW = 9999
}

enum ABErrorCode
{
    ERR_OK = 0
    ERR_INT = -1
    ERR_IO = -2
    ERR_SYS = -3
    ERR_INVALID = -4
    ERR_SSL_VERIFY_FAIL = -11
    ERR_AUTH = -12
    ERR_SERVER = -13
    ERR_TIMEOUT = -14
    ERR_NET_UNSTABLE = -15
    ERR_SERVER_OFFLINE = -16
    ERR_SERVER_DISABLE = -17
    ERR_SERVER_INVALID_OPTION = -18
    ERR_SERVER_DENY_IP = -19
    ERR_CONNECTION_ABORTED = -20
    ERR_NO_ROUTE_TO_HOST = -21
    ERR_CONNECTION_REFUSED = -22
    ERR_TEST_CONNECTION_FAILED = -23
    ERR_SSL_CONNECTION_REFUSED = -24
    ERR_COULDNOT_RESOLVE_HOST_NAME = -25
    ERR_SSH_KEY = -26
    ERR_NO_MATCHING_CIPHER = -28
    ERR_NETWORK_DROPPED_CONNECTION = -29
    ERR_OPERATION_NOT_SUPPORT = -31
    ERR_FILE_NOT_SUPPORT = -32
    ERR_ANOTHER_RESTORE_TASK = -33
    ERR_TASK_BACKUP_CONFLICT = -34
    ERR_TASK_RESTORE_CONFLICT = -35
    ERR_ANOTHER_BACKUP_TASK = -36
    ERR_ONLY_TRANSMITTED_PART_FILES = -37
    ERR_SET_ATTR = -38
    ERR_FILE_NAME_TOO_LONG = -39
    ERR_LOCAL_NO_SPACE = -41
    ERR_LOCAL_BKPFOLDER_NOT_FOUND = -42
    ERR_LOCAL_EXISTS = -43
    ERR_LOCAL_FILE_NOT_FOUND = -44
    ERR_LOCAL_NO_PERMISSION = -45
    ERR_LOCAL_NOT_DIR = -46
    ERR_LOCAL_IS_DIR = -47
    ERR_LOCAL_SHARE_UNMOUNTED = -48
    ERR_LOCAL_QUOTA_NOT_ENOUGH = -49
    ERR_LOCAL_READONLY_FS = -50
    ERR_SERVER_BKPFOLDER_NOT_FOUND = -61
    ERR_SERVER_NO_SPACE = -62
    ERR_SERVER_FILE_NOT_FOUND = -63
    ERR_SERVER_EXISTS = -64
    ERR_SERVER_NO_PERMISSION = -65
    ERR_SERVER_NOT_DIR = -66
    ERR_SERVER_IS_DIR = -67
    ERR_SERVER_DEVICE_RESOURCE_BUSY = -68
    ERR_SERVER_OPERATION_NOT_PERMMIT = -69
    ERR_SERVER_IO = -70
    ERR_VSS_NOT_FOUND = -71
    ERR_VSS_NOT_SUPPORTED_OPERATION = -72
    ERR_VSS_CREATE_STORAGE_FULL = -73
    ERR_VSS_BAD_STATE = -74
    ERR_VSS_ANOTHER_VSS_ALREADY_RUNNING = -75
    ERR_VSS_OPERATION_TIMEOUT = -76
    ERR_NOT_SUPPORT_ACLS = -80
    ERR_NOT_SUPPORT_XATTRS = -81
    ERR_RSYNC_COMMAND_NOT_FOUND = -82
    ERR_UNABLE_CONNECT_TO_DAEMON = -83
    ERR_UNKNOWN_MODULE = -84
    ERR_RSYNC_CONF_INVALID_UID = -85
    ERR_RSYNC_CONF_INVALID_GID = -86
    ERR_TASK_EXECUTION_FAILED = -91
    ERR_FAILED_VERIFICATION_UPDATE_DISCARD = -95
    ERR_READ_FILE = -100
    ERR_WRITE_FILE = -101
    ERR_SET_ACL = -102
    ERR_MAX = -200
}

enum ABLogMessageId
{
    TASK_CREATED = 1001
    TASK_REMOVED = 1002
    TASK_PAUSED = 1003
    TASK_RESUME = 1004
    TASK_EDIT_RENAME = 1005
    TASK_EDIT_BANDWIDTH = 1006
    TASK_EDIT_SCHEDULE_ON = 1007
    TASK_EDIT_SCHEDULE_OFF = 1008
    LOG_DELETE_ALL = 1009
    LOG_SET_RETENTION = 1010
    LOG_DISABLE_RETENTION = 1011
    DELEGATION_CREATE = 1012
    DELEGATION_UPDATE = 1013
    DELEGATION_DELETE = 1014
    TASK_START = 1101
    TASK_FINISH = 1102
    TASK_CANCEL = 1103
    TASK_ERROR = 1104
    TASK_WARNING = 1105
    TASK_BACKUP_CONFLICT = 1106
    TASK_ANOTHER_BACKUP_EXIST = 1107
    TASK_PARTIAL_SUCCESS = 1108
    VM_SPEED_INFO = 1110
    AGENT_SPEED_INFO = 1111
    TASK_VERIFY_EXIST = 1112
    TASK_EXPORT_CONFIG_FAIL = 1113
    TASK_DELETE_EXIST = 1114
    TASK_START_BY_EVENT = 1115
    TASK_FORBIDDEN = 1116
    TASK_FORBIDDEN_COPY = 1117
    TASK_DEDUP_ERROR = 1118
    TASK_DEDUP_CANCEL = 1119
    TASK_DEDUP_PARTIAL_SUCCESS = 1120
    DEDUP_SPEED_INFO = 1121
    TASK_DEDUP_START = 1122
    TASK_DEDUP_FINISH = 1123
    TASK_IGNORED_BY_BACKUP_WINDOW = 1124
    TASK_CANCEL_DEVICE_OFFLINE = 1125
    TASK_CANCEL_CACHE_UPLOAD = 1126
    TASK_BACKUP_WINDOW_START_ALLOW = 1127
    TASK_BACKUP_WINDOW_START_DENY = 1128
    AGENT_CONTINUOUS_CBT_SPEED_INFO = 1129
    TASK_CANCEL_DEDUP_FAIL = 1130
    TASK_FINISH_CBT_VERSION = 1131
    TASK_PAUSED_BY_BACKUP_WINDOW = 1132
    TASK_RESUMED_BY_BACKUP_WINDOW = 1133
    TASK_DEDUP_NOVERSION_START = 1134
    TASK_DEDUP_NOVERSION_ERROR = 1135
    TASK_PARTIAL_SUCCESS_CBT_VERSION = 1136
    TASK_SAME_BACKUP_EXIST = 1137
    TASK_UNEXPECTED_STOP = 1138
    VM_SPEED_INFO_V2 = 1139
    VM_SPEED_INFO_V3 = 1140
    VM_CONSOLIDATE_START = 1141
    VM_CONSOLIDATE_SUCCESS = 1143
    VM_CONSOLIDATE_ERROR = 1144
    TASK_CANCELLED_BY_BACKUP_WINDOW = 1145
    TASK_MISS_SCHEDULED = 1146
    RESTORE_START = 1201
    RESTORE_CANCEL = 1202
    RESTORE_FINISH = 1203
    RESTORE_ERROR = 1204
    RESTORE_WARNING = 1205
    RESTORE_CONFLICT = 1206
    RESTORE_ANOTHER_EXIST = 1207
    RESTORE_PARTIAL_SUCCESS = 1208
    RESTORE_TASK_NOT_FOUND = 1209
    RESTORE_TASK_VERSION_NOT_FOUND = 1210
    RESTORE_TASK_GET_USED_BLOCK_FAIL = 1211
    VM_INSTANT_RESTORE_PAUSE = 1212
    VM_INSTANT_RESTORE_RESUME = 1213
    VM_INSTANT_RESTORE_RESUME_FAIL = 1214
    RESTORE_CANCEL_DEVICE_OFFLINE = 1215
    TASK_VERSION_ROTATE = 1301
    TASK_VERSION_DELETE_START = 1302
    TASK_VERSION_DELETE_FINISH = 1303
    TASK_VERSION_DELETE_ERROR = 1304
    TASK_TARGET_DELETE_START = 1305
    TASK_TARGET_DELETE_FINISH = 1306
    TASK_TARGET_DELETE_ERROR = 1307
    TASK_VERSION_ROLLBACK = 1308
    REMOVE_SERVER_START = 1309
    REMOVE_SERVER_COMPLETED = 1310
    REMOVE_SERVER_FAILED = 1311
    REMOVE_VM_IN_TASK_START = 1312
    REMOVE_VM_IN_TASK_FINISH = 1313
    REMOVE_VM_IN_TASK_FAILED = 1314
    REMOVE_VM_NAME_IN_TASK = 1315
    RETENTION_DELETE_FAILED_BEING_RESTORED = 1316
    RETENTION_DELETE_FAILED_BEING_DELETED = 1317
    RETENTION_DELETE_FAILED_UNKNOWN_ERROR = 1318
    RETENTION_DELETE_FAILED_FORBIDDEN = 1319
    REMOVE_SERVER_START_GENERAL = 1320
    REMOVE_SERVER_COMPLETED_GENERAL = 1321
    REMOVE_SERVER_FAILED_GENERAL = 1322
    TASK_VERSION_DELETE_MISSING = 1323
    TASK_VERSION_DELETE_RESULT_PARTIAL_SUCCESS = 1324
    TASK_VERSION_DELETE_RESULT_FINISH = 1325
    TASK_VERSION_DELETE_RESULT_ERROR = 1326
    TASK_VERSION_DELETE_START_V2 = 1327
    TASK_VERSION_DELETE_FINISH_V2 = 1328
    TASK_VERSION_DELETE_ERROR_V2 = 1329
    RETENTION_DELETE_FAILED_BEING_RESTORED_V2 = 1330
    RETENTION_DELETE_FAILED_BEING_DELETED_V2 = 1331
    RETENTION_DELETE_FAILED_UNKNOWN_ERROR_V2 = 1332
    RETENTION_DELETE_FAILED_FORBIDDEN_V2 = 1333
    TASK_VERSION_DELETE_NOPERM_V2 = 1334
    TASK_VERSION_DELETE_IOERROR_V2 = 1335
    TASK_VERSION_DELETE_NOSPACE_V2 = 1336
    TASK_VERSION_DELETE_DATACORRUPT_V2 = 1337
    TEMPLATE_CREATE = 1401
    TEMPLATE_REMOVE = 1402
    TEMPLATE_EDIT = 1403
    TEMPLATE_EDIT_RENAME = 1404
    JOBQUEUE_DOWN = 1501
    JOB_REASON_STORAGE_READONLY = 1550
    JOB_REASON_STORAGE_BROKEN = 1551
    JOB_REASON_STORAGE_ENCRYPTION = 1552
    JOB_FORBIDDEN = 1553
    JOB_REASON_VMM_CONFLICT_DELETE_TARGET = 1554
    JOB_REASON_VMM_CONFLICT_DELETE_VERSION = 1555
    JOB_REASON_ENCRYPTED_STORAGE_MOUNT = 1556
    LICENSE_PUBLIC_BETA = 1602
    VERIFICATION_VMM_NOT_INSTALLED = 1701
    VERIFICATION_VMM_NOT_SUPPORTED = 1702
    VERIFICATION_VMM_NO_CLUSTER = 1703
    VERIFICATION_CREATE_IMAGES_ERROR = 1704
    VERIFICATION_CREATE_VIDEO_ERROR = 1705
    VERIFICATION_START = 1706
    VERIFICATION_SUCCESS = 1707
    VERIFICATION_PARTIAL_SUCCESS = 1708
    VERIFICATION_ERROR = 1709
    VERIFICATION_CANCEL = 1710
    VERIFICATION_REPORT_SUCCESS = 1711
    VERIFICATION_VMM_NO_SAME_VOLUME = 1712
    VERIFICATION_MOUNT_TEST_ERROR = 1713
    VERIFICATION_DSM_NOT_SUPPORTED = 1714
    VERIFICATION_ACTIVATE_CODEC_ERROR = 1715
    VERIFICATION_VMM_NO_VOLUME = 1716
    VERIFICATION_USE_DEFAULT_VIDEO_CARD = 1717
    VERIFICATION_NEED_MOUNT_STORAGE = 1718
    VERIFICATION_NOT_SUPPORT_OS = 1719
    VERIFICATION_NOT_SUPPORT_BIOS = 1720
    VERIFICATION_IMG_MOUNT_TEST_FAILED = 1780
    VMM_WEBAPI_ERROR = 1801
    VMM_WEBAPI_ERROR_POWERON_GUEST = 1802
    VMM_WEBAPI_ERROR_POWEROFF_GUEST = 1803
    VMM_WEBAPI_ERROR_POWERON_GUEST_SEL_HOST = 1804
    VMM_WEBAPI_ERROR_TASK_Q_REACH_MAX = 1805
    MOUNT_DIR_EXIST = 1901
    SHARE_DELETED = 2001
    SHARE_PATH_CHANGED = 2002
    SHARE_RENAME = 2003
    RELINK_TARGET_FINISH = 2004
    RELINK_TARGET_ERROR = 2005
    RELINK_DATA_CORRUPT = 2006
    RELINK_NO_ENOUGH_SPACE = 2007
    RELINK_PERMISSION_DENIED = 2008
    RELINK_TARGET_FINISH_V2 = 2009
    RELINK_TARGET_FOLDER_NOT_FOUND = 2010
    VM_CBT_ENABLE = 3001
    VM_CBT_ENABLE_ERROR = 3002
    VM_SNAPSHOT_TAKE = 3003
    VM_SNAPSHOT_TAKE_ERROR = 3004
    VM_SNAPSHOT_REMOVE = 3005
    VM_SNAPSHOT_REMOVE_ERROR = 3006
    VM_EXEC_SCRIPT_NOT_ALLOWED = 3007
    INCOMPATIBLE_VM_VERSION = 3008
    VM_AUTHENTICATION_FAIL = 3009
    VM_EXEC_SCRIPT_PATH_NOT_FOUND = 3010
    VM_EXEC_SCRIPT_ERROR = 3011
    VM_SNAPSHOT_TAKE_QUIESCE_ERROR = 3012
    VM_BACKUP_SPEC = 3013
    VM_BACKUP_DISK = 3014
    VM_RESTORE_NFS_MOUNT_ERROR = 3015
    VM_RESTORE_NFS_SERVICE_ERROR = 3016
    VM_BACKUP_START = 3017
    VM_BACKUP_FINISH = 3018
    VM_BACKUP_ERROR = 3019
    VM_BACKUP_CANCEL = 3020
    VM_RESTORE_START = 3021
    VM_RESTORE_FINISH = 3022
    VM_RESTORE_ERROR = 3023
    VM_RESTORE_CANCEL = 3024
    VM_MIGRATE_START = 3025
    VM_MIGRATE_FINISH = 3026
    VM_MIGRATE_PARTIAL_SUCCESS = 3027
    VM_MIGRATE_ERROR = 3028
    VM_MIGRATE_CANCEL = 3029
    VM_MIGRATE_VM_START = 3030
    VM_MIGRATE_VM_FINISH = 3031
    VM_MIGRATE_VM_ERROR = 3032
    VM_MIGRATE_VM_CANCEL = 3033
    VM_EXEC_PRE_SCRIPT = 3034
    VM_EXEC_PRE_SCRIPT_IGNORE_FAILURE = 3035
    VM_EXEC_PRE_SCRIPT_ERROR = 3036
    VM_EXEC_POST_SCRIPT = 3037
    VM_EXEC_POST_SCRIPT_IGNORE_FAILURE = 3038
    VM_EXEC_POST_SCRIPT_ERROR = 3039
    VM_EXEC_SCRIPT_NO_VMTOOL_ERROR = 3040
    VM_EXEC_SCRIPT_UPLOAD_ERROR = 3041
    VM_EXEC_SCRIPT_NO_RETURN_ERROR = 3042
    VM_RESTORE_LOAD_RECORDS = 3043
    VM_RESTORE_CREATE_NFS_FOLDER = 3044
    VM_RESTORE_FILE_TRANSFER = 3045
    VM_RESTORE_VM_POWER_ON = 3046
    VM_RESTORE_VM_REGISTER = 3047
    VM_RESTORE_VM_CREATE_FOLDER = 3048
    VM_RESTORE_VM_CREATE_DATASTORE = 3049
    VM_RESTORE_VM_REMOVE_CONFLICT = 3050
    VM_TASK_CREATED = 3051
    VM_TASK_REMOVED = 3052
    FREE_LICENSE_ESXI_NEED_SSH_CONNECT = 3053
    VM_CONNECTION_FAIL = 3054
    VM_ENTITY_NOT_FOUND = 3055
    VM_SEND_REQUEST_FAIL = 3056
    VM_DO_FULL_BACKUP = 3057
    VM_DO_FULL_BACKUP_FREE_LICENSE = 3058
    VM_RESTORE_CREATE_DISK_TIMEOUT = 3059
    VM_RESTORE_GUEST_NOT_ENOUGH_SPACE = 3061
    ADD_SERVER_COMPLETED = 3062
    VM_BACKUP_DATASTORE_NOT_ENOUGH_SPACE = 3063
    VM_RESTORE_STOP_WAIT_MIGRATION = 3064
    VMTOOL_NOT_INSTALLED = 3065
    VM_SKIP_NOT_SUPPORTED_DISK_FIRST_TIME = 3066
    VM_SKIP_NOT_SUPPORTED_DISK = 3067
    VM_SKIP_NOT_SUPPORTED_DISK_ONE = 3068
    VM_TASK_PARTIAL_SUCCESS = 3069
    VM_INVENTORY_THUMBPRINT_MISMATCH = 3070
    VM_SSH_CONNECTION_FAIL = 3071
    VM_RESTORE_OS_NOT_SUPPORT = 3072
    VM_SKIP_NOT_SUPPORTED_DISK_ONE_FIRST_TIME = 3073
    VM_CBT_NOT_SUPPORT = 3074
    VM_CBT_FREE_LICENSE_ERROR = 3075
    VM_CBT_ENABLE_GENERAL = 3076
    VM_CBT_ENABLE_ERROR_GENERAL = 3077
    VM_SKIP_NOT_SUPPORTED_DISK_FIRST_TIME_DISKNAME = 3078
    VM_SKIP_NOT_SUPPORTED_DISK_DISKNAME = 3079
    VM_SKIP_NOT_SUPPORTED_DISK_ONE_FIRST_TIME_DISKNAME = 3080
    VM_SKIP_NOT_SUPPORTED_DISK_ONE_DISKNAME = 3081
    VM_CANCEL_DEDUP_FAIL = 3082
    ISCSI_SERVICE_NOT_RUNNING = 3083
    VM_RESTORE_STOP_WAIT_MIGRATION_GENERAL = 3084
    INCOMPATIBLE_VM_VERSION_GENERAL = 3085
    ADD_SERVER_COMPLETED_GENERAL = 3086
    SNAPSHOT_NUM_REACH_LIMIT = 3087
    WINRM_PORT_NOT_AVAILABLE = 3088
    CONTINUOUS_NEED_CBT = 3089
    SAMBA_MOUNT_FAIL = 3090
    SAMBA_MOUNT_FAIL_DSM_6_1 = 3091
    VM_EXEC_SCRIPT_NO_POWER_ON_ERROR = 3092
    VM_HYPERVISOR_REVERSE_CONNECT_FAIL = 3093
    ISCSI_REVERSE_CONNECTION_FAIL = 3094
    ISCSI_NAT_REVERSE_CONNECTION_FAIL = 3095
    VM_UPLOAD_FILE_ERROR = 3096
    VM_REGISTER_ERROR = 3097
    VM_CREATE_DATASTORE_ERROR = 3098
    VM_CREATE_FOLDER_ERROR = 3099
    VM_CREATE_DISK_ERROR = 3100
    VM_POWER_ON_ERROR = 3101
    WINRM_CONNECTION_FAIL = 3102
    VM_SKIP_NOT_SUPPORTED_DISK_FIRST_TIME_DISKNAME_HYPERV = 3103
    VM_SKIP_NOT_SUPPORTED_DISK_DISKNAME_HYPERV = 3104
    VM_SKIP_NOT_SUPPORTED_DISK_ONE_FIRST_TIME_DISKNAME_HYPERV = 3105
    VM_SKIP_NOT_SUPPORTED_DISK_ONE_DISKNAME_HYPERV = 3106
    WINRM_UNKNOWN_PROTOCOL = 3107
    VM_INVENTORY_CERT_VERIFY_FAIL = 3108
    HYPERV_SAMBA_NOT_ENABLE = 3109
    HYPERV_SHARE_NOT_ENABLE = 3110
    HYPERV_SAMBA_MOUNT_FAIL = 3111
    HYPERV_SCRIPT_NOT_ENABLE = 3112
    SNAPSHOT_NO_CBT = 3113
    VM_DISK_FULL_BACKUP_SIZE_ZERO = 3114
    HYPERV_ACCOUNT_NO_DOMAIN = 3115
    VM_BACKUP_ZERO_DISK = 3116
    VM_API_INVALID_ARGUMENT = 3117
    SNAPSHOT_NO_CBT_OFF = 3118
    HYPERV_INCOMPATIBLE_VERSION = 3119
    VM_INVENTORY_UNAUTHENTICATION = 3120
    WRITE_OVER_IMAGE_SIZE = 3121
    VM_BACKUP_ENCRYPT_WITH_KEY = 3122
    VM_GET_CBT_FAIL = 3123
    HYPERV_SERVICE_NOT_ENABLED = 3124
    HYPERV_FAILOVER_CLUSTER_SERVICE_NOT_ENABLED = 3125
    HYPERV_SCVMM_SERVICE_NOT_ENABLED = 3126
    HYPERV_CLUSTER_IP_MISMATCH = 3127
    HYPERV_USE_CLUSTER_AS_STANDALONE = 3128
    HYPERV_CHILD_NODES_NOT_ENABLED = 3129
    REASON_POWERSHELL = 3130
    HYPERV_POWERSHELL_NOT_ENABLED = 3131
    SCVMM_INCOMPATIBLE_VERSION = 3132
    RESTORE_DEVICE_START = 3133
    RESTORE_DEVICE_FINISH = 3134
    RESTORE_DEVICE_ERROR = 3135
    RESTORE_DEVICE_CANCEL = 3136
    MIGRATE_DEVICE_START = 3137
    MIGRATE_DEVICE_FINISH = 3138
    MIGRATE_DEVICE_ERROR = 3139
    MIGRATE_DEVICE_CANCEL = 3140
    VMM_MIGRATE_CREATE_DISK_TIMEOUT = 3141
    VMM_MIGRATE_POWER_ON = 3142
    VMM_MIGRATE_REGISTER = 3143
    VMM_MIGRATE_CREATE_FOLDER = 3144
    VMM_MIGRATE_CREATE_DATASTORE = 3145
    VMM_MIGRATE_REMOVE_CONFLICT = 3146
    VMM_MIGRATE_FILE_TRANSFER = 3147
    VMM_WEBAPI_ERROR_CLONE_FAIL = 3148
    VMM_WEBAPI_ERROR_CLONE_POWER_ON = 3149
    VM_RESTORE_VM_REGISTER_DOWNGRADE = 3150
    VMM_MIGRATE_REGISTER_DOWNGRADE = 3151
    VMTOOL_NOT_INSTALLED_WHEN_RUNNING_APP_AWARE = 3152
    PCI_PASSTHROUGH = 3153
    VM_VIRTUAL_DISK_NOT_FOUND = 3154
    RESTORE_PHYSICAL_DISK_AS_EMPTY = 3155
    VM_DISK_BACKUP_TRANSFER = 3156
    VM_SNAPSHOT_REMOVE_TIME = 3157
    INSTANT_RESTORE_DEVICE_START = 3158
    INSTANT_RESTORE_DEVICE_FINISH = 3159
    INSTANT_RESTORE_DEVICE_ERROR = 3160
    INSTANT_RESTORE_DEVICE_CANCEL = 3161
    VM_INSTANT_RESTORE_WAIT_MIGRATE = 3162
    CHECK_APP_AWARE_FAILED = 3163
    CHECK_BROKEN_SNAPSHOT_FAILED = 3164
    CHECK_ENABLE_CBT_FAILED = 3165
    CHECK_HYPERVISOR_SSH_SERVICE_FAILED = 3166
    CHECK_PCI_PASSTHROUGH_FAILED = 3167
    CHECK_VM_SCRIPT_FAILED = 3168
    VM_HAS_FULL_BACKUP_CAPABILITY = 3169
    VM_NOT_FOUND = 3170
    WRITE_OVER_IMAGE_4K_SIZE = 3171
    HYPERV_SERVICE_NOT_ENABLED_v2 = 3172
    VM_NO_VALID_BACKUP_DISK = 3173
    VM_BACKUP_DISK_MISSING = 3174
    VM_CBT_RESET_GENERAL = 3175
    VM_UNSTABLE_FULL_BACKUP = 3176
    HYPERV_VIRTUAL_DISK_NOT_FOUND = 3177
    VM_RESTORE_VM_REGISTER_DOWNGRADE_OS = 3178
    VMM_MIGRATE_REGISTER_DOWNGRADE_OS = 3179
    CHECK_DISK_4K_ALIGNED_FAILED = 3180
    HYPERVISOR_ACCOUNT_ACCESS_DENIAL = 3181
    VM_SNAPSHOT_PRODUCTION_CHECKPOINT_FAIL_ERROR = 3182
    VM_SNAPSHOT_TAKE_QUIESCE_FAIL_ERROR = 3183
    REASON_GUEST_OS = 3500
    STORAGE_BUSY = 4001
    STORAGE_CREATE_SUCCESS = 4002
    STORAGE_REMOVE_SUCCESS = 4003
    STORAGE_REMOVE_SUCCESS_V2 = 4004
    STORAGE_NOT_SUPPORT_OLDER_VERSION = 4005
    STORAGE_NOT_SUPPORT_NEWER_VERSION = 4006
    STORAGE_NOT_VERIFIED = 4007
    STORAGE_COMPACT_START = 4008
    STORAGE_COMPACT_SUCCESS = 4009
    STORAGE_COMPACT_FAILED = 4010
    AUTOMOUNT_SUCCESS = 4011
    AUTOMOUNT_DEVICE_NOT_MOUNT = 4012
    AUTOMOUNT_KEY_NOT_EXIST = 4013
    AUTOMOUNT_FAIL = 4014
    AUTOMOUNT_ENABLED = 4015
    DEVICE_CONNECT = 5001
    DEVICE_REMOVE = 5002
    DEVICE_OPEN_VMM = 5003
    DEVICE_EXPORT_VM = 5004
    DEVICE_APPLY_TASK_TEMPLATE = 5005
    DEVICE_OFFLINE = 5006
    DEVICE_LOGOUT = 5007
    DEVICE_PC_OFFLINE = 5010
    DEVICE_NOT_FOUND = 5011
    DEVICE_DEDUP_ERROR = 5012
    DEVICE_DEDUP_CANCEL = 5013
    DEVICE_DEDUP_START = 5014
    DEVICE_DEDUP_SUCCESS = 5015
    DEVICE_RESTORE_DESTINATION = 5016
    OS_NOT_SUPPORT = 5017
    DEVICE_SHADOW_CHECK_SPARSE = 5018
    PATH_BACKUP = 6001
    PATH_BACKUP_ERROR = 6002
    PATH_RESTORE = 6003
    PATH_RESTORE_SKIP = 6004
    PATH_RESTORE_OVERWRITE = 6005
    PATH_RESTORE_ERROR = 6006
    PATH_RESTORE_CANCEL = 6007
    PATH_DOWNLOAD = 6008
    PATH_BACKUP_ATTR_ERROR = 6009
    PATH_RESTORE_ATTR_ERROR = 6010
    PATH_RESTORE_NOT_SUPPORT = 6011
    PATH_TOO_LONG = 6012
    PATH_RESTORE_META_CAPABILITY = 6013
    PATH_RESTORE_META_ERROR = 6014
    PATH_RESTORE_PARENT_NOT_EXIST = 6015
    PATH_RESTORE_PARENT_TYPE_CONFLICT = 6016
    PATH_RESTORE_NO_PERMISSION = 6017
    PATH_RESTORE_SOURCE_ERROR = 6018
    PATH_RESTORE_METADATA_ERROR = 6019
    PC_COLLECT_DEVICE_SPEC = 7001
    PC_TAKE_SNAPSHOT_START = 7002
    PC_TAKE_SNAPSHOT_FINISH = 7003
    PC_TAKE_SNAPSHOT_FINISH_ERROR = 7004
    PC_TAKE_SNAPSHOT_SET_START = 7005
    PC_TAKE_SNAPSHOT_SET_FINISH = 7006
    PC_TAKE_SNAPSHOT_SET_FINISH_ERROR = 7007
    PC_DATABASE_ERROR = 7008
    PC_UPLOAD_DEVICE_SPEC_START = 7009
    PC_UPLOAD_DEVICE_SPEC_FINISH = 7010
    PC_UPLOAD_DEVICE_SPEC_FINISH_ERROR = 7011
    PC_UPLOAD_VOLUME_START = 7012
    PC_UPLOAD_VOLUME_FINISH = 7013
    PC_UPLOAD_VOLUME_FINISH_ERROR = 7014
    PC_RESTORE_RETRY = 7015
    PC_UPDATE_AGENT_ERROR = 7016
    PC_CREATE_TASK_ERROR_SHARE_NAME = 7017
    PC_CREATE_TASK_ERROR_INTERNAL = 7018
    PC_AUTH_ERROR = 7019
    PC_READ_SNAPSHOT_ERROR = 7020
    PC_SNAPSHOT_NOT_FOUND = 7021
    PC_DEVICE_UPGRADE = 7022
    PC_RESTORE_CREATE_FILE_ERROR = 7023
    PC_RESTORE_WRITE_FILE_ERROR = 7024
    PC_RESTORE_MISSING_OFFSET = 7025
    PC_CREATE_TASK_ERROR_NO_QUOTA = 7026
    PC_CREATE_TASK_ERROR_NO_SPACE = 7027
    PC_CREATE_TASK_ERROR_STORAGE_EXISTED = 7028
    PC_TRIGGER_EVENT = 7029
    PC_CACHE_SIZE_NOT_ENOUGH = 7030
    PC_CACHE_BASE_SNAPSHOT_NOT_FOUND = 7031
    PC_CREATE_TASK_ERROR_STORAGE_EXISTED_OLD_VERSION = 7032
    PC_QUERY_UPDATE_SERVER_FAILED = 7033
    PC_CREATE_TASK_ERROR_DATA_CORRUPT = 7034
    PC_CACHE_CBT_INITIALIZE_FAIL = 7035
    PC_UNSUPPORTED_DYNAMIC_VOLUME = 7036
    PC_UNSUPPORTED_FILE_SYSTEM = 7037
    PC_BACKUP_ACCESS_DENIED = 7038
    PC_BACKUP_SECTOR_NOT_FOUND = 7039
    PC_BACKUP_PATH_NOT_FOUND = 7040
    PC_BACKUP_INVALID_FUNCTION = 7041
    PC_SNAPSHOT_OPEN_ERROR = 7042
    PC_BACKUP_DEVICE_BUSY = 7043
    PC_SNAPSHOT_SKIP_BAD_CLUSTER = 7044
    PC_EXEC_PRE_SCRIPT = 7045
    PC_EXEC_PRE_SCRIPT_IGNORE_FAILURE = 7046
    PC_EXEC_PRE_SCRIPT_ERROR = 7047
    PC_EXEC_PRE_SCRIPT_TIMEOUT = 7048
    PC_EXEC_POST_SCRIPT = 7049
    PC_EXEC_POST_SCRIPT_IGNORE_FAILURE = 7050
    PC_EXEC_POST_SCRIPT_ERROR = 7051
    PC_EXEC_POST_SCRIPT_TIMEOUT = 7052
    PC_EXEC_SCRIPT_CLIENT_CAN_NOT_ACCESS = 7053
    PC_EXEC_SCRIPT_SERVER_CAN_NOT_ACCESS = 7054
    PC_EXEC_SCRIPT_SIZE_TOO_LARGE = 7055
    PC_CACHE_LOCATION_DATA_VOLUME_NOT_FOUND = 7056
    PC_UPLOAD_VOLUME_BACKUP_CACHE_READ_START = 7057
    PC_UPLOAD_VOLUME_BACKUP_CACHE_READ_FINISH = 7058
    PC_UPLOAD_VOLUME_BACKUP_CACHE_READ_FINISH_ERROR = 7059
    PC_CACHE_CREATE_FILE_ERROR = 7060
    PC_CACHE_READ_FILE_ERROR = 7061
    PC_CACHE_WRITE_FILE_ERROR = 7062
    PC_UPLOAD_VOLUME_BACKUP_CACHE_WRITE_START = 7063
    PC_UPLOAD_VOLUME_BACKUP_CACHE_WRITE_FINISH = 7064
    PC_UPLOAD_VOLUME_BACKUP_CACHE_WRITE_FINISH_ERROR = 7065
    PC_CACHE_STORAGE_QUOTA_FULL = 7066
    PC_UPLOAD_SCRIPT_OUTPUT_FILE_ERROR = 7067
    PC_EXCLUDE_VOLUME_REMOVABLE = 7068
    PC_EXCLUDE_VOLUME_EXTERNAL = 7069
    PC_EXCLUDE_VOLUME_UNSUPPORTED_BUS = 7070
    PC_EXCLUDE_VOLUME_UNSUPPORTED_DEVICE = 7071
    PC_EXCLUDE_VOLUME_UNSUPPORTED_FS = 7072
    PC_EXCLUDE_VOLUME_UNKNOWN_FS = 7073
    PC_EXCLUDE_VOLUME_INFO_ERROR = 7074
    PC_SHADOW_NOT_FOUND = 7075
    WINDOWS_TAKE_SNAPSHOT_FINISH_ERROR = 7076
    WINDOWS_READ_SNAPSHOT_ERROR = 7077
    WINDOWS_SNAPSHOT_OPEN_ERROR = 7078
    WINDOWS_BACKUP_ACCESS_DENIED = 7079
    WINDOWS_BACKUP_SECTOR_NOT_FOUND = 7080
    WINDOWS_BACKUP_PATH_NOT_FOUND = 7081
    WINDOWS_BACKUP_INVALID_FUNCTION = 7082
    PC_SNAPSHOT_NO_AVAILABLE_VOLUME = 7083
    PC_SNAPSHOT_DRIVER_ERROR = 7084
    DSM_CLEAR_LOGS = 7500
    DSM_BACKUP_PRECHECK_FAIL = 7501
    DSM_RESTORE_SHARE_FAIL = 7502
    REASON_NO_SPACE = 8001
    REASON_NO_PERM = 8002
    REASON_NO_QUOTA = 8003
    REASON_READONLY_FS = 8004
    REASON_IO_ERR = 8005
    REASON_DATA_CORRUPT = 8006
    REASON_NO_SPACE_SYSTEM = 8007
    REASON_NO_QUOTA_SYSTEM = 8008
    REASON_NO_TARGET_FOLDER_LOG = 8009
    REASON_NO_TARGET_DATABASE = 8010
    REASON_NO_TARGET_VERSION_FOLDER = 8011
    REASON_BACKUP_IMAGE_OPEN_FAILURE = 8012
    REASON_NOT_SUPPORT_COMPRESS_SHARE = 8013
    REASON_VDDK_GENERAL_ERROR = 8100
    VDDK_NOT_SUPPORT_COMPRESSION = 8101
    REASON_VDDK_RETRY_WARNING = 8102
    REASON_HYPERVISOR_GENERAL_ERROR = 8103
    REASON_HYPERVISOR_RETRY_WARNING = 8104
    REASON_HYPERVISOR_CONNECT_FAIL = 8105
    REASON_HYPERVISOR_VCENTER_CONNECT_FAIL = 8106
    FS_PATH_SET_ACL = 9013
    FS_NOT_SUPPORT_ACLS = 9044
    FS_NOT_SUPPORT_XATTRS = 9045
    FS_PATH_SET_ATTR = 9071
    FS_PATH_SET_ATTR_XATTR_DATA_LIMIT = 9072
    FS_PATH_SET_ATTR_XATTR_ENOSPC = 9073
    FS_RSYNC_FILE_DELETE_SKIPPED = 9074
    FS_VSS_OPERATION_FAILED = 9075
    FS_SAMBA_ACL_NOT_SUPPORT = 9076
    PARTIAL_SUCCESS = 9077
    FS_DIR_NOT_FOUND = 9078
    FS_RSYNC_PROTOCOL_INCOMPATIBLE = 9088
    FS_OLD_TASK_CREATED = 9900
    FS_OLD_TASK_REMOVED = 9901
    FS_OLD_TASK_EDIT_RENAME = 9902
    FS_OLD_TASK_EDIT_BANDWIDTH = 9903
    FS_OLD_TASK_EDIT_SCHEDULE_ON = 9904
    FS_OLD_TASK_EDIT_SCHEDULE_OFF = 9905
    FS_OLD_TASK_EDIT_BACKUP_FOLDER = 9906
}
<# Methods
SYNO.ActiveBackup.Activation
   get
   set
SYNO.ActiveBackup.Agent
   get_client_dl_link
   get_creator_dl_link
SYNO.ActiveBackup.Agent.Device
   list_nodes
   update_agent
   upgrade
SYNO.ActiveBackup.Agentless
   test_connection
   test_task_settings
   list_device_folder
   test_rsync_module_connection
   test_ssh_key
   upload_ssh_key
   remove_ssh_key_tmp_file
   create_device
   set_device
   get_task_setting
   get_datapath_on_storage
SYNO.ActiveBackup.Device
   list
   remove
   list_version
   list_tasks
   set_credential
SYNO.ActiveBackup.Inventory
   create
   update
   test_connection
   create_check_job
   cancel_check_job
   list_child
   get_check_status
   remove
   list
   list_node
   get_node_path
   list_guest_node
   get_server_info
   get_server_cache
   update_cache
   get_host_interface
   check_identity
   check_iscsi
   list_cluster_shared_volume
SYNO.ActiveBackup.Log
   list_log
   list_result
   clear
   list_result_detail
   set_info
   set_send_log_setting
   get_info
   upload_cert
   send_test_log
   download
   check_progress
   cancel_download
SYNO.ActiveBackup.NFSPrivilege
   load
   save
SYNO.ActiveBackup.Overview
   list_device_last_backup
   list_activity
   list_device_transfer_size
   list_type_transfer_size
   list_result_status_summary
SYNO.ActiveBackup.Report
   create
   list
   delete
SYNO.ActiveBackup.ReportConfig
   get
   set
SYNO.ActiveBackup.Restore
   list
   status
   stop
   clear
   pause
   resume
SYNO.ActiveBackup.RestoreVM
   list_latest_version
   list_spec
   check_spec
   check_vmm
   restore
   migrate
   create_image
   remove_image
   status_image
   get_vmm_meta
   set_vmm_meta
   remove_vmm_meta
   check_support_tcmu
   clone_enc_cmp_image
SYNO.ActiveBackup.Server
   get_creation_limit
   set_creation_limit
SYNO.ActiveBackup.Setting
   list
   set
SYNO.ActiveBackup.Share
   list_storage
   list_file
   list
   check_file
   relink
   remove
SYNO.ActiveBackup.Storage
   verify
   unmount
   check_mount
   upload_private_key
   download_private_key
   automount_get
   automount_list_location
SYNO.ActiveBackup.Task
   list
   list_with_device
   create_vm_check
   list_vm_check
   vm_check_cancel
   create_vm
   create_agent
   create_agentless
   set
   backup
   remove
   cancel
   get_default_task_name
SYNO.ActiveBackup.TaskTemplate
   list
   create
   set
   set_priority
   remove
   translate_target_id
SYNO.ActiveBackup.UserGroup
   list
   list_admin
SYNO.ActiveBackup.Version
   list
   list_node
   restore
   lock
   download
   delete
   list_share

#>

