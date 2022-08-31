<#
    .SYNOPSIS
    Get Computer Information & Optionally Export To Text File
    .NOTES
    Original Idea
    https://github.com/farag2/PC-information/blob/master/PC.ps1
#>
function Get-ComputerInformation
{
    [CmdletBinding()]
    param
    (
        [Parameter(
            Mandatory = $false
        )]
        [switch]
        $Export
    )

    begin
    {
        # OS
        $OperatingSystem = Get-CimInstance -ClassName Win32_OperatingSystem
        $DisplayVersion = (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion").DisplayVersion
        $OldBuildNumber = (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion").ReleaseId
        $DisplayedVersionResult = '(' + @{ $true = $DisplayVersion; $false = $OldBuildNumber }[$null -ne $DisplayVersion] + ')'

        $Caption = @{
            Name       = 'OS'
            Expression = { $_.Caption }
        }
        $Version = @{
            Name       = 'Version'
            Expression = { Get-ComputerInfo | Select-Object -ExpandProperty windowsversion }
        }
        $Build = @{
            Name       = 'Build'
            Expression = { $DisplayedVersionResult }
        }
        $OS = ($OperatingSystem | Select-Object -Property $Caption, $Version, $Build | Format-Table | Out-String).Trim()

        # Last Reboot
        $LastBoot = @{
            Name       = 'LastBoot'
            Expression = { $_.LastBootUpTime }
        }
        $LastBootUpTime = ($OperatingSystem | Select-Object -Property $LastBoot | Format-Table | Out-String).Trim()

        # Windows Uptime
        <#
            $Uptime = @{
                Name       = 'Days, Hours, Minutes, Seconds'
                Expression = { $_.Days} {$_.Hours} {$_.Minutes} {$_.Seconds }
            }
            $SystemUpTime = (New-TimeSpan -Start $($OperatingSystem.LastBootUpTime) -End (Get-Date) | Select-Object -Property $Uptime | Format-Table | Out-String).Trim()

            $LBTime = $OperatingSystem.Lastbootuptime
            [TimeSpan]$UpTime = New-TimeSpan $LBTime $(Get-Date)
            Write-Output "$($UpTime.days) Days $($UpTime.hours) Hours $($UpTime.minutes) Minutes $($UpTime.seconds) Seconds"
            #>

        # Computer Name\Current User
        $Username = @{
            Name       = 'Computer Name\Current User'
            Expression = { $_.Username }
        }
        $LoggedOnUser = (Get-CimInstance -ClassName win32_computersystem | Select-Object -Property $Username | Format-Table | Out-String).Trim()

        # IP address
        $IPAddress = @{
            Name       = 'IPAddress'
            Expression = { $_.IPAddress }
        }
        $Description = @{
            Name       = 'Description'
            Expression = { $_.Description }
        }
        $IPAddress = (Get-CimInstance win32_NetworkadapterConfiguration | Where-Object IPAddress -NE $null | Select-Object -Property $Description, $IPAddress | Format-Table | Out-String).Trim()

        # BIOS
        $Manufacturer = @{
            Name       = 'BIOS'
            Expression = { $_.Manufacturer }
        }
        $Version = @{
            Name       = 'Version'
            Expression = { $_.SMBIOSBIOSVersion }
        }
        $BIOS = (Get-CimInstance -ClassName CIM_BIOSElement | Select-Object -Property $Manufacturer, $Version | Format-Table | Out-String).Trim()

        # Motherboard
        $Manufacturer = @{
            Name       = 'Motherboard'
            Expression = { $_.Manufacturer }
        }
        $Product = @{
            Name       = 'Model'
            Expression = { $_.Product }
        }
        $Motherboard = (Get-CimInstance -ClassName Win32_BaseBoard | Select-Object -Property $Manufacturer, $Product | Format-Table | Out-String).Trim()

        # CPU
        $Name = @{
            Name       = 'CPU'
            Expression = { $_.Name }
        }
        $Cores = @{
            Name       = 'Cores'
            Expression = { $_.NumberOfCores }
        }
        $L3CacheSize = @{
            Name       = 'L3, MB'
            Expression = { $_.L3CacheSize / 1024 }
        }
        $Threads = @{
            Name       = 'Threads'
            Expression = { $_.NumberOfLogicalProcessors }
        }
        $CPU = (Get-CimInstance -ClassName CIM_Processor | Select-Object -Property $Name, $Cores, $L3CacheSize, $Threads | Format-Table | Out-String).Trim()

        # RAM
        $PhysicalMemory = @{
            Name       = 'Physical Memory'
            Expression = { $_.Caption }
        }
        $Speed = @{
            Name       = 'Speed, MHz'
            Expression = { $_.ConfiguredClockSpeed }
        }
        $Capacity = @{
            Name       = 'Capacity, GB'
            Expression = { $_.Capacity / 1GB }
        }
        $RAM = (Get-CimInstance -ClassName CIM_PhysicalMemory | Select-Object -Property $PhysicalMemory, Manufacturer, PartNumber, $Speed, $Capacity | Format-Table | Out-String).Trim()

        # Physical disks
        $Model = @{
            Name       = 'Model'
            Expression = { $_.FriendlyName }
        }
        $MediaType = @{
            Name       = 'Drive type'
            Expression = { $_.MediaType }
        }
        $Size = @{
            Name       = 'Size, GB'
            Expression = { [math]::round($_.Size / 1GB, 2) }
        }
        $BusType = @{
            Name       = 'Bus type'
            Expression = { $_.BusType }
        }
        $PhysicalDisk = (Get-PhysicalDisk | Select-Object -Property $Model, $MediaType, $BusType, $Size | Format-Table | Out-String).Trim()

        # Video Controllers
        $VideoController = Get-CimInstance -ClassName CIM_VideoController

        if ((Get-CimInstance -ClassName CIM_VideoController | Where-Object -FilterScript { $_.AdapterDACType -eq 'Internal' }))
        {
            $Caption = @{
                Name       = 'Internal Graphics'
                Expression = { $_.Caption }
            }
            $VRAM = @{
                Name       = 'VRAM, GB'
                Expression = { [math]::round($_.AdapterRAM / 1GB) }
            }
            $IntegratedGraphics = ($VideoController | Where-Object -FilterScript { $_.AdapterDACType -eq "Internal" } | Select-Object -Property $Caption, $VRAM | Format-Table | Out-String).Trim()
        }

        if (($VideoController | Where-Object -FilterScript { $_.AdapterDACType -ne 'Internal' }))
        {
            $qwMemorySize = (Get-ItemProperty -Path "HKLM:\SYSTEM\ControlSet001\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0*" -Name HardwareInformation.qwMemorySize -ErrorAction SilentlyContinue)."HardwareInformation.qwMemorySize"
            $Caption = @{
                Name       = 'External Graphics'
                Expression = { $_.Caption }
            }
            $VRAM = @{
                Name       = 'VRAM, GB'
                Expression = { [math]::round($qwMemorySize / 1GB) }
            }
            $DedicatedGraphics = ($VideoController | Where-Object -FilterScript { $_.AdapterDACType -ne "Internal" } | Select-Object -Property $Caption, $VRAM | Format-Table | Out-String).Trim()
        }


    }

    process
    {
        Clear-Host

        # Write results to console
        $ComputerInfo = @(
            $OS
            "`n"
            $LastBootUpTime
            "`n"
            $LoggedOnUser
            "`n"
            $BIOS
            "`n"
            $CPU
            "`n"
            $DedicatedGraphics
            "`n"
            $IntegratedGraphics
            "`n"
            $Motherboard
            "`n"
            $RAM
            "`n"
            $IPAddress
            "`n"
            $PhysicalDisk
            "`n"
        )

        $ComputerInfo | Format-List
        Pause

        if ($Export)
        {
            Add-Content -Path $env:USERPROFILE\Desktop\ComputerInformation.txt -Value $ComputerInfo
        }
    }
}
