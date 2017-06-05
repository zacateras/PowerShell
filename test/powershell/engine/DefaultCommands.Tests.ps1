Describe "Verify approved aliases list" -Tags "CI" {
    BeforeAll {
        $FullCLR = !$isCoreCLR
        $CoreWindows = $isCoreCLR -and $IsWindows
        $CoreUnix = $isCoreCLR -and !$IsWindows

        $AllScope = '[System.Management.Automation.ScopedItemOptions]::AllScope'
        $ReadOnly = '[System.Management.Automation.ScopedItemOptions]::ReadOnly'
        $None     = '[System.Management.Automation.ScopedItemOptions]::None'

        $commandString = @"
"CommandType", "Name",                          "Definition",                         "Present",                                    "ReadOnlyOption",   "AllScopeOption"
"Alias",  "%",                                  "ForEach-Object",                     $($FullCLR -or $CoreWindows -or $CoreUnix),   "ReadOnly",         "AllScope"
"Alias",  "?",                                  "Where-Object",                       $($FullCLR -or $CoreWindows -or $CoreUnix),   "ReadOnly",         "AllScope"
"Alias",  "ac",                                 "Add-Content",                        $($FullCLR -or $CoreWindows              ),   "ReadOnly",         "AllScope"
"Alias",  "asnp",                               "Add-PSSnapIn",                       $($FullCLR                               ),   "ReadOnly",         "AllScope"
"Alias",  "cat",                                "Get-Content",                        $($FullCLR -or $CoreWindows              ),   "",                 "AllScope"
"Alias",  "cd",                                 "Set-Location",                       $($FullCLR -or $CoreWindows -or $CoreUnix),   "",                 "AllScope"
"Alias",  "CFS",                                "ConvertFrom-String",                 $($FullCLR                               ),   "ReadOnly",         "AllScope"
"Alias",  "chdir",                              "Set-Location",                       $($FullCLR -or $CoreWindows -or $CoreUnix),   "",                 "AllScope"
"Alias",  "clc",                                "Clear-Content",                      $($FullCLR -or $CoreWindows -or $CoreUnix),   "ReadOnly",         "AllScope"
"Alias",  "clear",                              "Clear-Host",                         $($FullCLR -or $CoreWindows -or $CoreUnix),   "",                 "AllScope"
"Alias",  "clhy",                               "Clear-History",                      $($FullCLR -or $CoreWindows -or $CoreUnix),   "ReadOnly",         "AllScope"
"Alias",  "cli",                                "Clear-Item",                         $($FullCLR -or $CoreWindows -or $CoreUnix),   "ReadOnly",         "AllScope"
"Alias",  "clp",                                "Clear-ItemProperty",                 $($FullCLR -or $CoreWindows -or $CoreUnix),   "ReadOnly",         "AllScope"
"Alias",  "cls",                                "Clear-Host",                         $($FullCLR -or $CoreWindows -or $CoreUnix),   "",                 "AllScope"
"Alias",  "clv",                                "Clear-Variable",                     $($FullCLR -or $CoreWindows -or $CoreUnix),   "ReadOnly",         "AllScope"
"Alias",  "cnsn",                               "Connect-PSSession",                  $($FullCLR -or $CoreWindows -or $CoreUnix),   "ReadOnly",         "AllScope"
"Alias",  "compare",                            "Compare-Object",                     $($FullCLR -or $CoreWindows              ),   "ReadOnly",         "AllScope"
"Alias",  "copy",                               "Copy-Item",                          $($FullCLR -or $CoreWindows -or $CoreUnix),   "",                 "AllScope"
"Alias",  "cp",                                 "Copy-Item",                          $($FullCLR -or $CoreWindows              ),   "",                 "AllScope"
"Alias",  "cpi",                                "Copy-Item",                          $($FullCLR -or $CoreWindows -or $CoreUnix),   "ReadOnly",         "AllScope"
"Alias",  "cpp",                                "Copy-ItemProperty",                  $($FullCLR -or $CoreWindows              ),   "ReadOnly",         "AllScope"
"Alias",  "curl",                               "Invoke-WebRequest",                  $($FullCLR                               ),   "ReadOnly",         "AllScope"
"Alias",  "cvpa",                               "Convert-Path",                       $($FullCLR -or $CoreWindows -or $CoreUnix),   "ReadOnly",         "AllScope"
"Alias",  "dbp",                                "Disable-PSBreakpoint",               $($FullCLR -or $CoreWindows -or $CoreUnix),   "ReadOnly",         "AllScope"
"Alias",  "del",                                "Remove-Item",                        $($FullCLR -or $CoreWindows -or $CoreUnix),   "",                 "AllScope"
"Alias",  "diff",                               "Compare-Object",                     $($FullCLR -or $CoreWindows              ),   "ReadOnly",         "AllScope"
"Alias",  "dir",                                "Get-ChildItem",                      $($FullCLR -or $CoreWindows -or $CoreUnix),   "",                 "AllScope"
"Alias",  "dnsn",                               "Disconnect-PSSession",               $($FullCLR -or $CoreWindows -or $CoreUnix),   "ReadOnly",         "AllScope"
"Alias",  "ebp",                                "Enable-PSBreakpoint",                $($FullCLR -or $CoreWindows -or $CoreUnix),   "ReadOnly",         "AllScope"
"Alias",  "echo",                               "Write-Output",                       $($FullCLR -or $CoreWindows -or $CoreUnix),   "",                 "AllScope"
"Alias",  "epal",                               "Export-Alias",                       $($FullCLR -or $CoreWindows -or $CoreUnix),   "ReadOnly",         "AllScope"
"Alias",  "epcsv",                              "Export-Csv",                         $($FullCLR -or $CoreWindows -or $CoreUnix),   "ReadOnly",         "AllScope"
"Alias",  "epsn",                               "Export-PSSession",                   $($FullCLR                               ),   "",                 "AllScope"
"Alias",  "erase",                              "Remove-Item",                        $($FullCLR -or $CoreWindows -or $CoreUnix),   "",                 "AllScope"
"Alias",  "etsn",                               "Enter-PSSession",                    $($FullCLR -or $CoreWindows -or $CoreUnix),   "",                 "AllScope"
"Alias",  "exsn",                               "Exit-PSSession",                     $($FullCLR -or $CoreWindows -or $CoreUnix),   "",                 "AllScope"
"Alias",  "fc",                                 "Format-Custom",                      $($FullCLR -or $CoreWindows -or $CoreUnix),   "ReadOnly",         "AllScope"
"Alias",  "fhx",                                "Format-Hex",                         $($FullCLR -or $CoreWindows -or $CoreUnix),   "",                 ""
"Alias",  "fl",                                 "Format-List",                        $($FullCLR -or $CoreWindows -or $CoreUnix),   "ReadOnly",         "AllScope"
"Alias",  "foreach",                            "ForEach-Object",                     $($FullCLR -or $CoreWindows -or $CoreUnix),   "ReadOnly",         "AllScope"
"Alias",  "ft",                                 "Format-Table",                       $($FullCLR -or $CoreWindows -or $CoreUnix),   "ReadOnly",         "AllScope"
"Alias",  "fw",                                 "Format-Wide",                        $($FullCLR -or $CoreWindows -or $CoreUnix),   "ReadOnly",         "AllScope"
"Alias",  "gal",                                "Get-Alias",                          $($FullCLR -or $CoreWindows -or $CoreUnix),   "ReadOnly",         "AllScope"
"Alias",  "gbp",                                "Get-PSBreakpoint",                   $($FullCLR -or $CoreWindows -or $CoreUnix),   "ReadOnly",         "AllScope"
"Alias",  "gc",                                 "Get-Content",                        $($FullCLR -or $CoreWindows -or $CoreUnix),   "ReadOnly",         "AllScope"
"Alias",  "gcb",                                "Get-Clipboard",                      $($FullCLR                               ),   "ReadOnly",         "AllScope"
"Alias",  "gci",                                "Get-ChildItem",                      $($FullCLR -or $CoreWindows -or $CoreUnix),   "ReadOnly",         "AllScope"
"Alias",  "gcm",                                "Get-Command",                        $($FullCLR -or $CoreWindows -or $CoreUnix),   "ReadOnly",         "AllScope"
"Alias",  "gcs",                                "Get-PSCallStack",                    $($FullCLR -or $CoreWindows -or $CoreUnix),   "ReadOnly",         "AllScope"
"Alias",  "gdr",                                "Get-PSDrive",                        $($FullCLR -or $CoreWindows -or $CoreUnix),   "ReadOnly",         "AllScope"
"Alias",  "ghy",                                "Get-History",                        $($FullCLR -or $CoreWindows -or $CoreUnix),   "ReadOnly",         "AllScope"
"Alias",  "gi",                                 "Get-Item",                           $($FullCLR -or $CoreWindows -or $CoreUnix),   "ReadOnly",         "AllScope"
"Alias",  "gin",                                "Get-ComputerInfo",                   $($FullCLR -or $CoreWindows              ),   "",                 ""
"Alias",  "gjb",                                "Get-Job",                            $($FullCLR -or $CoreWindows -or $CoreUnix),   "",                 "AllScope"
"Alias",  "gl",                                 "Get-Location",                       $($FullCLR -or $CoreWindows -or $CoreUnix),   "ReadOnly",         "AllScope"
"Alias",  "gm",                                 "Get-Member",                         $($FullCLR -or $CoreWindows -or $CoreUnix),   "ReadOnly",         "AllScope"
"Alias",  "gmo",                                "Get-Module",                         $($FullCLR -or $CoreWindows -or $CoreUnix),   "ReadOnly",         "AllScope"
"Alias",  "gp",                                 "Get-ItemProperty",                   $($FullCLR -or $CoreWindows -or $CoreUnix),   "ReadOnly",         "AllScope"
"Alias",  "gps",                                "Get-Process",                        $($FullCLR -or $CoreWindows -or $CoreUnix),   "ReadOnly",         "AllScope"
"Alias",  "gpv",                                "Get-ItemPropertyValue",              $($FullCLR -or $CoreWindows -or $CoreUnix),   "ReadOnly",         "AllScope"
"Alias",  "group",                              "Group-Object",                       $($FullCLR -or $CoreWindows -or $CoreUnix),   "ReadOnly",         "AllScope"
"Alias",  "gsn",                                "Get-PSSession",                      $($FullCLR -or $CoreWindows -or $CoreUnix),   "",                 "AllScope"
"Alias",  "gsnp",                               "Get-PSSnapIn",                       $($FullCLR                               ),   "ReadOnly",         "AllScope"
"Alias",  "gsv",                                "Get-Service",                        $($FullCLR -or $CoreWindows              ),   "ReadOnly",         "AllScope"
"Alias",  "gtz",                                "Get-TimeZone",                       $($FullCLR -or $CoreWindows -or $CoreUnix),   "",                 ""
"Alias",  "gu",                                 "Get-Unique",                         $($FullCLR -or $CoreWindows -or $CoreUnix),   "ReadOnly",         "AllScope"
"Alias",  "gv",                                 "Get-Variable",                       $($FullCLR -or $CoreWindows -or $CoreUnix),   "ReadOnly",         "AllScope"
"Alias",  "gwmi",                               "Get-WmiObject",                      $($FullCLR                               ),   "ReadOnly",         "AllScope"
"Alias",  "h",                                  "Get-History",                        $($FullCLR -or $CoreWindows -or $CoreUnix),   "",                 "AllScope"
"Alias",  "history",                            "Get-History",                        $($FullCLR -or $CoreWindows -or $CoreUnix),   "",                 "AllScope"
"Alias",  "icm",                                "Invoke-Command",                     $($FullCLR -or $CoreWindows -or $CoreUnix),   "",                 "AllScope"
"Alias",  "iex",                                "Invoke-Expression",                  $($FullCLR -or $CoreWindows -or $CoreUnix),   "ReadOnly",         "AllScope"
"Alias",  "ihy",                                "Invoke-History",                     $($FullCLR -or $CoreWindows -or $CoreUnix),   "ReadOnly",         "AllScope"
"Alias",  "ii",                                 "Invoke-Item",                        $($FullCLR -or $CoreWindows -or $CoreUnix),   "ReadOnly",         "AllScope"
"Alias",  "ipal",                               "Import-Alias",                       $($FullCLR -or $CoreWindows -or $CoreUnix),   "ReadOnly",         "AllScope"
"Alias",  "ipcsv",                              "Import-Csv",                         $($FullCLR -or $CoreWindows -or $CoreUnix),   "ReadOnly",         "AllScope"
"Alias",  "ipmo",                               "Import-Module",                      $($FullCLR -or $CoreWindows -or $CoreUnix),   "ReadOnly",         "AllScope"
"Alias",  "ipsn",                               "Import-PSSession",                   $($FullCLR                               ),   "",                 "AllScope"
"Alias",  "irm",                                "Invoke-RestMethod",                  $($FullCLR -or $CoreWindows -or $CoreUnix),   "ReadOnly",         "AllScope"
"Alias",  "ise",                                "powershell_ise.exe",                 $($FullCLR                               ),   "ReadOnly",         "AllScope"
"Alias",  "iwmi",                               "Invoke-WMIMethod",                   $($FullCLR                               ),   "ReadOnly",         "AllScope"
"Alias",  "iwr",                                "Invoke-WebRequest",                  $($FullCLR -or $CoreWindows -or $CoreUnix),   "ReadOnly",         "AllScope"
"Alias",  "kill",                               "Stop-Process",                       $($FullCLR -or $CoreWindows -or $CoreUnix),   "",                 "AllScope"
"Alias",  "lp",                                 "Out-Printer",                        $($FullCLR                               ),   "ReadOnly",         "AllScope"
"Alias",  "ls",                                 "Get-ChildItem",                      $($FullCLR -or $CoreWindows              ),   "",                 "AllScope"
"Alias",  "man",                                "help",                               $($FullCLR -or $CoreWindows              ),   "",                 "AllScope"
"Alias",  "md",                                 "mkdir",                              $($FullCLR -or $CoreWindows -or $CoreUnix),   "",                 "AllScope"
"Alias",  "measure",                            "Measure-Object",                     $($FullCLR -or $CoreWindows -or $CoreUnix),   "ReadOnly",         "AllScope"
"Alias",  "mi",                                 "Move-Item",                          $($FullCLR -or $CoreWindows -or $CoreUnix),   "ReadOnly",         "AllScope"
"Alias",  "mount",                              "New-PSDrive",                        $($FullCLR -or $CoreWindows              ),   "",                 "AllScope"
"Alias",  "move",                               "Move-Item",                          $($FullCLR -or $CoreWindows -or $CoreUnix),   "",                 "AllScope"
"Alias",  "mp",                                 "Move-ItemProperty",                  $($FullCLR -or $CoreWindows -or $CoreUnix),   "ReadOnly",         "AllScope"
"Alias",  "mv",                                 "Move-Item",                          $($FullCLR -or $CoreWindows              ),   "",                 "AllScope"
"Alias",  "nal",                                "New-Alias",                          $($FullCLR -or $CoreWindows -or $CoreUnix),   "ReadOnly",         "AllScope"
"Alias",  "ndr",                                "New-PSDrive",                        $($FullCLR -or $CoreWindows -or $CoreUnix),   "ReadOnly",         "AllScope"
"Alias",  "ni",                                 "New-Item",                           $($FullCLR -or $CoreWindows -or $CoreUnix),   "ReadOnly",         "AllScope"
"Alias",  "nmo",                                "New-Module",                         $($FullCLR -or $CoreWindows -or $CoreUnix),   "ReadOnly",         "AllScope"
"Alias",  "npssc",                              "New-PSSessionConfigurationFile",     $($FullCLR                               ),   "ReadOnly",         "AllScope"
"Alias",  "nsn",                                "New-PSSession",                      $($FullCLR -or $CoreWindows -or $CoreUnix),   "",                 "AllScope"
"Alias",  "nv",                                 "New-Variable",                       $($FullCLR -or $CoreWindows -or $CoreUnix),   "ReadOnly",         "AllScope"
"Alias",  "nwsn",                               "New-PSWorkflowSession",              $($FullCLR                               ),   "ReadOnly",         "AllScope"
"Alias",  "ogv",                                "Out-GridView",                       $($FullCLR                               ),   "ReadOnly",         "AllScope"
"Alias",  "oh",                                 "Out-Host",                           $($FullCLR -or $CoreWindows -or $CoreUnix),   "ReadOnly",         "AllScope"
"Alias",  "popd",                               "Pop-Location",                       $($FullCLR -or $CoreWindows -or $CoreUnix),   "",                 "AllScope"
"Alias",  "ps",                                 "Get-Process",                        $($FullCLR -or $CoreWindows              ),   "",                 "AllScope"
"Alias",  "pushd",                              "Push-Location",                      $($FullCLR -or $CoreWindows -or $CoreUnix),   "",                 "AllScope"
"Alias",  "pwd",                                "Get-Location",                       $($FullCLR -or $CoreWindows -or $CoreUnix),   "",                 "AllScope"
"Alias",  "r",                                  "Invoke-History",                     $($FullCLR -or $CoreWindows -or $CoreUnix),   "",                 "AllScope"
"Alias",  "rbp",                                "Remove-PSBreakpoint",                $($FullCLR -or $CoreWindows -or $CoreUnix),   "ReadOnly",         "AllScope"
"Alias",  "rcjb",                               "Receive-Job",                        $($FullCLR -or $CoreWindows -or $CoreUnix),   "",                 "AllScope"
"Alias",  "rcsn",                               "Receive-PSSession",                  $($FullCLR -or $CoreWindows -or $CoreUnix),   "ReadOnly",         "AllScope"
"Alias",  "rd",                                 "Remove-Item",                        $($FullCLR -or $CoreWindows -or $CoreUnix),   "",                 "AllScope"
"Alias",  "rdr",                                "Remove-PSDrive",                     $($FullCLR -or $CoreWindows -or $CoreUnix),   "ReadOnly",         "AllScope"
"Alias",  "ren",                                "Rename-Item",                        $($FullCLR -or $CoreWindows -or $CoreUnix),   "",                 "AllScope"
"Alias",  "ri",                                 "Remove-Item",                        $($FullCLR -or $CoreWindows -or $CoreUnix),   "ReadOnly",         "AllScope"
"Alias",  "rjb",                                "Remove-Job",                         $($FullCLR -or $CoreWindows -or $CoreUnix),   "",                 "AllScope"
"Alias",  "rm",                                 "Remove-Item",                        $($FullCLR -or $CoreWindows              ),   "",                 "AllScope"
"Alias",  "rmdir",                              "Remove-Item",                        $($FullCLR -or $CoreWindows              ),   "",                 "AllScope"
"Alias",  "rmo",                                "Remove-Module",                      $($FullCLR -or $CoreWindows -or $CoreUnix),   "ReadOnly",         "AllScope"
"Alias",  "rni",                                "Rename-Item",                        $($FullCLR -or $CoreWindows -or $CoreUnix),   "ReadOnly",         "AllScope"
"Alias",  "rnp",                                "Rename-ItemProperty",                $($FullCLR -or $CoreWindows -or $CoreUnix),   "ReadOnly",         "AllScope"
"Alias",  "rp",                                 "Remove-ItemProperty",                $($FullCLR -or $CoreWindows -or $CoreUnix),   "ReadOnly",         "AllScope"
"Alias",  "rsn",                                "Remove-PSSession",                   $($FullCLR -or $CoreWindows -or $CoreUnix),   "",                 "AllScope"
"Alias",  "rsnp",                               "Remove-PSSnapin",                    $($FullCLR                               ),   "",                 "AllScope"
"Alias",  "rujb",                               "Resume-Job",                         $($FullCLR                               ),   "",                 "AllScope"
"Alias",  "rv",                                 "Remove-Variable",                    $($FullCLR -or $CoreWindows -or $CoreUnix),   "ReadOnly",         "AllScope"
"Alias",  "rvpa",                               "Resolve-Path",                       $($FullCLR -or $CoreWindows -or $CoreUnix),   "ReadOnly",         "AllScope"
"Alias",  "rwmi",                               "Remove-WMIObject",                   $($FullCLR                               ),   "ReadOnly",         "AllScope"
"Alias",  "sajb",                               "Start-Job",                          $($FullCLR -or $CoreWindows -or $CoreUnix),   "",                 "AllScope"
"Alias",  "sal",                                "Set-Alias",                          $($FullCLR -or $CoreWindows -or $CoreUnix),   "ReadOnly",         "AllScope"
"Alias",  "saps",                               "Start-Process",                      $($FullCLR -or $CoreWindows -or $CoreUnix),   "ReadOnly",         "AllScope"
"Alias",  "sasv",                               "Start-Service",                      $($FullCLR -or $CoreWindows              ),   "ReadOnly",         "AllScope"
"Alias",  "sbp",                                "Set-PSBreakpoint",                   $($FullCLR -or $CoreWindows -or $CoreUnix),   "ReadOnly",         "AllScope"
"Alias",  "sc",                                 "Set-Content",                        $($FullCLR -or $CoreWindows -or $CoreUnix),   "ReadOnly",         "AllScope"
"Alias",  "scb",                                "Set-Clipboard",                      $($FullCLR                               ),   "ReadOnly",         "AllScope"
"Alias",  "select",                             "Select-Object",                      $($FullCLR -or $CoreWindows -or $CoreUnix),   "ReadOnly",         "AllScope"
"Alias",  "set",                                "Set-Variable",                       $($FullCLR -or $CoreWindows -or $CoreUnix),   "",                 "AllScope"
"Alias",  "shcm",                               "Show-Command",                       $($FullCLR                               ),   "ReadOnly",         "AllScope"
"Alias",  "si",                                 "Set-Item",                           $($FullCLR -or $CoreWindows -or $CoreUnix),   "ReadOnly",         "AllScope"
"Alias",  "sl",                                 "Set-Location",                       $($FullCLR -or $CoreWindows -or $CoreUnix),   "ReadOnly",         "AllScope"
"Alias",  "sleep",                              "Start-Sleep",                        $($FullCLR -or $CoreWindows              ),   "ReadOnly",         "AllScope"
"Alias",  "sls",                                "Select-String",                      $($FullCLR -or $CoreWindows -or $CoreUnix),   "",                 ""
"Alias",  "sort",                               "Sort-Object",                        $($FullCLR -or $CoreWindows              ),   "ReadOnly",         "AllScope"
"Alias",  "sp",                                 "Set-ItemProperty",                   $($FullCLR -or $CoreWindows -or $CoreUnix),   "ReadOnly",         "AllScope"
"Alias",  "spjb",                               "Stop-Job",                           $($FullCLR -or $CoreWindows -or $CoreUnix),   "",                 "AllScope"
"Alias",  "spps",                               "Stop-Process",                       $($FullCLR -or $CoreWindows -or $CoreUnix),   "ReadOnly",         "AllScope"
"Alias",  "spsv",                               "Stop-Service",                       $($FullCLR -or $CoreWindows              ),   "ReadOnly",         "AllScope"
"Alias",  "start",                              "Start-Process",                      $($FullCLR -or $CoreWindows              ),   "ReadOnly",         "AllScope"
"Alias",  "stz",                                "Set-TimeZone",                       $($FullCLR -or $CoreWindows              ),   "",                 ""
"Alias",  "sujb",                               "Suspend-Job",                        $($FullCLR                               ),   "",                 "AllScope"
"Alias",  "sv",                                 "Set-Variable",                       $($FullCLR -or $CoreWindows -or $CoreUnix),   "ReadOnly",         "AllScope"
"Alias",  "swmi",                               "Set-WMIInstance",                    $($FullCLR                               ),   "ReadOnly",         "AllScope"
"Alias",  "tee",                                "Tee-Object",                         $($FullCLR -or $CoreWindows              ),   "ReadOnly",         "AllScope"
"Alias",  "trcm",                               "Trace-Command",                      $($FullCLR                               ),   "ReadOnly",         "AllScope"
"Alias",  "type",                               "Get-Content",                        $($FullCLR -or $CoreWindows -or $CoreUnix),   "",                 "AllScope"
"Alias",  "wget",                               "Invoke-WebRequest",                  $($FullCLR                               ),   "ReadOnly",         "AllScope"
"Alias",  "where",                              "Where-Object",                       $($FullCLR -or $CoreWindows -or $CoreUnix),   "ReadOnly",         "AllScope"
"Alias",  "wjb",                                "Wait-Job",                           $($FullCLR -or $CoreWindows -or $CoreUnix),   "",                 "AllScope"
"Alias",  "write",                              "Write-Output",                       $($FullCLR -or $CoreWindows              ),   "ReadOnly",         "AllScope"
"Cmdlet", "Add-Computer",                                       ,                     $($FullCLR                               )
"Cmdlet", "Add-Content",                                        ,                     $($FullCLR -or $CoreWindows -or $CoreUnix)
"Cmdlet", "Add-History",                                        ,                     $($FullCLR -or $CoreWindows -or $CoreUnix)
"Cmdlet", "Add-Member",                                         ,                     $($FullCLR -or $CoreWindows -or $CoreUnix)
"Cmdlet", "Add-PSSnapin",                                       ,                     $($FullCLR                               )
"Cmdlet", "Add-Type",                                           ,                     $($FullCLR -or $CoreWindows -or $CoreUnix)
"Cmdlet", "Checkpoint-Computer",                                ,                     $($FullCLR                               )
"Cmdlet", "Clear-Content",                                      ,                     $($FullCLR -or $CoreWindows -or $CoreUnix)
"Cmdlet", "Clear-EventLog",                                     ,                     $($FullCLR                               )
"Cmdlet", "Clear-History",                                      ,                     $($FullCLR -or $CoreWindows -or $CoreUnix)
"Cmdlet", "Clear-Item",                                         ,                     $($FullCLR -or $CoreWindows -or $CoreUnix)
"Cmdlet", "Clear-ItemProperty",                                 ,                     $($FullCLR -or $CoreWindows -or $CoreUnix)
"Cmdlet", "Clear-RecycleBin",                                   ,                     $($FullCLR                               )
"Cmdlet", "Clear-Variable",                                     ,                     $($FullCLR -or $CoreWindows -or $CoreUnix)
"Cmdlet", "Compare-Object",                                     ,                     $($FullCLR -or $CoreWindows -or $CoreUnix)
"Cmdlet", "Complete-Transaction",                               ,                     $($FullCLR                               )
"Cmdlet", "Connect-PSSession",                                  ,                     $($FullCLR -or $CoreWindows -or $CoreUnix)
"Cmdlet", "Connect-WSMan",                                      ,                     $($FullCLR -or $CoreWindows              )
"Cmdlet", "ConvertFrom-Csv",                                    ,                     $($FullCLR -or $CoreWindows -or $CoreUnix)
"Cmdlet", "ConvertFrom-Json",                                   ,                     $($FullCLR -or $CoreWindows -or $CoreUnix)
"Cmdlet", "ConvertFrom-SecureString",                           ,                     $($FullCLR -or $CoreWindows -or $CoreUnix)
"Cmdlet", "ConvertFrom-SddlString",                             ,                     $($FullCLR -or $CoreWindows              )
"Cmdlet", "ConvertFrom-String",                                 ,                     $($FullCLR                               )
"Cmdlet", "ConvertFrom-StringData",                             ,                     $($FullCLR -or $CoreWindows -or $CoreUnix)
"Cmdlet", "Convert-Path",                                       ,                     $($FullCLR -or $CoreWindows -or $CoreUnix)
"Cmdlet", "Convert-String",                                     ,                     $($FullCLR                               )
"Cmdlet", "ConvertTo-Csv",                                      ,                     $($FullCLR -or $CoreWindows -or $CoreUnix)
"Cmdlet", "ConvertTo-Html",                                     ,                     $($FullCLR -or $CoreWindows -or $CoreUnix)
"Cmdlet", "ConvertTo-Json",                                     ,                     $($FullCLR -or $CoreWindows -or $CoreUnix)
"Cmdlet", "ConvertTo-SecureString",                             ,                     $($FullCLR -or $CoreWindows -or $CoreUnix)
"Cmdlet", "ConvertTo-Xml",                                      ,                     $($FullCLR -or $CoreWindows -or $CoreUnix)
"Cmdlet", "Copy-Item",                                          ,                     $($FullCLR -or $CoreWindows -or $CoreUnix)
"Cmdlet", "Copy-ItemProperty",                                  ,                     $($FullCLR -or $CoreWindows -or $CoreUnix)
"Cmdlet", "Debug-Job",                                          ,                     $($FullCLR -or $CoreWindows -or $CoreUnix)
"Cmdlet", "Debug-Process",                                      ,                     $($FullCLR -or $CoreWindows -or $CoreUnix)
"Cmdlet", "Debug-Runspace",                                     ,                     $($FullCLR -or $CoreWindows -or $CoreUnix)
"Cmdlet", "Disable-ComputerRestore",                            ,                     $($FullCLR                               )
"Cmdlet", "Disable-PSBreakpoint",                               ,                     $($FullCLR -or $CoreWindows -or $CoreUnix)
"Cmdlet", "Disable-PSRemoting",                                 ,                     $($FullCLR                               )
"Cmdlet", "Disable-PSSessionConfiguration",                     ,                     $($FullCLR -or $CoreWindows -or $CoreUnix)
"Cmdlet", "Disable-RunspaceDebug",                              ,                     $($FullCLR -or $CoreWindows -or $CoreUnix)
"Cmdlet", "Disable-WSManCredSSP",                               ,                     $($FullCLR -or $CoreWindows              )
"Cmdlet", "Disconnect-PSSession",                               ,                     $($FullCLR -or $CoreWindows -or $CoreUnix)
"Cmdlet", "Disconnect-WSMan",                                   ,                     $($FullCLR -or $CoreWindows              )
"Cmdlet", "Enable-ComputerRestore",                             ,                     $($FullCLR                               )
"Cmdlet", "Enable-PSBreakpoint",                                ,                     $($FullCLR -or $CoreWindows -or $CoreUnix)
"Cmdlet", "Enable-PSRemoting",                                  ,                     $($FullCLR                               )
"Cmdlet", "Enable-PSSessionConfiguration",                      ,                     $($FullCLR -or $CoreWindows -or $CoreUnix)
"Cmdlet", "Enable-RunspaceDebug",                               ,                     $($FullCLR -or $CoreWindows -or $CoreUnix)
"Cmdlet", "Enable-WSManCredSSP",                                ,                     $($FullCLR -or $CoreWindows              )
"Cmdlet", "Enter-PSHostProcess",                                ,                     $($FullCLR -or $CoreWindows -or $CoreUnix)
"Cmdlet", "Enter-PSSession",                                    ,                     $($FullCLR -or $CoreWindows -or $CoreUnix)
"Cmdlet", "Exit-PSHostProcess",                                 ,                     $($FullCLR -or $CoreWindows -or $CoreUnix)
"Cmdlet", "Exit-PSSession",                                     ,                     $($FullCLR -or $CoreWindows -or $CoreUnix)
"Cmdlet", "Export-Alias",                                       ,                     $($FullCLR -or $CoreWindows -or $CoreUnix)
"Cmdlet", "Export-Clixml",                                      ,                     $($FullCLR -or $CoreWindows -or $CoreUnix)
"Cmdlet", "Export-Console",                                     ,                     $($FullCLR                               )
"Cmdlet", "Export-Counter",                                     ,                     $($FullCLR -or $CoreWindows              )
"Cmdlet", "Export-Csv",                                         ,                     $($FullCLR -or $CoreWindows -or $CoreUnix)
"Cmdlet", "Export-FormatData",                                  ,                     $($FullCLR -or $CoreWindows -or $CoreUnix)
"Cmdlet", "Export-ModuleMember",                                ,                     $($FullCLR -or $CoreWindows -or $CoreUnix)
"Cmdlet", "Export-PSSession",                                   ,                     $($FullCLR -or $CoreWindows -or $CoreUnix)
"Cmdlet", "ForEach-Object",                                     ,                     $($FullCLR -or $CoreWindows -or $CoreUnix)
"Cmdlet", "Format-Custom",                                      ,                     $($FullCLR -or $CoreWindows -or $CoreUnix)
"Cmdlet", "Format-Default",                                     ,                     $($FullCLR                               )
"Cmdlet", "Format-Hex",                                         ,                     $(             $CoreWindows -or $CoreUnix)
"Cmdlet", "Format-List",                                        ,                     $($FullCLR -or $CoreWindows -or $CoreUnix)
"Cmdlet", "Format-Table",                                       ,                     $($FullCLR -or $CoreWindows -or $CoreUnix)
"Cmdlet", "Format-Wide",                                        ,                     $($FullCLR -or $CoreWindows -or $CoreUnix)
"Cmdlet", "Get-Acl",                                            ,                     $($FullCLR -or $CoreWindows              )
"Cmdlet", "Get-Alias",                                          ,                     $($FullCLR -or $CoreWindows -or $CoreUnix)
"Cmdlet", "Get-AuthenticodeSignature",                          ,                     $($FullCLR -or $CoreWindows              )
"Cmdlet", "Get-ChildItem",                                      ,                     $($FullCLR -or $CoreWindows -or $CoreUnix)
"Cmdlet", "Get-Clipboard",                                      ,                     $($FullCLR                               )
"Cmdlet", "Get-CmsMessage",                                     ,                     $($FullCLR -or $CoreWindows              )
"Cmdlet", "Get-Command",                                        ,                     $($FullCLR -or $CoreWindows -or $CoreUnix)
"Cmdlet", "Get-ComputerInfo",                                   ,                     $($FullCLR -or $CoreWindows              )
"Cmdlet", "Get-ComputerRestorePoint",                           ,                     $($FullCLR                               )
"Cmdlet", "Get-Content",                                        ,                     $($FullCLR -or $CoreWindows -or $CoreUnix)
"Cmdlet", "Get-ControlPanelItem",                               ,                     $($FullCLR                               )
"Cmdlet", "Get-Counter",                                        ,                     $($FullCLR -or $CoreWindows              )
"Cmdlet", "Get-Credential",                                     ,                     $($FullCLR -or $CoreWindows -or $CoreUnix)
"Cmdlet", "Get-Culture",                                        ,                     $($FullCLR -or $CoreWindows -or $CoreUnix)
"Cmdlet", "Get-Date",                                           ,                     $($FullCLR -or $CoreWindows -or $CoreUnix)
"Cmdlet", "Get-Event",                                          ,                     $($FullCLR -or $CoreWindows -or $CoreUnix)
"Cmdlet", "Get-EventLog",                                       ,                     $($FullCLR                               )
"Cmdlet", "Get-EventSubscriber",                                ,                     $($FullCLR -or $CoreWindows -or $CoreUnix)
"Cmdlet", "Get-ExecutionPolicy",                                ,                     $($FullCLR -or $CoreWindows -or $CoreUnix)
"Cmdlet", "Get-FileHash",                                       ,                     $(             $CoreWindows -or $CoreUnix)
"Cmdlet", "Get-FormatData",                                     ,                     $($FullCLR -or $CoreWindows -or $CoreUnix)
"Cmdlet", "Get-Help",                                           ,                     $($FullCLR -or $CoreWindows -or $CoreUnix)
"Cmdlet", "Get-History",                                        ,                     $($FullCLR -or $CoreWindows -or $CoreUnix)
"Cmdlet", "Get-Host",                                           ,                     $($FullCLR -or $CoreWindows -or $CoreUnix)
"Cmdlet", "Get-HotFix",                                         ,                     $($FullCLR                               )
"Cmdlet", "Get-Item",                                           ,                     $($FullCLR -or $CoreWindows -or $CoreUnix)
"Cmdlet", "Get-ItemProperty",                                   ,                     $($FullCLR -or $CoreWindows -or $CoreUnix)
"Cmdlet", "Get-ItemPropertyValue",                              ,                     $($FullCLR -or $CoreWindows -or $CoreUnix)
"Cmdlet", "Get-Job",                                            ,                     $($FullCLR -or $CoreWindows -or $CoreUnix)
"Cmdlet", "Get-Location",                                       ,                     $($FullCLR -or $CoreWindows -or $CoreUnix)
"Cmdlet", "Get-Member",                                         ,                     $($FullCLR -or $CoreWindows -or $CoreUnix)
"Cmdlet", "Get-Module",                                         ,                     $($FullCLR -or $CoreWindows -or $CoreUnix)
"Cmdlet", "Get-PfxCertificate",                                 ,                     $($FullCLR -or $CoreWindows -or $CoreUnix)
"Cmdlet", "Get-Process",                                        ,                     $($FullCLR -or $CoreWindows -or $CoreUnix)
"Cmdlet", "Get-PSBreakpoint",                                   ,                     $($FullCLR -or $CoreWindows -or $CoreUnix)
"Cmdlet", "Get-PSCallStack",                                    ,                     $($FullCLR -or $CoreWindows -or $CoreUnix)
"Cmdlet", "Get-PSDrive",                                        ,                     $($FullCLR -or $CoreWindows -or $CoreUnix)
"Cmdlet", "Get-PSHostProcessInfo",                              ,                     $($FullCLR -or $CoreWindows -or $CoreUnix)
"Cmdlet", "Get-PSProvider",                                     ,                     $($FullCLR -or $CoreWindows -or $CoreUnix)
"Cmdlet", "Get-PSSession",                                      ,                     $($FullCLR -or $CoreWindows -or $CoreUnix)
"Cmdlet", "Get-PSSessionCapability",                            ,                     $($FullCLR -or $CoreWindows -or $CoreUnix)
"Cmdlet", "Get-PSSessionConfiguration",                         ,                     $($FullCLR -or $CoreWindows -or $CoreUnix)
"Cmdlet", "Get-PSSnapin",                                       ,                     $($FullCLR                               )
"Cmdlet", "Get-Random",                                         ,                     $($FullCLR -or $CoreWindows -or $CoreUnix)
"Cmdlet", "Get-Runspace",                                       ,                     $($FullCLR -or $CoreWindows -or $CoreUnix)
"Cmdlet", "Get-RunspaceDebug",                                  ,                     $($FullCLR -or $CoreWindows -or $CoreUnix)
"Cmdlet", "Get-Service",                                        ,                     $($FullCLR -or $CoreWindows              )
"Cmdlet", "Get-TimeZone",                                       ,                     $($FullCLR -or $CoreWindows -or $CoreUnix)
"Cmdlet", "Get-TraceSource",                                    ,                     $($FullCLR -or $CoreWindows -or $CoreUnix)
"Cmdlet", "Get-Transaction",                                    ,                     $($FullCLR                               )
"Cmdlet", "Get-TypeData",                                       ,                     $($FullCLR -or $CoreWindows -or $CoreUnix)
"Cmdlet", "Get-Uptime",                                         ,                     $(             $CoreWindows -or $CoreUnix)
"Cmdlet", "Get-UICulture",                                      ,                     $($FullCLR -or $CoreWindows -or $CoreUnix)
"Cmdlet", "Get-Unique",                                         ,                     $($FullCLR -or $CoreWindows -or $CoreUnix)
"Cmdlet", "Get-Variable",                                       ,                     $($FullCLR -or $CoreWindows -or $CoreUnix)
"Cmdlet", "Get-Verb",                                           ,                     $($FullCLR -or $CoreWindows -or $CoreUnix)
"Cmdlet", "Get-WinEvent",                                       ,                     $($FullCLR -or $CoreWindows              )
"Cmdlet", "Get-WmiObject",                                      ,                     $($FullCLR                               )
"Cmdlet", "Get-WSManCredSSP",                                   ,                     $($FullCLR -or $CoreWindows              )
"Cmdlet", "Get-WSManInstance",                                  ,                     $($FullCLR -or $CoreWindows              )
"Cmdlet", "Group-Object",                                       ,                     $($FullCLR -or $CoreWindows -or $CoreUnix)
"Cmdlet", "Import-Alias",                                       ,                     $($FullCLR -or $CoreWindows -or $CoreUnix)
"Cmdlet", "Import-Clixml",                                      ,                     $($FullCLR -or $CoreWindows -or $CoreUnix)
"Cmdlet", "Import-Counter",                                     ,                     $($FullCLR -or $CoreWindows              )
"Cmdlet", "Import-Csv",                                         ,                     $($FullCLR -or $CoreWindows -or $CoreUnix)
"Cmdlet", "Import-LocalizedData",                               ,                     $($FullCLR -or $CoreWindows -or $CoreUnix)
"Cmdlet", "Import-Module",                                      ,                     $($FullCLR -or $CoreWindows -or $CoreUnix)
"Cmdlet", "Import-PowerShellDataFile",                          ,                     $($FullCLR -or $CoreWindows -or $CoreUnix)
"Cmdlet", "Import-PSSession",                                   ,                     $($FullCLR -or $CoreWindows -or $CoreUnix)
"Cmdlet", "Invoke-Command",                                     ,                     $($FullCLR -or $CoreWindows -or $CoreUnix)
"Cmdlet", "Invoke-Expression",                                  ,                     $($FullCLR -or $CoreWindows -or $CoreUnix)
"Cmdlet", "Invoke-History",                                     ,                     $($FullCLR -or $CoreWindows -or $CoreUnix)
"Cmdlet", "Invoke-Item",                                        ,                     $($FullCLR -or $CoreWindows -or $CoreUnix)
"Cmdlet", "Invoke-RestMethod",                                  ,                     $($FullCLR -or $CoreWindows -or $CoreUnix)
"Cmdlet", "Invoke-WebRequest",                                  ,                     $($FullCLR -or $CoreWindows -or $CoreUnix)
"Cmdlet", "Invoke-WmiMethod",                                   ,                     $($FullCLR                               )
"Cmdlet", "Invoke-WSManAction",                                 ,                     $($FullCLR -or $CoreWindows              )
"Cmdlet", "Join-Path",                                          ,                     $($FullCLR -or $CoreWindows -or $CoreUnix)
"Cmdlet", "Limit-EventLog",                                     ,                     $($FullCLR                               )
"Cmdlet", "Measure-Command",                                    ,                     $($FullCLR -or $CoreWindows -or $CoreUnix)
"Cmdlet", "Measure-Object",                                     ,                     $($FullCLR -or $CoreWindows -or $CoreUnix)
"Cmdlet", "Move-Item",                                          ,                     $($FullCLR -or $CoreWindows -or $CoreUnix)
"Cmdlet", "Move-ItemProperty",                                  ,                     $($FullCLR -or $CoreWindows -or $CoreUnix)
"Cmdlet", "New-Alias",                                          ,                     $($FullCLR -or $CoreWindows -or $CoreUnix)
"Cmdlet", "New-Event",                                          ,                     $($FullCLR -or $CoreWindows -or $CoreUnix)
"Cmdlet", "New-EventLog",                                       ,                     $($FullCLR                               )
"Cmdlet", "New-Item",                                           ,                     $($FullCLR -or $CoreWindows -or $CoreUnix)
"Cmdlet", "New-ItemProperty",                                   ,                     $($FullCLR -or $CoreWindows -or $CoreUnix)
"Cmdlet", "New-FileCatalog",                                    ,                     $($FullCLR -or $CoreWindows              )
"Cmdlet", "New-GUID",                                           ,                     $(             $CoreWindows -or $CoreUnix)
"Cmdlet", "New-Module",                                         ,                     $($FullCLR -or $CoreWindows -or $CoreUnix)
"Cmdlet", "New-ModuleManifest",                                 ,                     $($FullCLR -or $CoreWindows -or $CoreUnix)
"Cmdlet", "New-Object",                                         ,                     $($FullCLR -or $CoreWindows -or $CoreUnix)
"Cmdlet", "New-PSDrive",                                        ,                     $($FullCLR -or $CoreWindows -or $CoreUnix)
"Cmdlet", "New-PSRoleCapabilityFile",                           ,                     $(             $CoreWindows -or $CoreUnix)
"Cmdlet", "New-PSSession",                                      ,                     $($FullCLR -or $CoreWindows -or $CoreUnix)
"Cmdlet", "New-PSSessionConfigurationFile",                     ,                     $($FullCLR -or $CoreWindows -or $CoreUnix)
"Cmdlet", "New-PSSessionOption",                                ,                     $($FullCLR -or $CoreWindows -or $CoreUnix)
"Cmdlet", "New-PSTransportOption",                              ,                     $($FullCLR -or $CoreWindows -or $CoreUnix)
"Cmdlet", "New-Service",                                        ,                     $($FullCLR -or $CoreWindows              )
"Cmdlet", "New-TemporaryFile",                                  ,                     $(             $CoreWindows -or $CoreUnix)
"Cmdlet", "New-TimeSpan",                                       ,                     $($FullCLR -or $CoreWindows -or $CoreUnix)
"Cmdlet", "New-Variable",                                       ,                     $($FullCLR -or $CoreWindows -or $CoreUnix)
"Cmdlet", "New-WebServiceProxy",                                ,                     $($FullCLR                               )
"Cmdlet", "New-WinEvent",                                       ,                     $($FullCLR -or $CoreWindows              )
"Cmdlet", "New-WSManInstance",                                  ,                     $($FullCLR -or $CoreWindows              )
"Cmdlet", "New-WSManSessionOption",                             ,                     $($FullCLR -or $CoreWindows              )
"Cmdlet", "Out-Default",                                        ,                     $($FullCLR -or $CoreWindows -or $CoreUnix)
"Cmdlet", "Out-File",                                           ,                     $($FullCLR -or $CoreWindows -or $CoreUnix)
"Cmdlet", "Out-GridView",                                       ,                     $($FullCLR                               )
"Cmdlet", "Out-Host",                                           ,                     $($FullCLR -or $CoreWindows -or $CoreUnix)
"Cmdlet", "Out-LineOutput",                                     ,                     $($FullCLR                               )
"Cmdlet", "Out-Null",                                           ,                     $($FullCLR -or $CoreWindows -or $CoreUnix)
"Cmdlet", "Out-Printer",                                        ,                     $($FullCLR                               )
"Cmdlet", "Out-String",                                         ,                     $($FullCLR -or $CoreWindows -or $CoreUnix)
"Cmdlet", "Pop-Location",                                       ,                     $($FullCLR -or $CoreWindows -or $CoreUnix)
"Cmdlet", "Protect-CmsMessage",                                 ,                     $($FullCLR -or $CoreWindows              )
"Cmdlet", "Push-Location",                                      ,                     $($FullCLR -or $CoreWindows -or $CoreUnix)
"Cmdlet", "Read-Host",                                          ,                     $($FullCLR -or $CoreWindows -or $CoreUnix)
"Cmdlet", "Receive-Job",                                        ,                     $($FullCLR -or $CoreWindows -or $CoreUnix)
"Cmdlet", "Receive-PSSession",                                  ,                     $($FullCLR -or $CoreWindows -or $CoreUnix)
"Cmdlet", "Register-ArgumentCompleter",                         ,                     $($FullCLR -or $CoreWindows -or $CoreUnix)
"Cmdlet", "Register-EngineEvent",                               ,                     $($FullCLR -or $CoreWindows -or $CoreUnix)
"Cmdlet", "Register-ObjectEvent",                               ,                     $($FullCLR -or $CoreWindows -or $CoreUnix)
"Cmdlet", "Register-PSSessionConfiguration",                    ,                     $($FullCLR -or $CoreWindows -or $CoreUnix)
"Cmdlet", "Register-WmiEvent",                                  ,                     $($FullCLR                               )
"Cmdlet", "Remove-Computer",                                    ,                     $($FullCLR                               )
"Cmdlet", "Remove-Event",                                       ,                     $($FullCLR -or $CoreWindows -or $CoreUnix)
"Cmdlet", "Remove-EventLog",                                    ,                     $($FullCLR                               )
"Cmdlet", "Remove-Item",                                        ,                     $($FullCLR -or $CoreWindows -or $CoreUnix)
"Cmdlet", "Remove-ItemProperty",                                ,                     $($FullCLR -or $CoreWindows -or $CoreUnix)
"Cmdlet", "Remove-Job",                                         ,                     $($FullCLR -or $CoreWindows -or $CoreUnix)
"Cmdlet", "Remove-Module",                                      ,                     $($FullCLR -or $CoreWindows -or $CoreUnix)
"Cmdlet", "Remove-PSBreakpoint",                                ,                     $($FullCLR -or $CoreWindows -or $CoreUnix)
"Cmdlet", "Remove-PSDrive",                                     ,                     $($FullCLR -or $CoreWindows -or $CoreUnix)
"Cmdlet", "Remove-PSSession",                                   ,                     $($FullCLR -or $CoreWindows -or $CoreUnix)
"Cmdlet", "Remove-PSSnapin",                                    ,                     $($FullCLR                               )
"Cmdlet", "Remove-TypeData",                                    ,                     $($FullCLR -or $CoreWindows -or $CoreUnix)
"Cmdlet", "Remove-Variable",                                    ,                     $($FullCLR -or $CoreWindows -or $CoreUnix)
"Cmdlet", "Remove-WmiObject",                                   ,                     $($FullCLR                               )
"Cmdlet", "Remove-WSManInstance",                               ,                     $($FullCLR -or $CoreWindows              )
"Cmdlet", "Rename-Computer",                                    ,                     $($FullCLR -or $CoreWindows              )
"Cmdlet", "Rename-Item",                                        ,                     $($FullCLR -or $CoreWindows -or $CoreUnix)
"Cmdlet", "Rename-ItemProperty",                                ,                     $($FullCLR -or $CoreWindows -or $CoreUnix)
"Cmdlet", "Reset-ComputerMachinePassword",                      ,                     $($FullCLR                               )
"Cmdlet", "Resolve-Path",                                       ,                     $($FullCLR -or $CoreWindows -or $CoreUnix)
"Cmdlet", "Restart-Computer",                                   ,                     $($FullCLR -or $CoreWindows              )
"Cmdlet", "Restart-Service",                                    ,                     $($FullCLR -or $CoreWindows              )
"Cmdlet", "Restore-Computer",                                   ,                     $($FullCLR                               )
"Cmdlet", "Resume-Job",                                         ,                     $($FullCLR                               )
"Cmdlet", "Resume-Service",                                     ,                     $($FullCLR -or $CoreWindows              )
"Cmdlet", "Save-Help",                                          ,                     $($FullCLR -or $CoreWindows -or $CoreUnix)
"Cmdlet", "Select-Object",                                      ,                     $($FullCLR -or $CoreWindows -or $CoreUnix)
"Cmdlet", "Select-String",                                      ,                     $($FullCLR -or $CoreWindows -or $CoreUnix)
"Cmdlet", "Select-Xml",                                         ,                     $($FullCLR -or $CoreWindows -or $CoreUnix)
"Cmdlet", "Send-MailMessage",                                   ,                     $($FullCLR                               )
"Cmdlet", "Set-Acl",                                            ,                     $($FullCLR -or $CoreWindows              )
"Cmdlet", "Set-Alias",                                          ,                     $($FullCLR -or $CoreWindows -or $CoreUnix)
"Cmdlet", "Set-AuthenticodeSignature",                          ,                     $($FullCLR -or $CoreWindows              )
"Cmdlet", "Set-Clipboard",                                      ,                     $($FullCLR                               )
"Cmdlet", "Set-Content",                                        ,                     $($FullCLR -or $CoreWindows -or $CoreUnix)
"Cmdlet", "Set-Date",                                           ,                     $($FullCLR -or $CoreWindows -or $CoreUnix)
"Cmdlet", "Set-ExecutionPolicy",                                ,                     $($FullCLR -or $CoreWindows -or $CoreUnix)
"Cmdlet", "Set-Item",                                           ,                     $($FullCLR -or $CoreWindows -or $CoreUnix)
"Cmdlet", "Set-ItemProperty",                                   ,                     $($FullCLR -or $CoreWindows -or $CoreUnix)
"Cmdlet", "Set-Location",                                       ,                     $($FullCLR -or $CoreWindows -or $CoreUnix)
"Cmdlet", "Set-PSBreakpoint",                                   ,                     $($FullCLR -or $CoreWindows -or $CoreUnix)
"Cmdlet", "Set-PSDebug",                                        ,                     $($FullCLR -or $CoreWindows -or $CoreUnix)
"Cmdlet", "Set-PSSessionConfiguration",                         ,                     $($FullCLR -or $CoreWindows -or $CoreUnix)
"Cmdlet", "Set-Service",                                        ,                     $($FullCLR -or $CoreWindows              )
"Cmdlet", "Set-StrictMode",                                     ,                     $($FullCLR -or $CoreWindows -or $CoreUnix)
"Cmdlet", "Set-TimeZone",                                       ,                     $($FullCLR -or $CoreWindows              )
"Cmdlet", "Set-TraceSource",                                    ,                     $($FullCLR -or $CoreWindows -or $CoreUnix)
"Cmdlet", "Set-Variable",                                       ,                     $($FullCLR -or $CoreWindows -or $CoreUnix)
"Cmdlet", "Set-WmiInstance",                                    ,                     $($FullCLR                               )
"Cmdlet", "Set-WSManInstance",                                  ,                     $($FullCLR -or $CoreWindows              )
"Cmdlet", "Set-WSManQuickConfig",                               ,                     $($FullCLR -or $CoreWindows              )
"Cmdlet", "Show-Command",                                       ,                     $($FullCLR                               )
"Cmdlet", "Show-ControlPanelItem",                              ,                     $($FullCLR                               )
"Cmdlet", "Show-EventLog",                                      ,                     $($FullCLR                               )
"Cmdlet", "Sort-Object",                                        ,                     $($FullCLR -or $CoreWindows -or $CoreUnix)
"Cmdlet", "Split-Path",                                         ,                     $($FullCLR -or $CoreWindows -or $CoreUnix)
"Cmdlet", "Start-Job",                                          ,                     $($FullCLR -or $CoreWindows -or $CoreUnix)
"Cmdlet", "Start-Process",                                      ,                     $($FullCLR -or $CoreWindows -or $CoreUnix)
"Cmdlet", "Start-Service",                                      ,                     $($FullCLR -or $CoreWindows              )
"Cmdlet", "Start-Sleep",                                        ,                     $($FullCLR -or $CoreWindows -or $CoreUnix)
"Cmdlet", "Start-Transaction",                                  ,                     $($FullCLR                               )
"Cmdlet", "Start-Transcript",                                   ,                     $($FullCLR -or $CoreWindows -or $CoreUnix)
"Cmdlet", "Stop-Computer",                                      ,                     $($FullCLR -or $CoreWindows              )
"Cmdlet", "Stop-Job",                                           ,                     $($FullCLR -or $CoreWindows -or $CoreUnix)
"Cmdlet", "Stop-Process",                                       ,                     $($FullCLR -or $CoreWindows -or $CoreUnix)
"Cmdlet", "Stop-Service",                                       ,                     $($FullCLR -or $CoreWindows              )
"Cmdlet", "Stop-Transcript",                                    ,                     $($FullCLR -or $CoreWindows -or $CoreUnix)
"Cmdlet", "Suspend-Job",                                        ,                     $($FullCLR                               )
"Cmdlet", "Suspend-Service",                                    ,                     $($FullCLR -or $CoreWindows              )
"Cmdlet", "Tee-Object",                                         ,                     $($FullCLR -or $CoreWindows -or $CoreUnix)
"Cmdlet", "Test-ComputerSecureChannel",                         ,                     $($FullCLR                               )
"Cmdlet", "Test-Connection",                                    ,                     $($FullCLR -or $CoreWindows              )
"Cmdlet", "Test-FileCatalog",                                   ,                     $($FullCLR -or $CoreWindows              )
"Cmdlet", "Test-ModuleManifest",                                ,                     $($FullCLR -or $CoreWindows -or $CoreUnix)
"Cmdlet", "Test-Path",                                          ,                     $($FullCLR -or $CoreWindows -or $CoreUnix)
"Cmdlet", "Test-PSSessionConfigurationFile",                    ,                     $($FullCLR -or $CoreWindows -or $CoreUnix)
"Cmdlet", "Test-WSMan",                                         ,                     $($FullCLR -or $CoreWindows              )
"Cmdlet", "Trace-Command",                                      ,                     $($FullCLR -or $CoreWindows -or $CoreUnix)
"Cmdlet", "Unblock-File",                                       ,                     $($FullCLR -or $CoreWindows              )
"Cmdlet", "Undo-Transaction",                                   ,                     $($FullCLR                               )
"Cmdlet", "Unprotect-CmsMessage",                               ,                     $($FullCLR -or $CoreWindows              )
"Cmdlet", "Unregister-Event",                                   ,                     $($FullCLR -or $CoreWindows -or $CoreUnix)
"Cmdlet", "Unregister-PSSessionConfiguration",                  ,                     $($FullCLR -or $CoreWindows -or $CoreUnix)
"Cmdlet", "Update-FormatData",                                  ,                     $($FullCLR -or $CoreWindows -or $CoreUnix)
"Cmdlet", "Update-Help",                                        ,                     $($FullCLR -or $CoreWindows -or $CoreUnix)
"Cmdlet", "Update-List",                                        ,                     $($FullCLR                               )
"Cmdlet", "Update-TypeData",                                    ,                     $($FullCLR -or $CoreWindows -or $CoreUnix)
"Cmdlet", "Use-Transaction",                                    ,                     $($FullCLR                               )
"Cmdlet", "Wait-Debugger",                                      ,                     $($FullCLR -or $CoreWindows -or $CoreUnix)
"Cmdlet", "Wait-Event",                                         ,                     $($FullCLR -or $CoreWindows -or $CoreUnix)
"Cmdlet", "Wait-Job",                                           ,                     $($FullCLR -or $CoreWindows -or $CoreUnix)
"Cmdlet", "Wait-Process",                                       ,                     $($FullCLR -or $CoreWindows -or $CoreUnix)
"Cmdlet", "Where-Object",                                       ,                     $($FullCLR -or $CoreWindows -or $CoreUnix)
"Cmdlet", "Write-Debug",                                        ,                     $($FullCLR -or $CoreWindows -or $CoreUnix)
"Cmdlet", "Write-Error",                                        ,                     $($FullCLR -or $CoreWindows -or $CoreUnix)
"Cmdlet", "Write-EventLog",                                     ,                     $($FullCLR                               )
"Cmdlet", "Write-Host",                                         ,                     $($FullCLR -or $CoreWindows -or $CoreUnix)
"Cmdlet", "Write-Information",                                  ,                     $($FullCLR -or $CoreWindows -or $CoreUnix)
"Cmdlet", "Write-Output",                                       ,                     $($FullCLR -or $CoreWindows -or $CoreUnix)
"Cmdlet", "Write-Progress",                                     ,                     $($FullCLR -or $CoreWindows -or $CoreUnix)
"Cmdlet", "Write-Verbose",                                      ,                     $($FullCLR -or $CoreWindows -or $CoreUnix)
"Cmdlet", "Write-Warning",                                      ,                     $($FullCLR -or $CoreWindows -or $CoreUnix)
"@

            # We control only default engine aliases (Source -eq "") and aliases from following default loaded modules
            # We control only default engine Cmdlets (Source -eq "") and Cmdlets from following default loaded modules
            $moduleList = @("Microsoft.PowerShell.Utility", "Microsoft.PowerShell.Management", "Microsoft.PowerShell.Security", "Microsoft.PowerShell.Host", "Microsoft.PowerShell.Diagnostics", "PSWorkflow", "Microsoft.WSMan.Management", "Microsoft.PowerShell.Core")
            Import-Module -Name $moduleList -ErrorAction SilentlyContinue
            $currentAliasList = Get-Alias | Where-Object { $_.Source -eq "" -or $moduleList -contains $_.Source }

            $commandList  = $commandString | ConvertFrom-CSV -Delimiter ","
            $aliasFullList  = $commandList | Where-Object { $_.Present -eq "True" -and $_.CommandType -eq "Alias"  }
    }

    It "All approved aliases present (no new aliases added, no aliases removed)" {
        $currentDisplayNameAliasList = $currentAliasList | Select-Object -ExpandProperty DisplayName
        $aliasDisplayNameAliasList  = $aliasFullList | ForEach-Object { "{0} -> {1}" -f $_.Name, $_.Definition}

        $result = Compare-Object -ReferenceObject $currentDisplayNameAliasList -DifferenceObject $aliasDisplayNameAliasList

        # Below 'Should Be' don't show full list wrong aliases so we output them explicitly
        # if all aliases is Ok we output nothing
        $result | Write-Host
        $result | Should Be $null
    }

    It "All approved aliases have the correct 'AllScope' option" {
        $aliasAllScopeOptionList = $aliasFullList | Where-Object { $_.AllScopeOption -eq "AllScope"} | ForEach-Object { "{0} -> {1}" -f $_.Name, $_.Definition}
        $currentAllScopeOptionList = $currentAliasList | Where-Object { $_.Options -band [System.Management.Automation.ScopedItemOptions]::AllScope } | Select-Object -ExpandProperty DisplayName

        $result = Compare-Object -ReferenceObject $currentAllScopeOptionList -DifferenceObject  $aliasAllScopeOptionList

        # Below 'Should Be' don't show full list wrong aliases so we output them explicitly
        # if all aliases is Ok we output nothing
        $result | Write-Host
        $result | Should Be $null
    }

    It "All approved aliases have the correct 'ReadOnly' option" {
        $aliasReadOnlyOptionList = $aliasFullList | Where-Object { $_.ReadOnlyOption -eq "ReadOnly"} | ForEach-Object { "{0} -> {1}" -f $_.Name, $_.Definition}
        $currentReadOnlyOptionList = $currentAliasList | Where-Object { $_.Options -band [System.Management.Automation.ScopedItemOptions]::ReadOnly } | Select-Object -ExpandProperty DisplayName

        $result = Compare-Object -ReferenceObject $currentReadOnlyOptionList -DifferenceObject  $aliasReadOnlyOptionList

        # Below 'Should Be' don't show full list wrong aliases so we output them explicitly
        # if all aliases is Ok we output nothing
        $result | Write-Host
        $result | Should Be $null
    }

    It "All approved Cmdlets present (no new Cmdlets added, no Cmdlets removed)" {
        $cmdletList = $commandList | Where-Object { $_.Present -eq "True" -and $_.CommandType -eq "Cmdlet" } | Select-Object -ExpandProperty Name
        $currentCmdletList = (Get-Command -CommandType Cmdlet | Where-Object { $moduleList -contains $_.Source }).Name

        $result = Compare-Object -ReferenceObject $currentCmdletList -DifferenceObject $cmdletList

        # Below 'Should Be' don't show full list wrong Cmdlets so we output them explicitly
        # if all Cmdlets is Ok we output nothing
        $result | Write-Host
        $result | Should Be $null
    }

    It "Should have 'more' as a function" {
        Test-Path Function:more | Should Be $true
    }
}
