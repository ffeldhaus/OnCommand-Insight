# OCI Examples
$OciExamples=@{}

$OciExamples['Add-OciPatches'] = @"
"@

$OciExamples['Add-OciUsers'] = @"
"@

$OciExamples['Approve-OciPatch'] = @"
    .EXAMPLE
    Approve-OciPatch -Id 1
"@

$OciExamples['Delete-OciUser'] = @"
    .EXAMPLE
    Delete-OciUser -id 1
"@

$OciExamples['Get-OciAcquisitionUnit'] = @"
    .EXAMPLE
    Get-OciAcquisitionUnit -id 1

    id               : 1
    self             : /rest/v1/admin/acquisitionUnits/1
    name             : local
    ip               : 192.168.222.138
    status           : CONNECTED
    isActive         : True
    leaseContract    : 120000
    nextLeaseRenewal : 2015-08-17T21:19:46+0200
    lastReported     : 2015-08-17T21:17:41+0200
"@

$OciExamples['Get-OciAcquisitionUnits'] = @"
    .EXAMPLE
    Get-OciAcquisitionUnits

    id               : 1
    self             : /rest/v1/admin/acquisitionUnits/1
    name             : local
    ip               : 192.168.222.138
    status           : CONNECTED
    isActive         : True
    leaseContract    : 120000
    nextLeaseRenewal : 2015-08-17T21:18:46+0200
    lastReported     : 2015-08-17T21:16:52+0200
"@

$OciExamples['Get-OciActivePatchByDatasource'] = @"
    .EXAMPLE
    Get-OciActivePatchByDatasource -id 1
    .EXAMPLE
    Get-OciDatasources | Get-OciActivePatchByDatasource
"@

$OciExamples['Get-OciActivePatchByDatasource'] = @"
    .EXAMPLE
    Get-OciActivePatchByDatasource -id 1
    .EXAMPLE
    Get-OciDatasources | Get-OciActivePatchByDatasource
"@

$OciExamples['Get-OciAnnotation'] = @"
    .EXAMPLE
    Get-OciAnnotation -id 4977

    id                   : 4977
    self                 : /rest/v1/assets/annotations/4977
    name                 : Rack
    type                 : TEXT
    label                : Rack
    isUserDefined        : False
    enumValues           : {}
    supportedObjectTypes : {Host, Switch, Storage}
"@