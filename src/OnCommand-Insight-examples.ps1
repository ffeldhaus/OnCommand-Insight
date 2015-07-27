# Examples of all OCI Commands

$Credential = Get-Credential
Connect-OciServer -Name cbc-oci-01.muccbc.hq.netapp.com -Credential $Credential -Insecure

$CurrentOciServer.Timezone = [System.TimeZoneInfo]::FindSystemTimeZoneById("CEST")

## Acquisition Unit

Get-OciAcquisitionUnits

Get-OciAcquisitionUnit -id 1

Get-OciDatasourcesByAcquisitionUnit -id 1

# Restart-OciAcquisitionUnit -id 1
# Works
# TODO: Documentation should contain details on results

## Datasource

Get-OciDatasources

Get-OciDatasourceEventDetails -id 37
# should work, no event details available in test environment

# Remove-OciDatasource -id 37
# not tested, should work

Get-OciDatasource -id 37

Get-OciActivePatchByDatasource -id 37

Get-OciDatasourceChanges -id 37
# TODO: Documentation should contain details on results

Get-OciDatasourceDevices -id 37

Get-OciDatasourceEvents -id 37

Get-OciDatasourceNote -id 37

Update-OciDatasourceNote -id 37 -value "Test"
# TODO: Ask developers how to update note! REST Documentation should be updated to include information on body!

Get-OciDatasourcePackageStatus -id 37

Poll-OciDatasource -id 37

Suspend-OciDatasource -id 37 -Days 5

Resume-OciDatasource -id 37

Test-OciDatasource -id 37

Get-OciLicenses

Replace-OciLicenses
/rest/v1/admin/licenses
# TODO: Get implementation details and then implement

Update-OciLicenses
/rest/v1/admin/licenses
# TODO: Get implementation details and then implement

Get-OciPatches
/rest/v1/admin/patches
# Todo: Test

Add-OciPatches
/rest/v1/admin/patches
# TODO: Get implementation details and then implement

Get-OciPatch -id 1
/rest/v1/admin/patches/{id}
# Todo: Test

Update-OciPatch -id 1
/rest/v1/admin/patches/{id}
# TODO: Get implementation details and then implement

Approve-OciPatch -id 1
/rest/v1/admin/patches/{id}/approve
# Todo: Test

Get-OciPatchDatasources
/rest/v1/admin/patches/{id}/datasourceConclusions
# Todo: Test

Update-OciPatchNote
/rest/v1/admin/patches/{id}/note
# TODO: Get implementation details and then implement

Rollback-OciPatch
/rest/v1/admin/patches/{id}/rollback
# TODO: Get implementation details and then implement

Get-OciUsers
/rest/v1/admin/users

Add-OciUsers
/rest/v1/admin/users
# TODO: Get implementation details and then implement

Get-OciCurrentUser

# Delete-OciUser
# Todo: Test

Get-OciUser -id 1

Update-OciUser -id 1
/rest/v1/admin/users/{id}
# TODO: Get implementation details and then implement

Get-OciAnnotations

Get-OciAnnotation -id 4975

Get-OciAnnotationValues -id 4975

Update-OciAnnotationValues
/rest/v1/assets/annotations/{id}/values
# TODO: Get implementation details and then implement

Get-OciAnnotationValuesByObjectType
/rest/v1/assets/annotations/{id}/values/{objectType}
# TODO: Get implementation details and then implement

Get-OciDefinitionValuesByObjectTypeAndValue
/rest/v1/assets/annotations/{id}/values/{objectType}/{value}
# TODO: Get implementation details and then implement

Get-OciApplications

Get-OciApplication -id 122247

Get-OciComputeResourcesByApplication -id 122247

Get-OciStorageResourcesByApplication -id 122232
/rest/v1/assets/applications/{id}/storageResources
# Todo: Test

Get-OciDatastores

Get-OciDatastore -id 9222793051668263187
/rest/v1/assets/dataStores/{id}
# Todo: Test

Remove-OciAnnotationsByDatastore
/rest/v1/assets/dataStores/{id}/annotations
# Todo: Test

Get-OciAnnotationsByDatastore
/rest/v1/assets/dataStores/{id}/annotations
# Todo: Test

Update-OciAnnotationsByDatastore
/rest/v1/assets/dataStores/{id}/annotations
# Todo: Test

Get-OciHostsByDatastore
/rest/v1/assets/dataStores/{id}/hosts
# Todo: Test

Get-OciDatastorePerformance
/rest/v1/assets/dataStores/{id}/performance
# Todo: Test

Get-OciStorageResourcesByDatastore
/rest/v1/assets/dataStores/{id}/storageResources
# Todo: Test

Get-OciVmdksByDatastore
/rest/v1/assets/dataStores/{id}/vmdks

# why is there no Get-OciDisks?

Get-OciDisk
/rest/v1/assets/disks/{id}
# Todo: Test

Remove-OciAnnotationsByDisk
/rest/v1/assets/disks/{id}/annotations
# Todo: Test

Get-OciAnnotationsByDisk
/rest/v1/assets/disks/{id}/annotations
# Todo: Test

Update-OciAnnotationsByDisk
/rest/v1/assets/disks/{id}/annotations
# Todo: Test

Get-OciBackendVolumesByDisk
/rest/v1/assets/disks/{id}/backendVolumes
# Todo: Test

Get-OciDiskPerformance
/rest/v1/assets/disks/{id}/performance
# Todo: Test

Get-OciStoragePoolsByDisk
/rest/v1/assets/disks/{id}/storagePools
# Todo: Test

Get-OciStorageResourcesByDisk
/rest/v1/assets/disks/{id}/storageResources
# Todo: Test

Get-OciFabrics

Get-OciFabric -id 2246

Get-OciPortsByFabric -id 2246
/rest/v1/assets/fabrics/{id}/ports
# Todo: Implement Limit and Sort

Get-OciSwitchesByFabric -id 2246
/rest/v1/assets/fabrics/{id}/switches
# Todo: Test

Get-OciFilesystem
/rest/v1/assets/fileSystems/{id}
# Todo: Test

Get-OciComputeResourceByFileSystem
/rest/v1/assets/fileSystems/{id}/computeResource
# Todo: Test

Get-OciStorageResorcesByFileSystem
/rest/v1/assets/fileSystems/{id}/storageResources
# Todo: Test

Get-OciVmdksByFileSystem
/rest/v1/assets/fileSystems/{id}/vmdks
# Todo: Test

Get-OciHosts

Get-OciHost -id 
/rest/v1/assets/hosts/{id}
# Todo: Test

Remove-OciAnnotationsByHost
/rest/v1/assets/hosts/{id}/annotations
# Todo: Test

Get-OciAnnotationsByHost -id 129008
/rest/v1/assets/hosts/{id}/annotations
# Todo: Test

Update-OciAnnotationsByHosts
/rest/v1/assets/hosts/{id}/annotations
# Todo: Test

Get-OciApplicationsByHost
/rest/v1/assets/hosts/{id}/applications
# Todo: Test

Get-OciClusterHostsByHost -id 129008

Get-OciDataCenterByHost
/rest/v1/assets/hosts/{id}/dataCenter
# Todo: Test

Get-OciFileSystemsByHost -id 129008

Get-OciHostPerformance -id 129008

Get-OciPortsByHost
/rest/v1/assets/hosts/{id}/ports
# Todo: Test

Get-OciStorageResourcesByHost
/rest/v1/assets/hosts/{id}/storageResources
# Todo: Test

Get-OciVirtualMachinesByHost
/rest/v1/assets/hosts/{id}/virtualMachines
# Todo: Test

Get-OciInternalVolume
/rest/v1/assets/internalVolumes/{id}
# Todo: Test

Remove-OciAnnotationsByInternalVolume
/rest/v1/assets/internalVolumes/{id}/annotations
# Todo: Test

Get-OciAnnotationsByInternalVolume
/rest/v1/assets/internalVolumes/{id}/annotations
# Todo: Test

Update-OciAnnotationsByInternalVolume
/rest/v1/assets/internalVolumes/{id}/annotations
# Todo: Test

Get-OciApplicationsByInternalVolume
/rest/v1/assets/internalVolumes/{id}/applications
# Todo: Test

Get-OciComputeResourcesByInternalVolume
/rest/v1/assets/internalVolumes/{id}/computeResources
# Todo: Test

Get-OciDataStoresByInternalVolume
/rest/v1/assets/internalVolumes/{id}/dataStores
# Todo: Test

Get-OciInternalVolumePerformance
/rest/v1/assets/internalVolumes/{id}/performance
# Todo: Test

Get-OciSourceInternalVolumesByInternalVolume
/rest/v1/assets/internalVolumes/{id}/replicaSources
# Todo: Test

Get-OciStorageNodesByInternalVolume
/rest/v1/assets/internalVolumes/{id}/storageNodes
# Todo: Test

Get-OciVolumesByInternalVolume
/rest/v1/assets/internalVolumes/{id}/volumes
# Todo: Test

Get-OciPorts
/rest/v1/assets/ports/{id}
# Todo: Test

Remove-OciAnnotationsByPort
/rest/v1/assets/ports/{id}/annotations
# Todo: Test

Get-OciAnnotationsByPort
/rest/v1/assets/ports/{id}/annotations
# Todo: Test

Update-OciAnnotationsByPort
/rest/v1/assets/ports/{id}/annotations
# Todo: Test

Get-OciConnectedPortsByPort
/rest/v1/assets/ports/{id}/connectedPorts
# Todo: Test

Get-OciDeviceByPort
/rest/v1/assets/ports/{id}/device
# Todo: Test

Get-OciFabricsByPort
/rest/v1/assets/ports/{id}/fabrics
# Todo: Test

Get-OciPortPerformance
/rest/v1/assets/ports/{id}/performance
# Todo: Test

Get-OciStorageNode
/rest/v1/assets/storageNodes/{id}
# Todo: Test

Remove-OciAnnotationyByStorageNode
/rest/v1/assets/storageNodes/{id}/annotations
# Todo: Test

Get-OciAnnotationyByStorageNode
/rest/v1/assets/storageNodes/{id}/annotations
# Todo: Test

Update-OciAnnotationyByStorageNode
/rest/v1/assets/storageNodes/{id}/annotations
# Todo: Test

Get-OciStorageNodePerformance
/rest/v1/assets/storageNodes/{id}/performance
# Todo: Test

Get-OciPortsByStorageNode
/rest/v1/assets/storageNodes/{id}/ports
# Todo: Test

Get-OciStoragePoolsByNode
/rest/v1/assets/storageNodes/{id}/storagePools
# Todo: Test

Get-OciStoragePool
/rest/v1/assets/storagePools/{id}
# Todo: Test

Remove-OciAnnotationsByStoragePool
/rest/v1/assets/storagePools/{id}/annotations
# Todo: Test

Get-OciAnnotationsByStoragePool
/rest/v1/assets/storagePools/{id}/annotations
# Todo: Test

Update-OciAnnotationsByStoragePool
/rest/v1/assets/storagePools/{id}/annotations
# Todo: Test

Get-OciDisksByStoragePool
/rest/v1/assets/storagePools/{id}/disks
# Todo: Test

Get-OciInternalVolumesByStoragePool
/rest/v1/assets/storagePools/{id}/internalVolumes
# Todo: Test

Get-OciStoragePoolPerformance
/rest/v1/assets/storagePools/{id}/performance
# Todo: Test

Get-OciStorageByStoragePool
/rest/v1/assets/storagePools/{id}/storage
# Todo: Test

Get-OciStorageNodesByStoragePool
/rest/v1/assets/storagePools/{id}/storageNodes
# Todo: Test

Get-OciStorageResourcesByStoragePool
/rest/v1/assets/storagePools/{id}/storageResources
# Todo: Test

Get-OciVolumesByStoragePool
/rest/v1/assets/storagePools/{id}/volumes
# Todo: Test

Get-OciStorages
/rest/v1/assets/storages
# Todo: Test

Get-OciStorage
/rest/v1/assets/storages/{id}
# Todo: Test

Remove-OciAnnotationsByStorage
/rest/v1/assets/storages/{id}/annotations
# Todo: Test

Get-OciAnnotationsByStorage -id 118866
# Todo: Test

Update-OciAnnotationsByStorage -id 118866
# Todo: Test

Get-OciDisksByStorage -id 118866

Get-OciInternalVolumesByStorage -id 118866

Get-OciStoragePerformance -id 118866
Get-OciStoragePerformance -id 118866 -History

Get-OciPortsByStorage -id 118866

Get-OciStorageNodesByStorage -id 118866

Get-OciStoragePoolsByStorage -id 118866

Get-OciStorageResourcesByStorage -id 118866

Get-OciVolumesByStorage -id 118866

Get-OciSwitches

Get-OciSwitch -id 37122

# Remove-OciAnnotationsBySwitch -id 37122

Get-OciAnnotationsBySwitch -id 37122

# Update-OciAnnotationsBySwitch
/rest/v1/assets/switches/{id}/annotations

Get-OciFabricBySwitch -id 32480

Get-OciSwitchPerformance -id 32480

Get-OciPortsBySwitch -id 32480

Get-OciVirtualMachines

Get-OciVirtualMachine -id 9212782508076979269

# Remove-OciAnnotationsByVirtualMachine
/rest/v1/assets/virtualMachines/{id}/annotations

Get-OciAnnotationsByVirtualMachine -id 2485697109647576483

# Update-OciAnnotationsByVirtualMachine
/rest/v1/assets/virtualMachines/{id}/annotations

Get-OciApplicationsByVirtualMachine -id 2485697109647576483

Get-OciDataStoreByVirtualMachine -id 2485697109647576483

Get-OciFileSystemsByVirtualMachine -id 1601550169472768246

Get-OciHostByVirtualMachine -id 1601550169472768246

Get-OciVirtualMachinePerformance -id 1601550169472768246

Get-OciStorageResourcesByVirtualMachine -id 1601550169472768246

Get-OciVmdksByVirtualMachine -id 1601550169472768246

Get-OciVmdk -id 1411447141735558595

# Remove-OciAnnotationByVmdk -id 1
# /rest/v1/assets/vmdks/{id}/annotations

Get-OciDatastores | Get-OciVmdksByDatastore | Get-OciAnnotationsByVmdk

# Update-OciAnnotationsByVmdk -id 1
# /rest/v1/assets/vmdks/{id}/annotations

Get-OciVmdkPerformance -id 1411447141735558595

Get-OciStorageResourcesByVmdk -id 1411447141735558595

Get-OciVirtualMachineByVmdk -id 1411447141735558595

Get-OciVolume -id 124613

# Remove-OciAnnotationsByVolume -id 1
# /rest/v1/assets/volumes/{id}/annotations

Get-OciAnnotationsByVolume -id 1616

# Update-OciAnnotationsByVolume -id 1
# /rest/v1/assets/volumes/{id}/annotations

Get-OciPortsByVolume -id 65411

Get-OciSourceVolumesByVolume -id 65411

Get-OciStorageByVolume -id 65411

Get-OciStorageNodesByVolume -id 65411

Get-OciStoragePoolsByVolume -id 65411

Get-OciApplications

Get-OciAutoTierPolicyByVolume -id 1616
# TODO: Improve error handling

Get-OciComputeResourcesByVolume -id 76918

Get-OciDataStores

Get-OciInternalVolume -id 13288

Get-OciInternalVolumePerformance -id 13288