PROGRAM_TYPE equ native

include "OOP/x64.inc"
include 'ntddk.inc'
include "kdprint.inc"
include 'information.inc'
include "blacklist.inc"


importlib ntoskrnl,\
    IoCreateDevice,\
    IoCreateSymbolicLink,\
    IoDeleteDevice,\
    IoCompleteRequest,\
    IoGetCurrentIrpStackLocation,\
    IoRegisterBootDriverCallback,\
    IoUnregisterBootDriverCallback,\
    ZwCreateFile,\
    ZwClose,\
    PsCreateSystemThread,\
    KeInitializeEvent,\
    KeSetEvent,\
    KeWaitForSingleObject,\
    KeDelayExecutionThread,\
    ExAllocatePoolWithTag,\
    ExFreePoolWithTag,\
    RtlCompareMemory,\
    RtlInitUnicodeString,\
    RtlCompareUnicodeString,\
    DbgPrint

importlib cng,\
    BCryptOpenAlgorithmProvider,\
    BCryptCloseAlgorithmProvider,\
    BCryptCreateHash,\
    BCryptHashData,\
    BCryptFinishHash,\
    BCryptDestroyHash,\
    BCryptVerifySignature,\
    BCryptImportKeyPair,\
    BCryptDestroyKey

entry DriverEntry

.proc DriverUnload(.DriverObject)
    kdprint "unload called..."
    MOV    pax, [ElamCallbackHandle]
    TEST   pax, pax
    JZ     @F
    kdprint "unregistred callback..."
    $call  [IoUnregisterBootDriverCallback]([ElamCallbackHandle])
    MOV    QWORD [ElamCallbackHandle], 0
@@:
    MOV    pax, [hAlgProvider]
    TEST   pax, pax
    JZ     @F
    kdprint "close crypto provider..."
    $call  [BCryptCloseAlgorithmProvider]([hAlgProvider], 0)
    MOV    QWORD [hAlgProvider], 0
@@:
    MOV    pax, [pDeviceObject]
    TEST   pax, pax
    JZ     @F
    kdprint "delete DeviceObject..."
    $call  [IoDeleteDevice]([pDeviceObject])
    MOV    QWORD [pDeviceObject], 0
@@:
    kdprint "unloaded clean"
    $return
.endp


.proc DriverEntry(.DriverObject, .RegistryPath)
    kdprint "driver entry start..."
    MOV    pax, CreateCloseHandler
    MOV    pcx, [.DriverObject]
    MOV    [pcx + DRIVER_OBJECT.MajorFunction + IRP_MJ_CREATE * 8], pax
    MOV    [pcx + DRIVER_OBJECT.MajorFunction + IRP_MJ_CLOSE * 8], pax

    MOV    pax, IoControlHandler
    MOV    [pcx + DRIVER_OBJECT.MajorFunction + IRP_MJ_DEVICE_CONTROL * 8], pax

    MOV    pax, DriverUnload
    MOV    [pcx + DRIVER_OBJECT.DriverUnload], pax

    $call  [RtlInitUnicodeString](addr TrustedPub0, addr TrustedPub0Str)
    $call  [RtlInitUnicodeString](addr TrustedPub1, addr TrustedPub1Str)
    $call  [RtlInitUnicodeString](addr BlockedName0, addr BlockedName0Str)
    $call  [RtlInitUnicodeString](addr BlockedName1, addr BlockedName1Str)

    MOV    QWORD [GoodCount], 0
    MOV    QWORD [BadCount], 0
    MOV    QWORD [UnknownCount], 0
    MOV    DWORD [ActiveHashCount], BlacklistCount

    $call  eax = [IoCreateDevice]([.DriverObject], 0, addr DevName, FILE_DEVICE_UNKNOWN, 0, 0, addr pDeviceObject)
    TEST   eax, eax
    JS     @F

    $call  eax = [IoCreateSymbolicLink](addr SymName, addr DevName)
    TEST   eax, eax
    JS     .ERR_LINK_FAILED

    MOV    pax, [pDeviceObject]
    AND    DWORD [pax + DEVICE_OBJECT.Flags], NOT DO_DEVICE_INITIALIZING

    $call  eax = REGISTER_ELAM_CALLBACK()
    TEST   eax, eax
    JS     .ERR_LINK_FAILED

    kdprint "elam driver registred..."
    XOR    eax, eax
    $return

.ERR_LINK_FAILED:
    kdprint "init failed with code: 0x%X", eax
    $call  [IoDeleteDevice]([pDeviceObject])
@@:
    MOV    eax, STATUS_UNSUCCESSFUL
    $return
.endp


.proc REGISTER_ELAM_CALLBACK
    kdprint "registering callback..."
    $call  pax = [IoRegisterBootDriverCallback](addr ElamCallbackRoutine, 0)
    MOV    [ElamCallbackHandle], pax
    TEST   pax, pax
    JZ     .REGISTRATION_FAILED

    $call  eax = INIT_CNG_FUNCTIONS()
    TEST   eax, eax
    JS     .REGISTRATION_EXIT

    $call  eax = VerifyTrustSignature()

.REGISTRATION_EXIT:
    RET

.REGISTRATION_FAILED:
    kdprint "callback register error"
    MOV    eax, 0C0000001H
    RET
.endp


.proc INIT_CNG_FUNCTIONS
    kdprint "initialize crypto provider..."
    $call  eax = [BCryptOpenAlgorithmProvider](addr hAlgProvider, addr AlgSha256, 0, 0)
    TEST   eax, eax
    JZ     @F
    kdprint "cng provider open error: 0x%X", eax
@@:
    $return
.endp


.proc VerifyTrustSignature
    kdprint "verifying trust manifest signature..."

    $call  eax = [BCryptOpenAlgorithmProvider](addr hRsaAlgProvider, addr AlgRSA, 0, 0)
    TEST   eax, eax
    JNZ    .VERIFY_OPEN_FAILED

    $call  eax = [BCryptImportKeyPair]([hRsaAlgProvider], 0, addr RsaBlobTypeStr, addr hManifestKey, addr ManifestPublicKeyBlob, ManifestPublicKeyBlobSize, 0)
    TEST   eax, eax
    JNZ    .VERIFY_IMPORT_FAILED

    $call  eax = [BCryptCreateHash]([hAlgProvider], addr hManifestHash, 0, 0, 0, 0, 0)
    TEST   eax, eax
    JNZ    .VERIFY_HASH_FAILED

    $call  eax = [BCryptHashData]([hManifestHash], addr BlacklistTable, SignedRegionSize, 0)
    TEST   eax, eax
    JNZ    .VERIFY_HASH_FAILED

    $call  eax = [BCryptFinishHash]([hManifestHash], addr ManifestHashBuffer, HASH_SIZE, 0)
    $call  [BCryptDestroyHash]([hManifestHash])
    TEST   eax, eax
    JNZ    .VERIFY_HASH_FAILED

    LEA    pax, [AlgSha256]
    MOV    [PaddingInfo], pax

    $call  eax = [BCryptVerifySignature]([hManifestKey], addr PaddingInfo, addr ManifestHashBuffer, HASH_SIZE, addr ManifestSignature, ManifestSignatureSize, BCRYPT_PAD_PKCS1)

    $call  [BCryptDestroyKey]([hManifestKey])
    $call  [BCryptCloseAlgorithmProvider]([hRsaAlgProvider], 0)

    TEST   eax, eax
    JNZ    .VERIFY_SIGNATURE_FAILED

    kdprint "trust manifest signature valid"
    XOR    eax, eax
    RET

.VERIFY_OPEN_FAILED:
    kdprint "rsa provider open failed: 0x%X", eax
    MOV    eax, 0C0000001H
    RET

.VERIFY_IMPORT_FAILED:
    kdprint "public key import failed: 0x%X", eax
    $call  [BCryptCloseAlgorithmProvider]([hRsaAlgProvider], 0)
    MOV    eax, 0C0000001H
    RET

.VERIFY_HASH_FAILED:
    kdprint "manifest hash failed: 0x%X", eax
    $call  [BCryptDestroyKey]([hManifestKey])
    $call  [BCryptCloseAlgorithmProvider]([hRsaAlgProvider], 0)
    MOV    eax, 0C0000001H
    RET

.VERIFY_SIGNATURE_FAILED:
    kdprint "trust manifest signature INVALID: 0x%X", eax
    MOV    eax, 0C0000001H
    RET
.endp


.proc IsHashKnownBad(.pHash, .HashLen)
    MOV    pax, [.HashLen]
    CMP    eax, HASH_SIZE
    JNE    .HASH_MISMATCH

    XOR    ecx, ecx
@@:
    CMP    ecx, [ActiveHashCount]
    JGE    .HASH_MISMATCH

    MOV    eax, ecx
    IMUL   eax, HASH_SIZE
    LEA    pdx, [BlacklistTable]
    ADD    pdx, rax

    PUSH   pcx
    $call  eax = [RtlCompareMemory](pdx, [.pHash], HASH_SIZE)
    POP    pcx

    CMP    eax, HASH_SIZE
    JE     .HASH_MATCHED

    INC    ecx
    JMP    @b

.HASH_MATCHED:
    kdprint "hash matched black list index: %d", rcx
    MOV    eax, 1
    RET

.HASH_MISMATCH:
    XOR    eax, eax
    RET
.endp


.proc IsPublisherTrusted(.pPublisher)
    $call  eax = [RtlCompareUnicodeString]([.pPublisher], addr TrustedPub0, 1)
    TEST   eax, eax
    JZ     .PUBLISHER_TRUSTED

    $call  eax = [RtlCompareUnicodeString]([.pPublisher], addr TrustedPub1, 1)
    TEST   eax, eax
    JZ     .PUBLISHER_TRUSTED

    XOR    eax, eax
    RET
.PUBLISHER_TRUSTED:
    kdprint "publisher ok: %wZ", [.pPublisher]
    MOV    eax, 1
    RET
.endp


.proc IsNameBlocked(.pImageName)
    $call  eax = [RtlCompareUnicodeString]([.pImageName], addr BlockedName0, 1)
    TEST   eax, eax
    JZ     .NAME_BLOCKED

    $call  eax = [RtlCompareUnicodeString]([.pImageName], addr BlockedName1, 1)
    TEST   eax, eax
    JZ     .NAME_BLOCKED

    XOR    eax, eax
    RET
.NAME_BLOCKED:
    kdprint "name blacklisted: %wZ", [.pImageName]
    MOV    eax, 1
    RET
.endp


.proc ProcessInitializeImage(.pImageInfo)
    virtObj .info BDCB_IMAGE_INFORMATION at pcx from [.pImageInfo]

    kdprint "checking file: %wZ", [.info.ImageName]

    MOV    pdx, [.info.ImageName]
    $call  eax = IsNameBlocked(pdx)
    TEST   eax, eax
    JNZ    .INIT_SET_BAD

    MOV    eax, [.info.ImageHashAlgorithm]
    CMP    eax, CALG_SHA_256
    JNE    .INIT_SET_UNKNOWN

    MOV    pdx, [.info.ImageHash]
    MOV    ecx, [.info.ImageHashLength]
    $call  eax = IsHashKnownBad(pdx, ecx)
    TEST   eax, eax
    JNZ    .INIT_SET_BAD

    MOV    pdx, [.info.CertificatePublisher]
    TEST   pdx, pdx
    JZ     .INIT_SET_UNKNOWN
    $call  eax = IsPublisherTrusted(pdx)
    TEST   eax, eax
    JZ     .INIT_SET_UNKNOWN

    kdprint "file clean: %wZ", [.info.ImageName]
    MOV    DWORD [.info.Classification], BDCB_CLASS_GOOD
    LOCK   INC  QWORD [GoodCount]
    XOR    eax, eax
    $return

.INIT_SET_BAD:
    kdprint "file blocked: %wZ", [.info.ImageName]
    MOV    DWORD [.info.Classification], BDCB_CLASS_BAD
    LOCK   INC  QWORD [BadCount]
    XOR    eax, eax
    $return

.INIT_SET_UNKNOWN:
    kdprint "file skipped: %wZ", [.info.ImageName]
    MOV    DWORD [.info.Classification], BDCB_CLASS_UNKNOWN
    LOCK   INC  QWORD [UnknownCount]
    XOR    eax, eax
    $return
.endp


.proc ProcessStatusUpdate(.pStatusInfo)
    kdprint "got status update event"
    XOR    eax, eax
    $return
.endp


.proc ElamCallbackRoutine(.CallbackContext, .CallbackType, .CallbackInfo)
    MOV    pax, [.CallbackType]
    CMP    eax, BDCB_INITIALIZEIMAGE_TYPE
    JE     .ELAM_CASE_INIT

    CMP    eax, BDCB_STATUSUPDATE_TYPE
    JE     .ELAM_CASE_STATUS

    kdprint "unknown callback code: %d", eax
    XOR    eax, eax
    $return

.ELAM_CASE_INIT:
    MOV    pcx, [.CallbackInfo]
    $call  eax = ProcessInitializeImage(pcx)
    $return

.ELAM_CASE_STATUS:
    MOV    pcx, [.CallbackInfo]
    $call  eax = ProcessStatusUpdate(pcx)
    $return
.endp


.proc CreateCloseHandler(.DeviceObject, .Irp)
    kdprint "create close hit"
    MOV    pcx, [.Irp]
    XOR    eax, eax
    MOV    [pcx + IRP.IoStatus + IO_STATUS_BLOCK.Status], eax
    MOV    QWORD [pcx + IRP.IoStatus + IO_STATUS_BLOCK.Information], 0
    $call  [IoCompleteRequest](pcx, IO_NO_INCREMENT)
    XOR    eax, eax
    $return
.endp


.proc IoControlHandler(.DeviceObject, .Irp)
    $call  pax = [IoGetCurrentIrpStackLocation]([.Irp])
    MOV    ecx, [pax + IO_STACK_LOCATION.Parameters + DEVICE_IO_CONTROL.IoControlCode]

    CMP    ecx, IOCTL_AV_COMMAND
    JE     .IOCTL_DISPATCH_CMD

    CMP    ecx, IOCTL_AV_QUERY_STATS
    JE     .IOCTL_DISPATCH_STATS

    CMP    ecx, IOCTL_AV_ADD_HASH
    JE     .IOCTL_DISPATCH_ADDHASH
    JMP    .IOCTL_DISPATCH_INVALID

.IOCTL_DISPATCH_CMD:
    kdprint "ioctl command hit"
    MOV    pcx, [.Irp]
    XOR    eax, eax
    MOV    [pcx + IRP.IoStatus + IO_STATUS_BLOCK.Status], eax
    MOV    QWORD [pcx + IRP.IoStatus + IO_STATUS_BLOCK.Information], 4
    JMP    .IOCTL_COMPLETE

.IOCTL_DISPATCH_STATS:
    kdprint "ioctl query stats hit"
    MOV    pcx, [.Irp]
    MOV    pdx, [pcx + IRP.UserBuffer]

    MOV    pax, [GoodCount]
    MOV    [pdx + 00H], pax
    MOV    pax, [BadCount]
    MOV    [pdx + 08H], pax
    MOV    pax, [UnknownCount]
    MOV    [pdx + 10H], pax
    MOV    eax, [ActiveHashCount]
    MOV    [pdx + 18H], eax

    MOV    pcx, [.Irp]
    XOR    eax, eax
    MOV    [pcx + IRP.IoStatus + IO_STATUS_BLOCK.Status], eax
    MOV    QWORD [pcx + IRP.IoStatus + IO_STATUS_BLOCK.Information], 28
    JMP    .IOCTL_COMPLETE

.IOCTL_DISPATCH_ADDHASH:
    kdprint "ioctl add hash hit"
    MOV    eax, [ActiveHashCount]
    CMP    eax, MAX_BLACKLIST
    JGE    .IOCTL_ADDHASH_OVERFLOW

    MOV    pcx, [.Irp]
    MOV    psi, [pcx + IRP.UserBuffer]

    MOV    eax, [ActiveHashCount]
    IMUL   eax, HASH_SIZE
    LEA    pdi, [BlacklistTable]
    ADD    pdi, rax

    MOV    ecx, HASH_SIZE
    REP    MOVSB

    INC    DWORD [ActiveHashCount]
    kdprint "hash stored total items: %d", [ActiveHashCount]

    MOV    pcx, [.Irp]
    XOR    eax, eax
    MOV    [pcx + IRP.IoStatus + IO_STATUS_BLOCK.Status], eax
    MOV    QWORD [pcx + IRP.IoStatus + IO_STATUS_BLOCK.Information], 0
    JMP    .IOCTL_COMPLETE

.IOCTL_ADDHASH_OVERFLOW:
    kdprint "hash table full"
    MOV    pcx, [.Irp]
    MOV    eax, STATUS_INSUFFICIENT_RESOURCES
    MOV    [pcx + IRP.IoStatus + IO_STATUS_BLOCK.Status], eax
    MOV    QWORD [pcx + IRP.IoStatus + IO_STATUS_BLOCK.Information], 0
    JMP    .IOCTL_COMPLETE

.IOCTL_DISPATCH_INVALID:
    kdprint "unknown ioctl code: 0x%X", ecx
    MOV    pcx, [.Irp]
    MOV    eax, STATUS_NOT_SUPPORTED
    MOV    [pcx + IRP.IoStatus + IO_STATUS_BLOCK.Status], eax
    MOV    QWORD [pcx + IRP.IoStatus + IO_STATUS_BLOCK.Information], 0

.IOCTL_COMPLETE:
    $call  [IoCompleteRequest]([.Irp], IO_NO_INCREMENT)
    XOR    eax, eax
    $return
.endp


include 'data.inc'