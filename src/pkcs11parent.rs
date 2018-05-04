#![allow(non_camel_case_types)]
#![allow(non_snake_case)]
#![allow(unused)]

use std::process::{Command, Stdio};
use std::sync::Mutex;

use ipc_channel::ipc::{self, IpcOneShotServer, IpcReceiver, IpcSender};
use std::io::Write;

use pkcs11;
use pkcs11types::*;

extern "C" fn C_Initialize(pInitArgs: CK_C_INITIALIZE_ARGS_PTR) -> CK_RV {
    println!("C_Initialize");
    let mut child = Command::new("/home/keeler/src/ooppkcs11rs/target/debug/ooppkcs11rs")
        .stdin(Stdio::piped())
        .spawn()
        .expect("failed to start ooppkcs11rs");
    let (server, name): (IpcOneShotServer<pkcs11::Message>, String) =
        IpcOneShotServer::new().unwrap();
    {
        let mut stdin = child.stdin.as_mut().expect("failed to open child.stdin");
        println!("sending server name '{}' to child", name);
        stdin
            .write_all(name.as_bytes())
            .expect("failed to send server name to child");
        // This is a workaround because dropping stdin doesn't seem to actually close the child's
        // stdin as documented.
        stdin
            .write_all(&[0])
            .expect("failed to send null terminator to child");
    }
    println!("wrote server name to child");
    let (rx, msg): (IpcReceiver<pkcs11::Message>, pkcs11::Message) = server.accept().unwrap();
    println!("child_server_name: '{}'", msg.name());
    let tx: IpcSender<pkcs11::Message> = IpcSender::connect(msg.name().to_owned()).unwrap();
    let msg = pkcs11::Message::new("C_Initialize");
    tx.send(msg).unwrap();
    let msg_back = rx.recv().unwrap();
    println!("received back {:?}", msg_back);
    CKR_OK
}
extern "C" fn C_Finalize(pReserved: CK_VOID_PTR) -> CK_RV {
    println!("C_Finalize");
    CKR_FUNCTION_NOT_SUPPORTED
}
extern "C" fn C_GetInfo(pInfo: CK_INFO_PTR) -> CK_RV {
    println!("C_GetInfo");
    CKR_FUNCTION_NOT_SUPPORTED
}
extern "C" fn C_GetSlotList(
    tokenPresent: CK_BBOOL,
    pSlotList: CK_SLOT_ID_PTR,
    pulCount: CK_ULONG_PTR,
) -> CK_RV {
    println!("C_GetSlotList");
    CKR_FUNCTION_NOT_SUPPORTED
}
extern "C" fn C_GetSlotInfo(slotID: CK_SLOT_ID, pInfo: CK_SLOT_INFO_PTR) -> CK_RV {
    println!("C_GetSlotInfo");
    CKR_FUNCTION_NOT_SUPPORTED
}
extern "C" fn C_GetTokenInfo(slotID: CK_SLOT_ID, pInfo: CK_TOKEN_INFO_PTR) -> CK_RV {
    println!("C_GetTokenInfo");
    CKR_FUNCTION_NOT_SUPPORTED
}
extern "C" fn C_GetMechanismList(
    slotID: CK_SLOT_ID,
    pMechanismList: CK_MECHANISM_TYPE_PTR,
    pulCount: CK_ULONG_PTR,
) -> CK_RV {
    println!("C_GetMechanismList");
    CKR_FUNCTION_NOT_SUPPORTED
}
extern "C" fn C_GetMechanismInfo(
    slotID: CK_SLOT_ID,
    type_: CK_MECHANISM_TYPE,
    pInfo: CK_MECHANISM_INFO_PTR,
) -> CK_RV {
    println!("C_GetMechanismInfo");
    CKR_FUNCTION_NOT_SUPPORTED
}
extern "C" fn C_InitToken(
    slotID: CK_SLOT_ID,
    pPin: CK_UTF8CHAR_PTR,
    ulPinLen: CK_ULONG,
    pLabel: CK_UTF8CHAR_PTR,
) -> CK_RV {
    println!("C_InitToken");
    CKR_FUNCTION_NOT_SUPPORTED
}
extern "C" fn C_InitPIN(
    hSession: CK_SESSION_HANDLE,
    pPin: CK_UTF8CHAR_PTR,
    ulPinLen: CK_ULONG,
) -> CK_RV {
    println!("C_InitPIN");
    CKR_FUNCTION_NOT_SUPPORTED
}
extern "C" fn C_SetPIN(
    hSession: CK_SESSION_HANDLE,
    pOldPin: CK_UTF8CHAR_PTR,
    ulOldLen: CK_ULONG,
    pNewPin: CK_UTF8CHAR_PTR,
    ulNewLen: CK_ULONG,
) -> CK_RV {
    println!("C_SetPIN");
    CKR_FUNCTION_NOT_SUPPORTED
}
extern "C" fn C_OpenSession(
    slotID: CK_SLOT_ID,
    flags: CK_FLAGS,
    pApplication: CK_VOID_PTR,
    Notify: CK_NOTIFY,
    phSession: CK_SESSION_HANDLE_PTR,
) -> CK_RV {
    println!("C_OpenSession");
    CKR_FUNCTION_NOT_SUPPORTED
}
extern "C" fn C_CloseSession(hSession: CK_SESSION_HANDLE) -> CK_RV {
    println!("C_CloseSession");
    CKR_FUNCTION_NOT_SUPPORTED
}
extern "C" fn C_CloseAllSessions(slotID: CK_SLOT_ID) -> CK_RV {
    println!("C_CloseAllSessions");
    CKR_FUNCTION_NOT_SUPPORTED
}
extern "C" fn C_GetSessionInfo(hSession: CK_SESSION_HANDLE, pInfo: CK_SESSION_INFO_PTR) -> CK_RV {
    println!("C_GetSessionInfo");
    CKR_FUNCTION_NOT_SUPPORTED
}
extern "C" fn C_GetOperationState(
    hSession: CK_SESSION_HANDLE,
    pOperationState: CK_BYTE_PTR,
    pulOperationStateLen: CK_ULONG_PTR,
) -> CK_RV {
    println!("C_GetOperationState");
    CKR_FUNCTION_NOT_SUPPORTED
}
extern "C" fn C_SetOperationState(
    hSession: CK_SESSION_HANDLE,
    pOperationState: CK_BYTE_PTR,
    ulOperationStateLen: CK_ULONG,
    hEncryptionKey: CK_OBJECT_HANDLE,
    hAuthenticationKey: CK_OBJECT_HANDLE,
) -> CK_RV {
    println!("C_SetOperationState");
    CKR_FUNCTION_NOT_SUPPORTED
}
extern "C" fn C_Login(
    hSession: CK_SESSION_HANDLE,
    userType: CK_USER_TYPE,
    pPin: CK_UTF8CHAR_PTR,
    ulPinLen: CK_ULONG,
) -> CK_RV {
    println!("C_Login");
    CKR_FUNCTION_NOT_SUPPORTED
}
extern "C" fn C_Logout(hSession: CK_SESSION_HANDLE) -> CK_RV {
    println!("C_Logout");
    CKR_FUNCTION_NOT_SUPPORTED
}
extern "C" fn C_CreateObject(
    hSession: CK_SESSION_HANDLE,
    pTemplate: CK_ATTRIBUTE_PTR,
    ulCount: CK_ULONG,
    phObject: CK_OBJECT_HANDLE_PTR,
) -> CK_RV {
    println!("C_CreateObject");
    CKR_FUNCTION_NOT_SUPPORTED
}
extern "C" fn C_CopyObject(
    hSession: CK_SESSION_HANDLE,
    hObject: CK_OBJECT_HANDLE,
    pTemplate: CK_ATTRIBUTE_PTR,
    ulCount: CK_ULONG,
    phNewObject: CK_OBJECT_HANDLE_PTR,
) -> CK_RV {
    println!("C_CopyObject");
    CKR_FUNCTION_NOT_SUPPORTED
}
extern "C" fn C_DestroyObject(hSession: CK_SESSION_HANDLE, hObject: CK_OBJECT_HANDLE) -> CK_RV {
    println!("C_DestroyObject");
    CKR_FUNCTION_NOT_SUPPORTED
}
extern "C" fn C_GetObjectSize(
    hSession: CK_SESSION_HANDLE,
    hObject: CK_OBJECT_HANDLE,
    pulSize: CK_ULONG_PTR,
) -> CK_RV {
    println!("C_GetObjectSize");
    CKR_FUNCTION_NOT_SUPPORTED
}
extern "C" fn C_GetAttributeValue(
    hSession: CK_SESSION_HANDLE,
    hObject: CK_OBJECT_HANDLE,
    pTemplate: CK_ATTRIBUTE_PTR,
    ulCount: CK_ULONG,
) -> CK_RV {
    println!("C_GetAttributeValue");
    CKR_FUNCTION_NOT_SUPPORTED
}
extern "C" fn C_SetAttributeValue(
    hSession: CK_SESSION_HANDLE,
    hObject: CK_OBJECT_HANDLE,
    pTemplate: CK_ATTRIBUTE_PTR,
    ulCount: CK_ULONG,
) -> CK_RV {
    println!("C_SetAttributeValue");
    CKR_FUNCTION_NOT_SUPPORTED
}
extern "C" fn C_FindObjectsInit(
    hSession: CK_SESSION_HANDLE,
    pTemplate: CK_ATTRIBUTE_PTR,
    ulCount: CK_ULONG,
) -> CK_RV {
    println!("C_FindObjectsInit");
    CKR_FUNCTION_NOT_SUPPORTED
}
extern "C" fn C_FindObjects(
    hSession: CK_SESSION_HANDLE,
    phObject: CK_OBJECT_HANDLE_PTR,
    ulMaxObjectCount: CK_ULONG,
    pulObjectCount: CK_ULONG_PTR,
) -> CK_RV {
    println!("C_FindObjects");
    CKR_FUNCTION_NOT_SUPPORTED
}
extern "C" fn C_FindObjectsFinal(hSession: CK_SESSION_HANDLE) -> CK_RV {
    println!("C_FindObjectsFinal");
    CKR_FUNCTION_NOT_SUPPORTED
}
extern "C" fn C_EncryptInit(
    hSession: CK_SESSION_HANDLE,
    pMechanism: CK_MECHANISM_PTR,
    hKey: CK_OBJECT_HANDLE,
) -> CK_RV {
    println!("C_EncryptInit");
    CKR_FUNCTION_NOT_SUPPORTED
}
extern "C" fn C_Encrypt(
    hSession: CK_SESSION_HANDLE,
    pData: CK_BYTE_PTR,
    ulDataLen: CK_ULONG,
    pEncryptedData: CK_BYTE_PTR,
    pulEncryptedDataLen: CK_ULONG_PTR,
) -> CK_RV {
    println!("C_Encrypt");
    CKR_FUNCTION_NOT_SUPPORTED
}
extern "C" fn C_EncryptUpdate(
    hSession: CK_SESSION_HANDLE,
    pPart: CK_BYTE_PTR,
    ulPartLen: CK_ULONG,
    pEncryptedPart: CK_BYTE_PTR,
    pulEncryptedPartLen: CK_ULONG_PTR,
) -> CK_RV {
    println!("C_EncryptUpdate");
    CKR_FUNCTION_NOT_SUPPORTED
}
extern "C" fn C_EncryptFinal(
    hSession: CK_SESSION_HANDLE,
    pLastEncryptedPart: CK_BYTE_PTR,
    pulLastEncryptedPartLen: CK_ULONG_PTR,
) -> CK_RV {
    println!("C_EncryptFinal");
    CKR_FUNCTION_NOT_SUPPORTED
}
extern "C" fn C_DecryptInit(
    hSession: CK_SESSION_HANDLE,
    pMechanism: CK_MECHANISM_PTR,
    hKey: CK_OBJECT_HANDLE,
) -> CK_RV {
    println!("C_DecryptInit");
    CKR_FUNCTION_NOT_SUPPORTED
}
extern "C" fn C_Decrypt(
    hSession: CK_SESSION_HANDLE,
    pEncryptedData: CK_BYTE_PTR,
    ulEncryptedDataLen: CK_ULONG,
    pData: CK_BYTE_PTR,
    pulDataLen: CK_ULONG_PTR,
) -> CK_RV {
    println!("C_Decrypt");
    CKR_FUNCTION_NOT_SUPPORTED
}
extern "C" fn C_DecryptUpdate(
    hSession: CK_SESSION_HANDLE,
    pEncryptedPart: CK_BYTE_PTR,
    ulEncryptedPartLen: CK_ULONG,
    pPart: CK_BYTE_PTR,
    pulPartLen: CK_ULONG_PTR,
) -> CK_RV {
    println!("C_DecryptUpdate");
    CKR_FUNCTION_NOT_SUPPORTED
}
extern "C" fn C_DecryptFinal(
    hSession: CK_SESSION_HANDLE,
    pLastPart: CK_BYTE_PTR,
    pulLastPartLen: CK_ULONG_PTR,
) -> CK_RV {
    println!("C_DecryptFinal");
    CKR_FUNCTION_NOT_SUPPORTED
}
extern "C" fn C_DigestInit(hSession: CK_SESSION_HANDLE, pMechanism: CK_MECHANISM_PTR) -> CK_RV {
    println!("C_DigestInit");
    CKR_FUNCTION_NOT_SUPPORTED
}
extern "C" fn C_Digest(
    hSession: CK_SESSION_HANDLE,
    pData: CK_BYTE_PTR,
    ulDataLen: CK_ULONG,
    pDigest: CK_BYTE_PTR,
    pulDigestLen: CK_ULONG_PTR,
) -> CK_RV {
    println!("C_Digest");
    CKR_FUNCTION_NOT_SUPPORTED
}
extern "C" fn C_DigestUpdate(
    hSession: CK_SESSION_HANDLE,
    pPart: CK_BYTE_PTR,
    ulPartLen: CK_ULONG,
) -> CK_RV {
    println!("C_DigestUpdate");
    CKR_FUNCTION_NOT_SUPPORTED
}
extern "C" fn C_DigestKey(hSession: CK_SESSION_HANDLE, hKey: CK_OBJECT_HANDLE) -> CK_RV {
    println!("C_DigestKey");
    CKR_FUNCTION_NOT_SUPPORTED
}
extern "C" fn C_DigestFinal(
    hSession: CK_SESSION_HANDLE,
    pDigest: CK_BYTE_PTR,
    pulDigestLen: CK_ULONG_PTR,
) -> CK_RV {
    println!("C_DigestFinal");
    CKR_FUNCTION_NOT_SUPPORTED
}
extern "C" fn C_SignInit(
    hSession: CK_SESSION_HANDLE,
    pMechanism: CK_MECHANISM_PTR,
    hKey: CK_OBJECT_HANDLE,
) -> CK_RV {
    println!("C_SignInit");
    CKR_FUNCTION_NOT_SUPPORTED
}
extern "C" fn C_Sign(
    hSession: CK_SESSION_HANDLE,
    pData: CK_BYTE_PTR,
    ulDataLen: CK_ULONG,
    pSignature: CK_BYTE_PTR,
    pulSignatureLen: CK_ULONG_PTR,
) -> CK_RV {
    println!("C_Sign");
    CKR_FUNCTION_NOT_SUPPORTED
}
extern "C" fn C_SignUpdate(
    hSession: CK_SESSION_HANDLE,
    pPart: CK_BYTE_PTR,
    ulPartLen: CK_ULONG,
) -> CK_RV {
    println!("C_SignUpdate");
    CKR_FUNCTION_NOT_SUPPORTED
}
extern "C" fn C_SignFinal(
    hSession: CK_SESSION_HANDLE,
    pSignature: CK_BYTE_PTR,
    pulSignatureLen: CK_ULONG_PTR,
) -> CK_RV {
    println!("C_SignFinal");
    CKR_FUNCTION_NOT_SUPPORTED
}
extern "C" fn C_SignRecoverInit(
    hSession: CK_SESSION_HANDLE,
    pMechanism: CK_MECHANISM_PTR,
    hKey: CK_OBJECT_HANDLE,
) -> CK_RV {
    println!("C_SignRecoverInit");
    CKR_FUNCTION_NOT_SUPPORTED
}
extern "C" fn C_SignRecover(
    hSession: CK_SESSION_HANDLE,
    pData: CK_BYTE_PTR,
    ulDataLen: CK_ULONG,
    pSignature: CK_BYTE_PTR,
    pulSignatureLen: CK_ULONG_PTR,
) -> CK_RV {
    println!("C_SignRecover");
    CKR_FUNCTION_NOT_SUPPORTED
}
extern "C" fn C_VerifyInit(
    hSession: CK_SESSION_HANDLE,
    pMechanism: CK_MECHANISM_PTR,
    hKey: CK_OBJECT_HANDLE,
) -> CK_RV {
    println!("C_VerifyInit");
    CKR_FUNCTION_NOT_SUPPORTED
}
extern "C" fn C_Verify(
    hSession: CK_SESSION_HANDLE,
    pData: CK_BYTE_PTR,
    ulDataLen: CK_ULONG,
    pSignature: CK_BYTE_PTR,
    ulSignatureLen: CK_ULONG,
) -> CK_RV {
    println!("C_Verify");
    CKR_FUNCTION_NOT_SUPPORTED
}
extern "C" fn C_VerifyUpdate(
    hSession: CK_SESSION_HANDLE,
    pPart: CK_BYTE_PTR,
    ulPartLen: CK_ULONG,
) -> CK_RV {
    println!("C_VerifyUpdate");
    CKR_FUNCTION_NOT_SUPPORTED
}
extern "C" fn C_VerifyFinal(
    hSession: CK_SESSION_HANDLE,
    pSignature: CK_BYTE_PTR,
    ulSignatureLen: CK_ULONG,
) -> CK_RV {
    println!("C_VerifyFinal");
    CKR_FUNCTION_NOT_SUPPORTED
}
extern "C" fn C_VerifyRecoverInit(
    hSession: CK_SESSION_HANDLE,
    pMechanism: CK_MECHANISM_PTR,
    hKey: CK_OBJECT_HANDLE,
) -> CK_RV {
    println!("C_VerifyRecoverInit");
    CKR_FUNCTION_NOT_SUPPORTED
}
extern "C" fn C_VerifyRecover(
    hSession: CK_SESSION_HANDLE,
    pSignature: CK_BYTE_PTR,
    ulSignatureLen: CK_ULONG,
    pData: CK_BYTE_PTR,
    pulDataLen: CK_ULONG_PTR,
) -> CK_RV {
    println!("C_VerifyRecover");
    CKR_FUNCTION_NOT_SUPPORTED
}
extern "C" fn C_DigestEncryptUpdate(
    hSession: CK_SESSION_HANDLE,
    pPart: CK_BYTE_PTR,
    ulPartLen: CK_ULONG,
    pEncryptedPart: CK_BYTE_PTR,
    pulEncryptedPartLen: CK_ULONG_PTR,
) -> CK_RV {
    println!("C_DigestEncryptUpdate");
    CKR_FUNCTION_NOT_SUPPORTED
}
extern "C" fn C_DecryptDigestUpdate(
    hSession: CK_SESSION_HANDLE,
    pEncryptedPart: CK_BYTE_PTR,
    ulEncryptedPartLen: CK_ULONG,
    pPart: CK_BYTE_PTR,
    pulPartLen: CK_ULONG_PTR,
) -> CK_RV {
    println!("C_DecryptDigestUpdate");
    CKR_FUNCTION_NOT_SUPPORTED
}
extern "C" fn C_SignEncryptUpdate(
    hSession: CK_SESSION_HANDLE,
    pPart: CK_BYTE_PTR,
    ulPartLen: CK_ULONG,
    pEncryptedPart: CK_BYTE_PTR,
    pulEncryptedPartLen: CK_ULONG_PTR,
) -> CK_RV {
    println!("C_SignEncryptUpdate");
    CKR_FUNCTION_NOT_SUPPORTED
}
extern "C" fn C_DecryptVerifyUpdate(
    hSession: CK_SESSION_HANDLE,
    pEncryptedPart: CK_BYTE_PTR,
    ulEncryptedPartLen: CK_ULONG,
    pPart: CK_BYTE_PTR,
    pulPartLen: CK_ULONG_PTR,
) -> CK_RV {
    println!("C_DecryptVerifyUpdate");
    CKR_FUNCTION_NOT_SUPPORTED
}
extern "C" fn C_GenerateKey(
    hSession: CK_SESSION_HANDLE,
    pMechanism: CK_MECHANISM_PTR,
    pTemplate: CK_ATTRIBUTE_PTR,
    ulCount: CK_ULONG,
    phKey: CK_OBJECT_HANDLE_PTR,
) -> CK_RV {
    println!("C_GenerateKey");
    CKR_FUNCTION_NOT_SUPPORTED
}
extern "C" fn C_GenerateKeyPair(
    hSession: CK_SESSION_HANDLE,
    pMechanism: CK_MECHANISM_PTR,
    pPublicKeyTemplate: CK_ATTRIBUTE_PTR,
    ulPublicKeyAttributeCount: CK_ULONG,
    pPrivateKeyTemplate: CK_ATTRIBUTE_PTR,
    ulPrivateKeyAttributeCount: CK_ULONG,
    phPublicKey: CK_OBJECT_HANDLE_PTR,
    phPrivateKey: CK_OBJECT_HANDLE_PTR,
) -> CK_RV {
    println!("C_GenerateKeyPair");
    CKR_FUNCTION_NOT_SUPPORTED
}
extern "C" fn C_WrapKey(
    hSession: CK_SESSION_HANDLE,
    pMechanism: CK_MECHANISM_PTR,
    hWrappingKey: CK_OBJECT_HANDLE,
    hKey: CK_OBJECT_HANDLE,
    pWrappedKey: CK_BYTE_PTR,
    pulWrappedKeyLen: CK_ULONG_PTR,
) -> CK_RV {
    println!("C_WrapKey");
    CKR_FUNCTION_NOT_SUPPORTED
}
extern "C" fn C_UnwrapKey(
    hSession: CK_SESSION_HANDLE,
    pMechanism: CK_MECHANISM_PTR,
    hUnwrappingKey: CK_OBJECT_HANDLE,
    pWrappedKey: CK_BYTE_PTR,
    ulWrappedKeyLen: CK_ULONG,
    pTemplate: CK_ATTRIBUTE_PTR,
    ulAttributeCount: CK_ULONG,
    phKey: CK_OBJECT_HANDLE_PTR,
) -> CK_RV {
    println!("C_UnwrapKey");
    CKR_FUNCTION_NOT_SUPPORTED
}
extern "C" fn C_DeriveKey(
    hSession: CK_SESSION_HANDLE,
    pMechanism: CK_MECHANISM_PTR,
    hBaseKey: CK_OBJECT_HANDLE,
    pTemplate: CK_ATTRIBUTE_PTR,
    ulAttributeCount: CK_ULONG,
    phKey: CK_OBJECT_HANDLE_PTR,
) -> CK_RV {
    println!("C_DeriveKey");
    CKR_FUNCTION_NOT_SUPPORTED
}
extern "C" fn C_SeedRandom(
    hSession: CK_SESSION_HANDLE,
    pSeed: CK_BYTE_PTR,
    ulSeedLen: CK_ULONG,
) -> CK_RV {
    println!("C_SeedRandom");
    CKR_FUNCTION_NOT_SUPPORTED
}
extern "C" fn C_GenerateRandom(
    hSession: CK_SESSION_HANDLE,
    RandomData: CK_BYTE_PTR,
    ulRandomLen: CK_ULONG,
) -> CK_RV {
    println!("C_GenerateRandom");
    CKR_FUNCTION_NOT_SUPPORTED
}
extern "C" fn C_GetFunctionStatus(hSession: CK_SESSION_HANDLE) -> CK_RV {
    println!("C_GetFunctionStatus");
    CKR_FUNCTION_NOT_SUPPORTED
}
extern "C" fn C_CancelFunction(hSession: CK_SESSION_HANDLE) -> CK_RV {
    println!("C_CancelFunction");
    CKR_FUNCTION_NOT_SUPPORTED
}
extern "C" fn C_WaitForSlotEvent(
    flags: CK_FLAGS,
    pSlot: CK_SLOT_ID_PTR,
    pRserved: CK_VOID_PTR,
) -> CK_RV {
    println!("C_WaitForSlotEvent");
    CKR_FUNCTION_NOT_SUPPORTED
}

pub static FUNCTION_LIST: CK_FUNCTION_LIST = CK_FUNCTION_LIST {
    version: CK_VERSION { major: 2, minor: 2 },
    C_Initialize: Some(C_Initialize),
    C_Finalize: Some(C_Finalize),
    C_GetInfo: Some(C_GetInfo),
    C_GetFunctionList: None,
    C_GetSlotList: Some(C_GetSlotList),
    C_GetSlotInfo: Some(C_GetSlotInfo),
    C_GetTokenInfo: Some(C_GetTokenInfo),
    C_GetMechanismList: Some(C_GetMechanismList),
    C_GetMechanismInfo: Some(C_GetMechanismInfo),
    C_InitToken: Some(C_InitToken),
    C_InitPIN: Some(C_InitPIN),
    C_SetPIN: Some(C_SetPIN),
    C_OpenSession: Some(C_OpenSession),
    C_CloseSession: Some(C_CloseSession),
    C_CloseAllSessions: Some(C_CloseAllSessions),
    C_GetSessionInfo: Some(C_GetSessionInfo),
    C_GetOperationState: Some(C_GetOperationState),
    C_SetOperationState: Some(C_SetOperationState),
    C_Login: Some(C_Login),
    C_Logout: Some(C_Logout),
    C_CreateObject: Some(C_CreateObject),
    C_CopyObject: Some(C_CopyObject),
    C_DestroyObject: Some(C_DestroyObject),
    C_GetObjectSize: Some(C_GetObjectSize),
    C_GetAttributeValue: Some(C_GetAttributeValue),
    C_SetAttributeValue: Some(C_SetAttributeValue),
    C_FindObjectsInit: Some(C_FindObjectsInit),
    C_FindObjects: Some(C_FindObjects),
    C_FindObjectsFinal: Some(C_FindObjectsFinal),
    C_EncryptInit: Some(C_EncryptInit),
    C_Encrypt: Some(C_Encrypt),
    C_EncryptUpdate: Some(C_EncryptUpdate),
    C_EncryptFinal: Some(C_EncryptFinal),
    C_DecryptInit: Some(C_DecryptInit),
    C_Decrypt: Some(C_Decrypt),
    C_DecryptUpdate: Some(C_DecryptUpdate),
    C_DecryptFinal: Some(C_DecryptFinal),
    C_DigestInit: Some(C_DigestInit),
    C_Digest: Some(C_Digest),
    C_DigestUpdate: Some(C_DigestUpdate),
    C_DigestKey: Some(C_DigestKey),
    C_DigestFinal: Some(C_DigestFinal),
    C_SignInit: Some(C_SignInit),
    C_Sign: Some(C_Sign),
    C_SignUpdate: Some(C_SignUpdate),
    C_SignFinal: Some(C_SignFinal),
    C_SignRecoverInit: Some(C_SignRecoverInit),
    C_SignRecover: Some(C_SignRecover),
    C_VerifyInit: Some(C_VerifyInit),
    C_Verify: Some(C_Verify),
    C_VerifyUpdate: Some(C_VerifyUpdate),
    C_VerifyFinal: Some(C_VerifyFinal),
    C_VerifyRecoverInit: Some(C_VerifyRecoverInit),
    C_VerifyRecover: Some(C_VerifyRecover),
    C_DigestEncryptUpdate: Some(C_DigestEncryptUpdate),
    C_DecryptDigestUpdate: Some(C_DecryptDigestUpdate),
    C_SignEncryptUpdate: Some(C_SignEncryptUpdate),
    C_DecryptVerifyUpdate: Some(C_DecryptVerifyUpdate),
    C_GenerateKey: Some(C_GenerateKey),
    C_GenerateKeyPair: Some(C_GenerateKeyPair),
    C_WrapKey: Some(C_WrapKey),
    C_UnwrapKey: Some(C_UnwrapKey),
    C_DeriveKey: Some(C_DeriveKey),
    C_SeedRandom: Some(C_SeedRandom),
    C_GenerateRandom: Some(C_GenerateRandom),
    C_GetFunctionStatus: Some(C_GetFunctionStatus),
    C_CancelFunction: Some(C_CancelFunction),
    C_WaitForSlotEvent: Some(C_WaitForSlotEvent),
};
