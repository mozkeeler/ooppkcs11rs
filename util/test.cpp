/* -*- Mode: C++; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 2 -*- */
/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#include <iostream>
#include <unistd.h>

#include "nss.h"
#include "prerror.h"
#include "secmod.h"
#include "secmodt.h"
#include "pk11pub.h"
#include "cert.h"

int main(int argc, char* argv[])
{
  if (NSS_Initialize("sql:.", "", "", SECMOD_DB, NSS_INIT_NOROOTINIT)
        != SECSuccess) {
    std::cout << "(test) NSS_Initialize failed: ";
    std::cout << PR_ErrorToString(PR_GetError(), 0) << std::endl;
    return 1;
  }

  int unused;
  SECMOD_DeleteModule("Some Module", &unused);

  const char* path = "/home/keeler/src/ooppkcs11rs/target/debug/libooppkcs11rs.so";
  char params[] = "/usr/lib64/onepin-opensc-pkcs11.so";
  if (SECMOD_AddNewModuleEx("Some Module", path, 0, 0, params, nullptr)
        != SECSuccess) {
    std::cout << "(test) SECMOD_AddNewModuleEx failed: ";
    std::cout << PR_ErrorToString(PR_GetError(), 0) << std::endl;
    return 1;
  }

  SECMODModule* module = SECMOD_FindModule("Some Module");
  if (!module) {
    std::cout << "(test) SECMOD_FindModule failed: ";
    std::cout << PR_ErrorToString(PR_GetError(), 0) << std::endl;
    return 1;
  }
  for (int i = 0; i < module->slotCount; i++) {
    PK11SlotInfo* slot = module->slots[i];
    if (PK11_CheckUserPassword(slot, "123456") != SECSuccess) {
        std::cout << "(test) PK11_CheckUserPassword failed: ";
        std::cout << PR_ErrorToString(PR_GetError(), 0) << std::endl;
    }
    /*
    if (PK11_ChangePW(slot, "123456", "password") != SECSuccess) {
        std::cout << "(test) PK11_ChangePW failed: ";
        std::cout << PR_ErrorToString(PR_GetError(), 0) << std::endl;
    }
    if (PK11_CheckUserPassword(slot, "password") != SECSuccess) {
        std::cout << "(test) PK11_CheckUserPassword failed: ";
        std::cout << PR_ErrorToString(PR_GetError(), 0) << std::endl;
    }
    */
  }

  std::cout << "BEGIN LISTING CERTS..." << std::endl;
  CERTCertList* certs = PK11_ListCerts(PK11CertListUnique, nullptr);
  if (!certs) {
    std::cout << "(test) PK11_ListCerts failed: ";
    std::cout << PR_ErrorToString(PR_GetError(), 0) << std::endl;
    return 1;
  }
  for (CERTCertListNode* n = CERT_LIST_HEAD(certs); !CERT_LIST_END(n, certs);
       n = CERT_LIST_NEXT(n)) {
    std::cout << "'" << n->cert->subjectName << "' issued by '";
    std::cout << n->cert->issuerName << "'" << std::endl;
  }
  CERT_DestroyCertList(certs);
  std::cout << "END LISTING CERTS..." << std::endl;


  SECMOD_DestroyModule(module);

  if (NSS_Shutdown() != SECSuccess) {
    std::cout << "NSS_Shutdown failed: " << PR_ErrorToString(PR_GetError(), 0);
    std::cout << std::endl;
    return 1;
  }
  return 0;
}
