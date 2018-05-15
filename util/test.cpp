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
  if (NSS_Initialize("sql:.", "", "", SECMOD_DB, NSS_INIT_NOROOTINIT | NSS_INIT_NOCERTDB) != SECSuccess) {
    std::cout << "(test) NSS_Initialize failed: " << PR_ErrorToString(PR_GetError(), 0);
    std::cout << std::endl;
    return 1;
  }

  char buf[64];
  //const char* modulePath = "/usr/lib64/libnssckbi.so";
  const char* modulePath = "/usr/lib64/libykcs11.so.1";
  if (snprintf(buf, sizeof(buf), "%s", modulePath) >= sizeof(buf)) {
    std::cout << "(test) not enough buffer space?" << std::endl;
    return 1;
  }
  int unused;
  SECMOD_DeleteModule("Some Module", &unused);
  /*
  char pathBuf[2048];
  if (!getcwd(pathBuf, sizeof(pathBuf))) {
    std::cout << "(test) couldn't getcwd?" << std::endl;
    return 1;
  }

  // NB: this can fail
  snprintf(pathBuf + strlen(pathBuf), sizeof(pathBuf) - strlen(pathBuf),
           "/libooppkcs11.so");
  if (SECMOD_AddNewModuleEx("Some Module", pathBuf, 0, 0, buf, nullptr)
  */
  const char* path = "/home/keeler/src/ooppkcs11rs/target/debug/libooppkcs11rs.so";
  if (SECMOD_AddNewModuleEx("Some Module", path, 0, 0, buf, nullptr) != SECSuccess) {
    std::cout << "(test) SECMOD_AddNewModuleEx failed: ";
    std::cout << PR_ErrorToString(PR_GetError(), 0) << std::endl;
    return 1;
  }

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

  SECMODModule* module = SECMOD_FindModule("Some Module");
  if (!module) {
    std::cout << "(test) SECMOD_FindModule failed: ";
    std::cout << PR_ErrorToString(PR_GetError(), 0) << std::endl;
    return 1;
  }
  for (int i = 0; i < module->slotCount; i++) {
    PK11SlotInfo* slot = module->slots[i];
    if (PK11_NeedUserInit(slot)) {
      if (PK11_InitPin(slot, "", "password") != SECSuccess) {
        std::cout << "(test) PK11_InitPin failed: ";
        std::cout << PR_ErrorToString(PR_GetError(), 0) << std::endl;
      }
    }
  }

  SECMOD_DestroyModule(module);

  if (NSS_Shutdown() != SECSuccess) {
    std::cout << "NSS_Shutdown failed: " << PR_ErrorToString(PR_GetError(), 0);
    std::cout << std::endl;
    return 1;
  }
  return 0;
}
