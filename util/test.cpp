/* -*- Mode: C++; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 2 -*- */
/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#include <iostream>
#include <unistd.h>

#include "nss.h"
#include "prerror.h"
#include "secmod.h"
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
  if (snprintf(buf, sizeof(buf), "%s", "./libnssckbi.so") >= sizeof(buf)) {
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
  //const char* path = "/usr/lib64/libykcs11.so.1"; // YKCS11 isn't working?
  //const char* path = "/usr/lib64/libnssckbi.so";
  if (SECMOD_AddNewModuleEx("Some Module", path, 0, 0, buf, nullptr) != SECSuccess) {
    std::cout << "(test) SECMOD_AddNewModuleEx failed: ";
    std::cout << PR_ErrorToString(PR_GetError(), 0) << std::endl;
    return 1;
  }

  CERTCertList* certs = PK11_ListCerts(PK11CertListUnique, nullptr);
  if (!certs) {
    std::cout << "(test) PK11_ListCerts failed: ";
    std::cout << PR_ErrorToString(PR_GetError(), 0) << std::endl;
  } else {
    std::cout << "maybe found some certs" << std::endl;
    CERT_DestroyCertList(certs);
  }

  if (NSS_Shutdown() != SECSuccess) {
    std::cout << "NSS_Shutdown failed: " << PR_ErrorToString(PR_GetError(), 0);
    std::cout << std::endl;
    return 1;
  }
  return 0;
}
