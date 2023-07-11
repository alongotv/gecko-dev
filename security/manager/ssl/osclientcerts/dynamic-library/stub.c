/* -*- Mode: C++; tab-width: 2; indent-tabs-mode: nil; c-basic-offset: 2 -*- */
/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

// The build system builds the rust library osclientcerts as a static library
// called osclientcerts_static. On macOS, Windows and Android that static library can
// be linked with an empty file and turned into a shared library with the
// function C_GetFunctionList exposed. This allows that shared library to be
// used as a PKCS#11 module.
