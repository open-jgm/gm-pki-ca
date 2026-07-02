/*
 * Copyright 2026 open-gm-jca contributors
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.open.jgm.pki.ca.cert.dto.response;

import lombok.Value;

/**
 * CA 证书链数据（替代 CertCADTO）。
 */
@Value
public class CaChainResult {

    byte[] rcaBytes;
    byte[] rcaPemBytes;
    byte[] ocaBytes;
    byte[] ocaPemBytes;
    /** rca.pem + oca.pem 合并（trust.pem） */
    byte[] trustPemBytes;
    byte[] p7bBytes;
}
