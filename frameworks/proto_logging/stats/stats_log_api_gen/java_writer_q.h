/*
 * Copyright (C) 2019, The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef ANDROID_STATS_LOG_API_GEN_JAVA_WRITER_Q_H
#define ANDROID_STATS_LOG_API_GEN_JAVA_WRITER_Q_H

#include <stdio.h>
#include <string.h>

#include <map>
#include <set>
#include <vector>

#include "Collation.h"

namespace android {
namespace stats_log_api_gen {

void write_java_q_logging_constants(FILE* out, const string& indent);

int write_java_methods_q_schema(FILE* out, const SignatureInfoMap& signatureInfoMap,
                                const AtomDecl& attributionDecl, const string& indent);

void write_java_helpers_for_q_schema_methods(FILE* out, const AtomDecl& attributionDecl,
                                             const int requiredHelpers, const string& indent);

}  // namespace stats_log_api_gen
}  // namespace android

#endif  // ANDROID_STATS_LOG_API_GEN_JAVA_WRITER_Q_H
