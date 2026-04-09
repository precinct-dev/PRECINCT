// Copyright 2024-2026 The PRECINCT Authors
// SPDX-License-Identifier: Apache-2.0

package precinctcontrol

func IsControlServicePath(path string) bool {
	return IsAdminPath(path) || IsConnectorAuthorityPath(path)
}
