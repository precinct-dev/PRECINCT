package precinctcontrol

func IsControlServicePath(path string) bool {
	return IsAdminPath(path) || IsConnectorAuthorityPath(path)
}
