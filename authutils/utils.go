package authutils

import ()

func elem(searchValue string, collection []string) bool {
	for _, value := range collection {
		if searchValue == value {
			return true
		}
	}
	return false
}
