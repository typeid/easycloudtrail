package utils

import "regexp"

func MatchesRegexpList(value string, regexpList []string) (bool, error) {
	// Empty list, might be constructed off a single empty string.
	if len(regexpList) == 0 || len(regexpList) == 1 && regexpList[0] == "" {
		return false, nil
	}

	for _, regexpI := range regexpList {
		matched, err := regexp.MatchString(regexpI, value)
		if err != nil {
			return false, err
		}

		if matched {
			return true, nil
		}
	}
	return false, nil
}

func ReverseSlice[S ~[]E, E any](s S) {
	for i, j := 0, len(s)-1; i < j; i, j = i+1, j-1 {
		s[i], s[j] = s[j], s[i]
	}
}
