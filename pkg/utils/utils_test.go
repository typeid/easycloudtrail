package utils_test

import (
	"easycloudtrail/pkg/utils"

	"testing"
)

// Don't match if values differ.
func TestDoesntMatchesRegexpList(t *testing.T) {
	user := "root"
	regexpList := []string{"test,william,john"}
	matches, _ := utils.MatchesRegexpList(user, regexpList)

	if matches {
		t.Fail()
	}
}

// Don't match if the list is empty.
func TestDoesntMatchesRegexpList2(t *testing.T) {
	user := "root"
	regexpList := []string{}
	matches, _ := utils.MatchesRegexpList(user, regexpList)

	if matches {
		t.Fail()
	}
}

// Don't match if the list only contains empty string.
func TestDoesntMatchesRegexpList3(t *testing.T) {
	user := "root"
	regexpList := []string{""}
	matches, _ := utils.MatchesRegexpList(user, regexpList)

	if matches {
		t.Fail()
	}
}
