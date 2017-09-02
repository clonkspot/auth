package mwforum

import "testing"

type testpwhash struct {
	password, salt, result string
}

var pwhashtests = []testpwhash{
	{"ab", "c", "V928iP2yozamYoXQirCYiA"},
	{"password", "V928iP2yozamYoXQirCYiA", "5i0top-HI2BAMXzuGwE1tw"},
	{"äöü", "aou", "PAhGYO6CfD_Uzq5oVVGrtA"},
	{"🤣😂😥", "🥝🍕", "b-MvApFK_qLNkm_evknvmA"},
}

func TestHashPassword(t *testing.T) {
	for _, test := range pwhashtests {
		hash := hashPassword(test.password, test.salt)
		if hash != test.result {
			t.Error("For", test.password, test.salt,
				"expected", test.result, "got", hash)
		}
	}
}
