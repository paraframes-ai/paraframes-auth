package password

import "testing"

func TestHashAndVerify(t *testing.T) {
	p := DefaultParams()
	// Lower cost for a faster test.
	p.Memory = 8 * 1024
	p.Iterations = 1

	hash, err := Hash("correct horse battery staple 7", p)
	if err != nil {
		t.Fatalf("hash: %v", err)
	}
	if err := Verify("correct horse battery staple 7", hash); err != nil {
		t.Fatalf("verify valid password: %v", err)
	}
	if err := Verify("wrong password 1", hash); err == nil {
		t.Fatal("expected mismatch for wrong password")
	}
}

func TestHashIsSalted(t *testing.T) {
	p := DefaultParams()
	p.Memory = 8 * 1024
	p.Iterations = 1
	h1, _ := Hash("same password 1", p)
	h2, _ := Hash("same password 1", p)
	if h1 == h2 {
		t.Fatal("identical hashes for same password: salt not applied")
	}
}

func TestPolicy(t *testing.T) {
	cases := []struct {
		pw string
		ok bool
	}{
		{"short1", false},
		{"alllettersnodigits", false},
		{"1234567890", false},
		{"validpass123", true},
	}
	for _, c := range cases {
		err := Policy(c.pw)
		if (err == nil) != c.ok {
			t.Errorf("Policy(%q): got err=%v, want ok=%v", c.pw, err, c.ok)
		}
	}
}
