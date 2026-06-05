package bac

import "testing"

func obs(principal string, status, bodyLen int, hash string) AccessObservation {
	return AccessObservation{Principal: principal, Status: status, BodyLen: bodyLen, BodyHash: hash}
}

func TestClassify_UnauthenticatedAccess(t *testing.T) {
	priv := obs("user-a", 200, 500, "H1")
	others := []AccessObservation{obs("anonymous", 200, 500, "H1")}
	v := Classify(priv, others)
	if !v.Broken {
		t.Fatal("anonymous getting the same privileged 200 body must be broken access control")
	}
	if v.Kind != KindUnauthenticated {
		t.Errorf("expected %q, got %q", KindUnauthenticated, v.Kind)
	}
}

func TestClassify_CrossUserAccess(t *testing.T) {
	priv := obs("user-a", 200, 500, "H1")
	others := []AccessObservation{
		obs("anonymous", 302, 0, "redir"), // properly bounced to login
		obs("user-b", 200, 500, "H1"),     // but user B sees A's resource
	}
	v := Classify(priv, others)
	if !v.Broken {
		t.Fatal("user B getting user A's identical body must be broken access control")
	}
	if v.Kind != KindCrossUser {
		t.Errorf("expected %q, got %q", KindCrossUser, v.Kind)
	}
}

func TestClassify_ProperlyProtected(t *testing.T) {
	priv := obs("user-a", 200, 500, "H1")
	others := []AccessObservation{
		obs("anonymous", 401, 20, "unauth"),
		obs("user-b", 403, 18, "forbidden"),
	}
	v := Classify(priv, others)
	if v.Broken {
		t.Fatalf("401/403 for other principals is correct behavior, not broken: %+v", v)
	}
}

func TestClassify_DifferentContentNotBroken(t *testing.T) {
	priv := obs("user-a", 200, 500, "H1")
	others := []AccessObservation{
		obs("user-b", 200, 480, "H2"), // 200 but their own different resource
	}
	v := Classify(priv, others)
	if v.Broken {
		t.Fatalf("a 200 with different content is each user's own data, not BAC: %+v", v)
	}
}

func TestClassify_PrivilegedNotSuccessSkipped(t *testing.T) {
	// If even user A can't access it (404/401), there is no privileged
	// baseline to leak — nothing to classify.
	priv := obs("user-a", 404, 0, "nf")
	others := []AccessObservation{obs("anonymous", 404, 0, "nf")}
	v := Classify(priv, others)
	if v.Broken {
		t.Fatal("no privileged baseline means nothing is broken")
	}
}

func TestClassify_NearEqualLengthCounts(t *testing.T) {
	// Bodies whose hashes differ only by a per-request CSRF token but are
	// otherwise the same length should still count (within tolerance).
	priv := obs("user-a", 200, 1000, "Hx")
	others := []AccessObservation{obs("user-b", 200, 1004, "Hy")}
	v := Classify(priv, others)
	if !v.Broken {
		t.Fatal("near-identical length 200 responses across users should be flagged")
	}
}

func TestClassify_SmallBodiesIgnoredOnLengthHeuristic(t *testing.T) {
	// Tiny identical-length bodies (e.g. empty/"OK") are too weak a signal on
	// length alone; require exact hash for those.
	priv := obs("user-a", 200, 3, "Ha")
	others := []AccessObservation{obs("user-b", 200, 4, "Hb")}
	v := Classify(priv, others)
	if v.Broken {
		t.Fatalf("tiny differing-hash bodies must not be flagged on length alone: %+v", v)
	}
}
