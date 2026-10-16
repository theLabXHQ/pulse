package lru

import "testing"

func TestEvictsLeastRecentlyUsed(t *testing.T) {
	c := New[string, int](2)
	c.Set("a", 1)
	c.Set("b", 2)
	if _, ok := c.Get("a"); !ok { // a becomes most recent
		t.Fatal("a missing")
	}
	c.Set("c", 3) // evicts b
	if _, ok := c.Get("b"); ok {
		t.Fatal("b should be evicted")
	}
	if v, _ := c.Get("a"); v != 1 {
		t.Fatal("a lost")
	}
	if c.Len() != 2 {
		t.Fatalf("len %d", c.Len())
	}
	if v := c.Update("a", func(old int, found bool) int { return old + 10 }); v != 11 {
		t.Fatalf("update got %d", v)
	}
	c.Delete("a")
	if _, ok := c.Get("a"); ok {
		t.Fatal("delete failed")
	}
}
