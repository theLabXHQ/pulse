package dsl

import (
	"strings"
	"testing"
)

var vars = map[string]any{
	"status_code":    float64(200),
	"content_length": float64(1234),
	"title":          "Admin Login",
	"body":           "<html>wp-content/themes x</html>",
	"webserver":      "nginx/1.25",
	"tech":           []string{"WordPress:6.4", "PHP", "Nginx"},
	"empty":          "",
}

func lookup(name string) (any, bool) { v, ok := vars[name]; return v, ok }

func TestEval(t *testing.T) {
	for expr, want := range map[string]bool{
		`status_code == 200`:                                     true,
		`status_code != 200`:                                     false,
		`status_code == "200"`:                                   true,
		`content_length > 1000 && content_length <= 1234`:        true,
		`status_code == 404 || contains(title, "Login")`:         true,
		`status_code == 404 || status_code == 500`:               false,
		`!contains(body, "wp-admin")`:                            true,
		`contains(to_lower(title), "admin") && len(title) == 11`: true,
		`regex("wp-(content|includes)", body)`:                   true,
		`regex('^nginx/1\\.2', webserver)`:                       true,
		`contains(tech, "WordPress")`:                            true,
		`contains_any(tech, "Drupal", "Joomla")`:                 false,
		`contains_all(tech, "PHP", "Nginx")`:                     true,
		`tech == "PHP"`:                                          true,
		`len(tech) == 3`:                                         true,
		`starts_with(webserver, "apache", "nginx")`:              true,
		`ends_with(title, "Login")`:                              true,
		`empty`:                                                  false,
		`(status_code == 200 || false) && !(len(empty) > 0)`:     true,
		`tolower(title) == "admin login"`:                        true,
		`status_code == 200 && status_code == 200 || false`:      true,
	} {
		e, err := Compile(expr)
		if err != nil {
			t.Errorf("Compile(%s): %v", expr, err)
			continue
		}
		got, err := e.Eval(lookup)
		if err != nil || got != want {
			t.Errorf("%s = %v (%v), want %v", expr, got, err, want)
		}
	}
}

func TestShortCircuit(t *testing.T) {
	e, _ := Compile(`status_code == 404 && nosuchvar == 1`)
	if ok, err := e.Eval(lookup); ok || err != nil {
		t.Fatalf("right side must not be evaluated: %v %v", ok, err)
	}
	e, _ = Compile(`status_code == 200 && nosuchvar == 1`)
	if _, err := e.Eval(lookup); err == nil || !strings.Contains(err.Error(), "unknown variable nosuchvar") {
		t.Fatalf("unknown variable must be reported: %v", err)
	}
}

func TestCompileErrors(t *testing.T) {
	for expr, want := range map[string]string{
		`status_code ==`:         "unexpected end",
		`contains(body`:          "expected , or )",
		`nosuchfn(body)`:         "unknown function nosuchfn",
		`regex("(", body)`:       "regex",
		`"unterminated`:          "unterminated string",
		`contains(body)`:         "wrong number of arguments",
		`status_code == 200 200`: "unexpected",
		`status_code @ 200`:      "unexpected",
	} {
		_, err := Compile(expr)
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("Compile(%s) error = %v, want it to mention %q", expr, err, want)
		}
	}
}
