package authn

import (
	"strings"
	"testing"
)

func TestCLIPageEscapes(t *testing.T) {
	evil := `"><script>alert(1)</script>`
	body := cliConfirm(evil, `x"y`, cliParams{Port: 4242, State: "s<t", Challenge: "c&d"})
	if strings.Contains(body, "<script>") || strings.Contains(body, `x"y`) || strings.Contains(body, "s<t") || strings.Contains(body, "c&d") {
		t.Fatalf("unescaped value in page:\n%s", body)
	}
	for _, want := range []string{"&lt;script&gt;", `value="x&#34;y"`, `name="port" value="4242"`, `value="c&amp;d"`} {
		if !strings.Contains(body, want) {
			t.Errorf("missing %q in:\n%s", want, body)
		}
	}
	if m := cliMessage("<b>"); !strings.Contains(m, "&lt;b&gt;") {
		t.Errorf("message not escaped: %s", m)
	}
}
