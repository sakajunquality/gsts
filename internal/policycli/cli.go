// Package policycli provides offline policy checks, never JWT verification.
package policycli

import (
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/golang-jwt/jwt/v5"
	"github.com/sakajunquality/gsts/internal/policy"
)

type testCase struct {
	Name   string        `json:"name"`
	Expect string        `json:"expect"`
	Claims jwt.MapClaims `json:"claims"`
}
type suite struct {
	Cases []testCase `json:"cases"`
}

// Run executes validate or test without reading server configuration or contacting services.
func Run(args []string, out, errOut io.Writer) error {
	if len(args) == 0 {
		return errors.New("usage: gsts policy validate|test --policy FILE [--org] [--identifier AUDIENCE --fixtures FILE]")
	}
	command := args[0]
	if command != "validate" && command != "test" {
		return fmt.Errorf("unknown policy command %q", command)
	}
	fs := flag.NewFlagSet("policy "+command, flag.ContinueOnError)
	fs.SetOutput(errOut)
	path := fs.String("policy", "", "TOML policy file")
	org := fs.Bool("org", false, "validate as an organization policy (default: repository)")
	identifier := fs.String("identifier", "", "server GSTS_IDENTIFIER used for default audience matching")
	fixtures := fs.String("fixtures", "", "JSON fixture suite (test only)")
	if err := fs.Parse(args[1:]); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return err
	}
	if fs.NArg() != 0 || *path == "" {
		return errors.New("--policy is required; positional arguments are unsupported")
	}
	if command == "validate" && (*fixtures != "" || *identifier != "") {
		return errors.New("--fixtures and --identifier are test-only flags")
	}
	if command == "test" && (*fixtures == "" || *identifier == "") {
		return errors.New("test requires --fixtures and --identifier")
	}
	b, err := os.ReadFile(*path)
	if err != nil {
		return err
	}
	p, err := policy.Parse(b, *org)
	if err != nil {
		return err
	}
	if command == "validate" {
		fmt.Fprintln(out, "Policy valid (offline schema and constraints check).")
		return nil
	}
	b, err = os.ReadFile(*fixtures)
	if err != nil {
		return err
	}
	var s suite
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.UseNumber()
	dec.DisallowUnknownFields()
	if err = dec.Decode(&s); err != nil {
		return fmt.Errorf("invalid fixtures: %w", err)
	}
	if err = dec.Decode(new(any)); err != io.EOF {
		return errors.New("invalid fixtures: trailing JSON")
	}
	if len(s.Cases) == 0 {
		return errors.New("invalid fixtures: cases must be nonempty")
	}
	names := map[string]bool{}
	// Validate the whole suite before matching: malformed input cannot pass as an expected denial.
	for i, c := range s.Cases {
		if c.Name == "" || names[c.Name] {
			return fmt.Errorf("invalid fixture %d: name must be nonempty and unique", i+1)
		}
		names[c.Name] = true
		if c.Expect != "allow" && c.Expect != "deny" {
			return fmt.Errorf("invalid fixture %q: expect must be allow or deny", c.Name)
		}
		if err := validClaims(c.Claims); err != nil {
			return fmt.Errorf("invalid fixture %q: %w", c.Name, err)
		}
	}
	fmt.Fprintln(out, "Offline policy matching only; signatures, current-time validity, issuer trust and GitHub access are not verified.")
	failed := 0
	for _, c := range s.Cases {
		matchErr := p.Evaluate(c.Claims, *identifier)
		actual := "allow"
		if matchErr != nil {
			actual = "deny"
		}
		status := "PASS"
		if actual != c.Expect {
			status = "FAIL"
			failed++
		}
		fmt.Fprintf(out, "%s %s: expected %s, got %s", status, c.Name, c.Expect, actual)
		if matchErr != nil {
			fmt.Fprintf(out, " (%s)", matchErr)
		}
		fmt.Fprintln(out)
	}
	if failed > 0 {
		return fmt.Errorf("%d policy fixture(s) failed", failed)
	}
	return nil
}

func validClaims(c jwt.MapClaims) error {
	if c == nil {
		return errors.New("claims must be a JSON object")
	}
	for _, k := range []string{"iss", "sub"} {
		if v, ok := c[k].(string); !ok || v == "" {
			return fmt.Errorf("%s must be a nonempty string", k)
		}
	}
	aud, err := c.GetAudience()
	if err != nil || len(aud) == 0 {
		return errors.New("aud must be a string or nonempty array of strings")
	}
	for _, a := range aud {
		if a == "" {
			return errors.New("aud entries must be nonempty")
		}
	}
	for _, k := range []string{"iat", "exp", "nbf"} {
		if v, exists := c[k]; exists {
			n, ok := v.(json.Number)
			if !ok {
				return fmt.Errorf("%s must be integer seconds", k)
			}
			seconds, err := n.Int64()
			if err != nil || seconds < 0 || seconds > 253402300799 {
				return fmt.Errorf("%s must be integer seconds between 1970 and 9999", k)
			}
		}
	}
	if _, iat := c["iat"]; iat {
		if _, exp := c["exp"]; exp {
			i, _ := c.GetIssuedAt()
			e, _ := c.GetExpirationTime()
			if i == nil || e == nil || !e.After(i.Time) {
				return errors.New("exp must be after iat")
			}
		}
	}
	return nil
}
