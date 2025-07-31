package main

import (
	"crypto/x509"
	"encoding/json"
	"fmt"
	"html/template"
	"net/http"
	"time"

	"github.com/dmwm/auth-proxy-server/cric"
	"github.com/dmwm/cmsauth"
)

// Dummy check functions — replace with real logic
func isCMSVOMember(cert *x509.Certificate) bool {
	// TODO: need proper check VO membership
	return true
	//return strings.Contains(cert.Subject.String(), "CMS")
}

func userDetails(cert *x509.Certificate) (cmsauth.CricEntry, error) {
	dnParts := getDNParts(cert)
	rec, err := cric.FindUser(dnParts)
	if err != nil {
		return rec, err
	}
	return rec, nil
}

func map2string(roles map[string][]string) string {
	data, err := json.MarshalIndent(roles, "", "   ")
	if err != nil {
		return fmt.Sprintf("%+v", roles)
	}
	return string(data)
}

var tmpl = template.Must(template.New("help").Parse(`
<!DOCTYPE html>
<html>
<head><title>Certificate authentication help</title></head>
<body>
<h2>Certificate authentication help</h2>
<p>Your browser offered valid DN '{{.DN}}'.</p>
<p>Your certificate is valid from {{.NotBefore}} to {{.NotAfter}}; {{.DaysRemaining}} days of validity remain.</p>
<p>Your certificate {{.Passed}} basic validation.</p>
<p>Your certificate is {{.CMSVOMember}}.</p>
<p>Your certificate is mapped to {{.Userdetails}} in CRIC database</p>
<p>For more details please see <a href="https://twiki.cern.ch/twiki/bin/view/CMS/DQMGUIGridCertificate">certificate setup instructions</a> for the most commonly needed steps.</p>
</body>
</html>
`))

func authTroubleHandler(w http.ResponseWriter, r *http.Request) {
	if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
		http.Error(w, "No client certificate provided", http.StatusUnauthorized)
		return
	}

	cert := r.TLS.PeerCertificates[0]
	dn := cert.Subject.String()
	notBefore := cert.NotBefore.UTC().Format("Jan 2 15:04:05 2006 GMT")
	notAfter := cert.NotAfter.UTC().Format("Jan 2 15:04:05 2006 GMT")
	daysRemaining := int(time.Until(cert.NotAfter).Hours() / 24)

	// validation steps
	cmsVOMember := "CMS VO member"
	if !isCMSVOMember(cert) {
		cmsVOMember = "not CMS VO member"
	}
	passed := "passed"
	if daysRemaining < 0 {
		passed = "not passed"
	}

	var details string
	if rec, err := userDetails(cert); err == nil {
		details = fmt.Sprintf("<br/><b>Name:</b> %s<br/><b>Login:</b> %s<br/><b>ID:</b> %v<br/><b>Roles:</b> %+v<br/><b>DNs:</b> %v<br/>",
			rec.Name, rec.Login, rec.ID, map2string(rec.Roles), rec.DNs)
	} else {
		details = err.Error()
	}

	data := struct {
		DN            string
		NotBefore     string
		NotAfter      string
		DaysRemaining int
		Userdetails   template.HTML
		Passed        string
		CMSVOMember   string
	}{
		DN:            dn,
		NotBefore:     notBefore,
		NotAfter:      notAfter,
		DaysRemaining: daysRemaining,
		Userdetails:   template.HTML(details),
		Passed:        passed,
		CMSVOMember:   cmsVOMember,
	}

	err := tmpl.Execute(w, data)
	if err != nil {
		http.Error(w, "Internal template error", http.StatusInternalServerError)
	}
}
