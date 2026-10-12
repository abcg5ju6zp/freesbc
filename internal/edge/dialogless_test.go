package edge

import (
	"testing"
	"time"

	"github.com/emiago/sipgo/sip"
)

// ghostDialog returns an INVITE and a 200 for a dialog the edge has no
// record of, so a BYE or INFO built from them names no dialog.
func ghostDialog(c *client) (*sip.Request, *sip.Response) {
	invite := c.buildInvite("2002", "1001", "example.com", phoneOfferSDP(4000))
	res := sip.NewResponseFromRequest(invite, 200, "OK", nil)
	res.To().Params.Add("tag", "ghost-tag")
	return invite, res
}

// A public BYE or INFO that names no dialog is forwarded to the switch only
// for a registered client or a carrier. A stranger gets 481, nothing reaches
// the switch, and the refusal is counted.
func TestDialoglessByeInfoAdmission(t *testing.T) {
	for _, method := range []sip.RequestMethod{sip.INFO, sip.BYE} {
		t.Run(string(method)+" unregistered source is 481 and counted", func(t *testing.T) {
			h := startHarnessStrict(t, false, false)
			stranger := newUDPClient(t)
			invite, res := ghostDialog(stranger)
			req := inDialogRequest(stranger, method, 2, invite, res)
			if got := stranger.do(t, req, h.publicUDP); got.StatusCode != 481 {
				t.Fatalf("got %d, want 481", got.StatusCode)
			}
			time.Sleep(200 * time.Millisecond)
			if n := len(h.fs.received(method)); n != 0 {
				t.Errorf("the switch saw %d %ss from an unregistered source", n, method)
			}
			if n := admissionDrops(h, dropDialogless); n != 1 {
				t.Errorf("dialogless_not_admitted drops = %d, want 1", n)
			}
		})
		t.Run(string(method)+" registered source is forwarded", func(t *testing.T) {
			h := startHarnessStrict(t, false, false)
			phone := newUDPClient(t)
			auditRegisterPhone(t, h, phone, "1001")
			invite, res := ghostDialog(phone)
			req := inDialogRequest(phone, method, 2, invite, res)
			if got := phone.do(t, req, h.publicUDP); got.StatusCode != 200 {
				t.Fatalf("got %d, want the switch's 200", got.StatusCode)
			}
			if n := len(h.fs.received(method)); n != 1 {
				t.Errorf("the switch saw %d %ss, want 1", n, method)
			}
			if n := admissionDrops(h, dropDialogless); n != 0 {
				t.Errorf("dialogless_not_admitted drops = %d, want 0", n)
			}
		})
	}
}
