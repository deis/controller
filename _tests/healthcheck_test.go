package _tests_test

import (
	"fmt"
	"net/http"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"github.com/onsi/gomega/gbytes"
	"github.com/onsi/gomega/gexec"
)

var _ = Describe("Healthcheck", func() {
	appName := getRandAppName()
	Context("with a deployed app", func() {
		// create and deploy an app
		BeforeEach(func() {
			login(url, testUser, testPassword)
			sess, err := start("deis apps:create %s", appName)
			Expect(err).To(BeNil())
			Eventually(sess).Should(gexec.Exit(0))
			Eventually(sess).Should(gbytes.Say("Creating Application... done, created %s", appName))
			sess, err = start("deis pull deis/example-go -a %s", appName)
			Expect(err).To(BeNil())
			Eventually(sess).Should(gexec.Exit(0))
			Eventually(sess).Should(gbytes.Say("Creating build... done"))
		})

		// destroy the app
		AfterEach(func() {
			sess, err := start("deis apps:destroy --confirm=%s", appName)
			Expect(err).To(BeNil())
			Eventually(sess).Should(gexec.Exit(0))
			Eventually(sess).Should(gbytes.Say("Destroying %s...", appName))
			Eventually(sess).Should(gbytes.Say("done in "))
			Eventually(sess).Should(gbytes.Say("Git remote deis removed"))
		})

		It("can stay running during a scale event", func() {
			router, err := getRawRouter()
			Expect(err).To(BeNil())
			appURLStr := fmt.Sprintf("%s://%s.%s", router.Scheme, appName, router.Host)
			stopCh := make(chan struct{})
			doneCh := make(chan struct{})

			// start scaling the app
			go func() {
				for range stopCh {
					sess, err := start("deis ps:scale web=4 -a %s", appName)
					Expect(err).To(BeNil())
					Eventually(sess).Should(gexec.Exit(0))
				}
				close(doneCh)
			}()

			for i := 0; i < 10; i++ {
				// start the scale operation. waits until the last scale op has finished
				stopCh <- struct{}{}
				resp, err := http.Get(appURLStr)
				Expect(err).To(BeNil())
				Expect(resp.StatusCode).To(BeEquivalentTo(http.StatusOK))
			}

			// wait until the goroutine that was scaling the app shuts down. not strictly necessary, just good practice
			Eventually(doneCh).Should(BeClosed())
		})

	})
})
