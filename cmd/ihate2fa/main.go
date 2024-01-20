package main

import (
	"bytes"
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"sync/atomic"
	"syscall"
	"text/tabwriter"
	"time"

	"github.com/IlyaFloppy/ihate2fa/internal"
	"github.com/IlyaFloppy/ihate2fa/internal/migration"
	"github.com/IlyaFloppy/ihate2fa/internal/vault"
	"github.com/getlantern/systray"
	"golang.design/x/clipboard"
)

var (
	fLink   = flag.String("add", "", "add otp's from link like \"otpauth-migration://offline?data=...\"")
	fClean  = flag.Bool("clean", false, "clean all otp's saved by ihate2fa")
	fGen    = flag.Bool("gen", true, "generate otp's")
	fGenAcc = flag.String("acc", "", "generate otp for single account")
	fTray   = flag.Bool("tray", false, "run app in system tray")
)

func init() {
	flag.Parse()
}

func main() {
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGTERM, os.Interrupt)
	defer cancel()

	a := NewApp()
	err := a.Run(ctx)
	if err != nil && !errors.Is(err, context.Canceled) {
		fmt.Fprintf(os.Stderr, "failed to run ihate2fa: %s\n", err.Error())
		os.Exit(1)
	}

	return
}

type App struct {
	parser migration.Parser
	store  *vault.Store
}

func NewApp() *App {
	parser := migration.NewParser()
	store := vault.NewStore(parser)

	return &App{
		parser: parser,
		store:  store,
	}
}

func (a *App) Run(ctx context.Context) error {
	switch {
	case *fTray:
		return a.modRunInSystemTray(ctx)
	case *fClean:
		return a.modClean()
	case *fLink != "":
		return a.modAddLink(*fLink)
	case *fGenAcc != "":
		return a.modGenerateAccount(*fGenAcc)
	case *fGen:
		return a.modGenerate()
	}

	return nil
}

func (a *App) modClean() error {
	return a.store.Clean()
}

func (a *App) modRunInSystemTray(ctx context.Context) error {
	var (
		params atomic.Pointer[[]internal.OtpParameter]

		quitItem    *systray.MenuItem
		refreshItem *systray.MenuItem
		items       []*systray.MenuItem
	)

	err := clipboard.Init()
	if err != nil {
		panic(err)
	}

	refreshOtps := func() {
		list, err := a.store.List()
		if err != nil {
			panic(err)
		}
		params.Store(&list)
	}
	refreshOtps() // refresh on start.

	refreshHandler := func() {
		for {
			select {
			case <-ctx.Done():
				return
			case <-refreshItem.ClickedCh:
				refreshOtps()
			}
		}
	}

	quitHandler := func() {
		select {
		case <-ctx.Done():
		case <-quitItem.ClickedCh:
		}

		systray.Quit()
	}

	itemHandler := func(index int) {
		for {
			select {
			case <-ctx.Done():
				return
			case <-items[index].ClickedCh:
				params := *params.Load()
				code, _ := params[index].Data().Generate()
				_ = clipboard.Write(clipboard.FmtText, []byte(code))
			}
		}
	}

	uiHandler := func() {
		for {
			params := *params.Load()

			var buf bytes.Buffer
			tab := tabwriter.NewWriter(&buf, 1, 1, 4, ' ', 0)
			for i, param := range params {
				code, err := param.Data().Generate()
				if err != nil {
					code = err.Error()
				}

				_, _ = fmt.Fprintf(tab, "%d.\t%s\t%s\n",
					i+1,
					code,
					param.Data().Name,
				)
			}

			tab.Flush()
			lines := strings.Split(buf.String(), "\n")
			lines = lines[:len(lines)-1]
			for i, line := range lines {
				item := items[i]
				item.SetTitle(line)
				item.SetTooltip("Click to copy OTP for " + params[i].Data().Name)
				item.Show()
			}
			for _, item := range items[len(lines):] {
				item.Hide()
			}

			time.Sleep(time.Second)
		}
	}

	onReady := func() {
		systray.SetTitle("( ˘_˘ )")
		for i := 0; i < 20; i++ {
			item := systray.AddMenuItem("", "")
			item.Hide()
			items = append(items, item)

			go itemHandler(i)
		}
		systray.AddSeparator()
		refreshItem = systray.AddMenuItem("Refresh", "Refresh OTP's from keychain")
		quitItem = systray.AddMenuItem("Quit", "Quit ihate2fa")

		go refreshHandler()
		go quitHandler()
		go uiHandler()
	}

	onExit := func() {}

	systray.Run(onReady, onExit)
	return nil
}

func (a *App) modAddLink(link string) error {
	payload, err := a.parser.Parse(*fLink)
	if err != nil {
		panic(err)
	}

	var errs []error
	for _, op := range payload.OtpParameters {
		err := a.store.Add(op)
		errs = append(errs, err)
	}

	return errors.Join(errs...)
}

func (a *App) modGenerate() error {
	params, err := a.store.List()
	if err != nil {
		return err
	}

	for i, param := range params {
		code, err := param.Data().Generate()
		if err != nil {
			code = err.Error()
		}
		fmt.Printf("%d.\t%s:\t%s\n", i+1, param.Data().Name, code)
	}

	return nil
}

func (a *App) modGenerateAccount(account string) error {
	param, err := a.store.Get(account)
	if err != nil {
		return err
	}

	code, err := param.Data().Generate()
	if err != nil {
		code = err.Error()
	}
	fmt.Println(code)
	return nil
}
