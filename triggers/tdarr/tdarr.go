package tdarr

import (
	"encoding/json"
	"net/http"
	"path"
	"time"

	"github.com/buroa/autoscan"
	"github.com/rs/zerolog/hlog"
)

type Config struct {
	Name      string             `yaml:"name"`
	Priority  int                `yaml:"priority"`
	Rewrite   []autoscan.Rewrite `yaml:"rewrite"`
	Verbosity string             `yaml:"verbosity"`
}

// New creates an autoscan-compatible HTTP Trigger for Tdarr webhooks.
func New(c Config) (autoscan.HTTPTrigger, error) {
	rewriter, err := autoscan.NewRewriter(c.Rewrite)
	if err != nil {
		return nil, err
	}

	trigger := func(callback autoscan.ProcessorFunc) http.Handler {
		return handler{
			callback: callback,
			priority: c.Priority,
			rewrite:  rewriter,
		}
	}

	return trigger, nil
}

type handler struct {
	priority int
	rewrite  autoscan.Rewriter
	callback autoscan.ProcessorFunc
}

type tdarrEvent struct {
	Type    string `json:"eventType"`
	File    string `json:"file"`
	Analyze bool   `json:"analyze"`

	Meta struct {
		Directory string
	} `json:"meta"`
}

func (h handler) ServeHTTP(rw http.ResponseWriter, r *http.Request) {
	var err error
	rlog := hlog.FromRequest(r)

	event := new(tdarrEvent)
	err = json.NewDecoder(r.Body).Decode(event)
	if err != nil {
		rlog.Error().Err(err).Msg("Failed decoding request")
		rw.WriteHeader(http.StatusBadRequest)
		return
	}

	rlog.Trace().Interface("event", event).Msg("Received JSON body")

	if event.Type == "Test" {
		rlog.Debug().Msg("Received test event")
		rw.WriteHeader(http.StatusOK)
		return
	}

	if event.Type != "Transcoded" || event.File == "" || event.Meta.Directory == "" {
		rlog.Error().Msg("Required fields are missing")
		rw.WriteHeader(http.StatusBadRequest)
		return
	}

	// Rewrite the path based on the provided rewriter.
	folderPath := path.Dir(h.rewrite(path.Join(event.Meta.Directory, event.File)))

	scan := autoscan.Scan{
		Folder:   folderPath,
		Priority: h.priority,
		Analyze:  event.Analyze,
		Time:     now(),
	}

	err = h.callback(scan)
	if err != nil {
		rlog.Error().Err(err).Msg("Processor could not process scan")
		rw.WriteHeader(http.StatusInternalServerError)
		return
	}

	rw.WriteHeader(http.StatusOK)
	rlog.Info().
		Str("path", folderPath).
		Msg("Scan moved to processor")
}

var now = time.Now
