// Copyright 2022 The Moov Authors
// Use of this source code is governed by an Apache License
// license that can be found in the LICENSE file.

package search

import (
	"encoding/json"
	"net/http"

	"github.com/kimchhorng/watchman/pkg/csl"
	moovhttp "github.com/moov-io/base/http"
	"github.com/moov-io/base/log"
)

// search EUCLS
func searchEUCSL(logger log.Logger, searcher *Searcher) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w = wrapResponseWriter(logger, w, r)
		requestID := moovhttp.GetRequestID(r)

		limit := extractSearchLimit(r)
		filters := buildFilterRequest(r.URL)
		minMatch := extractSearchMinMatch(r)

		name := r.URL.Query().Get("name")
		resp := buildFullSearchResponseWith(searcher, euGatherings, filters, limit, minMatch, name)

		logger.Info().With(log.Fields{
			"name":      log.String(name),
			"requestID": log.String(requestID),
		}).Log("performing EU-CSL search")

		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(resp)
	}
}

// TopEUCSL searches the EU Sanctions list by Name and Alias
func (s *Searcher) TopEUCSL(limit int, minMatch float64, name string) []*Result[csl.EUCSLRecord] {
	s.RLock()
	defer s.RUnlock()

	s.Gate.Start()
	defer s.Gate.Done()

	return topResults[csl.EUCSLRecord](limit, minMatch, name, s.EUCSL)
}
