package uafvalidate

import (
	"encoding/json"
	"sync"
	"time"

	"github.com/google/syzkaller/pkg/db"
	"github.com/google/syzkaller/pkg/ddrd"
	"github.com/google/syzkaller/pkg/fuzzer"
	"github.com/google/syzkaller/pkg/log"
)

const (
	collectionMissFreeAttempts = 2
	collectionMissWeight       = 0.25
	collectionMissMaxDefer     = 0.75
)

type ReproductionBackoffConfig struct {
	FreeAttempts int
	Weight       float64
	MaxDefer     float64
}

func normalizeReproductionBackoffConfig(config ReproductionBackoffConfig) ReproductionBackoffConfig {
	if config.FreeAttempts <= 0 {
		config.FreeAttempts = collectionMissFreeAttempts
	}
	if config.Weight <= 0 {
		config.Weight = collectionMissWeight
	}
	if config.MaxDefer <= 0 || config.MaxDefer >= 1 {
		config.MaxDefer = collectionMissMaxDefer
	}
	return config
}

// ReproductionBackoffStats is separate from targeted-scheduling failure Fp.
// It only captures whether collection reproduced a stable VarName family.
type ReproductionBackoffStats struct {
	Attempts          int       `json:"attempts"`
	Hits              int       `json:"hits"`
	Misses            int       `json:"misses"`
	ConsecutiveMisses int       `json:"consecutive_misses"`
	LastAttempt       time.Time `json:"last_attempt"`
}

func (stats *ReproductionBackoffStats) DeferProbability() float64 {
	return stats.deferProbability(normalizeReproductionBackoffConfig(ReproductionBackoffConfig{}))
}

func (stats *ReproductionBackoffStats) deferProbability(config ReproductionBackoffConfig) float64 {
	if stats == nil || stats.ConsecutiveMisses <= config.FreeAttempts {
		return 0
	}
	effective := config.Weight * float64(stats.ConsecutiveMisses-config.FreeAttempts)
	probability := effective / (effective + 1)
	if probability > config.MaxDefer {
		return config.MaxDefer
	}
	return probability
}

// ReproductionBackoffStore persists soft collection-miss feedback by canonical
// unordered VarName family.
type ReproductionBackoffStore struct {
	mu     sync.RWMutex
	db     *db.DB
	cache  map[string]*ReproductionBackoffStats
	config ReproductionBackoffConfig
}

func NewReproductionBackoffStore(database *db.DB, configs ...ReproductionBackoffConfig) *ReproductionBackoffStore {
	config := ReproductionBackoffConfig{}
	if len(configs) != 0 {
		config = configs[0]
	}
	config = normalizeReproductionBackoffConfig(config)
	store := &ReproductionBackoffStore{
		db:     database,
		cache:  make(map[string]*ReproductionBackoffStats),
		config: config,
	}
	if database != nil {
		for key, record := range database.Records {
			var stats ReproductionBackoffStats
			if err := json.Unmarshal(record.Val, &stats); err != nil {
				log.Logf(0, "reproduction_backoff: failed to parse %s: %v", key, err)
				continue
			}
			store.cache[key] = &stats
		}
		log.Logf(0, "reproduction_backoff: loaded %d VarName families", len(store.cache))
	}
	log.Logf(0, "reproduction_backoff: config free_attempts=%d weight=%.3f max_defer=%.3f",
		config.FreeAttempts, config.Weight, config.MaxDefer)
	return store
}

func entryVarNameFamilies(entry *fuzzer.UAFCorpusEntry) []string {
	if entry == nil {
		return nil
	}
	seen := make(map[string]struct{})
	var families []string
	add := func(pair *ddrd.MayUAFPair) {
		key := canonicalVarNameFamilyKey(pair)
		if key == "" {
			return
		}
		if _, exists := seen[key]; exists {
			return
		}
		seen[key] = struct{}{}
		families = append(families, key)
	}
	for _, pair := range entry.Pairs {
		add(pair)
	}
	if len(families) == 0 && (entry.PairBasicInfo.FreeAccessName != 0 || entry.PairBasicInfo.UseAccessName != 0) {
		add(&entry.PairBasicInfo)
	}
	return families
}

func (store *ReproductionBackoffStore) ShouldDeferEntry(entry *fuzzer.UAFCorpusEntry,
	randomFloat func() float64) (bool, float64) {
	if store == nil || randomFloat == nil {
		return false, 0
	}
	families := entryVarNameFamilies(entry)
	if len(families) == 0 {
		return false, 0
	}
	store.mu.RLock()
	probability := 0.0
	for _, family := range families {
		probability += store.cache[family].deferProbability(store.config)
	}
	store.mu.RUnlock()
	probability /= float64(len(families))
	return probability > 0 && randomFloat() < probability, probability
}

func (store *ReproductionBackoffStore) RecordCollection(entry *fuzzer.UAFCorpusEntry,
	stablePairs []StablePairWithDelays) {
	if store == nil {
		return
	}
	originFamilies := entryVarNameFamilies(entry)
	if len(originFamilies) == 0 {
		return
	}
	hits := make(map[string]struct{})
	for _, stable := range stablePairs {
		if key := canonicalVarNameFamilyKey(&stable.Pair); key != "" {
			hits[key] = struct{}{}
		}
	}

	store.mu.Lock()
	defer store.mu.Unlock()
	for _, family := range originFamilies {
		stats := store.cache[family]
		if stats == nil {
			stats = &ReproductionBackoffStats{}
			store.cache[family] = stats
		}
		stats.Attempts++
		stats.LastAttempt = time.Now()
		if _, reproduced := hits[family]; reproduced {
			stats.Hits++
			stats.ConsecutiveMisses = 0
		} else {
			stats.Misses++
			stats.ConsecutiveMisses++
		}
		store.saveLocked(family, stats)
	}
	if store.db != nil {
		if err := store.db.Flush(); err != nil {
			log.Logf(0, "reproduction_backoff: failed to flush db: %v", err)
		}
	}
}

func (store *ReproductionBackoffStore) saveLocked(key string, stats *ReproductionBackoffStats) {
	if store.db == nil {
		return
	}
	data, err := json.Marshal(stats)
	if err != nil {
		log.Logf(0, "reproduction_backoff: failed to marshal %s: %v", key, err)
		return
	}
	store.db.Save(key, data, 0)
}
