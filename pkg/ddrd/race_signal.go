package ddrd

// Race signal types - using uint64 to match MayRacePair.Signal
type (
	elemType uint64 // Use uint64 for race signals (vs uint32 for normal signals)
	prioType int8   // Same priority type as normal signals
)

// Signal represents a mapping from elemType to prioType, used for feedback signal.
type Signal map[elemType]prioType

// Serial represents a serializable form of Signal with separate element and priority slices.
type Serial struct {
	Elems []elemType
	Prios []prioType
}

// Len returns the number of elements in the signal.
func (s Signal) Len() int {
	return len(s)
}

// Empty returns true if the signal contains no elements.
func (s Signal) Empty() bool {
	return len(s) == 0
}

// Copy creates a deep copy of the signal.
func (s Signal) Copy() Signal {
	c := make(Signal, len(s))
	for e, p := range s {
		c[e] = p
	}
	return c
}

// Split removes up to n elements from the signal and returns them as a new signal.
func (s *Signal) Split(n int) Signal {
	if s.Empty() {
		return nil
	}
	c := make(Signal, n)
	for e, p := range *s {
		delete(*s, e)
		c[e] = p
		n--
		if n == 0 {
			break
		}
	}
	if len(*s) == 0 {
		*s = nil
	}
	return c
}

// FromRaw creates a signal from raw uint32 elements with the given priority.
func FromRaw(raw []uint32, prio uint8) Signal {
	if len(raw) == 0 {
		return nil
	}
	s := make(Signal, len(raw))
	for _, e := range raw {
		s[elemType(e)] = prioType(prio)
	}
	return s
}

// Serialize converts the signal to a serializable form.
func (s Signal) Serialize() Serial {
	if s.Empty() {
		return Serial{}
	}
	res := Serial{
		Elems: make([]elemType, len(s)),
		Prios: make([]prioType, len(s)),
	}
	i := 0
	for e, p := range s {
		res.Elems[i] = e
		res.Prios[i] = p
		i++
	}
	return res
}

// AddElem adds an element with the given priority to the serial.
func (ser *Serial) AddElem(elem uint32, prio prioType) {
	ser.Elems = append(ser.Elems, elemType(elem))
	ser.Prios = append(ser.Prios, prio)
}

// Deserialize converts the serial back to a signal.
func (ser Serial) Deserialize() Signal {
	if len(ser.Elems) != len(ser.Prios) {
		panic("corrupted Serial")
	}
	if len(ser.Elems) == 0 {
		return nil
	}
	s := make(Signal, len(ser.Elems))
	for i, e := range ser.Elems {
		s[e] = ser.Prios[i]
	}
	return s
}

// Diff returns elements from s1 that are not in s or have higher priority.
func (s Signal) Diff(s1 Signal) Signal {
	if s1.Empty() {
		return nil
	}
	var res Signal
	for e, p1 := range s1 {
		if p, ok := s[e]; ok && p >= p1 {
			continue
		}
		if res == nil {
			res = make(Signal)
		}
		res[e] = p1
	}
	return res
}

// DiffRaw returns elements from raw that are not in s or have higher priority.
func (s Signal) DiffRaw(raw []uint32, prio uint8) Signal {
	var res Signal
	for _, e := range raw {
		if p, ok := s[elemType(e)]; ok && p >= prioType(prio) {
			continue
		}
		if res == nil {
			res = make(Signal)
		}
		res[elemType(e)] = prioType(prio)
	}
	return res
}

// Intersection returns elements that exist in both signals with the minimum priority.
func (s Signal) Intersection(s1 Signal) Signal {
	if s1.Empty() {
		return nil
	}
	res := make(Signal, len(s))
	for e, p := range s {
		if p1, ok := s1[e]; ok && p1 >= p {
			res[e] = p
		}
	}
	return res
}

// Merge merges s1 into s, keeping the maximum priority for each element.
func (s *Signal) Merge(s1 Signal) {
	if s1.Empty() {
		return
	}
	s0 := *s
	if s0 == nil {
		s0 = make(Signal, len(s1))
		*s = s0
	}
	for e, p1 := range s1 {
		if p, ok := s0[e]; !ok || p < p1 {
			s0[e] = p1
		}
	}
}

// Context represents a signal with associated context information.
type Context struct {
	Signal  Signal
	Context interface{}
}

// Minimize returns a minimal set of contexts that cover all signal elements.
func Minimize(corpus []Context) []interface{} {
	type ContextPrio struct {
		prio prioType
		idx  int
	}
	covered := make(map[elemType]ContextPrio)
	for i, inp := range corpus {
		for e, p := range inp.Signal {
			if prev, ok := covered[e]; !ok || p > prev.prio {
				covered[e] = ContextPrio{
					prio: p,
					idx:  i,
				}
			}
		}
	}
	indices := make(map[int]struct{}, len(corpus))
	for _, cp := range covered {
		indices[cp.idx] = struct{}{}
	}
	result := make([]interface{}, 0, len(indices))
	for idx := range indices {
		result = append(result, corpus[idx].Context)
	}
	return result
}

// ===============DDRD Race Signal Extensions====================

// FromRacePairs creates a race signal from MayRacePair slice
func FromRacePairs(pairs []MayRacePair, prio uint8) Signal {
	if len(pairs) == 0 {
		return nil
	}
	s := make(Signal)
	for _, pair := range pairs {
		if pair.Signal != 0 {
			s[elemType(pair.Signal)] = prioType(prio)
		}
	}
	return s
}

// ToRawUint64 converts signal elements to []uint64 for race processing
func (s Signal) ToRawUint64() []uint64 {
	if s.Empty() {
		return nil
	}
	raw := make([]uint64, 0, len(s))
	for e := range s {
		raw = append(raw, uint64(e))
	}
	return raw
}

// MergeRacePairs merges race pairs into existing signal
func (s *Signal) MergeRacePairs(pairs []MayRacePair, prio uint8) {
	if len(pairs) == 0 {
		return
	}
	s0 := *s
	if s0 == nil {
		s0 = make(Signal)
		*s = s0
	}
	for _, pair := range pairs {
		if pair.Signal != 0 {
			elem := elemType(pair.Signal)
			if p, ok := s0[elem]; !ok || p < prioType(prio) {
				s0[elem] = prioType(prio)
			}
		}
	}
}
