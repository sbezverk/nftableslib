package nftableslib

import "fmt"

func (r *nfRules) addRule(e *nfRule) {
	if r.rules == nil {
		r.Lock()
		defer r.Unlock()
		r.rules = e
		r.rules.next = nil
		r.rules.prev = nil
		r.rules.id = r.currentID
		r.currentID += 10
		return
	}
	last := getLast(r.rules)
	last.Lock()
	defer last.Unlock()
	last.next = e
	last.next.next = nil
	last.next.prev = last
	last.next.id = r.currentID
	r.currentID += 10

	return
}

func (r *nfRules) removeRule(id uint32) error {
	e := r.rules
	for ; e != nil; e = e.next {
		if e.id == id {
			if e.prev == nil {
				if e.next == nil {
					// Deleting first and the only element in the list
					r.Lock()
					defer r.Unlock()
					r.rules = nil
					return nil
				}
				r.rules = e.next
			} else {
				e.prev.Lock()
				defer e.prev.Unlock()
				e.prev.next = e.next
			}
			if e.next != nil {
				e.next.Lock()
				defer e.next.Unlock()
				e.next.prev = e.prev
			}
			return nil
		}
	}

	return fmt.Errorf("id %d is not found", id)
}

func (r *nfRules) countRules() int {
	count := 0
	e := r.rules
	for ; e != nil; e = e.next {
		count++
	}
	return count
}

func (r *nfRules) dumpRules() []*nfRule {
	rr := []*nfRule{}
	e := r.rules
	for ; e != nil; e = e.next {
		rr = append(rr, e)
	}
	return rr
}

func getLast(e *nfRule) *nfRule {
	if e.next == nil {
		return e
	}
	return getLast(e.next)
}
