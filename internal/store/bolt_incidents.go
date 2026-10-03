package store

import (
	bolt "go.etcd.io/bbolt"
)

// The incident buckets (incidents.go). They are record-level only: not in
// boltStateBuckets, never part of State, created on the first write.
var (
	boltBucketIncidents          = []byte("incidents")
	boltBucketMaintenanceWindows = []byte("maintenance_windows")
)

// LoadIncidents reads both incident buckets. A missing bucket reads as
// empty.
func (bs *BoltStateStore) LoadIncidents() ([]Incident, []MaintenanceWindow, error) {
	var (
		incidents []Incident
		windows   []MaintenanceWindow
	)
	err := bs.db.View(func(tx *bolt.Tx) error {
		if err := checkBoltVersion(tx); err != nil {
			return err
		}
		if err := forEachNotifyRecord(tx, boltBucketIncidents, func(inc Incident) { incidents = append(incidents, inc) }); err != nil {
			return err
		}
		return forEachNotifyRecord(tx, boltBucketMaintenanceWindows, func(w MaintenanceWindow) { windows = append(windows, w) })
	})
	return incidents, windows, err
}

// WriteIncidents applies one batch of incident changes in one transaction.
func (bs *BoltStateStore) WriteIncidents(w incidentWrite) error {
	return bs.db.Update(func(tx *bolt.Tx) error {
		if err := checkBoltVersion(tx); err != nil {
			return err
		}
		for _, bucket := range [][]byte{boltBucketIncidents, boltBucketMaintenanceWindows} {
			if _, err := tx.CreateBucketIfNotExists(bucket); err != nil {
				return err
			}
		}
		for _, id := range w.delIncidents {
			if err := deleteRecord(tx, boltBucketIncidents, id); err != nil {
				return err
			}
		}
		for _, inc := range w.putIncidents {
			if err := putRecord(tx, boltBucketIncidents, inc.ID, inc); err != nil {
				return err
			}
		}
		for _, id := range w.delWindows {
			if err := deleteRecord(tx, boltBucketMaintenanceWindows, id); err != nil {
				return err
			}
		}
		for _, mw := range w.putWindows {
			if err := putRecord(tx, boltBucketMaintenanceWindows, mw.ID, mw); err != nil {
				return err
			}
		}
		return nil
	})
}
