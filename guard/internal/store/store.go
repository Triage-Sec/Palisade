package store

import "database/sql"

// Store provides access to the PostgreSQL database for project and policy CRUD.
type Store struct {
	db *sql.DB
}

// NewStore creates a Store backed by the given database connection pool.
func NewStore(db *sql.DB) *Store {
	return &Store{db: db}
}
